import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { createReadStream } from 'node:fs';
import cors from '@fastify/cors';
import multipart from '@fastify/multipart';
import rateLimit from '@fastify/rate-limit';
import {
  CreateSignRequestMeta,
  MAX_PDF_BYTES,
  SIGN_REQUEST_TTL_MS,
  SignRequestState,
  type CreateSignRequestResponse,
  type SignRequestStatusResponse,
} from '@kysoqr/shared';
import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import { z } from 'zod';
import { CasError, type CasClient } from './cas-client';
import type { Env } from './env';
import { SignService } from './service';
import type { SignRequestRow, Store } from './store';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

function safeEqual(a: string, b: string) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

const WebhookPayload = z.object({
  webhookType: z.string(),
  webhookCode: z.string().optional(),
  signRequest: z
    .object({
      signRequestId: z.string(),
      state: SignRequestState,
      signedAt: z.string().nullish(),
      identityKey: z.string().nullish(),
      identityKeyExpiresAt: z.string().nullish(),
      orgIdSigned: z.string().nullish(),
    })
    .passthrough()
    .optional(),
});

export interface AppDeps {
  env: Env;
  store: Store;
  cas: CasClient;
  now?: () => number;
}

export async function buildApp({ env, store, cas, now = Date.now }: AppDeps) {
  const app = Fastify({
    logger: { redact: ['req.headers["x-access-token"]', 'req.query.token'] },
    trustProxy: true,
    bodyLimit: 1024 * 1024,
  });
  const service = new SignService(store, cas, app.log, now);
  app.decorate('signService', service);

  await app.register(cors, {
    origin: env.EXTENSION_ORIGINS.length ? env.EXTENSION_ORIGINS : /^chrome-extension:\/\//,
    allowedHeaders: ['content-type', 'x-access-token'],
  });
  await app.register(rateLimit, { global: false });
  await app.register(multipart, { limits: { fileSize: MAX_PDF_BYTES, files: 1, fields: 5 } });

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof CasError) {
      req.log.error({ status: err.status, body: err.body }, 'lỗi từ CAS');
      return reply.code(502).send({ error: 'CAS_ERROR', casStatus: err.status, detail: err.body });
    }
    if (err instanceof z.ZodError) {
      return reply.code(400).send({ error: 'INVALID_INPUT', issues: err.issues });
    }
    reply.send(err);
  });

  const toStatus = (row: SignRequestRow): SignRequestStatusResponse => ({
    signRequestId: row.signRequestId,
    state: row.state,
    signedAt: row.signedAt,
    expiresAt: new Date(row.expiresAt).toISOString(),
    expired: row.state === 'NEW' && now() > row.expiresAt,
    fileReady: row.filePath !== null,
    hasSigningRound: row.orgIdSigned !== null,
  });

  /** Chỉ extension đã tạo yêu cầu (có accessToken) mới xem được. */
  function authorize(req: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) {
    const row = store.get(req.params.id);
    const token = req.headers['x-access-token'];
    if (!row || typeof token !== 'string' || !safeEqual(sha256(token), row.accessTokenHash)) {
      reply.code(404).send({ error: 'NOT_FOUND' });
      return undefined;
    }
    return row;
  }

  app.get('/healthz', async () => ({ ok: true }));

  app.post(
    '/api/sign-requests',
    { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } },
    async (req, reply) => {
      let file: { bytes: Uint8Array; name: string } | undefined;
      let metaRaw: string | undefined;
      for await (const part of req.parts()) {
        if (part.type === 'file' && part.fieldname === 'file') {
          const buf = await part.toBuffer();
          if (part.file.truncated) return reply.code(413).send({ error: 'FILE_TOO_LARGE' });
          file = { bytes: new Uint8Array(buf), name: part.filename || 'document.pdf' };
        } else if (part.type === 'field' && part.fieldname === 'meta') {
          metaRaw = String(part.value);
        }
      }
      if (!file || !metaRaw) return reply.code(400).send({ error: 'MISSING_FILE_OR_META' });
      if (Buffer.from(file.bytes.subarray(0, 5)).toString('latin1') !== '%PDF-') {
        return reply.code(400).send({ error: 'NOT_A_PDF' });
      }
      const meta = CreateSignRequestMeta.parse(JSON.parse(metaRaw));

      const signRequestId = randomUUID();
      const accessToken = randomBytes(32).toString('base64url');
      const result = await cas.requestDocument({
        signRequestId,
        documentName: meta.documentName,
        file: file.bytes,
        fileName: file.name,
        signatureFields: meta.signatureFields,
        identificationNumber: meta.identificationNumber,
        language: meta.language,
      });

      req.log.info({ signRequestId, casResponseShape: result.shape }, 'CAS request-document trả về');
      const pushSent = Boolean(meta.identificationNumber);
      const initialState = SignRequestState.catch('NEW').parse(result.state);
      if (!result.qrContent && !pushSent) {
        // Không có QR và không gửi push → người dùng không có cách nào để ký.
        req.log.error({ signRequestId, casResponseShape: result.shape }, 'CAS không trả về qrContent');
        return reply.code(502).send({ error: 'CAS_NO_QR', casResponseShape: result.shape });
      }

      const createdAt = now();
      store.insert({
        signRequestId,
        accessTokenHash: sha256(accessToken),
        documentName: meta.documentName,
        state: initialState,
        createdAt,
        expiresAt: createdAt + SIGN_REQUEST_TTL_MS,
        lastSyncedAt: createdAt,
      });
      req.log.info({ signRequestId, fields: meta.signatureFields.length }, 'đã tạo yêu cầu ký');

      const body: CreateSignRequestResponse = {
        signRequestId,
        accessToken,
        qrContent: result.qrContent ?? '',
        state: initialState,
        pushSent,
        expiresAt: new Date(createdAt + SIGN_REQUEST_TTL_MS).toISOString(),
      };
      return reply.code(201).send(body);
    },
  );

  app.get<{ Params: { id: string } }>(
    '/api/sign-requests/:id',
    { config: { rateLimit: { max: 120, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const row = authorize(req, reply);
      if (!row) return;
      return toStatus(await service.syncIfStale(row));
    },
  );

  app.get<{ Params: { id: string } }>('/api/sign-requests/:id/file', async (req, reply) => {
    const row = authorize(req, reply);
    if (!row) return;
    if (!row.filePath) return reply.code(409).send({ error: 'FILE_NOT_READY' });
    return reply
      .type('application/pdf')
      .header('Cache-Control', 'no-store')
      .send(createReadStream(row.filePath));
  });

  app.get<{ Params: { id: string } }>('/api/sign-requests/:id/signing-round', async (req, reply) => {
    const row = authorize(req, reply);
    if (!row) return;
    if (!row.orgIdSigned) return reply.code(409).send({ error: 'SIGNING_ROUND_NOT_READY' });
    return cas.signingRound(row.orgIdSigned);
  });

  /**
   * Webhook SIGN từ CAS. CAS không ký payload, nên bảo vệ bằng token bí mật trong URL
   * (+ lọc IP nếu có cấu hình). Luôn trả 200 nhanh để CAS không gửi lại.
   */
  app.post<{ Querystring: { token?: string } }>('/webhooks/cas-sign', async (req, reply) => {
    if (!env.CAS_WEBHOOK_TOKEN) {
      return reply.code(503).send({ error: 'WEBHOOK_DISABLED' });
    }
    if (!req.query.token || !safeEqual(req.query.token, env.CAS_WEBHOOK_TOKEN)) {
      return reply.code(401).send({ error: 'UNAUTHORIZED' });
    }
    if (env.CAS_WEBHOOK_ALLOWED_IPS.length && !env.CAS_WEBHOOK_ALLOWED_IPS.includes(req.ip)) {
      req.log.warn({ ip: req.ip }, 'webhook từ IP không nằm trong danh sách cho phép');
      return reply.code(403).send({ error: 'FORBIDDEN' });
    }

    const parsed = WebhookPayload.safeParse(req.body);
    if (!parsed.success || parsed.data.webhookType !== 'SIGN' || !parsed.data.signRequest) {
      req.log.info({ webhookType: (req.body as { webhookType?: unknown })?.webhookType }, 'bỏ qua webhook');
      return { ok: true };
    }
    const sr = parsed.data.signRequest;
    // Log tên các field (không log giá trị) để đối chiếu với tài liệu CAS.
    req.log.info(
      { signRequestId: sr.signRequestId, state: sr.state, fields: Object.keys(sr) },
      'nhận webhook SIGN',
    );

    const row = store.get(sr.signRequestId);
    if (!row) return { ok: true };
    service.applyUpdate(row, sr);
    return { ok: true };
  });

  return app;
}

declare module 'fastify' {
  interface FastifyInstance {
    signService: SignService;
  }
}
