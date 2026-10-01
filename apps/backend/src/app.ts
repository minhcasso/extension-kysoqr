import { randomUUID } from 'node:crypto';
import cors from '@fastify/cors';
import multipart, { type MultipartFile } from '@fastify/multipart';
import rateLimit from '@fastify/rate-limit';
import {
  CreateSignRequestMeta,
  MAX_PDF_BYTES,
  SIGN_REQUEST_TTL_MS,
  SignRequestState,
  type CreateSignRequestResponse,
  type SignRequestStatusResponse,
} from '@kysoqr/shared';
import Fastify, { type FastifyRequest } from 'fastify';
import { z } from 'zod';
import { CasError, type CasClient } from './cas-client';
import type { Env } from './env';
import type { TrustStore } from './trustStore/TrustStore';
import { getTrustStore } from './trustStore/getTrustStore';
import { verifyPdfSignatures } from './verification/verifyPdfSignatures';

export interface AppDeps {
  env: Env;
  cas: CasClient;
  trustStore?: TrustStore;
}

const isPdf = (bytes: Uint8Array) =>
  Buffer.from(bytes.subarray(0, 5)).toString('latin1') === '%PDF-';

const SignRequestId = z.string().uuid();
const DownloadBody = z.object({ identityKey: z.string().min(1).max(200) });

/**
 * Backend không lưu gì (không DB, không file): chỉ giữ khoá CAS và chuyển tiếp yêu cầu.
 * File đã ký đi thẳng từ CAS về extension; xác minh chữ ký chạy trong bộ nhớ.
 */
export async function buildApp({ env, cas, trustStore = getTrustStore() }: AppDeps) {
  const app = Fastify({
    logger: { redact: ['req.body.identityKey'] },
    trustProxy: true,
    bodyLimit: 1024 * 1024,
  });
  if (!trustStore.isConfigured()) {
    app.log.warn('Không nạp được Root CA nào trong src/trustStore/roots: xác minh chữ ký sẽ không tới được gốc.');
  }

  await app.register(cors, {
    origin: env.EXTENSION_ORIGINS.length ? env.EXTENSION_ORIGINS : /^chrome-extension:\/\//,
    allowedHeaders: ['content-type'],
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

  /** Đọc file PDF (và field `meta` nếu có) từ multipart. */
  async function readPdfUpload(
    req: FastifyRequest,
  ): Promise<
    | { error: string; status: number }
    | { file: { bytes: Uint8Array; name: string }; meta: string | undefined }
  > {
    let file: { bytes: Uint8Array; name: string } | undefined;
    let meta: string | undefined;
    for await (const part of req.parts()) {
      if (part.type === 'file' && part.fieldname === 'file') {
        const buf = await (part as MultipartFile).toBuffer();
        if (part.file.truncated) return { error: 'FILE_TOO_LARGE', status: 413 };
        file = { bytes: new Uint8Array(buf), name: part.filename || 'document.pdf' };
      } else if (part.type === 'field' && part.fieldname === 'meta') {
        meta = String(part.value);
      }
    }
    if (!file) return { error: 'MISSING_FILE', status: 400 };
    if (!isPdf(file.bytes)) return { error: 'NOT_A_PDF', status: 400 };
    return { file, meta };
  }

  app.get('/healthz', async () => ({ ok: true }));

  app.post(
    '/api/sign-requests',
    { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const upload = await readPdfUpload(req);
      if ('error' in upload) return reply.code(upload.status).send({ error: upload.error });
      if (!upload.meta) return reply.code(400).send({ error: 'MISSING_FILE_OR_META' });
      const { file } = upload;
      const meta = CreateSignRequestMeta.parse(JSON.parse(upload.meta));

      const signRequestId = randomUUID();
      const result = await cas.requestDocument({
        signRequestId,
        documentName: meta.documentName,
        file: file.bytes,
        fileName: file.name,
        signatureFields: meta.signatureFields,
        identificationNumber: meta.identificationNumber,
        taxCode: meta.taxCode,
        organizationName: meta.organizationName,
        language: meta.language,
      });

      req.log.info({ signRequestId, casResponseShape: result.shape }, 'CAS request-document trả về');
      const pushSent = Boolean(meta.identificationNumber);
      const state = SignRequestState.catch('NEW').parse(result.state);
      if (!result.qrContent && !pushSent) {
        // Không có QR và không gửi push → người dùng không có cách nào để ký.
        req.log.error({ signRequestId, casResponseShape: result.shape }, 'CAS không trả về qrContent');
        return reply.code(502).send({ error: 'CAS_NO_QR', casResponseShape: result.shape });
      }
      req.log.info(
        { signRequestId, fields: meta.signatureFields.length, signerKind: meta.signerKind },
        'đã tạo yêu cầu ký',
      );

      const body: CreateSignRequestResponse = {
        signRequestId,
        qrContent: result.qrContent ?? '',
        state,
        pushSent,
        expiresAt: new Date(Date.now() + SIGN_REQUEST_TTL_MS).toISOString(),
      };
      return reply.code(201).send(body);
    },
  );

  app.get<{ Params: { id: string } }>(
    '/api/sign-requests/:id',
    { config: { rateLimit: { max: 120, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const id = SignRequestId.safeParse(req.params.id);
      if (!id.success) return reply.code(404).send({ error: 'NOT_FOUND' });
      const s = await cas.requestStatus(id.data);
      const body: SignRequestStatusResponse = {
        signRequestId: id.data,
        state: SignRequestState.catch('NEW').parse(s.state),
        signedAt: s.signedAt ?? null,
        identityKey: s.identityKey ?? null,
        identityKeyExpiresAt: s.identityKeyExpiresAt ?? null,
        orgIdSigned: s.orgIdSigned ?? null,
      };
      return body;
    },
  );

  /** identityKey gửi trong body (không nằm trên URL/log). Mỗi key CAS chỉ cho tải tối đa 5 lần. */
  app.post(
    '/api/signed-file',
    { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const { identityKey } = DownloadBody.parse(req.body);
      const pdf = await cas.downloadFile(identityKey);
      if (!isPdf(pdf)) {
        req.log.error({ bytes: pdf.byteLength }, 'download-file không trả về PDF');
        return reply.code(502).send({ error: 'CAS_NOT_PDF' });
      }
      return reply
        .type('application/pdf')
        .header('Cache-Control', 'no-store')
        .send(Buffer.from(pdf));
    },
  );

  app.get<{ Params: { orgIdSigned: string } }>(
    '/api/signing-round/:orgIdSigned',
    { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } },
    async (req) => cas.signingRound(req.params.orgIdSigned),
  );

  /**
   * Xác minh mọi chữ ký số trong PDF (port nguyên từ Xsign/kysoqr `/api/verify/upload`):
   * chữ ký CMS, toàn vẹn nội dung, chuỗi chứng thư tới Root CA lưu sẵn, thu hồi. Không lưu file.
   */
  app.post(
    '/api/verify',
    { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const upload = await readPdfUpload(req);
      if ('error' in upload) return reply.code(upload.status).send({ error: upload.error });
      try {
        const signatures = await verifyPdfSignatures(Buffer.from(upload.file.bytes), trustStore);
        return { signatures };
      } catch (err) {
        // Lỗi bất ngờ không được báo thành "không có chữ ký".
        req.log.error({ err }, 'xác minh chữ ký thất bại');
        return reply.code(500).send({ error: 'VERIFICATION_FAILED' });
      }
    },
  );

  return app;
}
