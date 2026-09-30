import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildApp } from './app';
import type { CasClient } from './cas-client';
import { loadEnv } from './env';
import { Store } from './store';

// Unit test cho logic của backend (xác thực, webhook, idempotent). Tích hợp CAS kiểm thử thật.
const TOKEN = 'x'.repeat(40);
const PDF = new TextEncoder().encode('%PDF-1.7\n...');

function fakeCas() {
  return {
    requestDocument: vi.fn(async () => ({
      state: 'NEW' as 'NEW' | undefined,
      qrContent: 'casid://sign?t=t' as string | undefined,
      shape: {},
    })),
    requestStatus: vi.fn(),
    downloadFile: vi.fn(async () => PDF),
    signingRound: vi.fn(async () => ({ signingRound: {} })),
  } satisfies CasClient;
}

function multipart(meta: unknown, file: Uint8Array = PDF) {
  const boundary = '----kysoqr';
  const head = (name: string, extra = '') =>
    `--${boundary}\r\nContent-Disposition: form-data; name="${name}"${extra}\r\n`;
  const body = Buffer.concat([
    Buffer.from(`${head('meta')}\r\n${JSON.stringify(meta)}\r\n`),
    Buffer.from(`${head('file', '; filename="a.pdf"')}Content-Type: application/pdf\r\n\r\n`),
    Buffer.from(file),
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  return { body, headers: { 'content-type': `multipart/form-data; boundary=${boundary}` } };
}

const meta = {
  documentName: 'Hop dong lao dong 2026',
  signatureFields: [{ page: 1, xRatio: 0.1, yRatio: 0.1, widthRatio: 0.3, heightRatio: 0.08 }],
};

describe('backend', () => {
  let dir: string;
  let store: Store;
  let cas: ReturnType<typeof fakeCas>;
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'kysoqr-'));
    store = new Store(dir);
    cas = fakeCas();
    const env = loadEnv({
      CAS_ESIGN_BASE_URL: 'https://sandbox.bankhub.dev',
      CAS_ESIGN_CLIENT_ID: 'c',
      CAS_ESIGN_API_KEY: 'k',
      CAS_WEBHOOK_TOKEN: TOKEN,
      DATA_DIR: dir,
    });
    app = await buildApp({ env, store, cas });
  });

  afterEach(async () => {
    await app.close();
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  async function create() {
    const res = await app.inject({ method: 'POST', url: '/api/sign-requests', ...multipart(meta) });
    expect(res.statusCode).toBe(201);
    return res.json() as { signRequestId: string; accessToken: string };
  }

  const webhook = (token: string, signRequest: object) =>
    app.inject({
      method: 'POST',
      url: `/webhooks/cas-sign?token=${token}`,
      payload: {
        environment: 'dev',
        webhookType: 'SIGN',
        webhookCode: 'DEFAULT_UPDATE',
        signRequest,
      },
    });

  it('tạo yêu cầu và gửi đúng dữ liệu sang CAS', async () => {
    const { signRequestId } = await create();
    expect(cas.requestDocument).toHaveBeenCalledWith(
      expect.objectContaining({ signRequestId, documentName: meta.documentName, language: 'vi' }),
    );
  });

  it('CAS không trả QR và không có CCCD → báo lỗi rõ ràng, không lưu yêu cầu', async () => {
    cas.requestDocument.mockResolvedValueOnce({
      state: undefined,
      qrContent: undefined,
      shape: { data: {} },
    });
    const res = await app.inject({ method: 'POST', url: '/api/sign-requests', ...multipart(meta) });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe('CAS_NO_QR');
  });

  it('CAS không trả QR nhưng đã gửi push qua CCCD → vẫn tạo yêu cầu', async () => {
    cas.requestDocument.mockResolvedValueOnce({
      state: undefined,
      qrContent: undefined,
      shape: {},
    });
    const res = await app.inject({
      method: 'POST',
      url: '/api/sign-requests',
      ...multipart({ ...meta, identificationNumber: '001099012345' }),
    });
    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({ qrContent: '', pushSent: true, state: 'NEW' });
  });

  it('ký cho doanh nghiệp: gửi mã số thuế sang CAS', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/sign-requests',
      ...multipart({
        ...meta,
        signerKind: 'business',
        taxCode: '0316794479',
        organizationName: 'CONG TY TNHH CASSO',
      }),
    });
    expect(res.statusCode).toBe(201);
    expect(cas.requestDocument).toHaveBeenCalledWith(
      expect.objectContaining({ taxCode: '0316794479', organizationName: 'CONG TY TNHH CASSO' }),
    );
  });

  it('ký cho doanh nghiệp mà thiếu mã số thuế → 400', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/sign-requests',
      ...multipart({ ...meta, signerKind: 'business' }),
    });
    expect(res.statusCode).toBe(400);
    expect(cas.requestDocument).not.toHaveBeenCalled();
  });

  it('ký cá nhân: không gửi mã số thuế dù extension lỡ gửi kèm', async () => {
    await app.inject({
      method: 'POST',
      url: '/api/sign-requests',
      ...multipart({ ...meta, taxCode: '0316794479' }),
    });
    expect(cas.requestDocument).toHaveBeenCalledWith(
      expect.objectContaining({ taxCode: undefined }),
    );
  });

  it('kiểm tra chứng thư: từ chối dữ liệu không phải chứng thư', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/certificates/check',
      payload: { certificates: [Buffer.from('không phải chứng thư').toString('base64')] },
    });
    expect(res.statusCode).toBe(400);
  });

  it('từ chối file không phải PDF', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/sign-requests',
      ...multipart(meta, new TextEncoder().encode('hello')),
    });
    expect(res.statusCode).toBe(400);
  });

  it('không cho xem trạng thái khi sai accessToken', async () => {
    const { signRequestId } = await create();
    const res = await app.inject({
      url: `/api/sign-requests/${signRequestId}`,
      headers: { 'x-access-token': 'sai' },
    });
    expect(res.statusCode).toBe(404);
  });

  it('webhook sai token bị từ chối', async () => {
    const res = await webhook('sai', { signRequestId: 'x', state: 'COMPLETED' });
    expect(res.statusCode).toBe(401);
  });

  it('webhook COMPLETED → tải file đúng 1 lần dù webhook gửi trùng', async () => {
    const { signRequestId, accessToken } = await create();
    const payload = {
      signRequestId,
      state: 'COMPLETED',
      identityKey: 'b3f1e2c4-8a2d-4c1a-9e3f-1a2b3c4d5e6f',
      identityKeyExpiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      orgIdSigned: 'KSQ#123',
    };
    await Promise.all([webhook(TOKEN, payload), webhook(TOKEN, payload)]);
    await app.signService.ensureDownloaded(signRequestId);
    expect(cas.downloadFile).toHaveBeenCalledTimes(1);

    const status = await app.inject({
      url: `/api/sign-requests/${signRequestId}`,
      headers: { 'x-access-token': accessToken },
    });
    expect(status.json()).toMatchObject({
      state: 'COMPLETED',
      fileReady: true,
      hasSigningRound: true,
    });

    const file = await app.inject({
      url: `/api/sign-requests/${signRequestId}/file`,
      headers: { 'x-access-token': accessToken },
    });
    expect(file.headers['content-type']).toBe('application/pdf');
    expect(file.rawPayload.subarray(0, 5).toString()).toBe('%PDF-');
  });

  it('job 5 giây: hỏi CAS và tải file khi đã ký, không cần webhook', async () => {
    const { signRequestId } = await create();
    cas.requestStatus = vi.fn(async () => ({
      signRequestId,
      state: 'COMPLETED' as const,
      lastUpdatedAt: null,
      signedAt: '2026-09-28T02:04:18.000Z',
      identityKey: 'b3f1e2c4-8a2d-4c1a-9e3f-1a2b3c4d5e6f',
      identityKeyExpiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      orgIdSigned: 'kysoqr.com#5xh7Oo',
    }));
    store.update(signRequestId, { lastSyncedAt: 0 });
    await app.signService.syncActive();
    await app.signService.ensureDownloaded(signRequestId);
    expect(store.get(signRequestId)).toMatchObject({
      state: 'COMPLETED',
      orgIdSigned: 'kysoqr.com#5xh7Oo',
    });
    expect(store.get(signRequestId)?.filePath).toBeTruthy();
  });

  it('không lùi trạng thái COMPLETED về NEW', async () => {
    const { signRequestId } = await create();
    await webhook(TOKEN, { signRequestId, state: 'REJECTED' });
    await webhook(TOKEN, { signRequestId, state: 'NEW' });
    expect(store.get(signRequestId)?.state).toBe('REJECTED');
  });
});
