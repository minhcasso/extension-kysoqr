import { readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildApp } from './app';
import type { CasClient } from './cas-client';
import { loadEnv } from './env';

// Unit test cho backend stateless (chuyển tiếp CAS, xác minh). Tích hợp CAS kiểm thử thật.
const PDF = new TextEncoder().encode('%PDF-1.7\n...');
const SIGN_ID = '4ec3397d-1b2c-4d5e-8f90-123456789abc';

function fakeCas() {
  return {
    requestDocument: vi.fn(async () => ({
      state: 'NEW' as 'NEW' | undefined,
      qrContent: 'casid://sign?t=t' as string | undefined,
      shape: {},
    })),
    requestStatus: vi.fn(async (signRequestId: string) => ({
      signRequestId,
      state: 'COMPLETED' as const,
      lastUpdatedAt: null,
      signedAt: '2026-09-28T02:04:18.000Z',
      identityKey: 'b3f1e2c4-8a2d-4c1a-9e3f-1a2b3c4d5e6f' as string | null,
      identityKeyExpiresAt: '2026-09-29T02:04:18.000Z' as string | null,
      orgIdSigned: 'kysoqr.com#5xh7Oo' as string | null,
    })),
    downloadFile: vi.fn(async () => PDF),
    signingRound: vi.fn(async () => ({ signingRound: {} })),
  } satisfies CasClient;
}

function multipart(meta: unknown, file: Uint8Array = PDF) {
  const boundary = '----kysoqr';
  const head = (name: string, extra = '') =>
    `--${boundary}\r\nContent-Disposition: form-data; name="${name}"${extra}\r\n`;
  const parts = [
    ...(meta === undefined ? [] : [Buffer.from(`${head('meta')}\r\n${JSON.stringify(meta)}\r\n`)]),
    Buffer.from(`${head('file', '; filename="a.pdf"')}Content-Type: application/pdf\r\n\r\n`),
    Buffer.from(file),
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ];
  return {
    body: Buffer.concat(parts),
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
  };
}

const meta = {
  documentName: 'Hop dong lao dong 2026',
  signatureFields: [{ page: 1, xRatio: 0.1, yRatio: 0.1, widthRatio: 0.3, heightRatio: 0.08 }],
};

describe('backend', () => {
  let cas: ReturnType<typeof fakeCas>;
  let app: Awaited<ReturnType<typeof buildApp>>;
  let tmpBefore: string[];

  beforeEach(async () => {
    tmpBefore = readdirSync(tmpdir());
    cas = fakeCas();
    const env = loadEnv({
      CAS_ESIGN_BASE_URL: 'https://sandbox.bankhub.dev',
      CAS_ESIGN_CLIENT_ID: 'c',
      CAS_ESIGN_API_KEY: 'k',
    });
    app = await buildApp({ env, cas });
  });

  afterEach(async () => {
    await app.close();
  });

  async function create() {
    const res = await app.inject({ method: 'POST', url: '/api/sign-requests', ...multipart(meta) });
    expect(res.statusCode).toBe(201);
    return res.json() as { signRequestId: string };
  }

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

  it('từ chối file không phải PDF', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/sign-requests',
      ...multipart(meta, new TextEncoder().encode('hello')),
    });
    expect(res.statusCode).toBe(400);
  });

  it('trạng thái: trả thẳng identityKey và orgIdSigned từ CAS', async () => {
    const res = await app.inject({ url: `/api/sign-requests/${SIGN_ID}` });
    expect(cas.requestStatus).toHaveBeenCalledWith(SIGN_ID);
    expect(res.json()).toMatchObject({
      signRequestId: SIGN_ID,
      state: 'COMPLETED',
      identityKey: 'b3f1e2c4-8a2d-4c1a-9e3f-1a2b3c4d5e6f',
      orgIdSigned: 'kysoqr.com#5xh7Oo',
    });
  });

  it('trạng thái: mã yêu cầu không phải UUID → 404, không gọi CAS', async () => {
    const res = await app.inject({ url: '/api/sign-requests/abc' });
    expect(res.statusCode).toBe(404);
    expect(cas.requestStatus).not.toHaveBeenCalled();
  });

  it('tải file đã ký: chuyển thẳng từ CAS, không ghi file nào ra đĩa', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/signed-file',
      payload: { identityKey: 'b3f1e2c4-8a2d-4c1a-9e3f-1a2b3c4d5e6f' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.rawPayload.subarray(0, 5).toString()).toBe('%PDF-');
    expect(cas.downloadFile).toHaveBeenCalledTimes(1);
    expect(readdirSync(tmpdir())).toEqual(tmpBefore);
  });

  it('tải file đã ký: CAS trả về thứ không phải PDF → 502', async () => {
    cas.downloadFile.mockResolvedValueOnce(new TextEncoder().encode('oops'));
    const res = await app.inject({
      method: 'POST',
      url: '/api/signed-file',
      payload: { identityKey: 'k' },
    });
    expect(res.statusCode).toBe(502);
  });

  it('xác minh: PDF không có chữ ký → danh sách rỗng', async () => {
    const res = await app.inject({ method: 'POST', url: '/api/verify', ...multipart(undefined) });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ signatures: [] });
  });

  it('xác minh: từ chối file không phải PDF', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/verify',
      ...multipart(undefined, new TextEncoder().encode('hello')),
    });
    expect(res.statusCode).toBe(400);
  });
});
