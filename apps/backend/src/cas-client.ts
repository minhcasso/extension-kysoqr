import type { SignRequestState, SignatureField } from '@kysoqr/shared';

/** Lỗi từ CAS; giữ nguyên status và body để debug (body không chứa dữ liệu nhạy cảm của mình). */
export class CasError extends Error {
  constructor(
    readonly status: number,
    readonly body: string,
  ) {
    super(`CAS trả về HTTP ${status}: ${body.slice(0, 500)}`);
  }
}

export interface CasRequestDocumentInput {
  signRequestId: string;
  documentName: string;
  file: Uint8Array;
  fileName: string;
  signatureFields: SignatureField[];
  identificationNumber?: string;
  /** Chỉ khi ký cho doanh nghiệp: 10 hoặc 10-3 chữ số. */
  taxCode?: string;
  organizationName?: string;
  language: 'vi' | 'en';
}

export interface CasRequestDocumentResult {
  state: SignRequestState | undefined;
  qrContent: string | undefined;
  /** Cấu trúc response (chỉ tên field + kiểu, không có giá trị) để log/debug. */
  shape: unknown;
}

export interface CasSignRequestStatus {
  signRequestId: string;
  state: SignRequestState;
  lastUpdatedAt: string | null;
  signedAt: string | null;
  identityKey: string | null;
  identityKeyExpiresAt: string | null;
  orgIdSigned?: string | null;
}

export interface CasClient {
  requestDocument(input: CasRequestDocumentInput): Promise<CasRequestDocumentResult>;
  requestStatus(signRequestId: string): Promise<CasSignRequestStatus>;
  downloadFile(identityKey: string): Promise<Uint8Array>;
  signingRound(orgIdSigned: string): Promise<unknown>;
}

interface Config {
  baseUrl: string;
  clientId: string;
  apiKey: string;
  apiVersion: string;
  timeoutMs?: number;
}

export function createCasClient(cfg: Config): CasClient {
  const base = cfg.baseUrl.replace(/\/+$/, '');
  const headers = {
    'x-client-id': cfg.clientId,
    'x-secret-key': cfg.apiKey,
    'X-BankHub-Api-Version': cfg.apiVersion,
  };

  async function call(path: string, init: RequestInit): Promise<Response> {
    const res = await fetch(`${base}${path}`, {
      ...init,
      headers: { ...headers, ...init.headers },
      signal: AbortSignal.timeout(cfg.timeoutMs ?? 30_000),
    });
    if (!res.ok) throw new CasError(res.status, await res.text());
    return res;
  }

  const json = (path: string, body: unknown) =>
    call(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

  return {
    async requestDocument(input) {
      const form = new FormData();
      form.set('signRequestId', input.signRequestId);
      form.set('documentName', input.documentName);
      form.set('file', new Blob([input.file.slice()], { type: 'application/pdf' }), input.fileName);
      form.set('signatureFields', JSON.stringify(input.signatureFields));
      form.set('language', input.language);
      if (input.identificationNumber) form.set('identificationNumber', input.identificationNumber);
      if (input.taxCode) form.set('taxCode', input.taxCode);
      if (input.organizationName) form.set('organizationName', input.organizationName);
      const res = await call('/esign/request-document', { method: 'POST', body: form });
      const data: unknown = await res.json();
      // Tài liệu ghi các field ở cấp gốc, nhưng thực tế có thể bị bọc trong object con.
      const state = findString(data, 'state');
      return {
        qrContent: findString(data, 'qrContent'),
        state: state as SignRequestState | undefined,
        shape: describeShape(data),
      };
    },

    async requestStatus(signRequestId) {
      const res = await json('/esign/request-status', { signRequestId });
      const data = (await res.json()) as { signRequestStatus: CasSignRequestStatus };
      return data.signRequestStatus;
    },

    async downloadFile(identityKey) {
      const res = await json('/esign/download-file', { identityKey });
      return new Uint8Array(await res.arrayBuffer());
    },

    async signingRound(orgIdSigned) {
      const res = await call(`/esign/signing-round/${encodeURIComponent(orgIdSigned)}`, {
        method: 'GET',
      });
      return res.json();
    },
  };
}

/** Tìm field dạng chuỗi theo tên, ở bất kỳ độ sâu nào (tối đa 4 cấp). */
export function findString(value: unknown, key: string, depth = 0): string | undefined {
  if (!value || typeof value !== 'object' || depth > 4) return undefined;
  const obj = value as Record<string, unknown>;
  if (typeof obj[key] === 'string' && obj[key]) return obj[key] as string;
  for (const v of Object.values(obj)) {
    const found = findString(v, key, depth + 1);
    if (found) return found;
  }
  return undefined;
}

/** Thay giá trị bằng kiểu dữ liệu, để log cấu trúc mà không lộ nội dung. */
export function describeShape(value: unknown, depth = 0): unknown {
  if (Array.isArray(value)) return depth > 4 ? 'array' : [describeShape(value[0], depth + 1)];
  if (value && typeof value === 'object') {
    if (depth > 4) return 'object';
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, describeShape(v, depth + 1)]),
    );
  }
  return value === null ? 'null' : typeof value;
}
