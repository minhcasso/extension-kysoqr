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
  language: 'vi' | 'en';
}

export interface CasRequestDocumentResult {
  requestId: string;
  signRequestId: string;
  signToken: string;
  state: SignRequestState;
  qrContent: string;
}

export interface CasSignRequestStatus {
  signRequestId: string;
  state: SignRequestState;
  lastUpdatedAt: string | null;
  signedAt: string | null;
  identityKey: string | null;
  identityKeyExpiresAt: string | null;
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
      const res = await call('/esign/request-document', { method: 'POST', body: form });
      return (await res.json()) as CasRequestDocumentResult;
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
