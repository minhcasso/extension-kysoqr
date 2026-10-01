import type {
  CreateSignRequestMeta,
  CreateSignRequestResponse,
  SignRequestStatusResponse,
  VerificationResult,
  VerifyResponse,
} from '@kysoqr/shared';

export const BACKEND_URL = (
  (import.meta.env.WXT_BACKEND_URL as string | undefined) ?? 'http://localhost:8787'
).replace(/\/+$/, '');

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
  ) {
    super(message);
  }
}

const MESSAGES: Record<string, string> = {
  NOT_A_PDF: 'File không phải PDF.',
  FILE_TOO_LARGE: 'File vượt quá 10MB.',
  MISSING_FILE_OR_META: 'Thiếu file hoặc thông tin ký.',
  NOT_FOUND: 'Không tìm thấy yêu cầu ký (có thể đã bị xoá).',
  CAS_NOT_PDF: 'Cas ID không trả về file PDF đã ký.',
  VERIFICATION_FAILED: 'Không xác minh được chữ ký trong file này.',
  CAS_NO_QR: 'Cas ID không trả về mã QR. Hãy nhập số CCCD để nhận thông báo ký trên app Cas ID.',
};

async function toError(res: Response): Promise<ApiError> {
  let body: {
    error?: string;
    casStatus?: number;
    detail?: string;
    issues?: { message: string }[];
  } = {};
  try {
    body = await res.json();
  } catch {
    // body không phải JSON
  }
  let message = `Máy chủ trả về lỗi ${res.status}.`;
  if (body.error === 'CAS_ERROR') {
    try {
      const d = JSON.parse(body.detail ?? '') as { errorMessage?: string; errorCode?: string };
      message = d.errorMessage
        ? `Cas ID: ${d.errorMessage} (${d.errorCode})`
        : `Cas ID trả về lỗi ${body.casStatus}.`;
    } catch {
      message = `Cas ID trả về lỗi ${body.casStatus}.`;
    }
  } else if (body.error === 'INVALID_INPUT') {
    message = `Dữ liệu không hợp lệ: ${body.issues?.map((i) => i.message).join('; ')}`;
  } else if (body.error === 'RATE_LIMITED' || res.status === 429) {
    message = 'Bạn thao tác quá nhanh, vui lòng thử lại sau ít phút.';
  } else if (body.error && MESSAGES[body.error]) {
    message = MESSAGES[body.error]!;
  }
  return new ApiError(message, res.status, body.error);
}

async function request(path: string, init?: RequestInit): Promise<Response> {
  let res: Response;
  try {
    res = await fetch(`${BACKEND_URL}${path}`, init);
  } catch {
    throw new ApiError(`Không kết nối được máy chủ KysoQR (${BACKEND_URL}).`, 0, 'NETWORK');
  }
  if (!res.ok) throw await toError(res);
  return res;
}

export async function createSignRequest(
  pdf: Uint8Array,
  fileName: string,
  meta: CreateSignRequestMeta,
): Promise<CreateSignRequestResponse> {
  const form = new FormData();
  form.set('meta', JSON.stringify(meta));
  form.set('file', new Blob([pdf.slice()], { type: 'application/pdf' }), fileName);
  const res = await request('/api/sign-requests', { method: 'POST', body: form });
  return res.json();
}

export async function getStatus(id: string): Promise<SignRequestStatusResponse> {
  const res = await request(`/api/sign-requests/${id}`);
  return res.json();
}

/** Tải file đã ký thẳng từ CAS (qua backend, không lưu lại). Mỗi identityKey dùng được tối đa 5 lần. */
export async function getSignedFile(identityKey: string): Promise<Uint8Array> {
  const res = await request('/api/signed-file', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ identityKey }),
  });
  return new Uint8Array(await res.arrayBuffer());
}

export interface SigningRound {
  device?: { model?: string | null };
  signer?: { displayName?: string };
  authMethod?: string;
  signedAt?: string | null;
  certificate?: {
    issuer?: { commonName?: string; organization?: string };
    signer?: { commonName?: string };
    documentIntegrity?: string;
    validFrom?: string | null;
    validTo?: string | null;
    signatureValidity?: string;
  };
}

export async function getSigningRound(orgIdSigned: string): Promise<SigningRound | null> {
  const res = await request(`/api/signing-round/${encodeURIComponent(orgIdSigned)}`);
  const data = (await res.json()) as { signingRound?: SigningRound };
  return data.signingRound ?? null;
}

/** Xác minh mọi chữ ký trong PDF ở backend (chuỗi chứng thư tới Root CA, thu hồi). Backend không lưu file. */
export async function verifyPdf(pdf: Uint8Array): Promise<VerificationResult[]> {
  const form = new FormData();
  form.set('file', new Blob([pdf.slice()], { type: 'application/pdf' }), 'document.pdf');
  const res = await request('/api/verify', { method: 'POST', body: form });
  return ((await res.json()) as VerifyResponse).signatures;
}
