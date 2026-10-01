import { z } from 'zod';

export const MAX_PDF_BYTES = 10 * 1024 * 1024;
/** CAS: QR / yêu cầu ký hết hạn sau 30 phút. */
export const SIGN_REQUEST_TTL_MS = 30 * 60 * 1000;

export const FieldType = z.enum(['SIGNATURE', 'INITIAL', 'STAMP']);
export type FieldType = z.infer<typeof FieldType>;

const ratio = z.number().min(0).max(1);

export const SignatureField = z
  .object({
    page: z.number().int().min(1),
    xRatio: ratio,
    yRatio: ratio,
    widthRatio: ratio.positive(),
    heightRatio: ratio.positive(),
    fieldType: FieldType.default('SIGNATURE'),
  })
  .refine((f) => f.xRatio + f.widthRatio <= 1, { message: 'xRatio + widthRatio phải ≤ 1' })
  .refine((f) => f.yRatio + f.heightRatio <= 1, { message: 'yRatio + heightRatio phải ≤ 1' });
export type SignatureField = z.infer<typeof SignatureField>;

export const Language = z.enum(['vi', 'en']);

/** Cá nhân ký bằng CCCD; doanh nghiệp ký bằng mã số thuế (CAS: `taxCode`). */
export const SignerKind = z.enum(['individual', 'business']);
export type SignerKind = z.infer<typeof SignerKind>;

export const TAX_CODE_RE = /^\d{10}(?:-\d{3})?$/;

/** Metadata extension gửi kèm file PDF (field `meta` của multipart). */
export const CreateSignRequestMeta = z
  .object({
    documentName: z.string().trim().min(10).max(240),
    signatureFields: z.array(SignatureField).min(1),
    signerKind: SignerKind.default('individual'),
    /** Cá nhân: CCCD người ký. Doanh nghiệp: CCCD người đại diện (để gửi thông báo Cas ID). */
    identificationNumber: z
      .string()
      .regex(/^\d{12}$/, 'CCCD phải gồm 12 chữ số')
      .optional(),
    taxCode: z.string().regex(TAX_CODE_RE, 'Mã số thuế gồm 10 chữ số, hoặc 10-3 chữ số').optional(),
    organizationName: z.string().trim().min(1).max(255).optional(),
    language: Language.default('vi'),
  })
  .refine((m) => m.signerKind !== 'business' || m.taxCode, {
    message: 'Cần mã số thuế khi ký cho doanh nghiệp',
    path: ['taxCode'],
  })
  // CAS coi yêu cầu có taxCode là ký tổ chức, nên cá nhân không được gửi kèm.
  .transform((m) =>
    m.signerKind === 'business' ? m : { ...m, taxCode: undefined, organizationName: undefined },
  );
export type CreateSignRequestMeta = z.infer<typeof CreateSignRequestMeta>;

export const SignRequestState = z.enum(['NEW', 'ACCEPTED', 'REJECTED', 'COMPLETED']);
export type SignRequestState = z.infer<typeof SignRequestState>;

export const isTerminalState = (s: SignRequestState) => s === 'REJECTED' || s === 'COMPLETED';

/** Response của backend KysoQR cho extension. Backend không lưu gì: mọi trạng thái lấy thẳng từ CAS. */
export interface CreateSignRequestResponse {
  signRequestId: string;
  qrContent: string;
  state: SignRequestState;
  pushSent: boolean;
  /** QR / yêu cầu ký hết hạn lúc này (extension tự tính `expired`). */
  expiresAt: string;
}

export interface SignRequestStatusResponse {
  signRequestId: string;
  state: SignRequestState;
  signedAt: string | null;
  /** Có khi COMPLETED: dùng để tải file đã ký (CAS cho tối đa 5 lần, có hạn dùng). */
  identityKey: string | null;
  identityKeyExpiresAt: string | null;
  /** Có khi COMPLETED: dùng để xem thông tin phiên ký. */
  orgIdSigned: string | null;
}

/** Kết quả xác minh chữ ký (giống hệt Xsign/kysoqr `verifyPdfSignatures`). */
export type VerificationStatus =
  | 'SIGNED_VALID'
  | 'CONTENT_DIGEST_MISMATCH'
  | 'CHAIN_VALIDATION_FAILED'
  | 'ROOT_NOT_TRUSTED'
  | 'SIGNATURE_INVALID'
  | 'TRUST_STORE_NOT_CONFIGURED'
  | 'UNSUPPORTED_SUBFILTER'
  | 'UNSUPPORTED_ALGORITHM';

export interface RevocationCheckResult {
  status: 'not_revoked' | 'revoked' | 'unavailable';
  url: string | null;
}

export interface ChainCertInfo {
  index: number;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  isCa: boolean;
  /** `null` với chứng thư gốc. */
  ocsp: RevocationCheckResult | null;
  crl: RevocationCheckResult | null;
}

export interface VerificationResult {
  status: VerificationStatus;
  message: string;
  signedAt?: string;
  certificate?: {
    subject: string;
    issuer: string;
    serialNumber: string;
    validFrom: string;
    validTo: string;
  };
  certificateChain?: ChainCertInfo[];
  certificateChainRootNotInTrustStore?: boolean;
  /** Chỉ để hiển thị: chứng thư đã hết hạn tính tới hôm nay (chữ ký vẫn hợp lệ nếu còn hạn lúc ký). */
  certificateExpiredNow?: boolean;
  contentIntact?: boolean;
}

export interface VerifyResponse {
  signatures: VerificationResult[];
}
