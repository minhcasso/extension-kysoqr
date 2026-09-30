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

/** Response của backend KysoQR cho extension. */
export interface CreateSignRequestResponse {
  signRequestId: string;
  accessToken: string;
  qrContent: string;
  state: SignRequestState;
  pushSent: boolean;
  expiresAt: string;
}

export interface SignRequestStatusResponse {
  signRequestId: string;
  state: SignRequestState;
  signedAt: string | null;
  expiresAt: string;
  /** Quá 30 phút mà chưa ký/từ chối. */
  expired: boolean;
  /** true khi backend đã tải và lưu xong file đã ký. */
  fileReady: boolean;
  /** true khi đã có orgIdSigned (từ webhook) để xem thông tin phiên ký. */
  hasSigningRound: boolean;
}

/** Kiểm tra chuỗi chứng thư số (chuỗi tin cậy + OCSP + CRL) do backend làm. */
export const CertificateCheckRequest = z.object({
  /** Chứng thư DER (base64) lấy từ chữ ký trong PDF; phần tử đầu là chứng thư người ký. */
  certificates: z.array(z.string().max(40_000)).min(1).max(10),
  /** Thời điểm ký (ISO), để xét hiệu lực chứng thư tại lúc ký. */
  signedAt: z.string().datetime({ offset: true }).optional(),
});
export type CertificateCheckRequest = z.infer<typeof CertificateCheckRequest>;

export type RevocationStatus =
  /** Chưa bị thu hồi. */
  | 'good'
  | 'revoked'
  /** Máy chủ OCSP không biết chứng thư này. */
  | 'unknown'
  /** Có địa chỉ nhưng không kiểm tra được (mạng, phản hồi sai, chữ ký phản hồi không hợp lệ...). */
  | 'error'
  /** Thiếu chứng thư của tổ chức phát hành nên không tạo được yêu cầu. */
  | 'unsupported'
  /** Chứng thư không khai báo địa chỉ OCSP/CRL (thường là chứng thư gốc). */
  | 'none';

export interface RevocationResult {
  status: RevocationStatus;
  url: string | null;
  revokedAt?: string;
  detail?: string;
}

export interface ChainCertificate {
  /** DER base64. */
  der: string;
  /** Có trong PDF, hay backend lấy thêm từ kho tin cậy / địa chỉ caIssuers. */
  source: 'document' | 'trust-store' | 'aia';
  /** Chữ ký của chứng thư này hợp lệ theo khoá công khai của chứng thư cấp trên. */
  signatureValid: boolean | null;
  ocsp: RevocationResult;
  crl: RevocationResult;
}

export interface CertificateCheckResponse {
  /** Từ chứng thư người ký lên tới chứng thư gốc (nếu tìm được). */
  chain: ChainCertificate[];
  /** Chuỗi kết thúc ở một chứng thư gốc có trong kho tin cậy của máy chủ. */
  trusted: boolean;
  /** Máy chủ chưa cấu hình kho chứng thư gốc tin cậy. */
  trustStoreConfigured: boolean;
  /** Mọi chữ ký trong chuỗi hợp lệ và các chứng thư còn hiệu lực tại thời điểm ký. */
  chainValid: boolean;
  chainError?: string;
}
