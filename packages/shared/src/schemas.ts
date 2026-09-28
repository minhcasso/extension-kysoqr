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

/** Metadata extension gửi kèm file PDF (field `meta` của multipart). */
export const CreateSignRequestMeta = z.object({
  documentName: z.string().trim().min(10).max(240),
  signatureFields: z.array(SignatureField).min(1),
  identificationNumber: z
    .string()
    .regex(/^\d{12}$/, 'CCCD phải gồm 12 chữ số')
    .optional(),
  language: Language.default('vi'),
});
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
