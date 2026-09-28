import { describe, expect, it } from 'vitest';
import { CreateSignRequestMeta, SignatureField } from './schemas';

const field = { page: 1, xRatio: 0.45, yRatio: 0.12, widthRatio: 0.48, heightRatio: 0.08 };

describe('SignatureField', () => {
  it('mặc định fieldType = SIGNATURE', () => {
    expect(SignatureField.parse(field).fieldType).toBe('SIGNATURE');
  });

  it('từ chối x + w > 1', () => {
    expect(SignatureField.safeParse({ ...field, xRatio: 0.6 }).success).toBe(false);
  });
});

describe('CreateSignRequestMeta', () => {
  const base = { documentName: 'Hop dong lao dong', signatureFields: [field] };

  it('hợp lệ khi không có CCCD', () => {
    expect(CreateSignRequestMeta.parse(base).language).toBe('vi');
  });

  it('CCCD phải đủ 12 số', () => {
    expect(CreateSignRequestMeta.safeParse({ ...base, identificationNumber: '12345' }).success).toBe(
      false,
    );
    expect(
      CreateSignRequestMeta.safeParse({ ...base, identificationNumber: '001099012345' }).success,
    ).toBe(true);
  });

  it('tên tài liệu tối thiểu 10 ký tự', () => {
    expect(CreateSignRequestMeta.safeParse({ ...base, documentName: 'HD' }).success).toBe(false);
  });

  it('phải có ít nhất 1 ô ký', () => {
    expect(CreateSignRequestMeta.safeParse({ ...base, signatureFields: [] }).success).toBe(false);
  });
});
