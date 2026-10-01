import type { VerificationResult } from '@kysoqr/shared';
import { useEffect, useState } from 'react';
import { verifyPdf } from './api';

export interface SignatureCheck {
  index: number;
  /** `null` khi đang chờ backend (hoặc backend lỗi, xem `error`). */
  result: VerificationResult | null;
  error: string | null;
}

export interface SignaturesState {
  loading: boolean;
  items: SignatureCheck[];
}

const BYTE_RANGE = new TextEncoder().encode('/ByteRange');

/**
 * Đếm số chữ ký bằng cách dò `/ByteRange` trực tiếp trên byte: không tạo chuỗi lớn,
 * file 10MB chỉ mất vài mili giây. PDF không có chữ ký thì dừng ở đây, không gửi gì lên máy chủ.
 */
export function countSignatures(bytes: Uint8Array): number {
  let count = 0;
  const first = BYTE_RANGE[0]!;
  const last = bytes.length - BYTE_RANGE.length;
  outer: for (let i = bytes.indexOf(first); i !== -1 && i <= last; i = bytes.indexOf(first, i + 1)) {
    for (let j = 1; j < BYTE_RANGE.length; j++) {
      if (bytes[i + j] !== BYTE_RANGE[j]) continue outer;
    }
    count++;
  }
  return count;
}

/** Chờ trình duyệt rảnh (trang đầu đã vẽ xong) rồi mới làm việc phụ. */
function whenIdle(fn: () => void): () => void {
  if ('requestIdleCallback' in window) {
    const id = requestIdleCallback(fn, { timeout: 1000 });
    return () => cancelIdleCallback(id);
  }
  const id = setTimeout(fn, 200);
  return () => clearTimeout(id);
}

const pending = (n: number): SignatureCheck[] =>
  Array.from({ length: n }, (_, i) => ({ index: i + 1, result: null, error: null }));

/**
 * Xác minh chữ ký có sẵn trong PDF. Việc kiểm tra thật (chữ ký CMS, toàn vẹn, chuỗi chứng thư
 * tới Root CA, thu hồi) chạy ở backend — giống hệt Xsign/kysoqr — nên extension không phải
 * mang theo thư viện mật mã.
 */
export function useSignatures(bytes: Uint8Array | null): SignaturesState {
  const [state, setState] = useState<SignaturesState>({ loading: false, items: [] });

  useEffect(() => {
    setState({ loading: false, items: [] });
    if (!bytes) return;
    let cancelled = false;

    const cancelIdle = whenIdle(() => {
      const count = countSignatures(bytes);
      if (!count || cancelled) return;
      setState({ loading: true, items: pending(count) });
      verifyPdf(bytes).then(
        (results) => {
          if (cancelled) return;
          setState({
            loading: false,
            items: results.map((result, i) => ({ index: i + 1, result, error: null })),
          });
        },
        (e: unknown) => {
          if (cancelled) return;
          const error = e instanceof Error ? e.message : String(e);
          setState({
            loading: false,
            items: pending(count).map((it) => ({ ...it, error })),
          });
        },
      );
    });

    return () => {
      cancelled = true;
      cancelIdle();
    };
  }, [bytes]);

  return state;
}

export type Verdict = 'checking' | 'valid' | 'untrusted' | 'modified' | 'revoked' | 'invalid';

/** Kết luận ngắn cho mỗi chữ ký, hiển thị ở nhãn màu. */
export function verdict({ result, error }: SignatureCheck): Verdict {
  if (!result) return error ? 'untrusted' : 'checking';
  const revoked = result.certificateChain?.some(
    (c) => c.ocsp?.status === 'revoked' || c.crl?.status === 'revoked',
  );
  if (revoked) return 'revoked';
  switch (result.status) {
    case 'SIGNED_VALID':
      return 'valid';
    case 'CONTENT_DIGEST_MISMATCH':
      return 'modified';
    case 'SIGNATURE_INVALID':
      return 'invalid';
    default:
      return 'untrusted';
  }
}

/** Lấy CN từ chuỗi DN kiểu "CN=Nguyễn Văn A, O=..., C=VN". */
export function commonName(dn: string | undefined): string | null {
  return dn?.match(/(?:^|,\s*)CN=([^,]+)/)?.[1]?.trim() ?? null;
}
