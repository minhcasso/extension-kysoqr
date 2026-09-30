import type { CertificateCheckResponse } from '@kysoqr/shared';
import { useEffect, useState } from 'react';
import { checkCertificates } from './api';
import { readPdfSignatures, type PdfSignature } from './verify';

export type ChainState =
  | { kind: 'loading' }
  | { kind: 'done'; result: CertificateCheckResponse }
  | { kind: 'error'; message: string };

export interface SignatureCheck {
  signature: PdfSignature;
  chain: ChainState;
}

export interface SignaturesState {
  loading: boolean;
  items: SignatureCheck[];
}

/** Đọc chữ ký có sẵn trong PDF (tại máy), rồi nhờ backend kiểm tra chuỗi chứng thư cho từng chữ ký. */
export function useSignatures(bytes: Uint8Array | null): SignaturesState {
  const [state, setState] = useState<SignaturesState>({ loading: false, items: [] });

  useEffect(() => {
    if (!bytes) {
      setState({ loading: false, items: [] });
      return;
    }
    let cancelled = false;
    setState({ loading: true, items: [] });

    void readPdfSignatures(bytes)
      .catch(() => [] as PdfSignature[])
      .then((signatures) => {
        if (cancelled) return;
        setState({
          loading: false,
          items: signatures.map((signature) => ({
            signature,
            chain: signature.certificates.length
              ? { kind: 'loading' }
              : { kind: 'error', message: 'Chữ ký không kèm chứng thư số.' },
          })),
        });
        signatures.forEach((signature, i) => {
          if (!signature.certificates.length) return;
          checkCertificates({
            certificates: signature.certificates.map((c) => c.der),
            signedAt: signature.signedAt?.toISOString(),
          }).then(
            (result) => update(i, { kind: 'done', result }),
            (e: unknown) =>
              update(i, { kind: 'error', message: e instanceof Error ? e.message : String(e) }),
          );
        });
      });

    function update(i: number, chain: ChainState) {
      if (cancelled) return;
      setState((s) => ({ ...s, items: s.items.map((it, j) => (j === i ? { ...it, chain } : it)) }));
    }

    return () => {
      cancelled = true;
    };
  }, [bytes]);

  return state;
}

export type Verdict = 'checking' | 'valid' | 'untrusted' | 'modified' | 'revoked' | 'invalid';

/** Kết luận ngắn cho mỗi chữ ký, hiển thị ở nhãn màu. */
export function verdict({ signature, chain }: SignatureCheck): Verdict {
  if (!signature.signatureValid) return 'invalid';
  if (chain.kind === 'done') {
    const revoked = chain.result.chain.some(
      (c) => c.ocsp.status === 'revoked' || c.crl.status === 'revoked',
    );
    if (revoked) return 'revoked';
  }
  if (signature.integrity === 'modified') return 'modified';
  if (chain.kind === 'loading') return 'checking';
  if (chain.kind === 'error') return 'untrusted';
  if (!chain.result.chainValid && chain.result.chain.some((c) => c.signatureValid === false))
    return 'invalid';
  return chain.result.trusted && chain.result.chainValid ? 'valid' : 'untrusted';
}
