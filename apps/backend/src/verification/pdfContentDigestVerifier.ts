import { createHash } from 'node:crypto';
import forge from 'node-forge';
import { parseCmsMessage } from './cmsAsn1';

export type PdfContentDigestCheckResult =
  { ok: true; reason?: undefined } | { ok: false; reason: string };

function mapDigestAlgorithm(oid: string | undefined): string | null {
  if (!oid) return 'sha256';

  switch (oid) {
    case forge.pki.oids.sha1:
    case '1.3.14.3.2.26':
      return 'sha1';
    case forge.pki.oids.sha256:
    case '2.16.840.1.101.3.4.2.1':
      return 'sha256';
    case forge.pki.oids.sha384:
    case '2.16.840.1.101.3.4.2.2':
      return 'sha384';
    case forge.pki.oids.sha512:
    case '2.16.840.1.101.3.4.2.3':
      return 'sha512';
    case forge.pki.oids.md5:
    case '1.2.840.113549.2.5':
      return 'md5';
    default:
      return null;
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractDigestAlgorithmOid(rawCapture: any): string | undefined {
  const digestAlgorithms = rawCapture?.digestAlgorithms;
  if (
    !digestAlgorithms ||
    !Array.isArray(digestAlgorithms.value) ||
    digestAlgorithms.value.length === 0
  ) {
    return undefined;
  }

  const firstAlg = digestAlgorithms.value[0];
  if (!firstAlg || !Array.isArray(firstAlg.value) || firstAlg.value.length === 0) {
    return undefined;
  }

  const oidNode = firstAlg.value[0];
  if (!oidNode || typeof oidNode.value !== 'string') {
    return undefined;
  }

  try {
    return forge.asn1.derToOid(oidNode.value);
  } catch {
    return undefined;
  }
}

interface MessageDigestExtraction {
  /** False when the SignerInfo has no `authenticatedAttributes` field at
   * all (RFC 5652 §5.4 -- it's optional). This is a real, valid CMS variant,
   * distinct from "attributes present but no messageDigest inside them"
   * (which stays a genuine `MISSING_MESSAGE_DIGEST` error, malformed either
   * way). Callers must check this before treating `digest: null` as a
   * failure. */
  hasAuthenticatedAttributes: boolean;
  digest: Buffer | null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractMessageDigestFromSignerInfos(rawCapture: any): MessageDigestExtraction {
  const signerInfos = rawCapture?.signerInfos;
  if (!Array.isArray(signerInfos) || signerInfos.length === 0) {
    return { hasAuthenticatedAttributes: false, digest: null };
  }

  const signerInfo = signerInfos[0];
  if (!signerInfo || !Array.isArray(signerInfo.value)) {
    return { hasAuthenticatedAttributes: false, digest: null };
  }

  // Find the [0] IMPLICIT authenticatedAttributes block
  const authAttrsNode = signerInfo.value.find(
    (child: unknown) =>
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (child as any)?.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC &&
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (child as any)?.type === 0
  ) as forge.asn1.Asn1 | undefined;

  if (!authAttrsNode || !Array.isArray(authAttrsNode.value)) {
    return { hasAuthenticatedAttributes: false, digest: null };
  }

  const attrs = authAttrsNode.value as forge.asn1.Asn1[];

  for (const attr of attrs) {
    if (
      !attr ||
      attr.tagClass !== forge.asn1.Class.UNIVERSAL ||
      attr.type !== forge.asn1.Type.SEQUENCE ||
      !Array.isArray(attr.value) ||
      attr.value.length < 2
    ) {
      continue;
    }

    const typeNode = attr.value[0] as forge.asn1.Asn1;
    const valuesNode = attr.value[1] as forge.asn1.Asn1;

    if (!typeNode || typeNode.type !== forge.asn1.Type.OID || typeof typeNode.value !== 'string') {
      continue;
    }

    let oid: string;
    try {
      oid = forge.asn1.derToOid(typeNode.value);
    } catch {
      continue;
    }

    if (oid !== forge.pki.oids.messageDigest) {
      continue;
    }

    if (
      !valuesNode ||
      valuesNode.type !== forge.asn1.Type.SET ||
      !Array.isArray(valuesNode.value) ||
      valuesNode.value.length === 0
    ) {
      return { hasAuthenticatedAttributes: true, digest: null };
    }

    const mdNode = valuesNode.value[0] as forge.asn1.Asn1;
    if (!mdNode || typeof mdNode.value !== 'string') {
      return { hasAuthenticatedAttributes: true, digest: null };
    }

    // OCTET STRING value is a binary-encoded string
    return { hasAuthenticatedAttributes: true, digest: Buffer.from(mdNode.value, 'binary') };
  }

  return { hasAuthenticatedAttributes: true, digest: null };
}

/**
 * Verify that the CMS `messageDigest` attribute matches the hash of the
 * signed PDF byte ranges.
 *
 * This is a "content integrity" check: it detects whether the visible PDF
 * bytes match what was signed. It is deliberately independent from
 * `signatureVerifier.ts`'s cryptographic check — a self-declared digest
 * matching is not proof of anything by itself, only useful once the
 * signature over it is also verified.
 */
export function verifyPdfContentDigest(
  pdfBytes: Buffer,
  cmsDer: Buffer,
  byteRange: [number, number, number, number]
): PdfContentDigestCheckResult {
  try {
    const [a, b, c, d] = byteRange;

    if (a < 0 || b < 0 || c < 0 || d < 0 || a + b > pdfBytes.length || c + d > pdfBytes.length) {
      return { ok: false, reason: 'BYTE_RANGE_OUT_OF_BOUNDS' };
    }

    const p7 = parseCmsMessage(cmsDer);

    // For messages parsed from ASN.1, forge does *not* populate `signers`,
    // but it does attach a `rawCapture` structure with all SignerInfos and
    // DigestAlgorithms. We rely on that here so this works for both
    // internally-generated and external CMS signatures.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rawCapture = (p7 as any)?.rawCapture;
    if (!rawCapture) {
      return { ok: false, reason: 'NO_SIGNER_INFO' };
    }

    const digestAlgorithmOid = extractDigestAlgorithmOid(rawCapture);
    const digestAlgorithm = mapDigestAlgorithm(digestAlgorithmOid);
    if (!digestAlgorithm) {
      return { ok: false, reason: 'UNSUPPORTED_DIGEST_ALGORITHM' };
    }

    const { hasAuthenticatedAttributes, digest: expectedDigest } =
      extractMessageDigestFromSignerInfos(rawCapture);
    if (!hasAuthenticatedAttributes) {
      // RFC 5652 §5.4: no signedAttrs means there is no separate
      // `messageDigest` attribute to compare against either -- content
      // integrity for this CMS variant is already established by
      // `signatureVerifier.ts`'s direct signature-over-content-hash check
      // (its "no signedAttrs" branch signs this exact same ByteRange-hashed
      // content directly), not a second, independent comparison here.
      return { ok: true };
    }
    if (!expectedDigest) {
      return { ok: false, reason: 'MISSING_MESSAGE_DIGEST' };
    }

    const hasher = createHash(digestAlgorithm);
    hasher.update(pdfBytes.subarray(a, a + b));
    hasher.update(pdfBytes.subarray(c, c + d));
    const computed = hasher.digest();

    const matches = computed.equals(expectedDigest);

    if (!matches) {
      return { ok: false, reason: 'CONTENT_DIGEST_MISMATCH' };
    }

    return { ok: true };
  } catch {
    return { ok: false, reason: 'DIGEST_VERIFICATION_ERROR' };
  }
}
