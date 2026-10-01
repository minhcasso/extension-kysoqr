import type { TrustStore } from '../trustStore/TrustStore';
import { parseCertificateInfo } from './certParser';
import { parseCmsMessage } from './cmsAsn1';
import { type ChainCertInfo, verifyCertificateChainFromCmsBuffer } from './certChainVerifier';
import { verifyPdfContentDigest } from './pdfContentDigestVerifier';
import {
  type ExtractCmsSuccess,
  extractAllCmsFromSignedPdf,
  isLastSignatureCoveringWholeFile,
} from './pdfSignatureExtractor';
import { verifySignerInfoSignature } from './signatureVerifier';
import { extractSigningTimeFromCms } from './signingTimeExtraction';

export type VerificationStatus =
  | 'SIGNED_VALID'
  | 'CONTENT_DIGEST_MISMATCH'
  | 'CHAIN_VALIDATION_FAILED'
  | 'ROOT_NOT_TRUSTED'
  | 'SIGNATURE_INVALID'
  | 'TRUST_STORE_NOT_CONFIGURED'
  | 'UNSUPPORTED_SUBFILTER'
  | 'UNSUPPORTED_ALGORITHM';

export interface VerificationCertificate {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
}

/** Verification outcome for one CMS signature/revision inside a PDF. */
export interface VerificationResult {
  status: VerificationStatus;
  message: string;
  signedAt?: string | undefined;
  certificate?: VerificationCertificate | undefined;
  certificateChain?: ChainCertInfo[] | undefined;
  certificateChainRootNotInTrustStore?: boolean | undefined;
  /** Informational only -- does not affect `status`. A signature stays
   * SIGNED_VALID forever once its certificate was valid AT SIGNING TIME;
   * this just tells the UI the certificate has since expired as of "now". */
  certificateExpiredNow?: boolean | undefined;
  contentIntact?: boolean | undefined;
}

function toVerificationCertificate(
  cert: import('node-forge').pki.Certificate
): VerificationCertificate {
  const parsed = parseCertificateInfo(cert);
  return {
    subject: parsed.subjectFull,
    issuer: parsed.issuerFull,
    serialNumber: parsed.serialNumber,
    validFrom: parsed.validFrom.toISOString(),
    validTo: parsed.validTo.toISOString(),
  };
}

async function verifyOneSignature(
  pdfBytes: Buffer,
  extracted: ExtractCmsSuccess,
  trustStore: TrustStore,
  wholeFileCovered: boolean
): Promise<VerificationResult> {
  const { cmsDer, byteRange, dictSigningTime } = extracted;

  const sigCheck = verifySignerInfoSignature(cmsDer, pdfBytes, byteRange);
  const certificate = sigCheck.leafCertificate
    ? toVerificationCertificate(sigCheck.leafCertificate)
    : undefined;

  let signedAt = dictSigningTime;
  try {
    signedAt = extractSigningTimeFromCms(parseCmsMessage(cmsDer)) ?? dictSigningTime;
  } catch {
    // keep dictSigningTime fallback
  }

  if (!sigCheck.ok && sigCheck.reason === 'UNSUPPORTED_KEY_ALGORITHM') {
    return {
      status: 'UNSUPPORTED_ALGORITHM',
      message: `The signature uses an unsupported key algorithm (${sigCheck.keyAlgorithm ?? 'unknown'}).`,
      signedAt,
    };
  }

  if (!sigCheck.ok) {
    return {
      status: 'SIGNATURE_INVALID',
      message:
        'The signature could not be cryptographically verified against the signer’s certificate.',
      signedAt,
      certificate,
    };
  }

  // Content-integrity check: the CMS messageDigest must match a fresh hash
  // of the actual signed byte ranges. `wholeFileCovered` is the PDF Shadow
  // Attack guard (only meaningful for the newest signature) -- unaccounted
  // trailing bytes after the last signed revision are treated the same as a
  // digest mismatch, since a viewer could render them as if they were part
  // of the signed content.
  const digestCheck = verifyPdfContentDigest(pdfBytes, cmsDer, byteRange);
  if (!digestCheck.ok || !wholeFileCovered) {
    return {
      status: 'CONTENT_DIGEST_MISMATCH',
      message: 'The PDF content does not match what was actually signed.',
      signedAt,
      certificate,
      contentIntact: false,
    };
  }

  if (!trustStore.isConfigured()) {
    return {
      status: 'TRUST_STORE_NOT_CONFIGURED',
      message:
        'The server trust store is not configured; the certificate chain could not be anchored.',
      signedAt,
      certificate,
      contentIntact: true,
    };
  }

  const signedAtDate = signedAt ? new Date(signedAt) : undefined;
  const validityCheckDate =
    signedAtDate && !Number.isNaN(signedAtDate.getTime()) ? signedAtDate : undefined;
  const chainResult = await verifyCertificateChainFromCmsBuffer(
    cmsDer,
    trustStore,
    validityCheckDate
  );

  if (!chainResult) {
    return {
      status: 'CHAIN_VALIDATION_FAILED',
      message: 'The PDF signature contains no valid certificate chain.',
      signedAt,
      certificate,
      contentIntact: true,
    };
  }

  if (!chainResult.valid) {
    if (chainResult.rootNotInTrustStore) {
      // The vulnerability this replaces: the legacy verifier treated this
      // exact case as still SIGNED_VALID. An untrusted root is now always
      // its own distinct, non-valid status.
      return {
        status: 'ROOT_NOT_TRUSTED',
        message:
          'The signature and content are cryptographically valid, but the root CA is not in the trust store.',
        signedAt,
        certificate,
        certificateChain: chainResult.chain,
        certificateChainRootNotInTrustStore: true,
        certificateExpiredNow: chainResult.certificateExpiredNow,
        contentIntact: true,
      };
    }

    return {
      status: 'CHAIN_VALIDATION_FAILED',
      message: chainResult.error ?? 'The signature certificate chain is invalid.',
      signedAt,
      certificate,
      certificateChain: chainResult.chain,
      contentIntact: true,
    };
  }

  return {
    status: 'SIGNED_VALID',
    message: chainResult.certificateExpiredNow
      ? 'The signature was valid at signing time; the certificate has since expired.'
      : 'The signature, content, and certificate chain are all valid.',
    signedAt,
    certificate,
    certificateChain: chainResult.chain,
    certificateExpiredNow: chainResult.certificateExpiredNow,
    contentIntact: true,
  };
}

/**
 * Upper bound on how many embedded signatures a single upload will actually
 * verify. Each signature can fan out into several outbound network calls
 * (AIA intermediate-CA fetch + OCSP + CRL, each independently SSRF-guarded
 * but still real requests) via `verifyCertificateChainFromCmsBuffer` --
 * without a cap, a PDF hand-crafted with dozens of fabricated
 * `/ByteRange`+`/SubFilter`+`/Contents` signature-dictionary-shaped blocks
 * (trivial: extraction is plain byte-scanning, not real PDF object parsing)
 * could fan out into a large multiple of that in outbound calls per request,
 * amplifying both cost and the surface of any one guarded-fetch edge case.
 * A real document with more than a handful of independent signatures is
 * already unusual -- excess entries beyond this cap are simply not verified.
 */
const MAX_SIGNATURES_PER_DOCUMENT = 10;

/**
 * Verify every CMS signature embedded in a PDF, independent of any DB/CAS
 * lookup -- the real cryptographic verification entry point.
 *
 * Each signature is verified independently: an unexpected error while
 * processing one (e.g. a malformed embedded certificate) produces a
 * SIGNATURE_INVALID entry for that signature rather than failing the whole
 * request. An unsigned PDF returns an empty array (not an error).
 */
export async function verifyPdfSignatures(
  pdfBytes: Buffer,
  trustStore: TrustStore
): Promise<VerificationResult[]> {
  const extraction = extractAllCmsFromSignedPdf(pdfBytes);
  if (!extraction.ok) {
    if (extraction.error.kind === 'NO_SIGNATURE_FIELD_FOUND') return [];
    return [
      {
        status: 'SIGNATURE_INVALID',
        message: 'The PDF signature structure is malformed and could not be parsed.',
      },
    ];
  }

  const values = extraction.values.slice(0, MAX_SIGNATURES_PER_DOCUMENT);

  // Coverage is still judged on the newest entry of any kind (a PAdES-LTA
  // document timestamp usually is the newest one), but the verdict is
  // attached to the newest signature we actually verify -- otherwise bytes
  // appended after an unsupported last entry would go unreported.
  const wholeFileCovered = isLastSignatureCoveringWholeFile(values, pdfBytes.length);
  let lastSupportedIndex = -1;
  values.forEach((value, index) => {
    if (value.supported) lastSupportedIndex = index;
  });

  return Promise.all(
    values.map((value, index) =>
      value.supported
        ? verifyOneSignature(
            pdfBytes,
            value,
            trustStore,
            index === lastSupportedIndex ? wholeFileCovered : true
          ).catch((): VerificationResult => ({
            status: 'SIGNATURE_INVALID',
            message: 'An unexpected error occurred while verifying this signature.',
          }))
        : Promise.resolve(unsupportedSubFilterResult(value))
    )
  );
}

/** One entry whose SubFilter this pipeline can't verify -- reported on its
 * own, without failing the other signatures in the document. */
function unsupportedSubFilterResult(value: ExtractCmsSuccess): VerificationResult {
  const isDocumentTimestamp = value.subFilter.toLowerCase() === 'etsi.rfc3161';
  return {
    status: 'UNSUPPORTED_SUBFILTER',
    message: isDocumentTimestamp
      ? 'Document timestamp (PAdES-LTA, ETSI.RFC3161): timestamps are not verified yet.'
      : `The PDF uses an unsupported digital signature format (${value.subFilter}).`,
    signedAt: value.dictSigningTime,
  };
}
