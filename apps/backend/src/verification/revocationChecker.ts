import forge from 'node-forge';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { fetchBytesWithGuards, isAddressAllowed } from './guardedFetch';

/**
 * Real OCSP (RFC 6960) and CRL (RFC 5280) revocation checks for one
 * certificate against its direct issuer.
 *
 * `node-forge` (used everywhere else in this codebase for X.509/PKCS7) has no
 * OCSP/CRL support at all -- it doesn't build or parse OCSP requests or
 * responses, doesn't parse CRLs, and doesn't even structurally decode a
 * cert's `authorityInfoAccess`/`cRLDistributionPoints` extensions. `pkijs`
 * (paired with `asn1js`) does all of this and runs in Node via the built-in
 * WebCrypto engine (`globalThis.crypto`, auto-detected by pkijs itself at
 * import time -- no manual engine setup needed on Node >= 20).
 *
 * IMPORTANT (see certChainVerifier.ts's caller): this is informational only.
 * A failed/unreachable/timed-out check must never throw and must never be
 * treated as "revoked" -- only a real, verified "revoked" response counts.
 * Every function here always resolves, never rejects.
 */

export type RevocationCheckStatus = 'not_revoked' | 'revoked' | 'unavailable';

export interface RevocationCheckResult {
  status: RevocationCheckStatus;
  /** The OCSP/CRL URL found on the certificate, even when the live check
   * itself failed -- lets the UI show "couldn't check, but here's where"
   * rather than nothing at all. `null` only when the certificate has no such
   * URL in the first place (e.g. most root CAs, or a leaf whose issuer only
   * publishes a CRL and not OCSP, or vice versa). */
  url: string | null;
}

const UNAVAILABLE_NO_URL: RevocationCheckResult = { status: 'unavailable', url: null };

/**
 * Network calls to real, external CA infrastructure -- but the URL itself
 * comes straight out of an attacker-supplied, self-signed certificate (OCSP/
 * CRL distribution point extensions), read BEFORE any chain-of-trust check
 * has happened. So unlike a URL the app itself configured (CAS_ESIGN_BASE_URL
 * etc., which legitimately just need a timeout), these must go through the
 * same SSRF-guarded fetch as `aiaCertFetcher.ts`'s AIA lookups (shared core in
 * `./guardedFetch.ts`) -- otherwise a hand-crafted certificate whose OCSP/CRL
 * URL points at an internal address (cloud metadata, loopback, RFC1918) would
 * make this server issue that request on the attacker's behalf, reachable via
 * the public, unauthenticated /api/verify/upload route. */
const FETCH_TIMEOUT_MS = 5000;
const MAX_REVOCATION_REDIRECTS = 3;
/** Real OCSP responses are a few KB; generous headroom, still bounded. */
const OCSP_MAX_RESPONSE_BYTES = 100_000;
/** Some long-lived root CA CRLs are legitimately several MB. */
const CRL_MAX_RESPONSE_BYTES = 20_000_000;

/**
 * Some CA infrastructure (confirmed live: rootca.gov.vn's own CRL
 * distribution point) serves a CRL as PEM text (`-----BEGIN X509 CRL-----`)
 * rather than raw DER, even though nothing in the certificate's own
 * `cRLDistributionPoints` entry says which encoding to expect. Detect and
 * strip PEM armor before handing bytes to `asn1js.fromBER`, which only
 * understands raw DER; pass raw DER through unchanged for CAs that do serve
 * it directly.
 */
function derFromPossiblyPem(bytes: ArrayBuffer): ArrayBuffer {
  const text = Buffer.from(bytes).toString('latin1');
  const match = /-----BEGIN ([\w ]+)-----([\s\S]+?)-----END \1-----/.exec(text);
  if (!match) return bytes;
  const base64 = match[2]!.replace(/\s+/g, '');
  return Uint8Array.from(Buffer.from(base64, 'base64')).buffer;
}

/** Re-parse a `node-forge` certificate's DER bytes into a `pkijs.Certificate`
 * -- the two libraries don't share an object model, but both operate on the
 * same raw DER, so converting is a one-shot re-parse, not deep friction. */
export function toPkijsCertificate(cert: forge.pki.Certificate): pkijs.Certificate {
  const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const derBuffer = Uint8Array.from(derBytes, (c) => c.charCodeAt(0)).buffer;
  const parsed = asn1js.fromBER(derBuffer);
  return new pkijs.Certificate({ schema: parsed.result });
}

const GENERAL_NAME_URI = 6;

/** Find the URL for one `accessMethod` (OCSP or CA-Issuers) inside a
 * certificate's `authorityInfoAccess` extension, if present. */
function findAiaUrl(cert: pkijs.Certificate, accessMethodOid: string): string | null {
  const ext = cert.extensions?.find((e) => e.extnID === pkijs.id_AuthorityInfoAccess);
  const infoAccess = ext?.parsedValue as pkijs.InfoAccess | undefined;
  const description = infoAccess?.accessDescriptions?.find(
    (d) => d.accessMethod === accessMethodOid && d.accessLocation.type === GENERAL_NAME_URI
  );
  return typeof description?.accessLocation.value === 'string'
    ? description.accessLocation.value
    : null;
}

/** Find the first CRL distribution point URL, if present. A cert can list
 * several distribution points; the first URI-typed one is enough here. */
function findCrlUrl(cert: pkijs.Certificate): string | null {
  const ext = cert.extensions?.find((e) => e.extnID === pkijs.id_CRLDistributionPoints);
  const dps =
    (ext?.parsedValue as pkijs.CRLDistributionPoints | undefined)?.distributionPoints ?? [];
  for (const dp of dps) {
    if (!Array.isArray(dp.distributionPoint)) continue; // RelativeDistinguishedNames form, not a URI list
    const uri = dp.distributionPoint.find((name) => name.type === GENERAL_NAME_URI);
    if (typeof uri?.value === 'string') return uri.value;
  }
  return null;
}

/** Real OCSP check (RFC 6960): build a request, POST it to the responder,
 * verify the response is genuinely signed by the issuer, then read the
 * per-certificate status out of it. */
export async function checkOcsp(
  cert: forge.pki.Certificate,
  issuer: forge.pki.Certificate,
  /** Override for tests only -- production callers always get the real
   * predicate, same convention as `fetchCaIssuerCertificates`. Needed because
   * a real local test server can only ever bind to a loopback address, which
   * the real predicate always (correctly) blocks. */
  isAddressAllowedOverride?: typeof isAddressAllowed
): Promise<RevocationCheckResult> {
  let pkijsCert: pkijs.Certificate;
  let pkijsIssuer: pkijs.Certificate;
  let url: string | null;
  try {
    pkijsCert = toPkijsCertificate(cert);
    pkijsIssuer = toPkijsCertificate(issuer);
    url = findAiaUrl(pkijsCert, pkijs.id_ad_ocsp);
  } catch {
    return UNAVAILABLE_NO_URL;
  }
  if (!url) return UNAVAILABLE_NO_URL;

  try {
    const request = new pkijs.OCSPRequest();
    await request.createForCertificate(pkijsCert, {
      hashAlgorithm: 'SHA-256',
      issuerCertificate: pkijsIssuer,
    });
    const requestDer = Buffer.from(request.toSchema(true).toBER());

    const responseBytes = await fetchBytesWithGuards(
      url,
      {
        timeoutMs: FETCH_TIMEOUT_MS,
        maxRedirects: MAX_REVOCATION_REDIRECTS,
        maxBytes: OCSP_MAX_RESPONSE_BYTES,
        isAddressAllowed: isAddressAllowedOverride,
      },
      { method: 'POST', headers: { 'Content-Type': 'application/ocsp-request' }, body: requestDer }
    );
    const ocspResponse = pkijs.OCSPResponse.fromBER(responseBytes);
    if (!ocspResponse.responseBytes) {
      return { status: 'unavailable', url };
    }
    const basicResponse = pkijs.BasicOCSPResponse.fromBER(
      Buffer.from(ocspResponse.responseBytes.response.valueBlock.valueHexView)
    );

    const signatureOk = await basicResponse
      .verify({ trustedCerts: [pkijsIssuer] })
      .catch(() => false);
    if (!signatureOk) {
      return { status: 'unavailable', url };
    }

    const result = await basicResponse.getCertificateStatus(pkijsCert, pkijsIssuer);
    if (!result.isForCertificate) return { status: 'unavailable', url };
    if (result.status === 0) return { status: 'not_revoked', url };
    if (result.status === 1) return { status: 'revoked', url };
    return { status: 'unavailable', url };
  } catch {
    return { status: 'unavailable', url };
  }
}

/** Real CRL check (RFC 5280): download the CRL, verify it's genuinely signed
 * by the issuer, then look up whether the certificate's serial number is in
 * the revoked list. */
export async function checkCrl(
  cert: forge.pki.Certificate,
  issuer: forge.pki.Certificate,
  /** Override for tests only -- see `checkOcsp`'s parameter of the same name. */
  isAddressAllowedOverride?: typeof isAddressAllowed
): Promise<RevocationCheckResult> {
  let pkijsCert: pkijs.Certificate;
  let pkijsIssuer: pkijs.Certificate;
  let url: string | null;
  try {
    pkijsCert = toPkijsCertificate(cert);
    pkijsIssuer = toPkijsCertificate(issuer);
    url = findCrlUrl(pkijsCert);
  } catch {
    return UNAVAILABLE_NO_URL;
  }
  if (!url) return UNAVAILABLE_NO_URL;

  try {
    const responseBytes = await fetchBytesWithGuards(url, {
      timeoutMs: FETCH_TIMEOUT_MS,
      maxRedirects: MAX_REVOCATION_REDIRECTS,
      maxBytes: CRL_MAX_RESPONSE_BYTES,
      isAddressAllowed: isAddressAllowedOverride,
    });

    const body = derFromPossiblyPem(responseBytes);
    const parsed = asn1js.fromBER(body);
    if (parsed.offset === -1) {
      return { status: 'unavailable', url };
    }
    const crl = new pkijs.CertificateRevocationList({ schema: parsed.result });

    const signatureOk = await crl.verify({ issuerCertificate: pkijsIssuer }).catch(() => false);
    if (!signatureOk) {
      return { status: 'unavailable', url };
    }

    const revoked = crl.isCertificateRevoked(pkijsCert);
    return { status: revoked ? 'revoked' : 'not_revoked', url };
  } catch {
    return { status: 'unavailable', url };
  }
}
