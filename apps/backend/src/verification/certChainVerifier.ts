import forge from 'node-forge';
import { derBytes } from '../trustStore/certBundleLoader';
import type { TrustStore } from '../trustStore/TrustStore';
import { fetchCaIssuerCertificates } from './aiaCertFetcher';
import { fixForgeString } from './fixForgeString';
import { getAttributeLabel, shouldHideAttribute } from './certParser';
import { parseCmsMessage } from './cmsAsn1';
import { checkCrl, checkOcsp, type RevocationCheckResult } from './revocationChecker';

/** Bound on how many hops `spliceDiscoveredIssuers` will walk in one chain --
 * just large enough for any real-world CA hierarchy, small enough to
 * guarantee termination even against a cyclic/malicious AIA response. */
const MAX_PATH_BUILD_HOPS = 5;

export type ChainCertInfo = {
  index: number;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  isCa: boolean;
  /**
   * Real OCSP/CRL revocation status for this cert against its direct issuer
   * (the next entry in `chain`). `null` only for the last entry (the root) --
   * self-signed roots aren't checked via OCSP/CRL; a compromised root is
   * removed from the bundled trust store directly instead. Informational
   * only: never affects `valid`/`error` above (see revocationChecker.ts).
   */
  ocsp: RevocationCheckResult | null;
  crl: RevocationCheckResult | null;
};

export type ChainVerificationResult = {
  valid: boolean;
  error?: string | undefined;
  chain: ChainCertInfo[];
  /**
   * The chain failed only because the trust anchor (root CA) is not present
   * in the configured trust store. The certificate path is otherwise
   * structurally sound, but we cannot fully anchor it.
   */
  rootNotInTrustStore?: boolean;
  /**
   * Informational only -- does NOT affect `valid`. A signature is valid
   * forever once its certificate was valid at signing time; this flag just
   * tells the UI the signer's certificate has since expired as of "now", so
   * it can show that fact alongside the (still-valid) verdict.
   */
  certificateExpiredNow?: boolean;
};

function normalizeDn(
  attributes: Array<{ name?: string; shortName?: string; value?: unknown }> | undefined
): string {
  if (!attributes || attributes.length === 0) return '';
  return attributes
    .map((a) => {
      const name = a.shortName || a.name || '';
      const raw = a.value;
      const value =
        typeof raw === 'string' ? raw : raw === undefined || raw === null ? '' : String(raw);
      return `${name}=${value}`;
    })
    .join(',');
}

function formatDn(attrs: forge.pki.CertificateField[]): string {
  return attrs
    .map((a) => {
      const raw = a.value;
      const value = typeof raw === 'string' ? fixForgeString(raw) : String(raw);
      const label = getAttributeLabel(a);
      // userID's own value is already self-describing (e.g. "MST:..." for a
      // business, "CCCD:..." for an individual) -- showing it as
      // "userID=MST:..." just repeats that, so show the bare value instead.
      return label === 'userID' ? value : `${label}=${value}`;
    })
    .join(', ');
}

/**
 * Starting from the CMS-provided certificates, extend the chain upwards using
 * the trust store's root certificates so that:
 * - Only certificates that actually continue the chain are appended.
 * - Unrelated bundled roots are not shown in the chain result.
 */
function buildExtendedChain(
  cmsCerts: forge.pki.Certificate[],
  trustedCerts: forge.pki.Certificate[]
): forge.pki.Certificate[] {
  if (!cmsCerts.length || !trustedCerts.length) return cmsCerts;

  const extended: forge.pki.Certificate[] = [...cmsCerts];

  const trustedBySubject = new Map<string, forge.pki.Certificate[]>();
  for (const cert of trustedCerts) {
    const key = normalizeDn(cert.subject.attributes);
    if (!key) continue;
    const list = trustedBySubject.get(key);
    if (list) {
      list.push(cert);
    } else {
      trustedBySubject.set(key, [cert]);
    }
  }

  const seenSerials = new Set(
    extended.map((c) => (c.serialNumber || '').toLowerCase()).filter((s) => s.length > 0)
  );

  // Walk upwards at most `trustedCerts.length` steps to avoid any accidental
  // loops in a misconfigured trust store.
  for (let i = 0; i < trustedCerts.length; i += 1) {
    const last = extended[extended.length - 1];
    if (!last) break;
    const issuerKey = normalizeDn(last.issuer.attributes);
    if (!issuerKey) break;

    const parents = trustedBySubject.get(issuerKey);
    if (!parents || parents.length === 0) break;

    let parent: forge.pki.Certificate | undefined;
    for (const candidate of parents) {
      const sn = (candidate.serialNumber || '').toLowerCase();
      if (!sn || seenSerials.has(sn)) continue;
      parent = candidate;
      break;
    }

    if (!parent) break;

    const parentSerial = (parent.serialNumber || '').toLowerCase();
    if (parentSerial) seenSerials.add(parentSerial);
    extended.push(parent);

    const subjectKey = normalizeDn(parent.subject.attributes);
    const parentIssuerKey = normalizeDn(parent.issuer.attributes);
    // Stop if we reached a self-signed root (subject == issuer).
    if (subjectKey && subjectKey === parentIssuerKey) break;
  }

  return extended;
}

/**
 * If the CMS-provided `certs` array doesn't already contain a certificate
 * whose subject matches the topmost cert's issuer, try to bridge the gap
 * one hop at a time -- exactly as if the CMS itself had embedded the missing
 * certificate (the same shape Viettel-CA's self-embedded intermediate
 * already takes today). Two candidate sources, tried in order, per hop:
 *
 *   B. A bundled trusted root whose subject matches directly (no network
 *      call needed -- this only ever matters when the missing issuer IS a
 *      root, i.e. a 1-tier hierarchy).
 *   C. The missing issuer's certificate, fetched live via the *current*
 *      cert's own `authorityInfoAccess` `id-ad-caIssuers` URL
 *      (`aiaCertFetcher.ts` -- SSRF-guarded, timeout-guarded, size-guarded).
 *
 * Neither source grants trust by itself: every appended cert still has to
 * pass `forge.pki.verifyCertificateChain`'s own `parent.verify(child)` check
 * below, same as any CMS-embedded cert would. `caStore` (built separately,
 * from `trustStore.getTrustedRootPems()` only) is never touched here --
 * mixing intermediates into `caStore` would make forge treat them as
 * independent trust anchors, silently skipping the real signature check
 * this function exists to feed candidates into, not bypass.
 *
 * If neither source yields a candidate for a given hop, the walk simply
 * stops -- the subsequent `forge.pki.verifyCertificateChain` call fails
 * closed with its own `unknown_ca` error (mapped to `ROOT_NOT_TRUSTED`
 * below), exactly as it already does today for any other unreachable chain.
 */
async function spliceDiscoveredIssuers(
  cmsCerts: forge.pki.Certificate[],
  trustedRootCerts: forge.pki.Certificate[]
): Promise<forge.pki.Certificate[]> {
  const extended = [...cmsCerts];
  const visited = new Set(extended.map((c) => derBytes(c)));

  for (let hop = 0; hop < MAX_PATH_BUILD_HOPS; hop += 1) {
    const last = extended[extended.length - 1];
    if (!last) break;

    const subjectKey = normalizeDn(last.subject.attributes);
    const issuerKey = normalizeDn(last.issuer.attributes);
    if (!issuerKey || (subjectKey && subjectKey === issuerKey)) break; // self-signed -- nothing left to bridge

    const alreadyPresent = extended.some((c) => normalizeDn(c.subject.attributes) === issuerKey);
    if (alreadyPresent) break;

    const rootMatch = trustedRootCerts.find((c) => normalizeDn(c.subject.attributes) === issuerKey);
    if (rootMatch) {
      const fp = derBytes(rootMatch);
      if (visited.has(fp)) break;
      visited.add(fp);
      extended.push(rootMatch);
      continue;
    }

    const outcome = await fetchCaIssuerCertificates(last);
    const candidate = outcome.certs.find((c) => normalizeDn(c.subject.attributes) === issuerKey);
    if (!candidate) {
      break;
    }

    const fp = derBytes(candidate);
    if (visited.has(fp)) break;
    visited.add(fp);
    extended.push(candidate);
  }

  return extended;
}

/**
 * Verify the certificate chain embedded in a CMS/PKCS#7 blob against the
 * configured trust store.
 *
 * Trust is decided in two places, deliberately redundant:
 * 1. `forge.pki.verifyCertificateChain`, given a CA store built from
 *    `trustStore.getTrustedRootPems()`, does the real cryptographic path
 *    validation (each `parent.verify(child)` link, validity windows).
 * 2. Once a chain validates, the actual anchoring root is re-checked
 *    explicitly through `trustStore.isTrustedRoot()` — the same
 *    byte-for-byte comparison this project's trust model is built on
 *    (see `lib/trustStore/BundledRootStore.ts`), rather than trusting step 1
 *    alone to have used an equivalent cert set.
 */
export async function verifyCertificateChainFromCmsBuffer(
  cmsDer: Buffer,
  trustStore: TrustStore,
  validityCheckDate?: Date
): Promise<ChainVerificationResult | null> {
  try {
    const p7 = parseCmsMessage(cmsDer);
    const certs = (p7 as unknown as { certificates?: forge.pki.Certificate[] }).certificates;

    if (!certs || certs.length === 0) {
      return null;
    }

    // The chain -- with the signer's own leaf certificate at index 0, per
    // node-forge's convention -- is checked against the SIGNING time (when
    // given), not "now": a signature must stay valid forever once the
    // certificate was good at the moment it signed, even if that cert has
    // since expired. "Currently expired" is tracked separately below, purely
    // for display.
    const leafCert = certs[0];
    const certificateExpiredNow = leafCert ? new Date() > leafCert.validity.notAfter : false;

    let valid = false;
    let error: string | undefined;
    let rootNotInTrustStore = false;
    let certsForChain = certs;
    let trustedRootCerts: forge.pki.Certificate[] = [];

    if (!trustStore.isConfigured()) {
      error = 'Trust store is not configured on the server';
    } else {
      const trustedPems = trustStore.getTrustedRootPems();
      trustedRootCerts = trustedPems
        .map((pem) => {
          try {
            return forge.pki.certificateFromPem(pem);
          } catch {
            return null;
          }
        })
        .filter((c): c is forge.pki.Certificate => c !== null);

      certsForChain = await spliceDiscoveredIssuers(certs, trustedRootCerts);

      try {
        const caStore = forge.pki.createCaStore(trustedPems);
        forge.pki.verifyCertificateChain(caStore, certsForChain, {
          validityCheckDate: validityCheckDate ?? new Date(),
        });
        valid = true;
      } catch (e) {
        valid = false;

        // node-forge throws rich error objects for certificate path issues.
        // Detect the specific "unknown_ca" case which means the path failed
        // only because the trust anchor (root CA) is missing from the store.
        const anyErr = e as unknown as { message?: string; error?: unknown };
        const errorCode = typeof anyErr?.error === 'string' ? anyErr.error : undefined;
        const errorMessage =
          typeof anyErr?.message === 'string'
            ? anyErr.message
            : e instanceof Error && e.message
              ? e.message
              : undefined;

        if (
          errorCode === 'forge.pki.UnknownCertificateAuthority' ||
          errorCode === 'unknown_ca' ||
          errorMessage === 'Certificate is not trusted.'
        ) {
          rootNotInTrustStore = true;
          error =
            errorMessage ||
            'Certificate chain could not be fully validated because the root CA is not in the trust store.';
        } else if (errorMessage) {
          error = errorMessage;
        } else {
          error = String(e);
        }
      }
    }

    let displayCerts: forge.pki.Certificate[] = certsForChain;

    if (valid) {
      if (trustedRootCerts.length > 0) {
        displayCerts = buildExtendedChain(certsForChain, trustedRootCerts);

        // Explicit, redundant re-check of the actual anchoring root against
        // the trust store's own byte-exact comparison (see doc comment).
        const anchoringRoot = displayCerts[displayCerts.length - 1];
        const anchorIsSelfSigned =
          anchoringRoot &&
          normalizeDn(anchoringRoot.subject.attributes) ===
            normalizeDn(anchoringRoot.issuer.attributes);
        if (anchorIsSelfSigned) {
          const anchorPem = forge.pki.certificateToPem(anchoringRoot);
          const isTrustedRootByteExact = trustStore.isTrustedRoot(anchorPem);
          if (!isTrustedRootByteExact) {
            valid = false;
            rootNotInTrustStore = true;
            error = 'Certificate chain root failed the trust store byte-exact check';
          }
        }
      }
    }

    const chain: ChainCertInfo[] = displayCerts.map((c, index) => {
      const subjectAttrs = (c.subject.attributes || []).filter((a) => !shouldHideAttribute(a));
      const issuerAttrs = (c.issuer.attributes || []).filter((a) => !shouldHideAttribute(a));

      const basicConstraints = (c.extensions || []).find((e) => e.name === 'basicConstraints') as
        { cA?: boolean } | undefined;

      return {
        index,
        subject: formatDn(subjectAttrs),
        issuer: formatDn(issuerAttrs),
        serialNumber: c.serialNumber || '',
        validFrom: c.validity.notBefore.toISOString(),
        validTo: c.validity.notAfter.toISOString(),
        isCa: !!basicConstraints?.cA,
        ocsp: null,
        crl: null,
      };
    });

    // Real OCSP/CRL revocation checks -- informational only, never affects
    // `valid`/`error` above (see revocationChecker.ts). Every cert except the
    // root (last entry) is checked against its direct issuer (the next cert
    // up in the chain); all checks for all certs run together in one
    // `Promise.all` so the total added latency for this signature is bounded
    // by roughly one network timeout, not N x timeout.
    const revocationChecks = await Promise.all(
      displayCerts.slice(0, -1).map(async (cert, index) => {
        const issuer = displayCerts[index + 1]!;
        const [ocsp, crl] = await Promise.all([checkOcsp(cert, issuer), checkCrl(cert, issuer)]);
        return { index, ocsp, crl };
      })
    );
    for (const { index, ocsp, crl } of revocationChecks) {
      chain[index]!.ocsp = ocsp;
      chain[index]!.crl = crl;
    }

    return { valid, error, chain, rootNotInTrustStore, certificateExpiredNow };
  } catch {
    return null;
  }
}
