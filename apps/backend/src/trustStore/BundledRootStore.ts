import { fileURLToPath } from 'node:url';
import path from 'node:path';
import forge from 'node-forge';
import { derBytes, loadCertsFromBase64Manifest, loadCertsFromDirectory } from './certBundleLoader';
import { generatedRootCerts } from './generated/rootCerts.generated';
import type { TrustStore } from './TrustStore';

const ROOTS_DIR = fileURLToPath(new URL('./roots', import.meta.url));

/**
 * Trust store backed by root CA certificates bundled directly in the repo
 * (`lib/trustStore/roots/*`), instead of an env var. Root CA certs are public
 * data — no reason to treat them as a secret — bundling them means they're
 * versioned and reviewable in a PR, and a deployment needs zero config to get
 * a working, correct trust store.
 *
 * IMPORTANT (see roots/README.md): this list is append-only. A new
 * generation of root (e.g. a "G3" replacing "G2") does NOT replace the old
 * one here — a document signed and chain-verified through an older root
 * while it was trusted must stay verifiable forever, the same principle
 * already applied to leaf-certificate expiry (signingTime governs, not
 * "now"). Only remove a root for an actual security incident.
 */
let cachedCerts: forge.pki.Certificate[] | null = null;

function getBundledCerts(): forge.pki.Certificate[] {
  if (!cachedCerts) {
    // Union of a live directory read (VPS, tests -- picks up anything not
    // yet regenerated) and the build-time-generated snapshot (works with no
    // real filesystem, e.g. Cloudflare Workers). Harmless duplication when
    // both sources yield the same cert -- every consumer here is
    // set-membership/boolean, never count-sensitive.
    cachedCerts = [...loadCertsFromDirectory(ROOTS_DIR), ...loadCertsFromBase64Manifest(generatedRootCerts)];
  }
  return cachedCerts;
}

export class BundledRootStore implements TrustStore {
  isConfigured(): boolean {
    return getBundledCerts().length > 0;
  }

  /** Full-certificate comparison (DER bytes), never just a serial number or
   * subject name — those are self-declared by whoever issued the candidate
   * cert and are not cryptographically bound to a specific keypair, so
   * matching on them alone would let a fake root with a copied serial/name
   * pass as trusted. */
  isTrustedRoot(rootCertPem: string): boolean {
    let candidate: forge.pki.Certificate;
    try {
      candidate = forge.pki.certificateFromPem(rootCertPem);
    } catch {
      return false;
    }
    const candidateDer = derBytes(candidate);
    return getBundledCerts().some((trusted) => derBytes(trusted) === candidateDer);
  }

  getTrustedRootPems(): string[] {
    return getBundledCerts().map((cert) => forge.pki.certificateToPem(cert));
  }
}

/** Test-only: clear the cached bundle so a test can reload under different files. */
export function resetBundledRootStoreCacheForTests(): void {
  cachedCerts = null;
}
