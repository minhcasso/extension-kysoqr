import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import forge from 'node-forge';

/**
 * Shared loader for a directory of curated certificate files (used by both
 * `BundledRootStore.ts` and `IntermediateCertStore.ts`). Accepts either plain
 * PEM or PKCS#7 (`.p7b`, DER) files per entry — CA download portals commonly
 * serve `.p7b`, and this avoids a manual `openssl` conversion step for every
 * future cert. Only ever parses files WE curate and commit, never
 * untrusted request-time input, so this is low-risk compared to the
 * request-time CMS/PDF parsing in the verification engine.
 */
export function loadCertsFromDirectory(dir: string): forge.pki.Certificate[] {
  let filenames: string[];
  try {
    filenames = readdirSync(dir);
  } catch {
    return [];
  }

  const certs: forge.pki.Certificate[] = [];
  for (const filename of filenames) {
    if (filename.toLowerCase().endsWith('.md')) continue;
    const fullPath = path.join(dir, filename);
    try {
      const raw = readFileSync(fullPath);
      certs.push(...parseCertFile(raw));
    } catch {
      // Malformed bundled file: skip it, don't crash the whole store over
      // one bad entry — but this should never happen for files we curate.
    }
  }
  return certs;
}

/**
 * A file/response is either plain PEM (starts with the ASCII marker), PKCS#7
 * DER (a "certs-only" degenerate SignedData, no actual signature — the same
 * container CA portals commonly hand out for certificate distribution), or a
 * single bare X.509 DER certificate (RFC 5280 §4.2.2.1 recommends
 * `application/pkix-cert` -- a bare cert, not PKCS#7 -- for AIA `caIssuers`
 * responses specifically, so this third branch matters for
 * `aiaCertFetcher.ts`, not just for locally-curated bundle files).
 *
 * Exported (not just used via `loadCertsFromDirectory`/`loadCertsFromBase64Manifest`)
 * so both locally-bundled files and network-fetched AIA responses share one
 * PEM/PKCS7/bare-DER implementation instead of two.
 */
export function parseCertFile(raw: Buffer): forge.pki.Certificate[] {
  const text = raw.toString('latin1');
  if (text.includes('-----BEGIN CERTIFICATE-----')) {
    // Some `openssl`-produced files prepend human-readable `subject=`/`issuer=`
    // lines before the actual PEM block — split on the marker, but also
    // discard anything before the first real block (the split's lookahead
    // still leaves that leading junk as its own non-empty chunk).
    return text
      .split(/(?=-----BEGIN CERTIFICATE-----)/g)
      .map((block) => block.trim())
      .filter((block) => block.startsWith('-----BEGIN CERTIFICATE-----'))
      .map((block) => forge.pki.certificateFromPem(block));
  }

  const asn1 = forge.asn1.fromDer(raw.toString('binary'));
  try {
    const p7 = forge.pkcs7.messageFromAsn1(asn1);
    const certs = (p7 as unknown as { certificates?: forge.pki.Certificate[] }).certificates ?? [];
    if (certs.length > 0) return certs;
  } catch {
    // Not a PKCS#7 SignedData -- fall through and try as a bare certificate.
  }

  return [forge.pki.certificateFromAsn1(asn1)];
}

export function derBytes(cert: forge.pki.Certificate): string {
  return forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
}

export interface CertManifestEntry {
  filename: string;
  base64: string;
}

/**
 * Pure counterpart to `loadCertsFromDirectory`: decodes a build-time-generated
 * manifest of base64-encoded raw file bytes (see
 * `scripts/generateCertManifest.js`) into certificates, with NO fs
 * dependency -- safe on Cloudflare Workers, which has no real filesystem at
 * runtime. Reuses `parseCertFile` so both loading paths share identical
 * PEM/PKCS#7 parsing and per-entry malformed-file resilience.
 */
export function loadCertsFromBase64Manifest(entries: CertManifestEntry[]): forge.pki.Certificate[] {
  const certs: forge.pki.Certificate[] = [];
  for (const entry of entries) {
    try {
      certs.push(...parseCertFile(Buffer.from(entry.base64, 'base64')));
    } catch {
      // Malformed generated entry: skip it, mirrors loadCertsFromDirectory's
      // per-file resilience.
    }
  }
  return certs;
}
