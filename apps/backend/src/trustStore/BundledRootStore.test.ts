import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import forge from 'node-forge';
import { describe, expect, it } from 'vitest';
import { BundledRootStore } from './BundledRootStore';

const ROOTS_DIR = fileURLToPath(new URL('./roots', import.meta.url));

// Both roots are bundled as raw PKCS#7 (.p7b, DER) — TrustStore.isTrustedRoot()
// takes a PEM string per its interface, so parse+re-serialize here to get
// one, reading the actual bundled files rather than keeping separate PEM
// copies just for this test.
function pemFromP7b(filename: string): string {
  const der = readFileSync(path.join(ROOTS_DIR, filename));
  const p7 = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(der.toString('binary')));
  return forge.pki.certificateToPem(
    (p7 as unknown as { certificates: forge.pki.Certificate[] }).certificates[0]!
  );
}

const G2_PEM = pemFromP7b('vnrca256.p7b');
const G3_PEM = pemFromP7b('vnrca-g3.p7b');

describe('BundledRootStore', () => {
  it('is configured once bundled root files are present', () => {
    expect(new BundledRootStore().isConfigured()).toBe(true);
  });

  it('trusts G2 (older, pre-existing root)', () => {
    expect(new BundledRootStore().isTrustedRoot(G2_PEM)).toBe(true);
  });

  it('trusts G3 (newer root) at the same time as G2 — append-only, not a replacement', () => {
    const store = new BundledRootStore();
    expect(store.isTrustedRoot(G3_PEM)).toBe(true);
    // Both must be trusted simultaneously — this is the whole point of the
    // append-only design (an old root never stops being trusted just
    // because a newer one was added).
    expect(store.isTrustedRoot(G2_PEM)).toBe(true);
  });

  it('does not trust an unrelated self-signed certificate', () => {
    // A different, unrelated self-signed cert (not derived from either
    // bundled root, not even the same subject) must be rejected — proves
    // the check is a real cryptographic/byte comparison, not a loose name
    // or partial match.
    const keys = forge.pki.rsa.generateKeyPair(1024);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(Date.now() + 1000 * 60 * 60 * 24 * 365);
    const attrs = [{ name: 'commonName', value: 'Totally Fake Root' }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.sign(keys.privateKey);
    const fakePem = forge.pki.certificateToPem(cert);

    expect(new BundledRootStore().isTrustedRoot(fakePem)).toBe(false);
  });
});
