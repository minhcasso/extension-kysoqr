import forge from 'node-forge';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { TrustStore } from '../trustStore/TrustStore';
import type { AiaFetchOutcome } from './aiaCertFetcher';

/**
 * Proves the dynamic AIA-based issuer-discovery mechanism
 * (`certChainVerifier.ts`'s `spliceDiscoveredIssuers`) that replaced the
 * bundled `lib/trustStore/intermediates/` lookup: when a CMS only embeds the
 * leaf certificate (mirrors the real CMC-CA case), the missing intermediate
 * is now discovered by calling out to `aiaCertFetcher.ts`'s
 * `fetchCaIssuerCertificates` -- mocked here so this file stays focused on
 * chain-building *logic* (splice order, cycle/bound safety, the real
 * cryptographic re-verification of whatever gets spliced in). The network,
 * SSRF-guard, and parsing layer itself is covered separately and thoroughly
 * in `aiaCertFetcher.test.ts` against a real local server.
 *
 * Uses entirely synthetic root/intermediate/leaf certificates, not the real
 * bundled root files.
 */

const mockFetchCaIssuerCertificates =
  vi.fn<(cert: forge.pki.Certificate) => Promise<AiaFetchOutcome>>();

vi.mock('./aiaCertFetcher', () => ({
  fetchCaIssuerCertificates: (cert: forge.pki.Certificate) => mockFetchCaIssuerCertificates(cert),
}));

const { verifyCertificateChainFromCmsBuffer } = await import('./certChainVerifier');

function createCert(
  subjectCN: string,
  issuerAttrs: forge.pki.CertificateField[],
  publicKey: forge.pki.rsa.PublicKey,
  signingKey: forge.pki.rsa.PrivateKey,
  options: { isCa: boolean }
): forge.pki.Certificate {
  const cert = forge.pki.createCertificate();
  cert.publicKey = publicKey;
  cert.serialNumber = Math.floor(Math.random() * 1_000_000)
    .toString(16)
    .padStart(2, '0');
  cert.validity.notBefore = new Date('2024-01-01T00:00:00Z');
  cert.validity.notAfter = new Date('2030-01-01T00:00:00Z');
  cert.setSubject([{ name: 'commonName', value: subjectCN }]);
  cert.setIssuer(issuerAttrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: options.isCa },
    { name: 'keyUsage', keyCertSign: options.isCa, digitalSignature: true },
  ]);
  cert.sign(signingKey, forge.md.sha256.create());
  return cert;
}

function buildDetachedCmsDer(
  leafCert: forge.pki.Certificate,
  leafKey: forge.pki.rsa.PrivateKey,
  extraCerts: forge.pki.Certificate[] = []
): Buffer {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const p7 = forge.pkcs7.createSignedData() as any;
  p7.content = forge.util.createBuffer('the exact bytes that were signed');
  p7.addCertificate(leafCert);
  for (const extra of extraCerts) p7.addCertificate(extra);
  p7.addSigner({
    key: leafKey,
    certificate: leafCert,
    digestAlgorithm: forge.pki.oids.sha256!,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date('2026-01-01T00:00:00Z') },
    ],
  });
  p7.sign({ detached: true });
  return Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), 'binary');
}

function outcome(certs: forge.pki.Certificate[], url = 'https://example.test/issuer.cer'): AiaFetchOutcome {
  return { certs, url: certs.length > 0 ? url : null };
}

afterEach(() => {
  mockFetchCaIssuerCertificates.mockReset();
});

describe('certChainVerifier: dynamic AIA-based issuer discovery', () => {
  it('completes and verifies a chain when the CMS only embeds the leaf, fetching the intermediate via AIA (mirrors the real CMC-CA case)', async () => {
    const rootKeys = forge.pki.rsa.generateKeyPair(2048);
    const rootCert = createCert(
      'Test Root CA',
      [{ name: 'commonName', value: 'Test Root CA' }],
      rootKeys.publicKey,
      rootKeys.privateKey,
      { isCa: true }
    );

    const intermediateKeys = forge.pki.rsa.generateKeyPair(2048);
    const intermediateCert = createCert(
      'Test Intermediate CA',
      rootCert.subject.attributes,
      intermediateKeys.publicKey,
      rootKeys.privateKey,
      { isCa: true }
    );

    const leafKeys = forge.pki.rsa.generateKeyPair(2048);
    const leafCert = createCert(
      'Test Signer',
      intermediateCert.subject.attributes,
      leafKeys.publicKey,
      intermediateKeys.privateKey,
      { isCa: false }
    );

    mockFetchCaIssuerCertificates.mockResolvedValue(outcome([intermediateCert]));

    const cmsDer = buildDetachedCmsDer(leafCert, leafKeys.privateKey);
    const rootPem = forge.pki.certificateToPem(rootCert);
    const fakeTrustStore: TrustStore = {
      isConfigured: () => true,
      isTrustedRoot: (pem) => pem === rootPem,
      getTrustedRootPems: () => [rootPem],
    };

    const result = await verifyCertificateChainFromCmsBuffer(cmsDer, fakeTrustStore, new Date('2026-01-01T00:00:00Z'));

    expect(result?.valid).toBe(true);
    expect(result?.rootNotInTrustStore).toBe(false);
    expect(mockFetchCaIssuerCertificates).toHaveBeenCalledTimes(1);
    // leaf + AIA-fetched intermediate + root, in that order
    expect(result?.chain.map((c) => c.subject)).toEqual([
      expect.stringContaining('Test Signer'),
      expect.stringContaining('Test Intermediate CA'),
      expect.stringContaining('Test Root CA'),
    ]);
  });

  it('does not grant trust just because AIA returns a cert with a matching subject name -- it still must cryptographically verify against a bundled root', async () => {
    const rootKeys = forge.pki.rsa.generateKeyPair(2048);
    const rootCert = createCert(
      'Test Root CA',
      [{ name: 'commonName', value: 'Test Root CA' }],
      rootKeys.publicKey,
      rootKeys.privateKey,
      { isCa: true }
    );

    // A DIFFERENT, unrelated keypair signs the "intermediate" -- same subject
    // name a legitimate intermediate would have, but never actually issued
    // by the real root's private key (a spoofed/forged intermediate served
    // by a malicious or compromised AIA endpoint).
    const attackerKeys = forge.pki.rsa.generateKeyPair(2048);
    const spoofedIntermediateKeys = forge.pki.rsa.generateKeyPair(2048);
    const spoofedIntermediateCert = createCert(
      'Test Intermediate CA',
      rootCert.subject.attributes, // claims to be issued by the real root...
      spoofedIntermediateKeys.publicKey,
      attackerKeys.privateKey, // ...but is actually self-styled/forged
      { isCa: true }
    );

    const leafKeys = forge.pki.rsa.generateKeyPair(2048);
    const leafCert = createCert(
      'Test Signer',
      spoofedIntermediateCert.subject.attributes,
      leafKeys.publicKey,
      spoofedIntermediateKeys.privateKey,
      { isCa: false }
    );

    mockFetchCaIssuerCertificates.mockResolvedValue(outcome([spoofedIntermediateCert]));

    const cmsDer = buildDetachedCmsDer(leafCert, leafKeys.privateKey);
    const rootPem = forge.pki.certificateToPem(rootCert);
    const fakeTrustStore: TrustStore = {
      isConfigured: () => true,
      isTrustedRoot: (pem) => pem === rootPem,
      getTrustedRootPems: () => [rootPem],
    };

    const result = await verifyCertificateChainFromCmsBuffer(cmsDer, fakeTrustStore, new Date('2026-01-01T00:00:00Z'));

    expect(result?.valid).toBe(false);
  });

  it('leaf whose issuer has no AIA caIssuers candidate and is not embedded in the CMS -> ROOT_NOT_TRUSTED, not a crash (the accepted CMC-CA-shaped regression)', async () => {
    const rootKeys = forge.pki.rsa.generateKeyPair(2048);
    const rootCert = createCert(
      'Test Root CA',
      [{ name: 'commonName', value: 'Test Root CA' }],
      rootKeys.publicKey,
      rootKeys.privateKey,
      { isCa: true }
    );

    const intermediateKeys = forge.pki.rsa.generateKeyPair(2048);
    const intermediateAttrs = [{ name: 'commonName', value: 'Unreachable Intermediate CA' }];
    const leafKeys = forge.pki.rsa.generateKeyPair(2048);
    const leafCert = createCert('Test Signer', intermediateAttrs, leafKeys.publicKey, intermediateKeys.privateKey, {
      isCa: false,
    });

    // Mirrors a real leaf whose AIA only has `ocsp`, not `caIssuers`.
    mockFetchCaIssuerCertificates.mockResolvedValue(outcome([]));

    const cmsDer = buildDetachedCmsDer(leafCert, leafKeys.privateKey);
    const rootPem = forge.pki.certificateToPem(rootCert);
    const fakeTrustStore: TrustStore = {
      isConfigured: () => true,
      isTrustedRoot: (pem) => pem === rootPem,
      getTrustedRootPems: () => [rootPem],
    };

    const result = await verifyCertificateChainFromCmsBuffer(cmsDer, fakeTrustStore, new Date('2026-01-01T00:00:00Z'));

    expect(result).not.toBeNull();
    expect(result?.valid).toBe(false);
    expect(result?.rootNotInTrustStore).toBe(true);
  });

  it('CMS already embeds the full chain (Viettel-CA-shaped) -> the AIA fetcher is never called', async () => {
    const rootKeys = forge.pki.rsa.generateKeyPair(2048);
    const rootCert = createCert(
      'Test Root CA',
      [{ name: 'commonName', value: 'Test Root CA' }],
      rootKeys.publicKey,
      rootKeys.privateKey,
      { isCa: true }
    );

    const intermediateKeys = forge.pki.rsa.generateKeyPair(2048);
    const intermediateCert = createCert(
      'Test Intermediate CA',
      rootCert.subject.attributes,
      intermediateKeys.publicKey,
      rootKeys.privateKey,
      { isCa: true }
    );

    const leafKeys = forge.pki.rsa.generateKeyPair(2048);
    const leafCert = createCert(
      'Test Signer',
      intermediateCert.subject.attributes,
      leafKeys.publicKey,
      intermediateKeys.privateKey,
      { isCa: false }
    );

    mockFetchCaIssuerCertificates.mockResolvedValue(outcome([])); // should never even be consulted

    const cmsDer = buildDetachedCmsDer(leafCert, leafKeys.privateKey, [intermediateCert]);
    const rootPem = forge.pki.certificateToPem(rootCert);
    const fakeTrustStore: TrustStore = {
      isConfigured: () => true,
      isTrustedRoot: (pem) => pem === rootPem,
      getTrustedRootPems: () => [rootPem],
    };

    const result = await verifyCertificateChainFromCmsBuffer(cmsDer, fakeTrustStore, new Date('2026-01-01T00:00:00Z'));

    expect(result?.valid).toBe(true);
    expect(mockFetchCaIssuerCertificates).not.toHaveBeenCalled();
  });

  it('cyclic AIA responses (A references B, B references A) resolve promptly without hanging, and end up invalid', async () => {
    const rootKeys = forge.pki.rsa.generateKeyPair(2048);
    const rootCert = createCert(
      'Test Root CA',
      [{ name: 'commonName', value: 'Test Root CA' }],
      rootKeys.publicKey,
      rootKeys.privateKey,
      { isCa: true }
    );

    const keysA = forge.pki.rsa.generateKeyPair(2048);
    const keysB = forge.pki.rsa.generateKeyPair(2048);
    // certA claims to be issued by "B", certB claims to be issued by "A" --
    // neither is self-signed, neither matches the real root: a pure cycle.
    const certA = createCert('Cycle CA A', [{ name: 'commonName', value: 'Cycle CA B' }], keysA.publicKey, keysB.privateKey, {
      isCa: true,
    });
    const certB = createCert('Cycle CA B', [{ name: 'commonName', value: 'Cycle CA A' }], keysB.publicKey, keysA.privateKey, {
      isCa: true,
    });

    const leafKeys = forge.pki.rsa.generateKeyPair(2048);
    const leafCert = createCert('Test Signer', certA.subject.attributes, leafKeys.publicKey, keysA.privateKey, {
      isCa: false,
    });

    mockFetchCaIssuerCertificates.mockImplementation(async (cert) => {
      const subject = cert.subject.attributes.map((a) => a.value).join(',');
      if (subject.includes('Test Signer')) return outcome([certA]);
      if (subject.includes('Cycle CA A')) return outcome([certB]);
      return outcome([]);
    });

    const cmsDer = buildDetachedCmsDer(leafCert, leafKeys.privateKey);
    const rootPem = forge.pki.certificateToPem(rootCert);
    const fakeTrustStore: TrustStore = {
      isConfigured: () => true,
      isTrustedRoot: (pem) => pem === rootPem,
      getTrustedRootPems: () => [rootPem],
    };

    const result = await verifyCertificateChainFromCmsBuffer(cmsDer, fakeTrustStore, new Date('2026-01-01T00:00:00Z'));

    expect(result?.valid).toBe(false);
    // Bounded: the walk must stop once "Cycle CA A" reappears as its own
    // grandparent, well before MAX_PATH_BUILD_HOPS (5) would even matter.
    expect(mockFetchCaIssuerCertificates.mock.calls.length).toBeLessThanOrEqual(5);
  });

  it('a genuinely longer chain than the hop bound fails closed rather than hanging or looping forever', async () => {
    const rootKeys = forge.pki.rsa.generateKeyPair(2048);
    const rootCert = createCert(
      'Test Root CA',
      [{ name: 'commonName', value: 'Test Root CA' }],
      rootKeys.publicKey,
      rootKeys.privateKey,
      { isCa: true }
    );

    // Build a real 7-tier chain: root -> tier1 -> tier2 -> ... -> tier6 -> leaf.
    // MAX_PATH_BUILD_HOPS is 5, so this cannot be fully bridged from AIA alone.
    let issuerAttrs = rootCert.subject.attributes;
    let signingKey = rootKeys.privateKey;
    const tiers: forge.pki.Certificate[] = [];
    for (let i = 1; i <= 6; i += 1) {
      const keys = forge.pki.rsa.generateKeyPair(2048);
      const cert = createCert(`Tier ${i} CA`, issuerAttrs, keys.publicKey, signingKey, { isCa: true });
      tiers.push(cert);
      issuerAttrs = cert.subject.attributes;
      signingKey = keys.privateKey;
    }

    const leafKeys = forge.pki.rsa.generateKeyPair(2048);
    const leafCert = createCert('Test Signer', issuerAttrs, leafKeys.publicKey, signingKey, { isCa: false });

    const bySubject = new Map<string, forge.pki.Certificate>();
    for (const t of [rootCert, ...tiers]) {
      bySubject.set(t.subject.attributes.map((a) => a.value).join(','), t);
    }

    mockFetchCaIssuerCertificates.mockImplementation(async (cert) => {
      const issuerKey = cert.issuer.attributes.map((a) => a.value).join(',');
      const match = bySubject.get(issuerKey);
      return outcome(match ? [match] : []);
    });

    const cmsDer = buildDetachedCmsDer(leafCert, leafKeys.privateKey);
    const rootPem = forge.pki.certificateToPem(rootCert);
    const fakeTrustStore: TrustStore = {
      isConfigured: () => true,
      isTrustedRoot: (pem) => pem === rootPem,
      getTrustedRootPems: () => [rootPem],
    };

    const result = await verifyCertificateChainFromCmsBuffer(cmsDer, fakeTrustStore, new Date('2026-01-01T00:00:00Z'));

    expect(result?.valid).toBe(false);
    expect(mockFetchCaIssuerCertificates.mock.calls.length).toBeLessThanOrEqual(5);
  });
});
