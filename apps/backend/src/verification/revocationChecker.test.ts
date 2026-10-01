import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import * as asn1js from 'asn1js';
import forge from 'node-forge';
import * as pkijs from 'pkijs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { checkCrl, checkOcsp } from './revocationChecker';

/**
 * Builds a real, self-signed root cert + a real leaf cert issued by it (both
 * via pkijs, signed for real with WebCrypto), plus real, correctly-signed
 * OCSP responses and CRLs referencing that exact pair -- so these tests
 * exercise the actual signature-verification code paths in
 * `revocationChecker.ts`, not just its error handling.
 *
 * Transport is a REAL local `node:http` server (started first, so its
 * ephemeral URL can be baked into the leaf cert's OCSP/CRL URLs), not a
 * `global.fetch` mock -- `checkOcsp`/`checkCrl` now route through
 * `guardedFetch.ts`'s SSRF guard, whose Node-runtime path uses
 * `node:http`/`node:https` directly and never calls `fetch()` at all (see
 * `aiaCertFetcher.test.ts`, which already tests that same guard core this
 * way).
 */

interface SyntheticPki {
  rootCert: pkijs.Certificate;
  rootKeys: CryptoKeyPair;
  leafCert: pkijs.Certificate;
  leafForge: forge.pki.Certificate;
  rootForge: forge.pki.Certificate;
}

function pkijsCertToForge(cert: pkijs.Certificate): forge.pki.Certificate {
  const der = Buffer.from(cert.toSchema().toBER());
  return forge.pki.certificateFromAsn1(forge.asn1.fromDer(der.toString('binary')));
}

async function buildSyntheticPki(ocspUrl: string | null, crlUrl: string | null): Promise<SyntheticPki> {
  const crypto = pkijs.getCrypto(true);
  const algorithm = pkijs.getAlgorithmParameters('RSASSA-PKCS1-v1_5', 'generateKey');
  if ('hash' in algorithm.algorithm) (algorithm.algorithm as { hash: { name: string } }).hash.name = 'SHA-256';

  const rootKeys = (await crypto.generateKey(
    algorithm.algorithm as RsaHashedKeyGenParams,
    true,
    algorithm.usages
  )) as CryptoKeyPair;

  const rootCert = new pkijs.Certificate();
  rootCert.version = 2;
  rootCert.serialNumber = new asn1js.Integer({ value: 1 });
  rootCert.issuer.typesAndValues.push(
    new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.BmpString({ value: 'Test Root CA' }) })
  );
  rootCert.subject.typesAndValues.push(
    new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.BmpString({ value: 'Test Root CA' }) })
  );
  rootCert.notBefore.value = new Date('2024-01-01T00:00:00Z');
  rootCert.notAfter.value = new Date('2030-01-01T00:00:00Z');
  rootCert.extensions = [];
  const basicConstr = new pkijs.BasicConstraints({ cA: true });
  rootCert.extensions.push(
    new pkijs.Extension({
      extnID: '2.5.29.19',
      critical: false,
      extnValue: basicConstr.toSchema().toBER(false),
      parsedValue: basicConstr,
    })
  );
  await rootCert.subjectPublicKeyInfo.importKey(rootKeys.publicKey);
  await rootCert.sign(rootKeys.privateKey, 'SHA-256');

  const leafKeys = (await crypto.generateKey(
    algorithm.algorithm as RsaHashedKeyGenParams,
    true,
    algorithm.usages
  )) as CryptoKeyPair;

  const leafCert = new pkijs.Certificate();
  leafCert.version = 2;
  leafCert.serialNumber = new asn1js.Integer({ value: 42 });
  leafCert.issuer.typesAndValues.push(
    new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.BmpString({ value: 'Test Root CA' }) })
  );
  leafCert.subject.typesAndValues.push(
    new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.BmpString({ value: 'Test Signer' }) })
  );
  leafCert.notBefore.value = new Date('2024-01-01T00:00:00Z');
  leafCert.notAfter.value = new Date('2030-01-01T00:00:00Z');
  leafCert.extensions = [];

  if (ocspUrl) {
    const infoAccess = new pkijs.InfoAccess({
      accessDescriptions: [
        new pkijs.AccessDescription({
          accessMethod: pkijs.id_ad_ocsp,
          accessLocation: new pkijs.GeneralName({ type: 6, value: ocspUrl }),
        }),
      ],
    });
    leafCert.extensions.push(
      new pkijs.Extension({
        extnID: pkijs.id_AuthorityInfoAccess,
        critical: false,
        extnValue: infoAccess.toSchema().toBER(false),
        parsedValue: infoAccess,
      })
    );
  }

  if (crlUrl) {
    const crlDp = new pkijs.CRLDistributionPoints({
      distributionPoints: [
        new pkijs.DistributionPoint({ distributionPoint: [new pkijs.GeneralName({ type: 6, value: crlUrl })] }),
      ],
    });
    leafCert.extensions.push(
      new pkijs.Extension({
        extnID: pkijs.id_CRLDistributionPoints,
        critical: false,
        extnValue: crlDp.toSchema().toBER(false),
        parsedValue: crlDp,
      })
    );
  }

  await leafCert.subjectPublicKeyInfo.importKey(leafKeys.publicKey);
  await leafCert.sign(rootKeys.privateKey, 'SHA-256');

  return { rootCert, rootKeys, leafCert, leafForge: pkijsCertToForge(leafCert), rootForge: pkijsCertToForge(rootCert) };
}

async function buildOcspResponse(pki: SyntheticPki, certStatusTag: 0 | 1): Promise<ArrayBuffer> {
  const certID = await pkijs.CertID.create(pki.leafCert, { hashAlgorithm: 'SHA-256', issuerCertificate: pki.rootCert });

  const certStatus =
    certStatusTag === 0
      ? new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } })
      : new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 1 },
          value: [new asn1js.GeneralizedTime({ valueDate: new Date() })],
        });

  const singleResponse = new pkijs.SingleResponse({
    certID,
    certStatus,
    thisUpdate: new Date(),
  });

  const responseData = new pkijs.ResponseData({
    responderID: pki.rootCert.subject,
    producedAt: new Date(),
    responses: [singleResponse],
  });

  const basicResponse = new pkijs.BasicOCSPResponse({ tbsResponseData: responseData, certs: [pki.rootCert] });
  await basicResponse.sign(pki.rootKeys.privateKey, 'SHA-256');

  const ocspResponse = new pkijs.OCSPResponse({
    responseStatus: new asn1js.Enumerated({ value: 0 }),
    responseBytes: new pkijs.ResponseBytes({
      responseType: pkijs.id_PKIX_OCSP_Basic,
      response: new asn1js.OctetString({ valueHex: basicResponse.toSchema().toBER() }),
    }),
  });

  return ocspResponse.toSchema().toBER();
}

async function buildCrl(pki: SyntheticPki, revokedSerials: number[]): Promise<ArrayBuffer> {
  const crl = new pkijs.CertificateRevocationList();
  crl.version = 1;
  crl.issuer = pki.rootCert.subject;
  crl.thisUpdate.value = new Date();
  crl.revokedCertificates = revokedSerials.map(
    (serial) => new pkijs.RevokedCertificate({ userCertificate: new asn1js.Integer({ value: serial }), revocationDate: new pkijs.Time({ value: new Date() }) })
  );
  await crl.sign(pki.rootKeys.privateKey, 'SHA-256');
  return crl.toSchema().toBER();
}

let activeServer: Server | null = null;

async function startServer(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<string> {
  const server = createServer(handler);
  activeServer = server;
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}`;
}

// A real local test server can only ever bind to loopback, which the real
// `isAddressAllowed` correctly always blocks -- same test-only override
// convention `fetchCaIssuerCertificates` already documents.
const allowAll = () => true;

afterEach(async () => {
  vi.doUnmock('node:dns');
  vi.resetModules();
  if (activeServer) {
    await new Promise<void>((resolve) => activeServer!.close(() => resolve()));
    activeServer = null;
  }
});

describe('revocationChecker (real signature verification, real local-server transport)', () => {
  it('checkOcsp: no AIA entry -> unavailable, no network call attempted', async () => {
    const pki = await buildSyntheticPki(null, null);
    const result = await checkOcsp(pki.rootForge, pki.rootForge); // root has no AIA extension
    expect(result).toEqual({ status: 'unavailable', url: null });
  });

  it('checkOcsp: real signed "good" response -> not_revoked', async () => {
    // Server must exist first so its ephemeral URL can be baked into the
    // leaf cert's OCSP AIA entry; the real handler (which needs `pki`) is
    // attached only once the cert + signed response are ready.
    const url = await startServer(() => {});
    activeServer!.removeAllListeners('request');
    const pki = await buildSyntheticPki(url, null);
    const responseBer = await buildOcspResponse(pki, 0);
    activeServer!.on('request', (_req, res) => {
      res.writeHead(200);
      res.end(Buffer.from(responseBer));
    });

    const result = await checkOcsp(pki.leafForge, pki.rootForge, allowAll);
    expect(result).toEqual({ status: 'not_revoked', url });
  });

  it('checkOcsp: real signed "revoked" response -> revoked', async () => {
    const url = await startServer(() => {});
    activeServer!.removeAllListeners('request');
    const pki = await buildSyntheticPki(url, null);
    const responseBer = await buildOcspResponse(pki, 1);
    activeServer!.on('request', (_req, res) => {
      res.writeHead(200);
      res.end(Buffer.from(responseBer));
    });

    const result = await checkOcsp(pki.leafForge, pki.rootForge, allowAll);
    expect(result).toEqual({ status: 'revoked', url });
  });

  it('checkOcsp: network failure -> unavailable, url preserved', async () => {
    const pki = await buildSyntheticPki('http://127.0.0.1:1/ocsp', null); // nothing listens on port 1
    const result = await checkOcsp(pki.leafForge, pki.rootForge, allowAll);
    expect(result).toEqual({ status: 'unavailable', url: 'http://127.0.0.1:1/ocsp' });
  });

  it('checkOcsp: HTTP error response -> unavailable, url preserved', async () => {
    const url = await startServer((_req, res) => {
      res.writeHead(500);
      res.end();
    });
    const pki = await buildSyntheticPki(url, null);
    const result = await checkOcsp(pki.leafForge, pki.rootForge, allowAll);
    expect(result).toEqual({ status: 'unavailable', url });
  });

  it('checkOcsp: malformed response bytes -> unavailable, never throws', async () => {
    const url = await startServer((_req, res) => {
      res.writeHead(200);
      res.end(Buffer.from([1, 2, 3]));
    });
    const pki = await buildSyntheticPki(url, null);
    const result = await checkOcsp(pki.leafForge, pki.rootForge, allowAll);
    expect(result.status).toBe('unavailable');
    expect(result.url).toBe(url);
  });

  it('checkCrl: no CRL distribution point -> unavailable, no network call attempted', async () => {
    const pki = await buildSyntheticPki(null, null);
    const result = await checkCrl(pki.rootForge, pki.rootForge);
    expect(result).toEqual({ status: 'unavailable', url: null });
  });

  it('checkCrl: real signed CRL, leaf not listed -> not_revoked', async () => {
    const url = await startServer(() => {});
    activeServer!.removeAllListeners('request');
    const pki = await buildSyntheticPki(null, url);
    const crlBer = await buildCrl(pki, []);
    activeServer!.on('request', (_req, res) => {
      res.writeHead(200);
      res.end(Buffer.from(crlBer));
    });

    const result = await checkCrl(pki.leafForge, pki.rootForge, allowAll);
    expect(result).toEqual({ status: 'not_revoked', url });
  });

  it('checkCrl: real signed CRL, leaf serial listed -> revoked', async () => {
    const url = await startServer(() => {});
    activeServer!.removeAllListeners('request');
    const pki = await buildSyntheticPki(null, url);
    const crlBer = await buildCrl(pki, [42]);
    activeServer!.on('request', (_req, res) => {
      res.writeHead(200);
      res.end(Buffer.from(crlBer));
    });

    const result = await checkCrl(pki.leafForge, pki.rootForge, allowAll);
    expect(result).toEqual({ status: 'revoked', url });
  });

  it('checkCrl: network failure -> unavailable, url preserved, never throws', async () => {
    const pki = await buildSyntheticPki(null, 'http://127.0.0.1:1/crl'); // nothing listens on port 1
    const result = await checkCrl(pki.leafForge, pki.rootForge, allowAll);
    expect(result).toEqual({ status: 'unavailable', url: 'http://127.0.0.1:1/crl' });
  });

  it('checkCrl: server returns PEM-armored CRL instead of raw DER -> still parses and verifies', async () => {
    // Regression test for a real bug found against production infrastructure:
    // rootca.gov.vn's own CRL distribution point serves "-----BEGIN X509
    // CRL-----" PEM text, not raw DER -- confirmed by downloading the real
    // file and feeding it through this exact code path.
    const url = await startServer(() => {});
    activeServer!.removeAllListeners('request');
    const pki = await buildSyntheticPki(null, url);
    const crlBer = await buildCrl(pki, [42]);
    const pem = `-----BEGIN X509 CRL-----\n${Buffer.from(crlBer).toString('base64')}\n-----END X509 CRL-----\n`;
    activeServer!.on('request', (_req, res) => {
      res.writeHead(200);
      res.end(pem);
    });

    const result = await checkCrl(pki.leafForge, pki.rootForge, allowAll);
    expect(result).toEqual({ status: 'revoked', url });
  });
});

describe('revocationChecker SSRF guard (the actual point of this fix)', () => {
  it('checkOcsp: production default (no override) refuses a loopback OCSP URL, never connects', async () => {
    let requestCount = 0;
    const url = await startServer((_req, res) => {
      requestCount += 1;
      res.writeHead(200);
      res.end();
    });
    const pki = await buildSyntheticPki(url, null);
    const result = await checkOcsp(pki.leafForge, pki.rootForge); // no override: real guard
    expect(result).toEqual({ status: 'unavailable', url });
    expect(requestCount).toBe(0);
  });

  it('checkCrl: production default (no override) refuses a loopback CRL URL, never connects', async () => {
    let requestCount = 0;
    const url = await startServer((_req, res) => {
      requestCount += 1;
      res.writeHead(200);
      res.end();
    });
    const pki = await buildSyntheticPki(null, url);
    const result = await checkCrl(pki.leafForge, pki.rootForge); // no override: real guard
    expect(result).toEqual({ status: 'unavailable', url });
    expect(requestCount).toBe(0);
  });

  it('checkOcsp: a hostname whose DNS resolution is a private address is blocked before connecting (DNS-rebinding shape)', async () => {
    vi.doMock('node:dns', async (importOriginal) => {
      const actual = await importOriginal<typeof import('node:dns')>();
      return {
        ...actual,
        lookup: (
          _hostname: string,
          options: unknown,
          callback: (err: NodeJS.ErrnoException | null, address: unknown, family?: number) => void
        ) => {
          callback(null, [{ address: '10.0.0.5', family: 4 }] as never, undefined);
        },
      };
    });
    vi.resetModules();
    const { checkOcsp: freshCheckOcsp } = await import('./revocationChecker');

    const pki = await buildSyntheticPki('http://internal.example.test/ocsp', null);
    const result = await freshCheckOcsp(pki.leafForge, pki.rootForge); // no override: real guard, mocked DNS only
    expect(result).toEqual({ status: 'unavailable', url: 'http://internal.example.test/ocsp' });
  });

  it('checkCrl: a hostname whose DNS resolution is a private address is blocked before connecting (DNS-rebinding shape)', async () => {
    vi.doMock('node:dns', async (importOriginal) => {
      const actual = await importOriginal<typeof import('node:dns')>();
      return {
        ...actual,
        lookup: (
          _hostname: string,
          options: unknown,
          callback: (err: NodeJS.ErrnoException | null, address: unknown, family?: number) => void
        ) => {
          callback(null, [{ address: '10.0.0.5', family: 4 }] as never, undefined);
        },
      };
    });
    vi.resetModules();
    const { checkCrl: freshCheckCrl } = await import('./revocationChecker');

    const pki = await buildSyntheticPki(null, 'http://internal.example.test/crl');
    const result = await freshCheckCrl(pki.leafForge, pki.rootForge); // no override: real guard, mocked DNS only
    expect(result).toEqual({ status: 'unavailable', url: 'http://internal.example.test/crl' });
  });
});
