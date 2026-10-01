import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import * as asn1js from 'asn1js';
import forge from 'node-forge';
import * as pkijs from 'pkijs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { resetAiaCertCacheForTests } from './aiaCertCache';
import {
  fetchBytesWithGuards,
  fetchCaIssuerCertificates,
  findAllAiaUrls,
  isAddressAllowed,
  KNOWN_AIA_URL_CORRECTIONS,
} from './aiaCertFetcher';

/**
 * Exercises the real network+security layer (`node:http`/`node:https` with a
 * custom `lookup`, redirect handling, size cap, `caIssuers` response
 * parsing) against a real local `node:http` server -- not `vi.stubGlobal`
 * `fetch` mocks, since that's exactly the transport this module deliberately
 * avoids (see the module's own doc comment on the DNS-rebinding TOCTOU gap).
 */

function pkijsCertToForge(cert: pkijs.Certificate): forge.pki.Certificate {
  const der = Buffer.from(cert.toSchema().toBER());
  return forge.pki.certificateFromAsn1(forge.asn1.fromDer(der.toString('binary')));
}

async function buildLeafWithAia(caIssuersUrls: string[]): Promise<{
  leafForge: forge.pki.Certificate;
  leafPkijs: pkijs.Certificate;
}> {
  const crypto = pkijs.getCrypto(true);
  const algorithm = pkijs.getAlgorithmParameters('RSASSA-PKCS1-v1_5', 'generateKey');
  if ('hash' in algorithm.algorithm) (algorithm.algorithm as { hash: { name: string } }).hash.name = 'SHA-256';
  const keys = (await crypto.generateKey(algorithm.algorithm as RsaHashedKeyGenParams, true, algorithm.usages)) as CryptoKeyPair;

  const leaf = new pkijs.Certificate();
  leaf.version = 2;
  leaf.serialNumber = new asn1js.Integer({ value: 7 });
  leaf.issuer.typesAndValues.push(
    new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.BmpString({ value: 'Test Intermediate CA' }) })
  );
  leaf.subject.typesAndValues.push(
    new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.BmpString({ value: 'Test Signer' }) })
  );
  leaf.notBefore.value = new Date('2024-01-01T00:00:00Z');
  leaf.notAfter.value = new Date('2030-01-01T00:00:00Z');
  leaf.extensions = [];

  if (caIssuersUrls.length > 0) {
    const infoAccess = new pkijs.InfoAccess({
      accessDescriptions: caIssuersUrls.map(
        (url) =>
          new pkijs.AccessDescription({
            accessMethod: pkijs.id_ad_caIssuers,
            accessLocation: new pkijs.GeneralName({ type: 6, value: url }),
          })
      ),
    });
    leaf.extensions.push(
      new pkijs.Extension({
        extnID: pkijs.id_AuthorityInfoAccess,
        critical: false,
        extnValue: infoAccess.toSchema().toBER(false),
        parsedValue: infoAccess,
      })
    );
  }

  await leaf.subjectPublicKeyInfo.importKey(keys.publicKey);
  await leaf.sign(keys.privateKey, 'SHA-256'); // self-signed for test convenience; signature validity is irrelevant here

  return { leafForge: pkijsCertToForge(leaf), leafPkijs: leaf };
}

async function buildIntermediateCert(): Promise<forge.pki.Certificate> {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date('2024-01-01T00:00:00Z');
  cert.validity.notAfter = new Date('2030-01-01T00:00:00Z');
  cert.setSubject([{ name: 'commonName', value: 'Test Intermediate CA' }]);
  cert.setIssuer([{ name: 'commonName', value: 'Test Root CA' }]);
  cert.setExtensions([{ name: 'basicConstraints', cA: true }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return cert;
}

let activeServer: Server | null = null;

async function startServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void
): Promise<string> {
  const server = createServer(handler);
  activeServer = server;
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}`;
}

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.doUnmock('node:dns');
  resetAiaCertCacheForTests();
  if (activeServer) {
    await new Promise<void>((resolve) => activeServer!.close(() => resolve()));
    activeServer = null;
  }
});

type DnsResolveCallback = (err: NodeJS.ErrnoException | null, addresses: string[]) => void;

const noRecords = (_hostname: string, callback: DnsResolveCallback) =>
  callback(Object.assign(new Error('no records'), { code: 'ENOTFOUND' }), []);

/**
 * Re-imports `aiaCertFetcher` with `node:dns`'s `resolve4`/`resolve6` mocked
 * (these are captured as import bindings at module load, so a plain
 * `vi.spyOn` after the fact wouldn't be seen -- same reimport dance the
 * existing Node-path DNS-rebinding test above already uses) and with
 * `navigator.userAgent` stubbed to the exact string Cloudflare Workers sets,
 * so `isCloudflareWorkers()` routes into the Workers-specific guard.
 */
async function importWorkersFetch(overrides: {
  resolve4?: (hostname: string, callback: DnsResolveCallback) => void;
  resolve6?: (hostname: string, callback: DnsResolveCallback) => void;
}): Promise<typeof import('./aiaCertFetcher').fetchBytesWithGuards> {
  vi.doMock('node:dns', async (importOriginal) => {
    const actual = await importOriginal<typeof import('node:dns')>();
    return {
      ...actual,
      resolve4: overrides.resolve4 ?? noRecords,
      resolve6: overrides.resolve6 ?? noRecords,
    };
  });
  vi.resetModules();
  vi.stubGlobal('navigator', { userAgent: 'Cloudflare-Workers' });
  const mod = await import('./aiaCertFetcher');
  return mod.fetchBytesWithGuards;
}

describe('isAddressAllowed', () => {
  it.each([
    ['127.0.0.1', 4, false],
    ['10.0.0.5', 4, false],
    ['172.16.0.1', 4, false],
    ['192.168.1.1', 4, false],
    ['169.254.169.254', 4, false], // cloud metadata
    ['100.64.0.1', 4, false], // CGNAT
    ['0.0.0.0', 4, false],
    ['8.8.8.8', 4, true], // ordinary public-looking address
    ['::1', 6, false],
    ['fe80::1', 6, false],
    ['fc00::1', 6, false],
    ['::ffff:127.0.0.1', 6, false], // IPv4-mapped loopback
    ['::ffff:8.8.8.8', 6, true], // IPv4-mapped public address
    ['2001:4860:4860::8888', 6, true], // ordinary public-looking IPv6
  ] as const)('isAddressAllowed(%s, %s) -> %s', (address, family, expected) => {
    expect(isAddressAllowed(address, family)).toBe(expected);
  });
});

describe('fetchBytesWithGuards', () => {
  it('real round trip: GET returns the response bytes', async () => {
    const url = await startServer((_req, res) => {
      res.writeHead(200);
      res.end('hello aia');
    });
    const bytes = await fetchBytesWithGuards(url, {
      timeoutMs: 2000,
      maxRedirects: 3,
      maxBytes: 1000,
      isAddressAllowed: () => true,
    });
    expect(Buffer.from(bytes).toString('utf8')).toBe('hello aia');
  });

  it('follows a redirect within the limit', async () => {
    const url = await startServer((req, res) => {
      if (req.url === '/start') {
        res.writeHead(302, { Location: '/final' });
        res.end();
        return;
      }
      res.writeHead(200);
      res.end('final content');
    });
    const bytes = await fetchBytesWithGuards(`${url}/start`, {
      timeoutMs: 2000,
      maxRedirects: 3,
      maxBytes: 1000,
      isAddressAllowed: () => true,
    });
    expect(Buffer.from(bytes).toString('utf8')).toBe('final content');
  });

  it('throws once redirects exceed maxRedirects', async () => {
    const url = await startServer((req, res) => {
      const n = Number(req.url?.slice(1) ?? '0');
      res.writeHead(302, { Location: `/${n + 1}` });
      res.end();
    });
    await expect(
      fetchBytesWithGuards(`${url}/0`, { timeoutMs: 2000, maxRedirects: 2, maxBytes: 1000, isAddressAllowed: () => true })
    ).rejects.toThrow(/too many redirects/);
  });

  it('a redirect pointed at a disallowed address is blocked, not followed (each hop is re-validated independently)', async () => {
    const url = await startServer((_req, res) => {
      res.writeHead(302, { Location: 'http://127.0.0.1:1/private' });
      res.end();
    });
    // Both the real test server and the redirect target are loopback
    // addresses, so a static allow-list can't tell them apart by address
    // alone -- this override allows only the *first* hop, proving the
    // second (redirect) hop is independently re-checked rather than reusing
    // an earlier "already validated" result.
    let hop = 0;
    const allowFirstHopOnly = () => {
      hop += 1;
      return hop === 1;
    };
    await expect(
      fetchBytesWithGuards(url, { timeoutMs: 2000, maxRedirects: 3, maxBytes: 1000, isAddressAllowed: allowFirstHopOnly })
    ).rejects.toThrow(/SSRF_BLOCKED/);
  });

  it('times out against a server that never responds', async () => {
    const url = await startServer(() => {
      // never calls res.end() -- simulates a hung responder
    });
    await expect(
      fetchBytesWithGuards(url, { timeoutMs: 200, maxRedirects: 3, maxBytes: 1000, isAddressAllowed: () => true })
    ).rejects.toThrow(/timed out/);
  });

  it('aborts an oversized response without buffering the full body', async () => {
    const url = await startServer((_req, res) => {
      res.writeHead(200);
      // Stream far more than the cap; if this were fully buffered the test
      // would hang/OOM instead of failing fast.
      const chunk = Buffer.alloc(4096, 'x');
      const interval = setInterval(() => {
        if (!res.write(chunk)) {
          res.once('drain', () => {});
        }
      }, 1);
      res.on('close', () => clearInterval(interval));
    });
    await expect(
      fetchBytesWithGuards(url, { timeoutMs: 2000, maxRedirects: 3, maxBytes: 1000, isAddressAllowed: () => true })
    ).rejects.toThrow(/byte limit/);
  });

  it('rejects a literal disallowed IP target even though no DNS lookup is ever performed', async () => {
    await expect(
      fetchBytesWithGuards('http://127.0.0.1:1/x', { timeoutMs: 500, maxRedirects: 3, maxBytes: 1000 })
    ).rejects.toThrow(/SSRF_BLOCKED/);
  });
});

describe('SSRF guard end-to-end via a hostname that resolves to a private address', () => {
  it('a hostname whose DNS resolution is a private IP is blocked before connecting', async () => {
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
    const { fetchBytesWithGuards: freshFetch } = await import('./aiaCertFetcher');
    await expect(
      freshFetch('http://internal.example.test/x', { timeoutMs: 2000, maxRedirects: 3, maxBytes: 1000 })
    ).rejects.toThrow(/SSRF_BLOCKED/);
    vi.doUnmock('node:dns');
    vi.resetModules();
  });
});

describe('fetchBytesWithGuards on Cloudflare Workers (dns.resolve4/resolve6 path, no custom `lookup`)', () => {
  it('blocks a hostname whose resolved address is private, and never calls fetch() at all', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const freshFetch = await importWorkersFetch({
      resolve4: (_hostname, callback) => callback(null, ['10.0.0.5']),
    });
    await expect(
      freshFetch('http://internal.example.test/x', { timeoutMs: 2000, maxRedirects: 3, maxBytes: 1000 })
    ).rejects.toThrow(/SSRF_BLOCKED/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('real round trip: resolved address passes the guard, then a real fetch() is made', async () => {
    const url = await startServer((_req, res) => {
      res.writeHead(200);
      res.end('hello from workers');
    });
    const { port } = activeServer!.address() as AddressInfo;
    const freshFetch = await importWorkersFetch({
      resolve4: (_hostname, callback) => callback(null, ['127.0.0.1']),
    });
    const bytes = await freshFetch(`http://localhost:${port}${new URL(url).pathname}`, {
      timeoutMs: 2000,
      maxRedirects: 3,
      maxBytes: 1000,
      isAddressAllowed: () => true, // override: the mocked 127.0.0.1 would otherwise be (correctly) blocked
    });
    expect(Buffer.from(bytes).toString('utf8')).toBe('hello from workers');
  });

  it('a redirect hop pointed at a private address is independently re-checked and blocked', async () => {
    await startServer((_req, res) => {
      res.writeHead(302, { Location: 'http://internal.example.test/private' });
      res.end();
    });
    const { port } = activeServer!.address() as AddressInfo;
    let call = 0;
    const freshFetch = await importWorkersFetch({
      resolve4: (_hostname, callback) => {
        call += 1;
        // First hop (localhost, the real test server) resolves "safely" under
        // the allow-all override below; the redirect target resolves private.
        callback(null, call === 1 ? ['127.0.0.1'] : ['10.0.0.5']);
      },
    });
    await expect(
      freshFetch(`http://localhost:${port}/start`, {
        timeoutMs: 2000,
        maxRedirects: 3,
        maxBytes: 1000,
        isAddressAllowed: (address) => address === '127.0.0.1',
      })
    ).rejects.toThrow(/SSRF_BLOCKED/);
  });

  it('times out against a server that never responds', async () => {
    const url = await startServer(() => {
      // never calls res.end() -- simulates a hung responder
    });
    const { port } = activeServer!.address() as AddressInfo;
    const freshFetch = await importWorkersFetch({
      resolve4: (_hostname, callback) => callback(null, ['127.0.0.1']),
    });
    await expect(
      freshFetch(`http://localhost:${port}${new URL(url).pathname}`, {
        timeoutMs: 200,
        maxRedirects: 3,
        maxBytes: 1000,
        isAddressAllowed: () => true,
      })
    ).rejects.toThrow(/timed out/);
  });

  it('aborts an oversized response without buffering the full body', async () => {
    await startServer((_req, res) => {
      res.writeHead(200);
      const chunk = Buffer.alloc(4096, 'x');
      const interval = setInterval(() => {
        if (!res.write(chunk)) {
          res.once('drain', () => {});
        }
      }, 1);
      res.on('close', () => clearInterval(interval));
    });
    const { port } = activeServer!.address() as AddressInfo;
    const freshFetch = await importWorkersFetch({
      resolve4: (_hostname, callback) => callback(null, ['127.0.0.1']),
    });
    await expect(
      freshFetch(`http://localhost:${port}/`, {
        timeoutMs: 2000,
        maxRedirects: 3,
        maxBytes: 1000,
        isAddressAllowed: () => true,
      })
    ).rejects.toThrow(/byte limit/);
  });

  it('a literal disallowed IP target is blocked before any DNS resolution is attempted', async () => {
    const resolve4 = vi.fn(noRecords);
    const freshFetch = await importWorkersFetch({ resolve4 });
    await expect(
      freshFetch('http://127.0.0.1:1/x', { timeoutMs: 500, maxRedirects: 3, maxBytes: 1000 })
    ).rejects.toThrow(/SSRF_BLOCKED/);
    expect(resolve4).not.toHaveBeenCalled();
  });
});

describe('findAllAiaUrls', () => {
  it('reads every caIssuers URI off a real AIA extension, bounded to 3', async () => {
    const urls = ['https://a.test/1', 'https://b.test/2', 'https://c.test/3', 'https://d.test/4'];
    const { leafPkijs } = await buildLeafWithAia(urls);
    const found = findAllAiaUrls(leafPkijs, pkijs.id_ad_caIssuers);
    expect(found).toEqual(urls.slice(0, 3));
  });

  it('returns an empty list for a cert with no AIA extension at all', async () => {
    const { leafPkijs } = await buildLeafWithAia([]);
    expect(findAllAiaUrls(leafPkijs, pkijs.id_ad_caIssuers)).toEqual([]);
  });
});

describe('fetchCaIssuerCertificates', () => {
  // A real local test server can only ever bind to loopback, which the real
  // `isAddressAllowed` correctly always blocks -- these tests exercise the
  // real network/parsing logic via the same test-only override convention
  // `fetchBytesWithGuards` already documents on `FetchGuards.isAddressAllowed`.
  const allowAll = () => true;

  it('cert with no caIssuers AIA entry -> zero network calls', async () => {
    const { leafForge } = await buildLeafWithAia([]);
    const result = await fetchCaIssuerCertificates(leafForge, allowAll);
    expect(result).toEqual({ certs: [], url: null });
  });

  it('real round trip: server returns a PEM certificate', async () => {
    const intermediate = await buildIntermediateCert();
    const url = await startServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/x-pem-file' });
      res.end(forge.pki.certificateToPem(intermediate));
    });
    const { leafForge } = await buildLeafWithAia([url]);
    const result = await fetchCaIssuerCertificates(leafForge, allowAll);
    expect(result.certs).toHaveLength(1);
    expect(forge.pki.certificateToPem(result.certs[0]!)).toBe(forge.pki.certificateToPem(intermediate));
    expect(result.url).toBe(url);
  });

  it('real round trip: server returns a bare DER certificate (RFC 5280 application/pkix-cert)', async () => {
    const intermediate = await buildIntermediateCert();
    const der = Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(intermediate)).getBytes(), 'binary');
    const url = await startServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/pkix-cert' });
      res.end(der);
    });
    const { leafForge } = await buildLeafWithAia([url]);
    const result = await fetchCaIssuerCertificates(leafForge, allowAll);
    expect(result.certs).toHaveLength(1);
    expect(forge.pki.certificateToPem(result.certs[0]!)).toBe(forge.pki.certificateToPem(intermediate));
  });

  it('real round trip: server returns a PKCS#7 "certs-only" bundle', async () => {
    const intermediate = await buildIntermediateCert();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const p7 = forge.pkcs7.createSignedData() as any;
    p7.addCertificate(intermediate);
    const der = Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), 'binary');
    const url = await startServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/x-pkcs7-certificates' });
      res.end(der);
    });
    const { leafForge } = await buildLeafWithAia([url]);
    const result = await fetchCaIssuerCertificates(leafForge, allowAll);
    expect(result.certs).toHaveLength(1);
    expect(forge.pki.certificateToPem(result.certs[0]!)).toBe(forge.pki.certificateToPem(intermediate));
  });

  it('malformed response bytes -> {certs: [], url, error}, never throws', async () => {
    const url = await startServer((_req, res) => {
      res.writeHead(200);
      res.end('not a certificate at all');
    });
    const { leafForge } = await buildLeafWithAia([url]);
    const result = await fetchCaIssuerCertificates(leafForge, allowAll);
    expect(result.certs).toEqual([]);
    expect(result.url).toBe(url);
    expect(result.error).toBeTruthy();
  });

  it('falls through to the next caIssuers URL if the first fails', async () => {
    const intermediate = await buildIntermediateCert();
    const goodUrl = await startServer((_req, res) => {
      res.writeHead(200);
      res.end(forge.pki.certificateToPem(intermediate));
    });
    const deadUrl = 'http://127.0.0.1:1/dead'; // nothing listens on port 1
    const { leafForge } = await buildLeafWithAia([deadUrl, goodUrl]);
    const result = await fetchCaIssuerCertificates(leafForge, allowAll);
    expect(result.certs).toHaveLength(1);
    expect(result.url).toBe(goodUrl);
  });

  it('production default (no override) really does refuse a loopback caIssuers URL', async () => {
    const url = await startServer((_req, res) => {
      res.writeHead(200);
      res.end('unreachable -- should never be requested successfully');
    });
    const { leafForge } = await buildLeafWithAia([url]);
    const result = await fetchCaIssuerCertificates(leafForge); // no override: real guard
    expect(result.certs).toEqual([]);
    expect(result.error).toMatch(/SSRF_BLOCKED/);
  });

  it('a second fetch for the same caIssuers URL is served from cache, not a second network call', async () => {
    const intermediate = await buildIntermediateCert();
    let requestCount = 0;
    const url = await startServer((_req, res) => {
      requestCount += 1;
      res.writeHead(200);
      res.end(forge.pki.certificateToPem(intermediate));
    });
    const { leafForge: firstLeaf } = await buildLeafWithAia([url]);
    const { leafForge: secondLeaf } = await buildLeafWithAia([url]); // a different document, same AIA URL

    const first = await fetchCaIssuerCertificates(firstLeaf, allowAll);
    expect(first.certs).toHaveLength(1);
    expect(requestCount).toBe(1);

    const second = await fetchCaIssuerCertificates(secondLeaf, allowAll);
    expect(second.certs).toHaveLength(1);
    expect(forge.pki.certificateToPem(second.certs[0]!)).toBe(forge.pki.certificateToPem(intermediate));
    expect(requestCount).toBe(1); // still 1 -- second call was served from the cache
  });
});

describe('KNOWN_AIA_URL_CORRECTIONS', () => {
  it('has the one confirmed IntrustCA correction, and only that one', () => {
    expect(KNOWN_AIA_URL_CORRECTIONS).toEqual({
      'https://intrustca.vn/cert/IntrustCA_Remote_Signing.cer':
        'https://intrustca.vn/assets/cert/IntrustCA_Remote_Signing.cer',
    });
  });

  it('real network: the declared (broken) IntrustCA URL is automatically corrected to the real file', async () => {
    const [declaredUrl] = Object.keys(KNOWN_AIA_URL_CORRECTIONS);
    const { leafForge } = await buildLeafWithAia([declaredUrl!]);

    // No isAddressAllowed override here -- intrustca.vn is a real, ordinary
    // public host, not something the SSRF guard would ever block.
    const result = await fetchCaIssuerCertificates(leafForge);

    expect(result.certs.length).toBeGreaterThan(0);
    expect(result.url).toBe(KNOWN_AIA_URL_CORRECTIONS[declaredUrl!]);
  }, 15000);
});
