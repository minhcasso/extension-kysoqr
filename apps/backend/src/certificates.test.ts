import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { describe, expect, it } from 'vitest';
import { CertificateChecker, parseCertificates } from './certificates';
import { isPrivateAddress, safeFetch, type Fetcher } from './safe-fetch';

// Chứng thư tự tạo trong test (không dùng chứng thư thật của ai).
const name = (cn: string) => [
  new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.Utf8String({ value: cn }) }),
];

const newKeys = () =>
  crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

interface Issued {
  cn: string;
  keys: CryptoKeyPair;
  der: Uint8Array<ArrayBuffer>;
  b64: string;
}

async function issue(
  cn: string,
  serial: number,
  opts: { issuer?: Issued; ca?: boolean; crl?: string } = {},
) {
  const keys = await newKeys();
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: serial });
  cert.subject.typesAndValues = name(cn);
  cert.issuer.typesAndValues = name(opts.issuer?.cn ?? cn);
  cert.notBefore.value = new Date(Date.now() - 86_400_000);
  cert.notAfter.value = new Date(Date.now() + 365 * 86_400_000);
  cert.extensions = [];
  if (opts.ca) {
    cert.extensions.push(
      new pkijs.Extension({
        extnID: '2.5.29.19',
        critical: true,
        extnValue: new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(false),
      }),
    );
  }
  if (opts.crl) {
    const dp = new pkijs.DistributionPoint({
      distributionPoint: [new pkijs.GeneralName({ type: 6, value: opts.crl })],
    });
    cert.extensions.push(
      new pkijs.Extension({
        extnID: '2.5.29.31',
        extnValue: new pkijs.CRLDistributionPoints({ distributionPoints: [dp] })
          .toSchema()
          .toBER(false),
      }),
    );
  }
  await cert.subjectPublicKeyInfo.importKey(keys.publicKey);
  await cert.sign(opts.issuer?.keys.privateKey ?? keys.privateKey, 'SHA-256');
  const der = new Uint8Array(cert.toSchema(true).toBER(false));
  return { cn, keys, der, b64: Buffer.from(der).toString('base64') } satisfies Issued;
}

async function crl(issuer: Issued, revokedSerials: number[], signer = issuer.keys.privateKey) {
  const list = new pkijs.CertificateRevocationList();
  list.version = 1;
  list.issuer.typesAndValues = name(issuer.cn);
  list.thisUpdate = new pkijs.Time({ type: 0, value: new Date() });
  list.nextUpdate = new pkijs.Time({ type: 0, value: new Date(Date.now() + 86_400_000) });
  list.revokedCertificates = revokedSerials.map(
    (s) =>
      new pkijs.RevokedCertificate({
        userCertificate: new asn1js.Integer({ value: s }),
        revocationDate: new pkijs.Time({ type: 0, value: new Date('2026-01-02T03:04:05Z') }),
      }),
  );
  await list.sign(signer, 'SHA-256');
  return new Uint8Array(list.toSchema(true).toBER(false));
}

function fakeFetch(routes: Record<string, Uint8Array>): Fetcher {
  return async (url) => {
    const body = routes[url];
    if (!body) throw new Error(`không có ${url}`);
    return body;
  };
}

describe('CertificateChecker', async () => {
  const root = await issue('Test Root CA', 1, { ca: true });
  const inter = await issue('Test Issuing CA', 2, { ca: true, issuer: root });
  const good = await issue('Nguoi ky hop le', 10, { issuer: inter, crl: 'http://crl.test/ca.crl' });
  const revoked = await issue('Nguoi ky bi thu hoi', 11, {
    issuer: inter,
    crl: 'http://crl.test/ca.crl',
  });
  const anchors = parseCertificates(root.der, 'trust-store');

  it('nối chuỗi tới gốc trong kho tin cậy, CRL báo chưa thu hồi', async () => {
    const checker = new CertificateChecker({
      trustAnchors: anchors,
      fetch: fakeFetch({ 'http://crl.test/ca.crl': await crl(inter, [11]) }),
    });
    const res = await checker.check({ certificates: [good.b64, inter.b64] });
    expect(res).toMatchObject({ trusted: true, trustStoreConfigured: true, chainValid: true });
    expect(res.chain.map((c) => c.source)).toEqual(['document', 'document', 'trust-store']);
    expect(res.chain.every((c) => c.signatureValid)).toBe(true);
    expect(res.chain[0]!.crl).toMatchObject({ status: 'good', url: 'http://crl.test/ca.crl' });
    expect(res.chain[0]!.ocsp.status).toBe('none');
  });

  it('phát hiện chứng thư đã bị thu hồi qua CRL', async () => {
    const checker = new CertificateChecker({
      trustAnchors: anchors,
      fetch: fakeFetch({ 'http://crl.test/ca.crl': await crl(inter, [11]) }),
    });
    const res = await checker.check({ certificates: [revoked.b64, inter.b64] });
    expect(res.chain[0]!.crl).toMatchObject({
      status: 'revoked',
      revokedAt: '2026-01-02T03:04:05.000Z',
    });
  });

  it('không tin CRL bị ký bởi khoá khác', async () => {
    const other = await newKeys();
    const checker = new CertificateChecker({
      trustAnchors: anchors,
      fetch: fakeFetch({ 'http://crl.test/ca.crl': await crl(inter, [], other.privateKey) }),
    });
    const res = await checker.check({ certificates: [good.b64, inter.b64] });
    expect(res.chain[0]!.crl.status).toBe('error');
  });

  it('không có kho tin cậy → không coi là tin cậy; thiếu CA cấp trên → không kiểm tra thu hồi được', async () => {
    const checker = new CertificateChecker({ trustAnchors: [], fetch: fakeFetch({}) });
    const res = await checker.check({ certificates: [good.b64] });
    expect(res).toMatchObject({ trusted: false, trustStoreConfigured: false, chainValid: false });
    expect(res.chain[0]!.crl.status).toBe('unsupported');
  });

  it('chứng thư hết hạn tại thời điểm ký → chuỗi không hợp lệ', async () => {
    const checker = new CertificateChecker({
      trustAnchors: anchors,
      fetch: fakeFetch({ 'http://crl.test/ca.crl': await crl(inter, []) }),
    });
    const res = await checker.check({
      certificates: [good.b64, inter.b64],
      signedAt: '2000-01-01T00:00:00Z',
    });
    expect(res.chainValid).toBe(false);
  });
});

describe('safeFetch', () => {
  it('nhận ra địa chỉ nội bộ', () => {
    for (const ip of [
      '127.0.0.1',
      '10.1.2.3',
      '172.16.0.1',
      '192.168.1.1',
      '169.254.169.254',
      '::1',
      'fd00::1',
      '::ffff:10.0.0.1',
      '0.0.0.0',
    ]) {
      expect(isPrivateAddress(ip), ip).toBe(true);
    }
    for (const ip of ['8.8.8.8', '103.154.62.146', '2001:4860:4860::8888']) {
      expect(isPrivateAddress(ip), ip).toBe(false);
    }
  });

  it('từ chối gọi tới IP nội bộ và giao thức lạ', async () => {
    await expect(safeFetch('http://127.0.0.1:8787/healthz')).rejects.toThrow(/Không cho phép/);
    await expect(safeFetch('http://localhost:8787/healthz')).rejects.toThrow(/Không cho phép/);
    await expect(safeFetch('file:///etc/passwd')).rejects.toThrow(/giao thức/);
  });
});
