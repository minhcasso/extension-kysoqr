import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type {
  CertificateCheckRequest,
  CertificateCheckResponse,
  ChainCertificate,
  RevocationResult,
} from '@kysoqr/shared';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import type { Fetcher } from './safe-fetch';

pkijs.setEngine(
  'node',
  new pkijs.CryptoEngine({ name: 'node', crypto: webcrypto as unknown as Crypto }),
);

const OID = {
  authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
  ocsp: '1.3.6.1.5.5.7.48.1',
  caIssuers: '1.3.6.1.5.5.7.48.2',
  ocspBasic: '1.3.6.1.5.5.7.48.1.1',
  crlDistributionPoints: '2.5.29.31',
  signedData: '1.2.840.113549.1.7.2',
};

const MAX_CHAIN = 8;
const OCSP_TTL_MS = 5 * 60_000;
const CRL_TTL_MS = 60 * 60_000;
const MAX_CRL_BYTES = 20 * 1024 * 1024;

type Bytes = Uint8Array<ArrayBuffer>;

interface Cert {
  cert: pkijs.Certificate;
  der: Bytes;
  source: ChainCertificate['source'];
}

const toBase64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const fingerprint = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');

function parseCert(der: Bytes, source: Cert['source']): Cert {
  return { cert: pkijs.Certificate.fromBER(der), der, source };
}

/** Đọc một hoặc nhiều chứng thư từ DER, PEM, hoặc gói PKCS#7 (.p7b/.p7c). */
export function parseCertificates(data: Bytes, source: Cert['source']): Cert[] {
  const text = Buffer.from(data).toString('latin1');
  if (text.includes('-----BEGIN')) {
    const blocks = [...text.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g)];
    return blocks.flatMap((m) =>
      parseCertificates(new Uint8Array(Buffer.from(m[2]!, 'base64')), source),
    );
  }
  const asn1 = asn1js.fromBER(data);
  if (asn1.offset === -1) throw new Error('Dữ liệu chứng thư không hợp lệ');
  try {
    const ci = new pkijs.ContentInfo({ schema: asn1.result });
    if (ci.contentType === OID.signedData) {
      const sd = new pkijs.SignedData({ schema: ci.content });
      return (sd.certificates ?? [])
        .filter((c): c is pkijs.Certificate => c instanceof pkijs.Certificate)
        .map((c) => ({ cert: c, der: new Uint8Array(c.toSchema().toBER()), source }));
    }
  } catch {
    // không phải PKCS#7 → thử như một chứng thư
  }
  return [parseCert(data, source)];
}

export function loadTrustAnchors(path: string | undefined): Cert[] {
  if (!path) return [];
  return parseCertificates(new Uint8Array(readFileSync(path)), 'trust-store');
}

function generalNameUris(names: pkijs.GeneralName[] | undefined): string[] {
  return (names ?? [])
    .filter((n) => n.type === 6 && typeof n.value === 'string')
    .map((n) => n.value as string);
}

const httpFirst = (urls: string[]) =>
  urls.find((u) => u.startsWith('http://')) ?? urls.find((u) => u.startsWith('https://')) ?? null;

function accessUrls(cert: pkijs.Certificate, method: string): string[] {
  const ext = cert.extensions?.find((e) => e.extnID === OID.authorityInfoAccess);
  const info = ext?.parsedValue as pkijs.InfoAccess | undefined;
  return generalNameUris(
    info?.accessDescriptions.filter((d) => d.accessMethod === method).map((d) => d.accessLocation),
  );
}

function crlUrls(cert: pkijs.Certificate): string[] {
  const ext = cert.extensions?.find((e) => e.extnID === OID.crlDistributionPoints);
  const dps =
    (ext?.parsedValue as pkijs.CRLDistributionPoints | undefined)?.distributionPoints ?? [];
  return dps.flatMap((dp) =>
    Array.isArray(dp.distributionPoint) ? generalNameUris(dp.distributionPoint) : [],
  );
}

export const certificateUrls = (cert: pkijs.Certificate) => ({
  ocsp: httpFirst(accessUrls(cert, OID.ocsp)),
  crl: httpFirst(crlUrls(cert)),
  caIssuers: httpFirst(accessUrls(cert, OID.caIssuers)),
});

const isSelfIssued = (c: pkijs.Certificate) => c.subject.isEqual(c.issuer);

const message = (err: unknown) => (err instanceof Error ? err.message : String(err));

interface Cached<T> {
  value: T;
  expiresAt: number;
}

export interface CertificateCheckerOptions {
  trustAnchors: Cert[];
  fetch: Fetcher;
  now?: () => number;
}

export class CertificateChecker {
  private ocspCache = new Map<string, Cached<RevocationResult>>();
  private crlCache = new Map<string, Cached<Promise<ParsedCrl>>>();
  private now: () => number;

  constructor(private opts: CertificateCheckerOptions) {
    this.now = opts.now ?? Date.now;
  }

  get trustStoreConfigured() {
    return this.opts.trustAnchors.length > 0;
  }

  async check(req: CertificateCheckRequest): Promise<CertificateCheckResponse> {
    const input = req.certificates.map((b64) =>
      parseCert(new Uint8Array(Buffer.from(b64, 'base64')), 'document'),
    );
    const chain = await this.buildChain(input);
    const at = req.signedAt ? new Date(req.signedAt) : new Date(this.now());

    const signatureValid = await Promise.all(
      chain.map(async (c, i) => {
        const issuer = chain[i + 1] ?? (isSelfIssued(c.cert) ? c : undefined);
        if (!issuer) return null;
        try {
          return await c.cert.verify(issuer.cert);
        } catch {
          return false;
        }
      }),
    );

    const anchors = new Set(this.opts.trustAnchors.map((a) => fingerprint(a.der)));
    const trusted = chain.some((c) => anchors.has(fingerprint(c.der)));

    let chainError: string | undefined;
    const invalidAt = chain.findIndex(
      (c) => at < c.cert.notBefore.value || at > c.cert.notAfter.value,
    );
    if (signatureValid.some((v) => v === false))
      chainError = 'Chữ ký của một chứng thư trong chuỗi không hợp lệ.';
    else if (invalidAt >= 0)
      chainError = 'Có chứng thư trong chuỗi không còn hiệu lực tại thời điểm ký.';
    else if (signatureValid.some((v) => v === null))
      chainError = 'Không tìm được chứng thư của tổ chức phát hành.';

    const revocation = await Promise.all(
      chain.map(async (c, i) => {
        const issuer = chain[i + 1];
        const urls = certificateUrls(c.cert);
        if (isSelfIssued(c.cert) && !urls.ocsp && !urls.crl) {
          return { ocsp: none(), crl: none() };
        }
        const [ocsp, crl] = await Promise.all([
          this.checkOcsp(c, issuer, urls.ocsp),
          this.checkCrl(c, issuer, urls.crl),
        ]);
        return { ocsp, crl };
      }),
    );

    return {
      chain: chain.map((c, i) => ({
        der: toBase64(c.der),
        source: c.source,
        signatureValid: signatureValid[i] ?? null,
        ...revocation[i]!,
      })),
      trusted,
      trustStoreConfigured: this.trustStoreConfigured,
      chainValid: !chainError,
      chainError,
    };
  }

  /** Nối từ chứng thư người ký lên gốc: chứng thư trong PDF → kho tin cậy → tải qua caIssuers. */
  private async buildChain(input: Cert[]): Promise<Cert[]> {
    const [leaf, ...pool] = input;
    const chain: Cert[] = [leaf!];
    const candidates = [...pool, ...this.opts.trustAnchors];
    while (chain.length < MAX_CHAIN) {
      const last = chain[chain.length - 1]!.cert;
      if (isSelfIssued(last)) break;
      let issuer = await findIssuer(last, candidates);
      if (!issuer) {
        const url = certificateUrls(last).caIssuers;
        if (!url) break;
        try {
          const raw = await this.fetchSigned(url, { maxBytes: 256 * 1024, timeoutMs: 8_000 });
          const fetched = parseCertificates(new Uint8Array(raw), 'aia');
          issuer = await findIssuer(last, fetched);
          // Chứng thư tải về trùng với kho tin cậy → coi như lấy từ kho tin cậy.
          if (issuer) {
            const fp = fingerprint(issuer.der);
            issuer = this.opts.trustAnchors.find((a) => fingerprint(a.der) === fp) ?? issuer;
          }
        } catch {
          break;
        }
      }
      if (!issuer || chain.some((c) => fingerprint(c.der) === fingerprint(issuer!.der))) break;
      chain.push(issuer);
    }
    return chain;
  }

  /**
   * CRL và chứng thư CA đều tự mang chữ ký và được kiểm tra sau khi tải, nên nếu HTTPS lỗi (nhiều máy chủ
   * CA thiếu chứng thư trung gian) thì thử lại không kiểm tra TLS, rồi qua HTTP, vẫn an toàn.
   */
  private async fetchSigned(url: string, options: Parameters<Fetcher>[1]) {
    try {
      return await this.opts.fetch(url, options);
    } catch (err) {
      if (!url.startsWith('https://')) throw err;
      try {
        return await this.opts.fetch(url, { ...options, insecureTls: true });
      } catch {
        return this.opts.fetch(`http://${url.slice('https://'.length)}`, options);
      }
    }
  }

  private async checkOcsp(
    c: Cert,
    issuer: Cert | undefined,
    url: string | null,
  ): Promise<RevocationResult> {
    if (!url) return none();
    if (!issuer)
      return { status: 'unsupported', url, detail: 'Thiếu chứng thư của tổ chức phát hành' };
    const key = fingerprint(c.der);
    const hit = this.ocspCache.get(key);
    if (hit && hit.expiresAt > this.now()) return hit.value;

    let result: RevocationResult;
    try {
      const req = new pkijs.OCSPRequest();
      await req.createForCertificate(c.cert, {
        hashAlgorithm: 'SHA-1',
        issuerCertificate: issuer.cert,
      });
      const raw = await this.opts.fetch(url, {
        method: 'POST',
        body: new Uint8Array(req.toSchema(true).toBER()),
        contentType: 'application/ocsp-request',
        maxBytes: 512 * 1024,
      });
      const resp = pkijs.OCSPResponse.fromBER(new Uint8Array(raw));
      const code = resp.responseStatus.valueBlock.valueDec;
      if (code !== 0 || !resp.responseBytes || resp.responseBytes.responseType !== OID.ocspBasic) {
        throw new Error(`Máy chủ OCSP trả về mã ${code}`);
      }
      const basic = pkijs.BasicOCSPResponse.fromBER(
        resp.responseBytes.response.valueBlock.valueHex,
      );
      let authentic = false;
      try {
        authentic = await basic.verify({ trustedCerts: [issuer.cert], issuerCerts: [issuer.cert] });
      } catch {
        authentic = false;
      }
      if (!authentic) throw new Error('Chữ ký của phản hồi OCSP không hợp lệ');
      const { isForCertificate, status } = await basic.getCertificateStatus(c.cert, issuer.cert);
      if (!isForCertificate) throw new Error('Phản hồi OCSP không dành cho chứng thư này');
      result =
        status === 0
          ? { status: 'good', url }
          : status === 1
            ? { status: 'revoked', url, revokedAt: ocspRevocationTime(basic) }
            : { status: 'unknown', url };
    } catch (err) {
      result = { status: 'error', url, detail: message(err) };
    }
    this.ocspCache.set(key, { value: result, expiresAt: this.now() + OCSP_TTL_MS });
    return result;
  }

  private async checkCrl(
    c: Cert,
    issuer: Cert | undefined,
    url: string | null,
  ): Promise<RevocationResult> {
    if (!url) return none();
    if (!issuer)
      return { status: 'unsupported', url, detail: 'Thiếu chứng thư của tổ chức phát hành' };
    try {
      const crl = await this.loadCrl(url, issuer);
      const revokedAt = crl.revoked.get(serialHex(c.cert.serialNumber.valueBlock.valueHexView));
      if (revokedAt) return { status: 'revoked', url, revokedAt: revokedAt.toISOString() };
      const stale = crl.nextUpdate && crl.nextUpdate.getTime() < this.now();
      return stale
        ? { status: 'good', url, detail: 'Danh sách thu hồi đã quá hạn cập nhật' }
        : { status: 'good', url };
    } catch (err) {
      return { status: 'error', url, detail: message(err) };
    }
  }

  private loadCrl(url: string, issuer: Cert): Promise<ParsedCrl> {
    const key = `${url}|${fingerprint(issuer.der)}`;
    const hit = this.crlCache.get(key);
    if (hit && hit.expiresAt > this.now()) return hit.value;
    const value = (async () => {
      let raw: Bytes = new Uint8Array(
        await this.fetchSigned(url, { maxBytes: MAX_CRL_BYTES, timeoutMs: 20_000 }),
      );
      const text = Buffer.from(raw.subarray(0, 64)).toString('latin1');
      if (text.includes('-----BEGIN')) {
        const b64 = Buffer.from(raw)
          .toString('latin1')
          .replace(/-----[^-]+-----|\s/g, '');
        raw = new Uint8Array(Buffer.from(b64, 'base64'));
      }
      const crl = parseCrl(raw);
      if (!crl.issuer.isEqual(issuer.cert.subject))
        throw new Error('Danh sách thu hồi không do tổ chức phát hành này cấp');
      const ok = await pkijs
        .getCrypto(true)
        .verifyWithPublicKey(
          crl.tbs,
          crl.signature,
          issuer.cert.subjectPublicKeyInfo,
          crl.signatureAlgorithm,
        );
      if (!ok) throw new Error('Chữ ký của danh sách thu hồi không hợp lệ');
      return crl;
    })();
    // Lỗi thì không giữ lại, để lần sau thử tải lại.
    value.catch(() => this.crlCache.delete(key));
    this.crlCache.set(key, { value, expiresAt: this.now() + CRL_TTL_MS });
    return value;
  }
}

const serialHex = (b: Uint8Array) =>
  Buffer.from(b)
    .toString('hex')
    .replace(/^(00)+(?=.)/, '');

interface ParsedCrl {
  tbs: Bytes;
  signatureAlgorithm: pkijs.AlgorithmIdentifier;
  signature: asn1js.BitString;
  issuer: pkijs.RelativeDistinguishedNames;
  nextUpdate: Date | null;
  revoked: Map<string, Date>;
}

interface Tlv {
  tag: number;
  /** Vị trí bắt đầu của cả phần tử (kể cả header). */
  pos: number;
  /** Vị trí bắt đầu nội dung. */
  start: number;
  end: number;
}

function readTlv(buf: Bytes, pos: number, limit = buf.length): Tlv {
  if (pos + 2 > limit) throw new Error('Danh sách thu hồi không hợp lệ');
  const tag = buf[pos]!;
  let len = buf[pos + 1]!;
  let start = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || start + n > limit) throw new Error('Danh sách thu hồi không hợp lệ');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i]!;
    start += n;
  }
  const end = start + len;
  if (end > limit) throw new Error('Danh sách thu hồi không hợp lệ');
  return { tag, pos, start, end };
}

function children(buf: Bytes, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let p = parent.start; p < parent.end;) {
    const t = readTlv(buf, p, parent.end);
    out.push(t);
    p = t.end;
  }
  return out;
}

const UTC_TIME = 0x17;
const GENERALIZED_TIME = 0x18;
const isTimeTag = (t: Tlv | undefined) => t?.tag === UTC_TIME || t?.tag === GENERALIZED_TIME;

function derTime(buf: Bytes, t: Tlv): Date {
  const s = Buffer.from(buf.subarray(t.start, t.end)).toString('latin1');
  const full = t.tag === UTC_TIME ? `${Number(s.slice(0, 2)) >= 50 ? '19' : '20'}${s}` : s;
  const m = full.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/);
  if (!m) throw new Error('Thời gian trong danh sách thu hồi không hợp lệ');
  return new Date(Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +(m[6] ?? 0)));
}

const asn1At = (buf: Bytes, t: Tlv) => asn1js.fromBER(buf.subarray(t.pos, t.end)).result;

/**
 * Đọc CRL (RFC 5280) bằng cách duyệt DER trực tiếp. CRL thật có thể vài MB với hàng chục nghìn
 * dòng (vd. Viettel-CA): pkijs/asn1js dựng cây đối tượng quá lớn và từ chối, nên chỉ lấy
 * số serial + ngày thu hồi; phần nhỏ (tên, thuật toán, chữ ký) mới đưa cho asn1js.
 */
function parseCrl(raw: Bytes): ParsedCrl {
  const outer = readTlv(raw, 0);
  const [tbs, alg, sig] = children(raw, outer);
  if (!tbs || !alg || !sig || tbs.tag !== 0x30 || alg.tag !== 0x30 || sig.tag !== 0x03) {
    throw new Error('Danh sách thu hồi không hợp lệ');
  }
  const items = children(raw, tbs);
  let i = items[0]?.tag === 0x02 ? 1 : 0;
  i++; // signature AlgorithmIdentifier bên trong tbs
  const issuer = new pkijs.RelativeDistinguishedNames({ schema: asn1At(raw, items[i++]!) });
  i++; // thisUpdate
  const nextUpdate = isTimeTag(items[i]) ? derTime(raw, items[i++]!) : null;
  const revoked = new Map<string, Date>();
  const list = items[i];
  if (list?.tag === 0x30) {
    for (const entry of children(raw, list)) {
      const [serial, date] = children(raw, entry);
      if (serial?.tag === 0x02 && date && isTimeTag(date)) {
        revoked.set(serialHex(raw.subarray(serial.start, serial.end)), derTime(raw, date));
      }
    }
  }
  return {
    tbs: raw.slice(tbs.pos, tbs.end),
    signatureAlgorithm: new pkijs.AlgorithmIdentifier({ schema: asn1At(raw, alg) }),
    signature: asn1At(raw, sig) as asn1js.BitString,
    issuer,
    nextUpdate,
    revoked,
  };
}

const none = (): RevocationResult => ({ status: 'none', url: null });

async function findIssuer(cert: pkijs.Certificate, candidates: Cert[]): Promise<Cert | undefined> {
  for (const c of candidates) {
    if (!c.cert.subject.isEqual(cert.issuer)) continue;
    try {
      if (await cert.verify(c.cert)) return c;
    } catch {
      // khoá không khớp → thử ứng viên khác
    }
  }
  // Trùng tên nhưng chữ ký không khớp: vẫn trả về để báo "chữ ký không hợp lệ" thay vì "thiếu".
  return candidates.find((c) => c.cert.subject.isEqual(cert.issuer));
}

function ocspRevocationTime(basic: pkijs.BasicOCSPResponse): string | undefined {
  try {
    for (const r of basic.tbsResponseData.responses) {
      const status = r.certStatus as asn1js.Constructed;
      if (status.idBlock.tagNumber !== 1) continue;
      const time = status.valueBlock.value[0] as asn1js.GeneralizedTime;
      return time.toDate().toISOString();
    }
  } catch {
    // không đọc được thời điểm thu hồi
  }
  return undefined;
}
