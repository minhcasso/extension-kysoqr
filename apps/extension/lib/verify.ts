import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

/**
 * Đọc và kiểm tra các chữ ký số có sẵn trong file PDF, ngay trên máy người dùng
 * (nội dung file không rời trình duyệt). Kiểm tra: chữ ký CMS khớp với phần nội dung được ký,
 * và phần nội dung đó có còn là toàn bộ file hay đã bị thêm/sửa sau khi ký.
 * Chuỗi tin cậy, OCSP, CRL do backend kiểm tra (xem `checkCertificates`).
 */

pkijs.setEngine(
  'webcrypto',
  new pkijs.CryptoEngine({ name: 'webcrypto', crypto: globalThis.crypto }),
);

type Bytes = Uint8Array<ArrayBuffer>;

export interface CertInfo {
  /** DER base64, gửi lên backend để kiểm tra chuỗi. */
  der: string;
  subject: string;
  issuer: string;
  commonName: string | null;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
  isCa: boolean;
  ocspUrl: string | null;
  crlUrl: string | null;
}

/**
 * intact: phần được ký là toàn bộ file.
 * later-revision: sau chữ ký này có chữ ký khác được thêm vào (ký nhiều lần, bình thường).
 * modified: file có nội dung thêm/sửa sau chữ ký cuối cùng.
 */
export type Integrity = 'intact' | 'later-revision' | 'modified';

export interface PdfSignature {
  index: number;
  kind: 'signature' | 'document-timestamp';
  subFilter: string;
  signedAt: Date | null;
  signedAtSource: 'timestamp' | 'signing-time' | 'dictionary' | null;
  hasTimestamp: boolean;
  signerName: string | null;
  reason: string | null;
  location: string | null;
  /** Chữ ký CMS hợp lệ với phần nội dung được ký. */
  signatureValid: boolean;
  error: string | null;
  integrity: Integrity;
  /** Chứng thư người ký đứng đầu, sau đó là các chứng thư khác đi kèm chữ ký. */
  certificates: CertInfo[];
}

const OID = {
  signingTime: '1.2.840.113549.1.9.5',
  timestampToken: '1.2.840.113549.1.9.16.2.14',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  basicConstraints: '2.5.29.19',
  authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
  ocsp: '1.3.6.1.5.5.7.48.1',
  crlDistributionPoints: '2.5.29.31',
};

const DN_LABELS: Record<string, string> = {
  '2.5.4.6': 'C',
  '2.5.4.8': 'ST',
  '2.5.4.7': 'L',
  '2.5.4.9': 'STREET',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.3': 'CN',
  '2.5.4.4': 'SN',
  '2.5.4.42': 'GN',
  '2.5.4.5': 'SERIALNUMBER',
  '2.5.4.12': 'T',
  '0.9.2342.19200300.100.1.1': 'UID',
};
/** Không hiển thị email, số điện thoại trong chứng thư. */
const HIDDEN_DN = new Set(['1.2.840.113549.1.9.1', '2.5.4.20']);

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const toBase64 = (b: Uint8Array) => btoa(Array.from(b, (x) => String.fromCharCode(x)).join(''));

function dnValue(tv: pkijs.AttributeTypeAndValue): string {
  const v = tv.value as { valueBlock?: { value?: unknown } };
  return typeof v.valueBlock?.value === 'string' ? v.valueBlock.value : '';
}

function formatDn(dn: pkijs.RelativeDistinguishedNames): string {
  return dn.typesAndValues
    .filter((tv) => !HIDDEN_DN.has(tv.type))
    .map((tv) => {
      const value = dnValue(tv);
      const label = DN_LABELS[tv.type] ?? tv.type;
      // CA Việt Nam hay ghi "MST:0101..." hoặc "CCCD:0012..." vào UID: hiển thị nguyên giá trị.
      return label === 'UID' && /^[A-Z]+:/.test(value) ? value : `${label}=${value}`;
    })
    .join(', ');
}

const commonName = (dn: pkijs.RelativeDistinguishedNames) => {
  const tv = dn.typesAndValues.find((t) => t.type === '2.5.4.3');
  return tv ? dnValue(tv) : null;
};

function uris(names: pkijs.GeneralName[] | undefined) {
  const list = (names ?? []).filter((n) => n.type === 6).map((n) => n.value as string);
  return list.find((u) => u.startsWith('http://')) ?? list[0] ?? null;
}

export function certInfo(cert: pkijs.Certificate, der?: Uint8Array): CertInfo {
  const ext = (id: string) => cert.extensions?.find((e) => e.extnID === id)?.parsedValue;
  const aia = ext(OID.authorityInfoAccess) as pkijs.InfoAccess | undefined;
  const dps = (ext(OID.crlDistributionPoints) as pkijs.CRLDistributionPoints | undefined)
    ?.distributionPoints;
  return {
    der: toBase64(der ?? new Uint8Array(cert.toSchema().toBER())),
    subject: formatDn(cert.subject),
    issuer: formatDn(cert.issuer),
    commonName: commonName(cert.subject),
    serialNumber: toHex(cert.serialNumber.valueBlock.valueHexView),
    validFrom: cert.notBefore.value,
    validTo: cert.notAfter.value,
    isCa: Boolean((ext(OID.basicConstraints) as pkijs.BasicConstraints | undefined)?.cA),
    ocspUrl: uris(
      aia?.accessDescriptions
        .filter((d) => d.accessMethod === OID.ocsp)
        .map((d) => d.accessLocation),
    ),
    crlUrl: uris(
      dps?.flatMap((dp) => (Array.isArray(dp.distributionPoint) ? dp.distributionPoint : [])),
    ),
  };
}

const HASHES: Record<string, string> = {
  '1.3.14.3.2.26': 'SHA-1',
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
};

const bigint = (b: Uint8Array) => BigInt(`0x${toHex(b) || '0'}`);

function modPow(base: bigint, exp: bigint, mod: bigint) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

/**
 * Kiểm tra chữ ký RSA PKCS#1 v1.5 "bằng tay". WebCrypto chỉ chấp nhận DigestInfo có tham số NULL,
 * trong khi một số CA Việt Nam (vd. CMC-CA) bỏ NULL — RFC 8017 cho phép, Adobe/OpenSSL đều chấp nhận.
 */
async function rsaPkcs1Verify(
  cert: pkijs.Certificate,
  signature: Uint8Array,
  tbs: Bytes,
  hashOid: string,
) {
  const hash = HASHES[hashOid];
  if (!hash) return false;
  const key = asn1js.fromBER(
    cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
  ).result;
  const [n, e] = (key as asn1js.Sequence).valueBlock.value as asn1js.Integer[];
  if (!n || !e) return false;
  const modulus = bigint(n.valueBlock.valueHexView);
  const em = modPow(bigint(signature), bigint(e.valueBlock.valueHexView), modulus).toString(16);
  // EM = 00 01 FF..FF 00 || DigestInfo (số 0 đầu bị mất khi đổi sang hex).
  const m = em.match(/^1(?:ff){8,}00([0-9a-f]+)$/);
  if (!m) return false;
  const info = asn1js.fromBER(new Uint8Array(m[1]!.match(/../g)!.map((h) => parseInt(h, 16))));
  if (info.offset === -1) return false;
  const [alg, digest] = (info.result as asn1js.Sequence).valueBlock.value;
  const oid = (
    (alg as asn1js.Sequence)?.valueBlock.value[0] as asn1js.ObjectIdentifier
  )?.valueBlock.toString();
  if (oid !== hashOid || !(digest instanceof asn1js.OctetString)) return false;
  const expected = new Uint8Array(await crypto.subtle.digest(hash, tbs));
  return toHex(expected) === toHex(digest.valueBlock.valueHexView);
}

/** Dự phòng khi pkijs báo sai: so messageDigest và kiểm tra chữ ký RSA trên signedAttrs. */
async function verifySignerFallback(
  signer: pkijs.SignerInfo,
  cert: pkijs.Certificate,
  data: Bytes,
) {
  const hashOid = signer.digestAlgorithm.algorithmId;
  const hash = HASHES[hashOid];
  if (!hash || !signer.signedAttrs) return false;
  const md = signer.signedAttrs.attributes.find((a) => a.type === '1.2.840.113549.1.9.4')
    ?.values[0];
  if (!(md instanceof asn1js.OctetString)) return false;
  const digest = new Uint8Array(await crypto.subtle.digest(hash, data));
  if (toHex(digest) !== toHex(md.valueBlock.valueHexView)) return false;
  const tbs = new Uint8Array(signer.signedAttrs.encodedValue);
  tbs[0] = 0x31; // [0] IMPLICIT → SET OF khi tính chữ ký
  return rsaPkcs1Verify(cert, signer.signature.valueBlock.valueHexView, tbs, hashOid);
}

export function certInfoFromDer(b64: string): CertInfo {
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return certInfo(pkijs.Certificate.fromBER(der), der);
}

interface RawSignature {
  byteRange: [number, number, number, number];
  contents: Bytes;
  dict: string;
}

/** Tìm các từ điển chữ ký qua /ByteRange; /Contents nằm đúng ở khoảng trống giữa hai đoạn. */
function findSignatures(bytes: Bytes, text: string): RawSignature[] {
  const found: RawSignature[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g)) {
    const byteRange = m.slice(1, 5).map(Number) as RawSignature['byteRange'];
    const [a, b, c, d] = byteRange;
    const key = byteRange.join(',');
    if (seen.has(key) || c + d > bytes.length || a + b >= c) continue;
    seen.add(key);
    const hex = text.slice(a + b, c).replace(/[<>\s]/g, '');
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length < 2) continue;
    const contents = new Uint8Array(hex.length / 2);
    for (let i = 0; i < contents.length; i++)
      contents[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    const start = text.lastIndexOf(' obj', m.index);
    const end = text.indexOf('endobj', c);
    const dict = text.slice(Math.max(0, start), a + b) + text.slice(c, end < 0 ? c + 2000 : end);
    found.push({ byteRange, contents, dict });
  }
  return found.sort((x, y) => x.byteRange[2] + x.byteRange[3] - (y.byteRange[2] + y.byteRange[3]));
}

function pdfDate(dict: string): Date | null {
  const m = dict.match(
    /\/M\s*\(D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Zz+-])?(\d{2})?'?(\d{2})?/,
  );
  if (!m) return null;
  const [, y, mo = '01', d = '01', h = '00', mi = '00', s = '00', tz, th = '00', tm = '00'] = m;
  const offset = !tz || tz.toUpperCase() === 'Z' ? 'Z' : `${tz}${th}:${tm}`;
  const date = new Date(`${y}-${mo}-${d}T${h}:${mi}:${s}${offset}`);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Chuỗi literal PDF ngắn (/Reason, /Location); bỏ qua chuỗi UTF-16 mã hoá phức tạp. */
function pdfText(dict: string, key: string): string | null {
  const m = dict.match(new RegExp(`/${key}\\s*\\(((?:\\\\.|[^\\\\)])*)\\)`));
  if (!m?.[1]) return null;
  const raw = m[1].replace(
    /\\([nrtbf()\\])/g,
    (_, c: string) => ({ n: '\n', r: '\r', t: '\t', b: '', f: '' })[c] ?? c,
  );
  if (raw.startsWith('þÿ')) {
    let out = '';
    for (let i = 2; i + 1 < raw.length; i += 2)
      out += String.fromCharCode((raw.charCodeAt(i) << 8) | raw.charCodeAt(i + 1));
    return out.trim() || null;
  }
  try {
    return decodeURIComponent(escape(raw)).trim() || null;
  } catch {
    return raw.trim() || null;
  }
}

function signedBytes(bytes: Bytes, [a, b, c, d]: RawSignature['byteRange']): Bytes {
  const out = new Uint8Array(b + d);
  out.set(bytes.subarray(a, a + b), 0);
  out.set(bytes.subarray(c, c + d), b);
  return out;
}

function attrTime(attrs: pkijs.SignedAndUnsignedAttributes | undefined, oid: string): Date | null {
  const v = attrs?.attributes.find((a) => a.type === oid)?.values[0] as asn1js.UTCTime | undefined;
  return v && 'toDate' in v ? v.toDate() : null;
}

function timestampTime(signer: pkijs.SignerInfo): Date | null {
  const token = signer.unsignedAttrs?.attributes.find((a) => a.type === OID.timestampToken)
    ?.values[0];
  if (!token) return null;
  try {
    const sd = new pkijs.SignedData({ schema: new pkijs.ContentInfo({ schema: token }).content });
    const content = sd.encapContentInfo.eContent;
    if (!content) return null;
    return pkijs.TSTInfo.fromBER(content.getValue()).genTime;
  } catch {
    return null;
  }
}

async function verifyOne(bytes: Bytes, raw: RawSignature) {
  const asn1 = asn1js.fromBER(raw.contents);
  if (asn1.offset === -1) throw new Error('Không đọc được dữ liệu chữ ký (CMS).');
  const sd = new pkijs.SignedData({
    schema: new pkijs.ContentInfo({ schema: asn1.result }).content,
  });
  const data = signedBytes(bytes, raw.byteRange);
  const subFilter = raw.dict.match(/\/SubFilter\s*\/([^\s/<>[\]()]+)/)?.[1] ?? '';
  const isDocTimestamp = subFilter === 'ETSI.RFC3161' || /\/Type\s*\/DocTimeStamp/.test(raw.dict);
  const encapsulated = isDocTimestamp || subFilter === 'adbe.pkcs7.sha1';

  let signatureValid = false;
  let signerCert: pkijs.Certificate | null = null;
  let error: string | null = null;
  try {
    const res = await sd.verify({
      signer: 0,
      data: encapsulated ? undefined : data.buffer,
      extendedMode: true,
      checkChain: false,
    });
    signatureValid = Boolean(res.signatureVerified);
    signerCert = res.signerCertificate ?? null;
  } catch (e) {
    const err = e as { signerCertificate?: pkijs.Certificate | null; message?: string };
    signerCert = err.signerCertificate ?? null;
    error = err.message ?? String(e);
  }

  const signer = sd.signerInfos[0];
  if (!signatureValid && !encapsulated && signer && signerCert) {
    try {
      signatureValid = await verifySignerFallback(signer, signerCert, data);
    } catch {
      signatureValid = false;
    }
  }

  // Với chữ ký kiểu "đóng gói", nội dung được ký là mã băm của file, phải so thêm.
  let signedAt: Date | null = null;
  if (signatureValid && encapsulated) {
    const content = sd.encapContentInfo.eContent?.getValue();
    if (!content) {
      signatureValid = false;
    } else if (isDocTimestamp) {
      const tst = pkijs.TSTInfo.fromBER(content);
      signatureValid = await tst.verify({ data: data.buffer });
      signedAt = tst.genTime;
    } else {
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', data));
      signatureValid = toHex(digest) === toHex(new Uint8Array(content));
    }
    if (!signatureValid) error = 'Mã băm trong chữ ký không khớp với nội dung tài liệu.';
  }

  const tsTime = signer ? timestampTime(signer) : null;
  const signingTime = attrTime(signer?.signedAttrs, OID.signingTime);
  const dictTime = pdfDate(raw.dict);
  const source: PdfSignature['signedAtSource'] =
    (signedAt ?? tsTime)
      ? 'timestamp'
      : signingTime
        ? 'signing-time'
        : dictTime
          ? 'dictionary'
          : null;

  const all = (sd.certificates ?? []).filter(
    (c): c is pkijs.Certificate => c instanceof pkijs.Certificate,
  );
  const ordered = signerCert
    ? [
        signerCert,
        ...all.filter((c) => c !== signerCert && !c.serialNumber.isEqual(signerCert!.serialNumber)),
      ]
    : all;

  return {
    kind: isDocTimestamp ? ('document-timestamp' as const) : ('signature' as const),
    subFilter,
    signedAt: signedAt ?? tsTime ?? signingTime ?? dictTime,
    signedAtSource: source,
    hasTimestamp: Boolean(tsTime) || isDocTimestamp,
    signerName: signerCert ? commonName(signerCert.subject) : pdfText(raw.dict, 'Name'),
    reason: pdfText(raw.dict, 'Reason'),
    location: pdfText(raw.dict, 'Location'),
    signatureValid,
    error: signatureValid ? null : friendlyError(error),
    certificates: ordered.map((c) => certInfo(c)),
  };
}

function friendlyError(raw: string | null) {
  if (raw && /digest/i.test(raw))
    return 'Nội dung tài liệu đã bị thay đổi sau khi ký (mã băm không khớp).';
  if (raw && /Unable to find signer certificate/i.test(raw))
    return 'Chữ ký không kèm chứng thư số của người ký.';
  return 'Chữ ký không khớp với nội dung tài liệu.';
}

/** Chỉ còn khoảng trắng / dấu xuống dòng sau phần được ký thì vẫn coi là nguyên vẹn. */
function onlyWhitespaceAfter(bytes: Bytes, end: number) {
  for (let i = end; i < bytes.length; i++) {
    const b = bytes[i]!;
    if (b !== 0x0a && b !== 0x0d && b !== 0x20 && b !== 0x09 && b !== 0x00) return false;
  }
  return true;
}

export async function readPdfSignatures(input: Uint8Array): Promise<PdfSignature[]> {
  const bytes = new Uint8Array(input);
  let text = '';
  // Giải mã từng khúc để không tạo chuỗi trung gian quá lớn.
  for (let i = 0; i < bytes.length; i += 0x8000) {
    text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  const raws = findSignatures(bytes, text);
  const results: PdfSignature[] = [];
  for (const [i, raw] of raws.entries()) {
    const end = raw.byteRange[2] + raw.byteRange[3];
    const integrity: Integrity =
      raw.byteRange[0] !== 0
        ? 'modified'
        : onlyWhitespaceAfter(bytes, end)
          ? 'intact'
          : i < raws.length - 1
            ? 'later-revision'
            : 'modified';
    try {
      results.push({ index: i + 1, integrity, ...(await verifyOne(bytes, raw)) });
    } catch (e) {
      results.push({
        index: i + 1,
        kind: 'signature',
        subFilter: '',
        signedAt: pdfDate(raw.dict),
        signedAtSource: pdfDate(raw.dict) ? 'dictionary' : null,
        hasTimestamp: false,
        signerName: pdfText(raw.dict, 'Name'),
        reason: pdfText(raw.dict, 'Reason'),
        location: pdfText(raw.dict, 'Location'),
        signatureValid: false,
        error: e instanceof Error ? e.message : String(e),
        integrity,
        certificates: [],
      });
    }
  }
  return results;
}
