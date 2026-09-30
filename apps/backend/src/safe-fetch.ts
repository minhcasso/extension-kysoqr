import { lookup, type LookupAddress } from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import { isIP, type LookupFunction } from 'node:net';

/**
 * Tải địa chỉ OCSP / CRL / caIssuers lấy từ chứng thư số trong PDF người dùng.
 * Địa chỉ đó do người khác đặt vào, nên chặn mọi IP nội bộ (SSRF) ngay ở bước phân giải DNS
 * (kiểm tra trong `lookup` nên không bị vượt qua bằng DNS rebinding), không tự theo redirect
 * sang mạng nội bộ, giới hạn dung lượng và thời gian.
 */

export class FetchError extends Error {}

export interface FetchOptions {
  method?: 'GET' | 'POST';
  body?: Uint8Array;
  contentType?: string;
  maxBytes?: number;
  timeoutMs?: number;
  /**
   * Bỏ kiểm tra chứng thư TLS. CHỈ dùng cho dữ liệu tự mang chữ ký (CRL, chứng thư CA) và được
   * kiểm tra chữ ký sau khi tải: nhiều máy chủ CA cấu hình TLS thiếu chứng thư trung gian.
   */
  insecureTls?: boolean;
}

export type Fetcher = (url: string, options?: FetchOptions) => Promise<Uint8Array>;

const MAX_REDIRECTS = 3;

function ipv4Private(ip: string) {
  const [a = 0, b = 0] = ip.split('.').map(Number);
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

/** IP nội bộ, loopback, link-local, multicast, dành riêng: không được gọi tới. */
export function isPrivateAddress(ip: string): boolean {
  if (isIP(ip) === 4) return ipv4Private(ip);
  const v6 = ip.toLowerCase();
  const mapped = v6.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return ipv4Private(mapped[1]!);
  return (
    v6 === '::' ||
    v6 === '::1' ||
    v6.startsWith('fc') ||
    v6.startsWith('fd') ||
    /^fe[89ab]/.test(v6) ||
    v6.startsWith('ff') ||
    v6.startsWith('::ffff:')
  );
}

const guardedLookup: LookupFunction = (hostname, options, callback) => {
  lookup(hostname, { ...options, all: true }, (err, addresses: LookupAddress[]) => {
    if (err) return callback(err, '', 4);
    const blocked = addresses.length === 0 || addresses.some((a) => isPrivateAddress(a.address));
    if (blocked) return callback(new FetchError(`Không cho phép gọi tới ${hostname}`), '', 4);
    if (options.all)
      return (callback as unknown as (e: null, a: LookupAddress[]) => void)(null, addresses);
    callback(null, addresses[0]!.address, addresses[0]!.family);
  });
};

function once(
  url: URL,
  options: FetchOptions,
): Promise<{ status: number; location?: string; body: Uint8Array }> {
  const maxBytes = options.maxBytes ?? 1024 * 1024;
  const client = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = client.request(
      url,
      {
        method: options.method ?? 'GET',
        lookup: guardedLookup,
        ...(url.protocol === 'https:' && options.insecureTls ? { rejectUnauthorized: false } : {}),
        timeout: options.timeoutMs ?? 10_000,
        headers: {
          'user-agent': 'KysoQR-verifier',
          ...(options.contentType ? { 'content-type': options.contentType } : {}),
          ...(options.body ? { 'content-length': String(options.body.byteLength) } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxBytes) {
            req.destroy(new FetchError(`Phản hồi vượt quá ${Math.round(maxBytes / 1024)} KB`));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            location: res.headers.location,
            body: new Uint8Array(Buffer.concat(chunks)),
          }),
        );
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new FetchError('Hết thời gian chờ phản hồi')));
    req.on('error', reject);
    req.end(options.body ? Buffer.from(options.body) : undefined);
  });
}

export const safeFetch: Fetcher = async (rawUrl, options = {}) => {
  let url = new URL(rawUrl);
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new FetchError(`Không hỗ trợ giao thức ${url.protocol}`);
    }
    if (url.username || url.password) throw new FetchError('Địa chỉ không hợp lệ');
    const host = url.hostname.replace(/^\[|\]$/g, '');
    // IP viết thẳng trong URL không đi qua lookup.
    if (isIP(host) && isPrivateAddress(host))
      throw new FetchError(`Không cho phép gọi tới ${host}`);

    const res = await once(url, options);
    if (res.status >= 300 && res.status < 400 && res.location) {
      url = new URL(res.location, url);
      continue;
    }
    if (res.status < 200 || res.status >= 300)
      throw new FetchError(`Máy chủ trả về HTTP ${res.status}`);
    return res.body;
  }
  throw new FetchError('Chuyển hướng quá nhiều lần');
};
