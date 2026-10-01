import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import {
  lookup as dnsLookup,
  resolve4 as dnsResolve4,
  resolve6 as dnsResolve6,
  type LookupOptions,
  type LookupAddress,
} from 'node:dns';
import { BlockList, isIPv4, isIPv6 } from 'node:net';

/**
 * SSRF-safe fetch core, shared by any caller that must fetch a URL taken from
 * untrusted, attacker-influenced input (a certificate's AIA/OCSP/CRL URLs are
 * the two current cases — see `aiaCertFetcher.ts` and `revocationChecker.ts`).
 * Extracted out of `aiaCertFetcher.ts` (which used to own all of this) into
 * its own leaf module so `revocationChecker.ts` can reuse it too without
 * creating an import cycle (`aiaCertFetcher.ts` already imports
 * `toPkijsCertificate` from `revocationChecker.ts`).
 *
 * **Two SSRF-guard implementations, chosen at runtime (`isCloudflareWorkers`
 * below), not one.** On a real Node.js process (VPS), `fetchBytesWithGuards`
 * uses `http(s).request` with a custom `lookup` option, so the address we
 * validate is the *only* address the connection can ever use -- no
 * DNS-rebinding TOCTOU window at all (see `createGuardedLookup`'s own doc
 * comment). Confirmed via research (developers.cloudflare.com/workers/
 * runtime-apis/nodejs/{http,dns,net}/) that this exact mechanism silently
 * does not work on Cloudflare Workers: `http.request`'s `lookup` option is
 * unsupported there (Workers' `node:http` is itself just a wrapper around
 * global `fetch()`, so the callback is simply never invoked -- not an
 * error, a silent fail-open), and `dns.lookup()` itself throws "not
 * implemented". `net.BlockList` alone works fine on Workers, it just has
 * nothing to plug into for connection-time enforcement without `lookup`.
 * Disabling these fetches entirely on Workers was considered and rejected
 * (explicit product decision) -- most real CA hierarchies/revocation
 * infrastructure legitimately need this network path. Instead, the Workers
 * path resolves via `dns.resolve4`/`resolve6` (confirmed working there,
 * routed through Cloudflare's own DoH resolver) and validates against the
 * same `isAddressAllowed` predicate, *then* calls `fetch()` -- this still
 * blocks the overwhelming majority of real SSRF targets (cloud metadata,
 * RFC1918, loopback) but leaves a narrower, harder-to-execute
 * DNS-rebinding race (the attacker's DNS must flip between our check and
 * `fetch()`'s own internal resolution). A real, accepted, and deliberately
 * *not* silently unified with the Node path -- see
 * `docs/DEPLOY_CLOUDFLARE.md` §0 for the user-facing version of this
 * tradeoff.
 */

/** Standard, documented Cloudflare Workers feature-detection idiom: Workers
 * sets `navigator.userAgent` to exactly this string. No new dependency. */
function isCloudflareWorkers(): boolean {
  return typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers';
}

// --- SSRF guard --------------------------------------------------------

const blockedV4 = new BlockList();
blockedV4.addSubnet('0.0.0.0', 8, 'ipv4'); // "this network"
blockedV4.addSubnet('127.0.0.0', 8, 'ipv4'); // loopback
blockedV4.addSubnet('10.0.0.0', 8, 'ipv4'); // RFC1918
blockedV4.addSubnet('172.16.0.0', 12, 'ipv4'); // RFC1918
blockedV4.addSubnet('192.168.0.0', 16, 'ipv4'); // RFC1918
blockedV4.addSubnet('169.254.0.0', 16, 'ipv4'); // link-local, incl. 169.254.169.254 cloud metadata
blockedV4.addSubnet('100.64.0.0', 10, 'ipv4'); // CGNAT

const blockedV6 = new BlockList();
blockedV6.addAddress('::1', 'ipv6'); // loopback
blockedV6.addSubnet('fc00::', 7, 'ipv6'); // unique local
blockedV6.addSubnet('fe80::', 10, 'ipv6'); // link-local
blockedV6.addSubnet('ff00::', 8, 'ipv6'); // multicast

const IPV4_MAPPED_PREFIX = '::ffff:';

/** Pure predicate, no I/O -- deliberately separate from the fetch layer so it
 * can be table-tested on its own. Fails closed (returns false) for anything
 * it doesn't recognize as an ordinary public-looking address. */
export function isAddressAllowed(address: string, family: 4 | 6): boolean {
  if (family === 4 || isIPv4(address)) {
    return isIPv4(address) && !blockedV4.check(address, 'ipv4');
  }
  const lower = address.toLowerCase();
  if (lower.startsWith(IPV4_MAPPED_PREFIX)) {
    const v4 = lower.slice(IPV4_MAPPED_PREFIX.length);
    if (isIPv4(v4)) return !blockedV4.check(v4, 'ipv4');
  }
  if (isIPv6(address)) {
    return !blockedV6.check(address, 'ipv6');
  }
  return false;
}

/**
 * Builds a `lookup` option for `http(s).request` that resolves DNS itself and
 * only ever hands back an address that already passed `isAddressAllowed` --
 * this is the one thing that actually closes the SSRF gap. A separate
 * "resolve, check, then call fetch()" sequence leaves a DNS-rebinding TOCTOU
 * window (the attacker's DNS server can answer the pre-check safely and the
 * real connection differently); here, the address we validate is the only
 * address `http(s).request` can ever connect to, because there is no
 * separate later resolution step at all.
 *
 * Node's own dual-stack connection logic (Happy Eyeballs / RFC 8305, on by
 * default) calls this function with `options.all: true`, expecting the
 * callback back with an ARRAY of every candidate address it should race --
 * confirmed empirically: answering with a single scalar address instead (as
 * an earlier version of this function did) makes Node misread that string as
 * an array internally, surfacing as a confusing `ERR_INVALID_IP_ADDRESS:
 * Invalid IP address: undefined` instead of ever actually connecting. Must
 * match whichever shape Node asked for.
 */
function createGuardedLookup(allow: typeof isAddressAllowed) {
  return (
    hostname: string,
    options: LookupOptions,
    callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void
  ): void => {
    dnsLookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
      if (err) {
        callback(err, '');
        return;
      }
      const list: LookupAddress[] = Array.isArray(addresses) ? addresses : [addresses];
      const safeList = list.filter((a) => allow(a.address, a.family as 4 | 6));
      if (safeList.length === 0) {
        callback(new Error(`SSRF_BLOCKED: no allowed address for host "${hostname}"`), '');
        return;
      }
      if (options.all) {
        callback(null, safeList);
        return;
      }
      const [first] = safeList;
      callback(null, first!.address, first!.family);
    });
  };
}

export interface FetchGuards {
  timeoutMs: number;
  maxRedirects: number;
  maxBytes: number;
  /** Override for tests only -- production callers always get the real predicate. */
  isAddressAllowed?: typeof isAddressAllowed;
}

/** Extra per-request options for `fetchBytesWithGuards` -- method/headers/body,
 * so POST-with-a-body callers (OCSP) can reuse the exact same guard/redirect/
 * size-cap loop as GET-only callers (AIA, CRL) instead of duplicating it. */
export interface GuardedRequestOptions {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: Buffer | Uint8Array;
}

interface OneRequestResult {
  status: number;
  location?: string;
  body?: Buffer;
}

/**
 * Node's `lookup` option is only consulted when a hostname actually needs DNS
 * resolution -- `net.connect` checks `net.isIP(host)` first and, for a
 * literal IP address, connects to it directly without ever calling `lookup`
 * (confirmed empirically: a `lookup` that always errors is simply never
 * invoked when `hostname` is `"127.0.0.1"`). That means an untrusted URL --
 * or a redirect `Location` -- pointing straight at a literal IP would
 * silently bypass `createGuardedLookup` entirely. Validate literal IPs here,
 * before the request is ever opened, so nothing can reach `http(s).request`
 * without passing the same `isAddressAllowed` check either way.
 */
function checkLiteralIpAllowed(hostname: string, allow: typeof isAddressAllowed): void {
  const unbracketed = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  if (isIPv4(unbracketed)) {
    if (!allow(unbracketed, 4)) throw new Error(`SSRF_BLOCKED: literal address "${unbracketed}" is not allowed`);
    return;
  }
  if (isIPv6(unbracketed)) {
    if (!allow(unbracketed, 6)) throw new Error(`SSRF_BLOCKED: literal address "${unbracketed}" is not allowed`);
  }
}

function requestOnce(
  url: URL,
  guards: FetchGuards,
  allow: typeof isAddressAllowed,
  requestOptions: GuardedRequestOptions
): Promise<OneRequestResult> {
  return new Promise((resolve, reject) => {
    try {
      checkLiteralIpAllowed(url.hostname, allow);
    } catch (error) {
      reject(error);
      return;
    }
    const transport = url.protocol === 'https:' ? httpsRequest : httpRequest;
    const req = transport(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: requestOptions.method ?? 'GET',
        headers: requestOptions.headers,
        lookup: createGuardedLookup(allow),
        timeout: guards.timeoutMs,
      },
      (res: IncomingMessage) => {
        const status = res.statusCode ?? 0;

        if (status >= 300 && status < 400 && res.headers.location) {
          res.resume();
          resolve({ status, location: res.headers.location });
          return;
        }

        if (status < 200 || status >= 300) {
          res.resume();
          resolve({ status });
          return;
        }

        const chunks: Buffer[] = [];
        let total = 0;
        res.on('data', (chunk: Buffer) => {
          total += chunk.length;
          if (total > guards.maxBytes) {
            req.destroy(new Error(`Guarded fetch response exceeded ${guards.maxBytes} byte limit`));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => resolve({ status, body: Buffer.concat(chunks) }));
        res.on('error', reject);
      }
    );
    req.on('timeout', () => req.destroy(new Error(`Guarded fetch to ${url.hostname} timed out`)));
    req.on('error', reject);
    if (requestOptions.body) req.write(requestOptions.body);
    req.end();
  });
}

/** Node/VPS path (existing, unchanged): SSRF-safe DNS resolution via the
 * `lookup` option, bounded redirects (each hop re-validated the same way),
 * bounded response size, bounded timeout. Never trusts `Content-Length` for
 * the size cap -- aborts mid-stream instead. */
async function fetchBytesWithGuardsOnNode(
  url: string,
  guards: FetchGuards,
  requestOptions: GuardedRequestOptions
): Promise<ArrayBuffer> {
  const allow = guards.isAddressAllowed ?? isAddressAllowed;
  let currentUrl = url;

  for (let redirectCount = 0; ; redirectCount += 1) {
    const parsed = new URL(currentUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`Unsupported protocol for guarded fetch: ${parsed.protocol}`);
    }

    const result = await requestOnce(parsed, guards, allow, requestOptions);

    if (result.location) {
      if (redirectCount >= guards.maxRedirects) {
        throw new Error('Guarded fetch: too many redirects');
      }
      currentUrl = new URL(result.location, currentUrl).toString();
      continue;
    }

    if (result.status < 200 || result.status >= 300) {
      throw new Error(`Guarded fetch: HTTP ${result.status}`);
    }
    if (!result.body) {
      throw new Error('Guarded fetch: empty response body');
    }
    return Uint8Array.from(result.body).buffer;
  }
}

/**
 * Resolves both A and AAAA records for `hostname` via `dns.resolve4`/
 * `resolve6` -- confirmed (see this module's top doc comment) to work on
 * Cloudflare Workers, unlike `dns.lookup()`. Either query failing (e.g. no
 * AAAA record at all, the common case) is not itself an error -- only both
 * failing means "unresolvable"; that plain empty-array result is what makes
 * the caller reject the fetch, so no separate error path is needed here.
 */
function resolveAddresses(hostname: string): Promise<LookupAddress[]> {
  const results: LookupAddress[] = [];
  return new Promise((resolve) => {
    let pending = 2;
    const done = () => {
      pending -= 1;
      if (pending === 0) resolve(results);
    };
    dnsResolve4(hostname, (err, addresses) => {
      if (!err) results.push(...addresses.map((address) => ({ address, family: 4 as const })));
      done();
    });
    dnsResolve6(hostname, (err, addresses) => {
      if (!err) results.push(...addresses.map((address) => ({ address, family: 6 as const })));
      done();
    });
  });
}

/**
 * Cloudflare Workers path (see this module's top doc comment for why this
 * differs from `fetchBytesWithGuardsOnNode`): resolves via `dns.resolve4`/
 * `resolve6`, validates every returned address against the exact same
 * `isAddressAllowed` predicate the Node path uses, and only then calls plain
 * `fetch()`. `redirect: 'manual'` so every hop goes back through this same
 * resolve-then-validate step before being followed -- otherwise an open
 * redirect would be a trivial SSRF bypass. This has a real, accepted
 * DNS-rebinding TOCTOU gap that the Node path does not (the address `fetch()`
 * actually connects to is resolved independently, moments after this check);
 * narrower than "no guard at all", not airtight.
 */
async function fetchBytesWithGuardsOnWorkers(
  url: string,
  guards: FetchGuards,
  requestOptions: GuardedRequestOptions
): Promise<ArrayBuffer> {
  const allow = guards.isAddressAllowed ?? isAddressAllowed;
  let currentUrl = url;

  for (let redirectCount = 0; ; redirectCount += 1) {
    const parsed = new URL(currentUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`Unsupported protocol for guarded fetch: ${parsed.protocol}`);
    }

    checkLiteralIpAllowed(parsed.hostname, allow);
    const unbracketed =
      parsed.hostname.startsWith('[') && parsed.hostname.endsWith(']')
        ? parsed.hostname.slice(1, -1)
        : parsed.hostname;
    if (!isIPv4(unbracketed) && !isIPv6(unbracketed)) {
      const resolved = await resolveAddresses(unbracketed);
      const safe = resolved.filter((a) => allow(a.address, a.family as 4 | 6));
      if (safe.length === 0) {
        throw new Error(`SSRF_BLOCKED: no allowed address for host "${unbracketed}"`);
      }
    }

    let response: Response;
    try {
      response = await fetch(parsed.toString(), {
        method: requestOptions.method ?? 'GET',
        headers: requestOptions.headers,
        body: requestOptions.body ? new Uint8Array(requestOptions.body) : undefined,
        redirect: 'manual',
        signal: AbortSignal.timeout(guards.timeoutMs),
      });
    } catch (error) {
      if (error instanceof Error && error.name === 'TimeoutError') {
        throw new Error(`Guarded fetch to ${parsed.hostname} timed out`);
      }
      throw error;
    }

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location) throw new Error(`Guarded fetch: HTTP ${response.status} redirect with no Location header`);
      if (redirectCount >= guards.maxRedirects) throw new Error('Guarded fetch: too many redirects');
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`Guarded fetch: HTTP ${response.status}`);
    }
    if (!response.body) {
      throw new Error('Guarded fetch: empty response body');
    }

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > guards.maxBytes) {
        await reader.cancel();
        throw new Error(`Guarded fetch response exceeded ${guards.maxBytes} byte limit`);
      }
      chunks.push(value);
    }
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return merged.buffer;
  }
}

/** Guarded fetch, dispatched to whichever SSRF-guard implementation actually
 * works on the current runtime -- see this module's top doc comment.
 * `requestOptions` defaults to `{}` (GET, no body, no extra headers) --
 * every pre-existing 2-arg call site keeps behaving identically. */
export async function fetchBytesWithGuards(
  url: string,
  guards: FetchGuards,
  requestOptions: GuardedRequestOptions = {}
): Promise<ArrayBuffer> {
  return isCloudflareWorkers()
    ? fetchBytesWithGuardsOnWorkers(url, guards, requestOptions)
    : fetchBytesWithGuardsOnNode(url, guards, requestOptions);
}
