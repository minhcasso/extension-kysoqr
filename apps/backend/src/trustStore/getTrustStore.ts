import type { TrustStore } from './TrustStore';
import { BundledRootStore } from './BundledRootStore';

let cached: TrustStore | undefined;

/** The trust store implementation for this deployment. Like CAS itself, there
 * is only one implementation: Root CA certificates are public data, bundled
 * directly in the repo (see `roots/README.md`) -- no mode switch needed. */
export function getTrustStore(): TrustStore {
  if (!cached) cached = new BundledRootStore();
  return cached;
}
