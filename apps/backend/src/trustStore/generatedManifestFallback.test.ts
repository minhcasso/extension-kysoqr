import { afterEach, describe, expect, it, vi } from 'vitest';

/**
 * Proves the actual Cloudflare Workers fix: simulates "no real filesystem
 * available" by stubbing only `loadCertsFromDirectory` (the fs-dependent
 * half of certBundleLoader) to always return `[]`, while keeping the real
 * `loadCertsFromBase64Manifest` decoder untouched. If the store still works
 * under this condition, the build-time-generated manifest alone is
 * sufficient -- exactly the situation on Cloudflare Workers, which has no
 * real filesystem at runtime.
 */
vi.mock('./certBundleLoader', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./certBundleLoader')>();
  return { ...actual, loadCertsFromDirectory: () => [] };
});

const { BundledRootStore, resetBundledRootStoreCacheForTests } = await import('./BundledRootStore');

afterEach(() => {
  resetBundledRootStoreCacheForTests();
});

describe('generated manifest fallback (simulated Cloudflare Workers: no real fs)', () => {
  it('BundledRootStore is still configured from the generated manifest alone', () => {
    expect(new BundledRootStore().isConfigured()).toBe(true);
  });
});
