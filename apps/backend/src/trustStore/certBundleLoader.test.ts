import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadCertsFromBase64Manifest } from './certBundleLoader';

const ROOTS_DIR = fileURLToPath(new URL('./roots', import.meta.url));

describe('loadCertsFromBase64Manifest', () => {
  it('decodes a real bundled .p7b file re-encoded as base64', () => {
    const raw = readFileSync(path.join(ROOTS_DIR, 'vnrca256.p7b'));
    const certs = loadCertsFromBase64Manifest([{ filename: 'vnrca256.p7b', base64: raw.toString('base64') }]);
    expect(certs).toHaveLength(1);
  });

  it('skips a malformed entry without dropping the good ones alongside it', () => {
    const raw = readFileSync(path.join(ROOTS_DIR, 'vnrca256.p7b'));
    const certs = loadCertsFromBase64Manifest([
      { filename: 'garbage.p7b', base64: Buffer.from('not a cert').toString('base64') },
      { filename: 'vnrca256.p7b', base64: raw.toString('base64') },
    ]);
    expect(certs).toHaveLength(1);
  });

  it('returns an empty array for an empty manifest', () => {
    expect(loadCertsFromBase64Manifest([])).toEqual([]);
  });
});
