/** node-forge decodes some non-ASCII certificate string fields (e.g.
 * PrintableString/UTF8String subject attributes) as a raw byte-per-char
 * "binary string" rather than proper UTF-8 — re-interpret it correctly. */
export function fixForgeString(str: string): string {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    bytes.push(str.charCodeAt(i) & 0xff);
  }
  return Buffer.from(bytes).toString('utf8');
}
