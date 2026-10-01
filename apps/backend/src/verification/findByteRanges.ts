export interface ByteRangeMatch {
  /** Raw `[a, b, c, d]` tokens as they appear in the PDF, not yet validated as numeric. */
  range: string[];
  /** The exact `/ByteRange [...]` substring, used to locate the enclosing signature dictionary. */
  rangeString: string;
}

/**
 * Locate every `/ByteRange [...]` occurrence in a PDF buffer.
 *
 * Adapted from `@signpdf/utils`'s `findByteRange` — that package also tracks an
 * unsigned placeholder range (`/ByteRange [0 ********** ********** **********]`)
 * for building a new signature, which this app never does (CAS renders and
 * signs the PDF; we only ever verify an already-signed one), so that part is
 * dropped here.
 */
export function findByteRanges(pdf: Buffer): ByteRangeMatch[] {
  const matches: ByteRangeMatch[] = [];
  let offset = 0;

  for (;;) {
    const position = pdf.indexOf('/ByteRange', offset);
    if (position === -1) break;

    const rangeStart = pdf.indexOf('[', position);
    const rangeEnd = rangeStart === -1 ? -1 : pdf.indexOf(']', rangeStart);
    if (rangeStart === -1 || rangeEnd === -1) break;

    const rangeString = pdf.subarray(position, rangeEnd + 1).toString('ascii');
    const range = pdf
      .subarray(rangeStart + 1, rangeEnd)
      .toString('ascii')
      .split(' ')
      .map((token) => token.trim())
      .filter((token) => token !== '');

    matches.push({ range, rangeString });
    offset = rangeEnd;
  }

  return matches;
}
