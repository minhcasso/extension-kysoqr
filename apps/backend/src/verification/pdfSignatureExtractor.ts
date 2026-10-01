import { findByteRanges } from './findByteRanges';

export type PdfSignatureExtractionError =
  | { kind: 'NO_SIGNATURE_FIELD_FOUND' }
  | { kind: 'MALFORMED_BYTE_RANGE'; detail?: string }
  | { kind: 'MALFORMED_CONTENTS'; detail?: string }
  | { kind: 'MALFORMED_SIGNATURE_DICTIONARY'; detail?: string };

export type ExtractCmsSuccess = {
  cmsDer: Buffer;
  byteRange: [number, number, number, number];
  subFilter: string;
  /**
   * False for a SubFilter this pipeline can't verify (e.g. an `ETSI.RFC3161`
   * PAdES-LTA document timestamp). Such entries are reported one by one as
   * unsupported rather than failing the whole document, so the ordinary
   * signatures next to them still get verified.
   */
  supported: boolean;
  /**
   * ISO timestamp from the signature dictionary's `/M` entry, when present.
   *
   * CAdES signatures often carry no CMS `signingTime` attribute, so this is
   * the only claimed signing time available for them.
   */
  dictSigningTime?: string | undefined;
};

export type ExtractAllCmsResult =
  { ok: true; values: ExtractCmsSuccess[] } | { ok: false; error: PdfSignatureExtractionError };

const SUPPORTED_SUBFILTERS = new Set(['adbe.pkcs7.detached', 'etsi.cades.detached']);

function parseByteRange(range: string[] | undefined): [number, number, number, number] | null {
  if (!Array.isArray(range) || range.length !== 4) {
    return null;
  }

  const parsed = range.map((v) => Number.parseInt(v, 10));
  if (parsed.some((v) => !Number.isFinite(v) || v < 0)) {
    return null;
  }

  const [a, b, c, d] = parsed as [number, number, number, number];
  return [a, b, c, d];
}

type ObjectScope = { start: number; end: number };

/**
 * Locate the boundaries of the indirect object that holds the signature
 * dictionary containing `byteRangePosition`.
 *
 * Signature dictionaries are always indirect objects (`N G obj … endobj`) and
 * PDF dictionary keys have no required order, so we must search the whole
 * object rather than assuming `/SubFilter` and `/Contents` sit on a particular
 * side of `/ByteRange`.
 */
function findSignatureObjectScope(pdfBytes: Buffer, byteRangePosition: number): ObjectScope {
  const objToken = Buffer.from('obj', 'ascii');
  const endObjToken = Buffer.from('endobj', 'ascii');

  // Walking backwards, the nearest `obj` is this object's own header: anything
  // between it and /ByteRange is dictionary content (a hex /Contents string
  // cannot contain the letters o/b/j).
  const objPos = pdfBytes.lastIndexOf(objToken, byteRangePosition);
  const endObjPos = pdfBytes.indexOf(endObjToken, byteRangePosition);

  return {
    start: objPos === -1 ? 0 : objPos + objToken.length,
    end: endObjPos === -1 ? pdfBytes.length : endObjPos,
  };
}

function extractSubFilter(pdfBytes: Buffer, scope: ObjectScope): string | null {
  const token = Buffer.from('/SubFilter', 'ascii');
  const pos = pdfBytes.indexOf(token, scope.start);
  if (pos === -1 || pos >= scope.end) return null;

  const window = pdfBytes.subarray(pos, Math.min(pos + 96, scope.end)).toString('ascii');
  const match = /\/SubFilter\s*\/([^\s/>\r\n]+)/.exec(window);
  return match?.[1] ?? null;
}

/**
 * Trim the reserved-space padding that follows the CMS blob inside /Contents.
 *
 * The signature placeholder is zero-filled, but a BER indefinite-length CMS
 * ends with its own 0x00 0x00 end-of-content octets, so blindly stripping
 * trailing NULs would corrupt it. Prefer cutting at the length declared in the
 * outer ASN.1 header and only fall back to NUL stripping when that length is
 * indefinite or unreadable.
 */
function trimCmsPadding(cmsDer: Buffer): Buffer {
  if (cmsDer.length >= 2) {
    const lengthByte = cmsDer[1] as number;

    if (lengthByte < 0x80) {
      const total = 2 + lengthByte;
      if (total <= cmsDer.length) return cmsDer.subarray(0, total);
    } else if (lengthByte > 0x80) {
      const lengthBytes = lengthByte & 0x7f;
      if (lengthBytes <= 4 && cmsDer.length >= 2 + lengthBytes) {
        let declared = 0;
        for (let i = 0; i < lengthBytes; i += 1) {
          declared = declared * 256 + (cmsDer[2 + i] as number);
        }
        const total = 2 + lengthBytes + declared;
        if (total <= cmsDer.length) return cmsDer.subarray(0, total);
      }
    } else {
      // Indefinite length (0x80): the parser stops at the end-of-content
      // octets on its own, so leave any trailing padding in place.
      return cmsDer;
    }
  }

  let trimmedLength = cmsDer.length;
  while (trimmedLength > 0 && cmsDer[trimmedLength - 1] === 0x00) {
    trimmedLength -= 1;
  }
  return trimmedLength === cmsDer.length ? cmsDer : cmsDer.subarray(0, trimmedLength);
}

/**
 * Read the claimed signing time from the signature dictionary's `/M` entry.
 *
 * PDF date strings look like `D:20260420164330+07'00'`. CAdES signatures
 * frequently omit the CMS `signingTime` attribute, leaving this as the only
 * signing time in the document.
 */
function extractDictSigningTime(pdfBytes: Buffer, scope: ObjectScope): string | undefined {
  const dict = pdfBytes.subarray(scope.start, scope.end).toString('latin1');
  const match =
    /\/M\s*\(\s*D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?([+\-Z])?(\d{2})?'?(\d{2})?/.exec(
      dict
    );
  if (!match) return undefined;

  const [, year, month, day, hour, minute, second, sign, tzHour, tzMinute] = match;

  const offset = !sign || sign === 'Z' ? 'Z' : `${sign}${tzHour ?? '00'}:${tzMinute ?? '00'}`;

  const parsed = new Date(`${year}-${month}-${day}T${hour}:${minute}:${second ?? '00'}${offset}`);

  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function extractContents(pdfBytes: Buffer, scope: ObjectScope): { cmsDer: Buffer } | null {
  const token = Buffer.from('/Contents', 'ascii');

  const pos = pdfBytes.indexOf(token, scope.start);
  if (pos === -1 || pos >= scope.end) return null;

  let start = pos;
  while (start < scope.end && pdfBytes[start] !== 0x3c) {
    // 0x3c = '<'
    start += 1;
  }
  if (start >= scope.end || pdfBytes[start] !== 0x3c) return null;

  const end = pdfBytes.indexOf(0x3e, start + 1); // 0x3e = '>'
  if (end === -1 || end >= scope.end) return null;

  const hexSlice = pdfBytes.subarray(start + 1, end).toString('ascii');
  const hex = hexSlice.replace(/[^0-9A-Fa-f]/g, '');
  if (!hex || hex.length % 2 !== 0) {
    return null;
  }

  return { cmsDer: trimCmsPadding(Buffer.from(hex, 'hex')) };
}

/**
 * Best-effort extraction of CMS (PKCS#7) signature(s) from a signed PDF.
 *
 * - Locates every signed /ByteRange occurrence.
 * - Reads associated /SubFilter and /Contents.
 * - Supports CMS-based signatures (adbe.pkcs7.detached, ETSI.CAdES.detached);
 *   any other SubFilter is still extracted, flagged `supported: false`.
 * - Returns a trimmed DER buffer (without trailing null padding) per signature.
 */
export function extractAllCmsFromSignedPdf(pdfBytes: Buffer): ExtractAllCmsResult {
  const byteRangeMatches = findByteRanges(pdfBytes);
  const signedMatches = byteRangeMatches.filter(
    ({ range }) => range.length === 4 && range.every((value) => /^\d+$/.test(value))
  );

  if (signedMatches.length === 0) {
    return { ok: false, error: { kind: 'NO_SIGNATURE_FIELD_FOUND' } };
  }

  const values: ExtractCmsSuccess[] = [];
  let searchOffset = 0;

  for (const { range, rangeString } of signedMatches) {
    const byteRange = parseByteRange(range);
    if (!byteRange) {
      return {
        ok: false,
        error: { kind: 'MALFORMED_BYTE_RANGE', detail: 'Unable to parse /ByteRange array' },
      };
    }

    const byteRangeBuf = Buffer.from(rangeString, 'ascii');
    const byteRangePosition = pdfBytes.indexOf(byteRangeBuf, searchOffset);
    if (byteRangePosition === -1) {
      return {
        ok: false,
        error: {
          kind: 'MALFORMED_BYTE_RANGE',
          detail: 'Could not locate /ByteRange string in PDF buffer',
        },
      };
    }
    searchOffset = byteRangePosition + byteRangeBuf.length;

    const scope = findSignatureObjectScope(pdfBytes, byteRangePosition);
    const subFilterRaw = extractSubFilter(pdfBytes, scope);
    if (!subFilterRaw) {
      return {
        ok: false,
        error: {
          kind: 'MALFORMED_SIGNATURE_DICTIONARY',
          detail: 'Missing or malformed /SubFilter',
        },
      };
    }
    const contents = extractContents(pdfBytes, scope);
    if (!contents) {
      return {
        ok: false,
        error: { kind: 'MALFORMED_CONTENTS', detail: 'Unable to parse /Contents hex string' },
      };
    }

    values.push({
      cmsDer: contents.cmsDer,
      byteRange,
      subFilter: subFilterRaw,
      supported: SUPPORTED_SUBFILTERS.has(subFilterRaw.toLowerCase()),
      dictSigningTime: extractDictSigningTime(pdfBytes, scope),
    });
  }

  // Incremental PDF signatures cover progressively larger revisions. Sorting
  // by the end of the covered revision makes the API/UI order deterministic.
  values.sort((left, right) => {
    const leftEnd = left.byteRange[2] + left.byteRange[3];
    const rightEnd = right.byteRange[2] + right.byteRange[3];
    return leftEnd - rightEnd;
  });

  return { ok: true, values };
}

/**
 * PDF Shadow Attack guard: the LAST (most recent) signature's /ByteRange must
 * cover the entire file — `byteRange[2] + byteRange[3] === totalFileLength`.
 *
 * Incremental-update-based "Shadow Attack" research shows a file can carry
 * extra bytes appended after the last signed revision. A compliant viewer
 * applies those bytes as a content update (e.g. a hidden object becoming
 * visible, or annotation content changing) while the digest of the OLDER,
 * signed range still matches — so the signature reads as valid even though
 * what the viewer actually renders was never signed. Any unaccounted trailing
 * bytes on the newest signature must be treated as tampering.
 */
export function isLastSignatureCoveringWholeFile(
  values: ExtractCmsSuccess[],
  totalFileLength: number
): boolean {
  const last = values[values.length - 1];
  if (!last) return true;
  const [, , c, d] = last.byteRange;
  return c + d === totalFileLength;
}
