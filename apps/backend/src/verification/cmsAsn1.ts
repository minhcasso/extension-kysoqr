import forge from 'node-forge';

type ForgeDerOptions = { strict?: boolean; parseAllBytes?: boolean };

/**
 * Parse a CMS/PKCS#7 blob that was read out of a PDF `/Contents` entry.
 *
 * Two things make this different from parsing a plain DER file:
 *
 * - `/Contents` is a fixed-size placeholder, so the CMS is followed by zero
 *   padding. node-forge defaults to `parseAllBytes: true` and rejects that
 *   padding with "Unparsed DER bytes remain after ASN.1 parsing".
 * - Some signers (e.g. Viettel-CA) emit BER indefinite-length CMS (`30 80`),
 *   which ends in its own end-of-content octets. Those cannot be told apart
 *   from padding by stripping trailing NULs, so the padding has to stay and
 *   the parser has to tolerate it.
 *
 * `@types/node-forge` still declares the legacy `strict` boolean parameter, so
 * the options object needs a cast; forge 1.4 accepts it at runtime.
 */
export function parseCmsAsn1(cmsDer: Buffer): forge.asn1.Asn1 {
  const fromDer = forge.asn1.fromDer as unknown as (
    bytes: string,
    options: ForgeDerOptions
  ) => forge.asn1.Asn1;

  return fromDer(cmsDer.toString('binary'), { parseAllBytes: false });
}

/** Parse a PDF-embedded CMS blob into a node-forge PKCS#7 message. */
export function parseCmsMessage(cmsDer: Buffer) {
  return forge.pkcs7.messageFromAsn1(parseCmsAsn1(cmsDer));
}
