import forge from 'node-forge';
import { describe, expect, it } from 'vitest';
import type { TrustStore } from '../trustStore/TrustStore';
import { verifyPdfSignatures } from './verifyPdfSignatures';

/**
 * Builds small but structurally real signed PDFs (signature dictionaries with
 * a /ByteRange that excludes their own /Contents, as a signer would write
 * them) to exercise document-level behaviour: several signatures per file,
 * incremental revisions and unsupported SubFilters.
 */

const CONTENTS_HEX_LENGTH = 8192;
const RANGE_PLACEHOLDER = '[0000000000 0000000000 0000000000 0000000000]';

function buildSelfSignedCert() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date('2024-01-01T00:00:00Z');
  cert.validity.notAfter = new Date('2030-01-01T00:00:00Z');
  const attrs = [{ name: 'commonName', value: 'PDF Test Signer' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert, privateKey: keys.privateKey };
}

function signatureObject(objectNumber: number, subFilter: string): string {
  return (
    `${objectNumber} 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /${subFilter} ` +
    `/ByteRange ${RANGE_PLACEHOLDER} /Contents <${'0'.repeat(CONTENTS_HEX_LENGTH)}> >>\nendobj\n`
  );
}

/** Fills in the /ByteRange of the signature dictionary that starts at
 * `objectOffset` so it covers the whole buffer except that dictionary's own
 * /Contents hex string; returns the covered range. */
function fillByteRange(pdf: Buffer, objectOffset: number): [number, number, number, number] {
  const contentsOpen = pdf.indexOf('<', pdf.indexOf('/Contents', objectOffset));
  const contentsClose = pdf.indexOf('>', contentsOpen) + 1;
  const range: [number, number, number, number] = [
    0,
    contentsOpen,
    contentsClose,
    pdf.length - contentsClose,
  ];
  const rangeText = `[${range.map((n) => String(n).padStart(10, '0')).join(' ')}]`;
  pdf.write(rangeText, pdf.indexOf(RANGE_PLACEHOLDER, objectOffset), 'latin1');
  return range;
}

function writeContents(pdf: Buffer, objectOffset: number, der: Buffer): void {
  const contentsOpen = pdf.indexOf('<', pdf.indexOf('/Contents', objectOffset));
  pdf.write(der.toString('hex'), contentsOpen + 1, 'latin1');
}

function signDetached(
  signedBytes: Buffer,
  cert: forge.pki.Certificate,
  privateKey: forge.pki.rsa.PrivateKey
): Buffer {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const p7 = forge.pkcs7.createSignedData() as any;
  p7.content = forge.util.createBuffer(signedBytes.toString('binary'));
  p7.addCertificate(cert);
  p7.addSigner({
    key: privateKey,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() },
    ],
  });
  p7.sign({ detached: true });
  return Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), 'binary');
}

/**
 * Revision 1: a normal RSA signature (adbe.pkcs7.detached).
 * Revision 2 (incremental update): a PAdES-LTA document timestamp
 * (ETSI.RFC3161) covering the whole file, as signing tools append it.
 */
function buildPdfWithDocumentTimestamp(cert: forge.pki.Certificate, privateKey: forge.pki.rsa.PrivateKey) {
  const header = '%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n';
  const revision1 = Buffer.from(`${header}${signatureObject(2, 'adbe.pkcs7.detached')}%%EOF\n`, 'latin1');
  const sig1Offset = header.length;
  const [a, b, c, d] = fillByteRange(revision1, sig1Offset);
  const signed = Buffer.concat([revision1.subarray(a, a + b), revision1.subarray(c, c + d)]);
  writeContents(revision1, sig1Offset, signDetached(signed, cert, privateKey));

  const revision2 = Buffer.from(`${signatureObject(3, 'ETSI.RFC3161')}%%EOF\n`, 'latin1');
  const pdf = Buffer.concat([revision1, revision2]);
  fillByteRange(pdf, revision1.length);
  // The timestamp token itself is never parsed (unsupported SubFilter).
  writeContents(pdf, revision1.length, Buffer.from('3003020100', 'hex'));
  return pdf;
}

describe('verifyPdfSignatures — unsupported SubFilters', () => {
  const { cert, privateKey } = buildSelfSignedCert();
  const certPem = forge.pki.certificateToPem(cert);
  const trustStore: TrustStore = {
    isConfigured: () => true,
    isTrustedRoot: (pem) => pem.trim() === certPem.trim(),
    getTrustedRootPems: () => [certPem],
  };

  it('still verifies the ordinary signature when the file also carries a document timestamp', async () => {
    const results = await verifyPdfSignatures(buildPdfWithDocumentTimestamp(cert, privateKey), trustStore);

    expect(results).toHaveLength(2);
    expect(results[0]!.status).toBe('SIGNED_VALID');
    expect(results[1]!.status).toBe('UNSUPPORTED_SUBFILTER');
    expect(results[1]!.message).toMatch(/Document timestamp/);
  });

  it('keeps the shadow-attack guard when bytes are appended after an unsupported last entry', async () => {
    const pdf = Buffer.concat([
      buildPdfWithDocumentTimestamp(cert, privateKey),
      Buffer.from('4 0 obj\n<< /Injected true >>\nendobj\n', 'latin1'),
    ]);
    const results = await verifyPdfSignatures(pdf, trustStore);

    expect(results[0]!.status).toBe('CONTENT_DIGEST_MISMATCH');
    expect(results[1]!.status).toBe('UNSUPPORTED_SUBFILTER');
  });
});
