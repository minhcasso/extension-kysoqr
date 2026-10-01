import * as asn1js from 'asn1js';
import forge from 'node-forge';
import * as pkijs from 'pkijs';
import { describe, expect, it } from 'vitest';
import { verifySignerInfoSignature } from './signatureVerifier';

function buildSelfSignedCert(): {
  cert: forge.pki.Certificate;
  privateKey: forge.pki.rsa.PrivateKey;
} {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date('2024-01-01T00:00:00Z');
  cert.validity.notAfter = new Date('2030-01-01T00:00:00Z');
  const attrs = [{ name: 'commonName', value: 'Test Signer' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert, privateKey: keys.privateKey };
}

/** Build a real, correctly-signed detached CMS/PKCS#7 over `content`, using
 * the given digest algorithm OID for both the messageDigest and the actual
 * RSA signature over the signed attributes. */
function buildSignedCmsAsn1(
  content: Buffer,
  cert: forge.pki.Certificate,
  privateKey: forge.pki.rsa.PrivateKey,
  digestAlgorithmOid: string
): forge.asn1.Asn1 {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const p7 = forge.pkcs7.createSignedData() as any;
  p7.content = forge.util.createBuffer(content.toString('binary'));
  p7.addCertificate(cert);
  p7.addSigner({
    key: privateKey,
    certificate: cert,
    digestAlgorithm: digestAlgorithmOid,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() },
    ],
  });
  p7.sign({ detached: true });
  return p7.toAsn1();
}

function toDerBuffer(asn1: forge.asn1.Asn1): Buffer {
  return Buffer.from(forge.asn1.toDer(asn1).getBytes(), 'binary');
}

/** Locate the SignerInfos SET within a SignedData ContentInfo tree -- the
 * last top-level UNIVERSAL/SET child of SignedData (digestAlgorithms is the
 * only other UNIVERSAL/SET, and always comes first). */
function findSignerInfoNode(contentInfoAsn1: forge.asn1.Asn1): forge.asn1.Asn1 {
  const signedData = (contentInfoAsn1.value as forge.asn1.Asn1[])[1]!.value as forge.asn1.Asn1[];
  const signedDataInner = (signedData[0] as forge.asn1.Asn1).value as forge.asn1.Asn1[];
  const sets = signedDataInner.filter(
    (n) => n.tagClass === forge.asn1.Class.UNIVERSAL && n.type === forge.asn1.Type.SET
  );
  const signerInfos = sets[sets.length - 1]!;
  return (signerInfos.value as forge.asn1.Asn1[])[0]!;
}

/** Build a real, correctly-signed detached CMS/PKCS#7 over `content` with NO
 * `authenticatedAttributes` at all (RFC 5652 §5.4's optional-signedAttrs
 * variant) -- forge supports this directly via an empty attributes array
 * (see node_modules/node-forge/lib/pkcs7.js: "no custom attributes to
 * digest; use content message digest"), which is exactly the real-world
 * shape confirmed against a live, NEAC-valid FastCA-issued signature. */
function buildSignedCmsAsn1NoSignedAttrs(
  content: Buffer,
  cert: forge.pki.Certificate,
  privateKey: forge.pki.rsa.PrivateKey,
  digestAlgorithmOid: string
): forge.asn1.Asn1 {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const p7 = forge.pkcs7.createSignedData() as any;
  p7.content = forge.util.createBuffer(content.toString('binary'));
  p7.addCertificate(cert);
  p7.addSigner({
    key: privateKey,
    certificate: cert,
    digestAlgorithm: digestAlgorithmOid,
    authenticatedAttributes: [],
  });
  p7.sign({ detached: true });
  return p7.toAsn1();
}

describe('verifySignerInfoSignature', () => {
  const content = Buffer.from('the exact bytes that were signed');
  // Unused by the signedAttrs-present branch (only the no-signedAttrs branch
  // reads pdfBytes/byteRange) -- passed anyway since the parameter is
  // required, not optional, for real callers.
  const unusedByteRange: [number, number, number, number] = [0, content.length, content.length, 0];

  it('accepts a real, correctly-signed CMS (SHA-256)', () => {
    const { cert, privateKey } = buildSelfSignedCert();
    const asn1 = buildSignedCmsAsn1(content, cert, privateKey, forge.pki.oids.sha256!);
    const result = verifySignerInfoSignature(toDerBuffer(asn1), content, unusedByteRange);
    expect(result.ok).toBe(true);
    expect(result.leafCertificate?.serialNumber).toBe(cert.serialNumber);
  });

  it('rejects a forged CMS with a correct messageDigest but a tampered signature', () => {
    // This is the concrete regression test for the original vulnerability:
    // the legacy verifier only ever compared messageDigest against the PDF
    // content and never checked this signature field at all.
    const { cert, privateKey } = buildSelfSignedCert();
    const asn1 = buildSignedCmsAsn1(content, cert, privateKey, forge.pki.oids.sha256!);
    const signerInfo = findSignerInfoNode(asn1);
    const children = signerInfo.value as forge.asn1.Asn1[];
    const signatureNode = children.find(
      (n) => n.tagClass === forge.asn1.Class.UNIVERSAL && n.type === forge.asn1.Type.OCTETSTRING
    )!;
    const original = signatureNode.value as string;
    // Flip one byte in the middle of the signature -- messageDigest and every
    // other field stay exactly as a legitimate signer produced them.
    const mid = Math.floor(original.length / 2);
    const corrupted =
      original.slice(0, mid) +
      String.fromCharCode(original.charCodeAt(mid) ^ 0xff) +
      original.slice(mid + 1);
    signatureNode.value = corrupted;

    // A single flipped byte in an RSA-signed blob almost always breaks the
    // PKCS#1v1.5 padding itself (RSA's avalanche effect), so this can
    // legitimately surface as either a clean false from forge's verify() or
    // an unpad exception -- both are the same security property: rejected.
    const result = verifySignerInfoSignature(toDerBuffer(asn1), content, unusedByteRange);
    expect(result.ok).toBe(false);
    expect(result).toMatchObject({
      reason: expect.stringMatching(/^SIGNATURE_VERIFICATION_(FAILED|ERROR)$/),
    });
  });

  it('rejects a signature using a weak digest algorithm (SHA-1) when signedAttrs IS present, even before attempting the RSA check', () => {
    const { cert, privateKey } = buildSelfSignedCert();
    const asn1 = buildSignedCmsAsn1(content, cert, privateKey, forge.pki.oids.sha1!);
    const result = verifySignerInfoSignature(toDerBuffer(asn1), content, unusedByteRange);
    expect(result).toEqual({ ok: false, reason: 'WEAK_OR_UNSUPPORTED_DIGEST_ALGORITHM' });
  });

  it('accepts a real, correctly-signed CMS with NO signedAttrs (SHA-256), verifying directly against the content digest', () => {
    const { cert, privateKey } = buildSelfSignedCert();
    const asn1 = buildSignedCmsAsn1NoSignedAttrs(content, cert, privateKey, forge.pki.oids.sha256!);
    const byteRange: [number, number, number, number] = [0, content.length, content.length, 0];
    const result = verifySignerInfoSignature(toDerBuffer(asn1), content, byteRange);
    expect(result.ok).toBe(true);
    expect(result.leafCertificate?.serialNumber).toBe(cert.serialNumber);
  });

  it('accepts a real, correctly-signed CMS with NO signedAttrs using SHA-1 -- the exact real-world FastCA/NEAC-valid shape this fix targets', () => {
    const { cert, privateKey } = buildSelfSignedCert();
    const asn1 = buildSignedCmsAsn1NoSignedAttrs(content, cert, privateKey, forge.pki.oids.sha1!);
    const byteRange: [number, number, number, number] = [0, content.length, content.length, 0];
    const result = verifySignerInfoSignature(toDerBuffer(asn1), content, byteRange);
    expect(result.ok).toBe(true);
  });

  it('rejects a NO-signedAttrs CMS whose content was tampered with after signing', () => {
    const { cert, privateKey } = buildSelfSignedCert();
    const asn1 = buildSignedCmsAsn1NoSignedAttrs(content, cert, privateKey, forge.pki.oids.sha256!);
    const tamperedContent = Buffer.from('THE EXACT bytes that were signed'); // case-flipped
    const byteRange: [number, number, number, number] = [
      0,
      tamperedContent.length,
      tamperedContent.length,
      0,
    ];
    const result = verifySignerInfoSignature(toDerBuffer(asn1), tamperedContent, byteRange);
    expect(result.ok).toBe(false);
    expect(result).toMatchObject({ reason: 'SIGNATURE_VERIFICATION_FAILED' });
  });

  it('rejects a NO-signedAttrs CMS using an unsupported digest algorithm (MD5)', () => {
    const { cert, privateKey } = buildSelfSignedCert();
    const asn1 = buildSignedCmsAsn1NoSignedAttrs(content, cert, privateKey, forge.pki.oids.md5!);
    const byteRange: [number, number, number, number] = [0, content.length, content.length, 0];
    const result = verifySignerInfoSignature(toDerBuffer(asn1), content, byteRange);
    expect(result).toEqual({ ok: false, reason: 'WEAK_OR_UNSUPPORTED_DIGEST_ALGORITHM' });
  });
});

/** A real, correctly-signed detached CMS whose signer holds an ECDSA P-256
 * key -- built with pkijs/WebCrypto, since node-forge can't create (or even
 * parse) non-RSA certificates. */
async function buildEcdsaSignedCmsDer(content: Buffer): Promise<Buffer> {
  const crypto = pkijs.getCrypto(true);
  const keys = (await crypto.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;

  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 7 });
  const name = new pkijs.AttributeTypeAndValue({
    type: '2.5.4.3',
    value: new asn1js.BmpString({ value: 'ECDSA Signer' }),
  });
  cert.issuer.typesAndValues.push(name);
  cert.subject.typesAndValues.push(name);
  cert.notBefore.value = new Date('2024-01-01T00:00:00Z');
  cert.notAfter.value = new Date('2030-01-01T00:00:00Z');
  await cert.subjectPublicKeyInfo.importKey(keys.publicKey);
  await cert.sign(keys.privateKey, 'SHA-256');

  const signedData = new pkijs.SignedData({
    version: 1,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: '1.2.840.113549.1.7.1' }),
    signerInfos: [
      new pkijs.SignerInfo({
        version: 1,
        sid: new pkijs.IssuerAndSerialNumber({
          issuer: cert.issuer,
          serialNumber: cert.serialNumber,
        }),
      }),
    ],
    certificates: [cert],
  });
  await signedData.sign(keys.privateKey, 0, 'SHA-256', new Uint8Array(content).buffer);

  const contentInfo = new pkijs.ContentInfo({
    contentType: '1.2.840.113549.1.7.2',
    content: signedData.toSchema(true),
  });
  return Buffer.from(contentInfo.toSchema().toBER(false));
}

describe('verifySignerInfoSignature — non-RSA signer keys', () => {
  it('reports an ECDSA signer as an unsupported key algorithm, not as a verification error', async () => {
    const content = Buffer.from('ECDSA-signed PDF bytes', 'utf8');
    const cmsDer = await buildEcdsaSignedCmsDer(content);
    const byteRange: [number, number, number, number] = [0, content.length, content.length, 0];

    expect(verifySignerInfoSignature(cmsDer, content, byteRange)).toEqual({
      ok: false,
      reason: 'UNSUPPORTED_KEY_ALGORITHM',
      keyAlgorithm: 'ECDSA',
    });
  });
});
