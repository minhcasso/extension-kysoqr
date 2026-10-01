import forge from 'node-forge';
import { fixForgeString } from './fixForgeString';

// Map selected attribute OIDs to human-readable names when forge
// does not populate `name` / `shortName` for them.
const ATTRIBUTE_OID_LABELS: Record<string, string> = {
  // 0.9.2342.19200300.100.1.1 – userID (X.500, often used for tax/ID numbers)
  '0.9.2342.19200300.100.1.1': 'userID',
  // 1.2.840.113549.1.9.1 – emailAddress (PKCS #9, deprecated but still widely used)
  '1.2.840.113549.1.9.1': 'emailAddress',
  // 2.5.4.20 – telephoneNumber (we support labeling but will hide its value from API responses)
  '2.5.4.20': 'telephoneNumber',
};

export function getAttributeLabel(attr: forge.pki.CertificateField): string {
  const oidLabel = attr.type ? ATTRIBUTE_OID_LABELS[attr.type] : undefined;
  return (
    attr.shortName ||
    attr.name ||
    oidLabel ||
    // Fallback to raw OID so we never end up with "undefined=<value>"
    (attr.type ?? 'UNKNOWN')
  );
}

// Central place to decide which certificate attributes must never be exposed
// to API consumers (e.g. telephone numbers, email).
export function shouldHideAttribute(attr: forge.pki.CertificateField): boolean {
  const label = getAttributeLabel(attr);
  const type = attr.type;
  return (
    label === 'telephoneNumber' ||
    label === 'emailAddress' ||
    type === '2.5.4.20' ||
    type === '1.2.840.113549.1.9.1' ||
    attr.name === 'telephoneNumber' ||
    attr.shortName === 'telephoneNumber' ||
    attr.name === 'emailAddress' ||
    attr.shortName === 'emailAddress'
  );
}

export interface CertificateInfo {
  subjectCN: string | undefined;
  subjectFull: string;
  issuerCN: string | undefined;
  issuerFull: string;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
}

function formatDn(attrs: forge.pki.CertificateField[]): string {
  return attrs
    .map((a) => {
      const value = typeof a.value === 'string' ? fixForgeString(a.value) : String(a.value);
      const label = getAttributeLabel(a);
      // userID's own value is already self-describing (e.g. "MST:..." for a
      // business, "CCCD:..." for an individual) -- showing it as
      // "userID=MST:..." just repeats that, so show the bare value instead.
      return label === 'userID' ? value : `${label}=${value}`;
    })
    .join(', ');
}

/** Extract the certificate details the verification response needs, applying
 * the same privacy filter as the chain builder (never expose e.g. phone/email
 * subject attributes). */
export function parseCertificateInfo(cert: forge.pki.Certificate): CertificateInfo {
  const subjectAttrs = (cert.subject.attributes || []).filter((a) => !shouldHideAttribute(a));
  const issuerAttrs = (cert.issuer.attributes || []).filter((a) => !shouldHideAttribute(a));

  const findCN = (attrs: forge.pki.CertificateField[]) =>
    attrs.find((a) => a.shortName === 'CN' || a.name === 'commonName');

  const subjectCNValue = findCN(subjectAttrs)?.value;
  const subjectCN = typeof subjectCNValue === 'string' ? fixForgeString(subjectCNValue) : undefined;

  const issuerCNValue = findCN(issuerAttrs)?.value;
  const issuerCN = typeof issuerCNValue === 'string' ? fixForgeString(issuerCNValue) : undefined;

  return {
    subjectCN,
    subjectFull: formatDn(subjectAttrs),
    issuerCN,
    issuerFull: formatDn(issuerAttrs),
    serialNumber: cert.serialNumber || '',
    validFrom: cert.validity.notBefore,
    validTo: cert.validity.notAfter,
  };
}
