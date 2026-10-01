import forge from 'node-forge';

function parseCmsSigningTimeValue(rawValue: unknown): string | undefined {
  if (rawValue instanceof Date) {
    return rawValue.toISOString();
  }

  if (typeof rawValue !== 'string' || !rawValue) {
    return undefined;
  }

  const utcMatch = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(rawValue);
  if (utcMatch) {
    const yearTwoDigits = Number(utcMatch[1]);
    const year = yearTwoDigits >= 50 ? 1900 + yearTwoDigits : 2000 + yearTwoDigits;
    const [, , month, day, hour, minute, second] = utcMatch;
    return new Date(`${year}-${month}-${day}T${hour}:${minute}:${second}Z`).toISOString();
  }

  const generalizedMatch = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(rawValue);
  if (generalizedMatch) {
    const [, year, month, day, hour, minute, second] = generalizedMatch;
    return new Date(`${year}-${month}-${day}T${hour}:${minute}:${second}Z`).toISOString();
  }

  const parsed = new Date(rawValue);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function extractSigningTimeFromAttributes(attrs: unknown): string | undefined {
  if (!Array.isArray(attrs)) return undefined;

  for (const attr of attrs) {
    if (!attr || typeof attr !== 'object') continue;

    const attrValue = attr as {
      tagClass?: number;
      type?: number;
      value?: Array<{ value?: unknown }>;
    };

    if (
      attrValue.tagClass !== forge.asn1.Class.UNIVERSAL ||
      attrValue.type !== forge.asn1.Type.SEQUENCE ||
      !Array.isArray(attrValue.value) ||
      attrValue.value.length < 2
    ) {
      continue;
    }

    const oidNode = attrValue.value[0] as unknown as forge.asn1.Asn1;
    const valuesNode = attrValue.value[1] as unknown as forge.asn1.Asn1;

    if (!oidNode || oidNode.type !== forge.asn1.Type.OID || typeof oidNode.value !== 'string') {
      continue;
    }

    let oid: string;
    try {
      oid = forge.asn1.derToOid(oidNode.value);
    } catch {
      continue;
    }

    if (oid !== forge.pki.oids.signingTime) continue;
    if (!valuesNode || !Array.isArray(valuesNode.value) || valuesNode.value.length === 0)
      return undefined;

    return parseCmsSigningTimeValue(valuesNode.value[0]?.value);
  }

  return undefined;
}

/** Best-effort extraction of the CMS `signingTime` authenticated attribute,
 * when the signer included one. CAdES signatures frequently omit it -- the
 * signature dictionary's `/M` entry is the fallback (see
 * `pdfSignatureExtractor.ts`'s `dictSigningTime`). */
export function extractSigningTimeFromCms(cmsMessage: unknown): string | undefined {
  try {
    const rawCapture = (cmsMessage as { rawCapture?: { signerInfos?: unknown[] } })?.rawCapture;
    const signerInfo = rawCapture?.signerInfos?.[0] as { value?: unknown[] } | undefined;
    if (!signerInfo) return undefined;

    const authAttrsNode = signerInfo.value?.find(
      (child) =>
        (child as { tagClass?: number })?.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC &&
        (child as { type?: number })?.type === 0
    ) as { value?: unknown } | undefined;

    return extractSigningTimeFromAttributes(authAttrsNode?.value);
  } catch {
    return undefined;
  }
}
