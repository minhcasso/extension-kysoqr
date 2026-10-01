/**
 * Trust store abstraction (TSD mục 18) —
 * verification core depends on this interface only, so the trust source can
 * change without touching verify logic.
 */
export interface TrustStore {
  /** Root CA certificates (PEM strings) currently configured as trusted. */
  isConfigured(): boolean;
  /** Whether the given root certificate (PEM) is a trusted anchor. */
  isTrustedRoot(rootCertPem: string): boolean;
  /**
   * All trusted root certificates, as PEM strings — used by the chain
   * verifier to build a candidate CA store for name-based issuer lookup
   * during chain walking. This is never itself the trust decision: whichever
   * root the walk lands on must still separately pass `isTrustedRoot`'s
   * byte-exact comparison (or, equivalently, the underlying CA store's own
   * `hasCertificate`, backed by the same cert set).
   */
  getTrustedRootPems(): string[];
}
