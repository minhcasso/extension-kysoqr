# Bundled Root CA certificates

Root CA certificates are **public data by design** — anyone can already download
them from the issuing authority's own website. Bundling them here (instead of
an env var) means they are versioned, reviewable in a PR, and don't need to be
copy-pasted into every deployment's `.env`.

## Provenance

| File           | Downloaded from                                                                                                                                                                                                                                                                                                                                                                            | Date       |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `vnrca256.p7b` | Downloaded directly from the official rootca.gov.vn (NEAC) public root list (`.p7b`, PKCS#7 container, "SHA-256-G2" entry) — no conversion needed, `BundledRootStore.ts` reads PKCS#7 directly. Byte-for-byte verified identical (DER comparison) to the cert previously supplied via this project's legacy `TRUSTED_CA_PEM` env var, so the older `.pem` copy was removed as a duplicate. | 2026-09-15 |
| `vnrca-g3.p7b` | Downloaded as-is from the official NEAC public root list (`.p7b`, PKCS#7 container, "SHA-256-G3" entry) — no conversion needed, `BundledRootStore.ts` reads PKCS#7 directly.                                                                                                                                                                                                               | 2026-09    |

Both are self-signed, RSA-4096 / SHA-256 X.509 v3 certificates issued under the
Ministry of Information and Communications.

## ⚠️ Append-only — never delete a root just because a newer one exists

`vnrca256.p7b` (G2) and `vnrca-g3.p7b` (G3) are **two entirely independent
certificates** (different serial number, different keypair, different validity
window) — G3 is **not** a renewal of G2, and it does not replace it.

A document signed and chain-verified through G2 while G2 was a recognized
trust anchor must **stay verifiable forever**, even after G3 becomes the
"current" root for new signings — the exact same principle already applied to
leaf-certificate expiry in this project (a signature is judged against
`signingTime`, not against "now"). Removing G2 from this folder once G3 exists
would silently break verification of every document legitimately signed under
G2 in the past.

**Only remove a root file for an actual security incident** (the CA's private
key is compromised, or the root is formally revoked by its issuer) — never
just because a newer generation was added. When in doubt, add a new file;
don't delete an old one.

## Format

Either plain PEM (`-----BEGIN CERTIFICATE-----...`) or PKCS#7 (`.p7b`, DER) is
accepted — see `BundledRootStore.ts`. If a future NEAC download comes as
`.p7b`, drop it in as-is; no manual `openssl` conversion needed.

## Generated manifest (Cloudflare Workers has no real filesystem)

`lib/trustStore/generated/rootCerts.generated.ts` is a committed, auto-generated
base64 snapshot of every file in this folder, produced by
`scripts/generateCertManifest.js`. `BundledRootStore.ts` loads the **union** of
this folder read live via `fs.readdirSync` (VPS, tests, local dev) and that
snapshot — so a Cloudflare Workers deployment (no real filesystem at runtime)
still gets a working trust store from whatever was baked in at the last build.

Regenerate after adding/removing a file here: `npm run gen:certs` (also runs
automatically before every `npm run build`). Commit the regenerated file
together with the cert file change.
