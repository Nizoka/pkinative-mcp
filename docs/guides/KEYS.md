# Keys guide — PKCS#8 and PKCS#12 without a key byte leaving (for AI agents and operators)

Applies to pkinative-mcp v1.0.0 · pkinative 1.0.0.

This guide explains how the three key tools — `inspect_private_key`, `inspect_pkcs12` and
`open_pkcs12` — describe and open key material, the doctrine behind what they refuse, the
two password channels, and why no result of this server can ever carry a key byte. The
server-side recipe is the `open_keys_safely` prompt; using a key to sign is in
[SIGNING.md](SIGNING.md).

## TL;DR — describe first, open second, export never

"None" below means no `password` input **and** `PKINATIVE_MCP_PASSWORD` unset: the variable
counts as the password of every password-accepting tool, and with it set the describe calls
open the file instead (a legacy `.p12` is then `PKI_KEY_MAC_UNSUPPORTED` rather than described).

| Question | Tool | Password | Returns |
| --- | --- | --- | --- |
| What is this key, and what protects it? | `inspect_private_key { key }` | none | format, kind, curve, algorithm, the PBES2 parameters of an encrypted key |
| Is this encrypted key usable with this password? | `inspect_private_key { key, tryImport: true, password, keyType }` | yes | `imported`: the non-extractable handle described (type, algorithm, usages) |
| What is in this `.p12`, and how is it protected? | `inspect_pkcs12 { pkcs12 }` | none | version, MAC construction, every SafeContents with its scheme, the bags of the plain ones |
| Does the password fit, and what does every bag hold? | `inspect_pkcs12 { pkcs12, password }` | yes | `macVerified` and `opened` — every bag as an allow-list view; a wrong password on an encrypted SafeContents is `PKI_CRYPTO_DECRYPTION_FAILED` (`macVerified: false` is reported only when nothing is encrypted) |
| Open it: MAC, decryption, key import, certificates | `open_pkcs12 { pkcs12, password, exportCertificates }` | yes | the verdict (`valid`, `integrity`, `reasons[]`), keys as handles, certificates (+ a PEM bundle), CRL count |

Worked examples: [`inspect-private-key-describe.json`](../../examples/inspect-private-key-describe.json),
[`inspect-private-key-import.json`](../../examples/inspect-private-key-import.json),
[`inspect-private-key-rsa-scheme-required.json`](../../examples/inspect-private-key-rsa-scheme-required.json),
[`inspect-pkcs12-describe.json`](../../examples/inspect-pkcs12-describe.json),
[`inspect-pkcs12-open.json`](../../examples/inspect-pkcs12-open.json),
[`inspect-pkcs12-legacy.json`](../../examples/inspect-pkcs12-legacy.json),
[`open-pkcs12-export.json`](../../examples/open-pkcs12-export.json),
[`open-pkcs12-rsa.json`](../../examples/open-pkcs12-rsa.json),
[`open-pkcs12-nomac.json`](../../examples/open-pkcs12-nomac.json),
[`open-pkcs12-no-password.json`](../../examples/open-pkcs12-no-password.json).

```jsonc
// Describe without a password (PKINATIVE_MCP_PASSWORD unset — the variable counts as one)
{ "tool": "inspect_private_key", "arguments": { "key": { "path": "fixtures/leaf.key.enc.pem" } } }
// → { format: "encrypted-pkcs8", encrypted: true, encryption: { scheme: "PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC)", algorithm, pbes2: { iterations, prf, keyBits, cipher, saltBytes } }, encryptedBytes, … }
{ "tool": "inspect_pkcs12", "arguments": { "pkcs12": { "path": "fixtures/leaf.p12" }, "verbosity": "summary" } }
// → { macKind: "pbmac1", contentCount, bagKinds: [...], diagnosticCount }
// Prove an encrypted EC key is usable (the key never leaves the engine)
{ "tool": "inspect_private_key", "arguments": {
  "key": { "path": "fixtures/leaf.key.enc.pem" }, "tryImport": true, "password": "test-only-password", "keyType": "ec-p256",
  "fields": ["imported", "encryption.scheme"] } }
// Open a .p12 and export its certificate chain as PEM
{ "tool": "open_pkcs12", "arguments": { "pkcs12": { "path": "fixtures/leaf.p12" }, "password": "test-only-password", "exportCertificates": true } }
// → { valid: true, integrity: "verified", keys: [{ path, friendlyName, localKeyId, certificate: { subject, issuer, serialNumber, notAfter }, signingKey: { algorithm, key: { type, algorithm, extractable: false, usages } } }], certificates: [...], keyCount, certificateCount, crlCount }
//   + an embedded PEM resource holding the certificates (then the CRLs) — never a key
```

## What a report may contain — the allow-list

Every other tool serialises the engine's parsed object through the wire form; the key tools
do **not**, because the engine results here carry secret bytes (`PrivateKeyInfo.der` is the
plaintext key, a PKCS#12 keyBag holds plaintext in its value, the AuthenticatedSafe holds
every unencrypted bag). `src/key-views.ts` builds these reports field by field from an
allow-list — the interfaces **are** the allow-list — so no secret byte can reach
`structuredContent`, a message or a log, whatever a future engine adds:

| View | Members |
| --- | --- |
| `PrivateKeyView` | `format: 'pkcs8'`, `version`, `kind` (`ec` `rsa` `rsa-pss` `ed25519` `ed448` `x25519` `x448` `ml-dsa` `unknown`), `curve`, `algorithm` (OID), `attributes[]` (OIDs), `publicKey` (whether one is embedded) |
| `EncryptedKeyView` | `format: 'encrypted-pkcs8'`, `encryption { scheme, algorithm, pbes2 { iterations, prf, keyBits, cipher, saltBytes } }`, `encryptedBytes` |
| `MacView` | `kind` (`pbmac1` — RFC 9579 — or `pkcs12-kdf`, the RFC 7292 Appendix B MAC pkinative never verifies), `algorithm`, `iterations`, `pbmac1 { iterations, prf, hmac, keyLength }` |
| `BagView` | `path`, `kind` (`certBag` `keyBag` `pkcs8ShroudedKeyBag` `crlBag` `secretBag` `safeContentsBag`), `oid`, `friendlyName`, `localKeyId`, `certificate { subject, issuer, serialNumber }` (or `{ unreadable, bytes }`), `crlBytes`, `key` (a `PrivateKeyView` / `EncryptedKeyView` — algorithm and curve, never a byte) |
| `CryptoKeyView` / `SigningKeyView` | `type`, `algorithm`, `extractable: false`, `usages[]` — a Web Crypto handle described, never exported |

A challengePassword in a CSR is reported as present, never by its text; a password never
appears anywhere; `tests/secret-leak.test.ts` sweeps every result of every key tool on every
key fixture and every password situation with needles computed from the fixtures (PEM
bodies, DER hex / base64, private scalars in every encoding, encrypted-key bodies, the
password), and `assertResultClean` guards every such result in every suite.

## The two password channels

| Channel | Where the secret lives | When |
| --- | --- | --- |
| the `password` input (`inspect_private_key`, `inspect_pkcs12`, `open_pkcs12`; `signer.password` on the signing tools) | the tool call — the host's transcript and the model's context | a throwaway or TEST-ONLY password; interactive use |
| `PKINATIVE_MCP_PASSWORD` (operator environment) | the server process only | production keys and PKCS#12 files; anything the model should never see |

Both at once is `VALIDATION_ERROR` ("give the password once"); neither when one is needed is
`SECRET_REQUIRED` ([`open-pkcs12-no-password.json`](../../examples/open-pkcs12-no-password.json));
a wrong one is `PKI_CRYPTO_DECRYPTION_FAILED` on an encrypted key or SafeContents, and on
`open_pkcs12` a **report** — `integrity: 'mismatch'` + `PKI_REASON_PKCS12_MAC_MISMATCH`,
nothing decrypted. The value is never echoed, logged, written to a cache key or a cache file
(a call carrying a password is never cached, nor any password-accepting tool while the
variable is set). A tool that does not open a key does not accept a `password` at all.

## Doctrine: what is refused, and the remedy

| Refusal | Code | Remedy |
| --- | --- | --- |
| A legacy PKCS#12 cipher — RFC 7292 Appendix C `pbeWithSHAAnd3-KeyTripleDES-CBC`, `pbeWithSHAAnd40BitRC2-CBC` and the rest — or PBES1, or PBES2 with a KDF / cipher Web Crypto does not run | `PKI_KEY_ENCRYPTION_UNSUPPORTED` (`open_pkcs12`: `PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED`, the rest of the file still read) | Convert once with **OpenSSL 3.4 or later**: `openssl pkcs12 -in legacy.p12 -legacy -aes256 -out bundle.pem`, then `openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12` (delete `bundle.pem` afterwards). `inspect_pkcs12` names the scheme **before** anyone types a password ([`inspect-pkcs12-legacy.json`](../../examples/inspect-pkcs12-legacy.json)). |
| A legacy PBES1 / 3DES PKCS#8 key | `PKI_KEY_ENCRYPTION_UNSUPPORTED` | `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -in legacy.key -out modern.key` (PBES2, what pkinative reads). |
| A PKCS#12 MAC that is not PBMAC1 (the RFC 7292 Appendix B KDF — every MAC OpenSSL wrote before 3.4 and most it still writes), or public-key integrity mode | `PKI_KEY_MAC_UNSUPPORTED` when a MAC check is asked for; on `open_pkcs12` a negative verdict `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED` | Re-export with `openssl pkcs12 -export -pbmac1_pbkdf2`; or `allowUnverifiedIntegrity: true` on `open_pkcs12` **only for a file whose origin you trust by other means** — the report still says `integrity: 'unverified'` ([`open-pkcs12-nomac.json`](../../examples/open-pkcs12-nomac.json)). |
| No MAC at all | the same `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED` | the same; without a MAC an unencrypted bag can be replaced by anyone who can write the file. |
| An RSA key without a scheme | `RSA_SCHEME_REQUIRED` (`open_pkcs12`: `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED`, that key's `signingKey` null) | `rsaScheme: 'pkcs1'` (what nearly every RSA certificate in use signs with) or `'pss'` — pkinative has no default (its ADR 0015) ([`open-pkcs12-rsa.json`](../../examples/open-pkcs12-rsa.json)). |
| An encrypted PKCS#8 key imported without its type | `KEY_TYPE_REQUIRED` | `keyType` (`ec-p256` `ec-p384` `ec-p521` `ed25519` `ed448` `rsa` `rsa-pss`): the type is visible only once decrypted, and Web Crypto unwraps into a key for one algorithm. |
| A key bag whose `localKeyId` matches no certificate | `PKI_REASON_PKCS12_KEY_UNMATCHED` | Re-export with the key's certificate (`openssl pkcs12 -export` writes the localKeyId on both). |
| A key of a kind Web Crypto does not import as a signing key (DSA, X25519 / X448, a non-NIST curve) or one this runtime refused | `PKI_REASON_PKCS12_KEY_UNSUPPORTED`, `PKI_CRYPTO_KEY_UNSUPPORTED`, `UNSUPPORTED_KEY` | Described, never signed with; try another runtime before concluding the file is at fault. |
| A PUBLIC KEY or a non-PKCS#8 DER fed to `inspect_private_key` | the `PKI_*` cause (`PKI_PEM_UNEXPECTED_LABEL`, `PKI_KEY_STRUCTURE_INVALID`) | Pass the right object to the right tool. |
| A key fed anywhere else — `convert_pem extractIndex`, `decode_asn1`, `encode_asn1`, `resources/read`, a certificate input | `SECURITY_VIOLATION` (by PEM label and by parsing the DER as PKCS#8 / PKCS#12), or `PKI_PEM_UNEXPECTED_LABEL` | The remedy names `inspect_private_key` / `inspect_pkcs12` / `open_pkcs12`; a refusal never echoes the key ([`convert-pem-private-key-refused.json`](../../examples/convert-pem-private-key-refused.json), [`decode-asn1-private-key-refused.json`](../../examples/decode-asn1-private-key-refused.json), [`inspect-certificate-private-key-refused.json`](../../examples/inspect-certificate-private-key-refused.json)). |

Nothing in this server **generates** a key (bring one from your HSM, KMS or
`openssl genpkey`), **exports** a key (`exportCertificates: true` exports the certificates
and CRLs of a PKCS#12 only, and only from a file that opened), or **writes** a key-bearing
file (`outputPath` with `.key` `.p8` `.p12` `.pfx` is `SECURITY_VIOLATION`; the engine has no
PKCS#8 / PKCS#12 writer — its ADR 0003). `compute_fingerprint` may digest a private key: the
digest reveals nothing and no input byte is returned.

## PKCS#12 in the sandbox and as a signer

A `.key` / `.p8` / `.p12` / `.pfx` dropped into `PKINATIVE_MCP_OUTPUT_DIR` is read by the key
and signer tools through `path`, never listed by `resources/list`, never served by
`resources/read` (a PEM text holding a private-key block is refused there too). `signer.p12`
on `create_certificate`, `create_csr`, `sign_cms` and `encode_x509_structure signature-algorithm`
opens the file the same way `open_pkcs12` does — the bag's certificate serves as the signer
certificate or the issuer, the key signs — with the same refusals (`RSA_SCHEME_REQUIRED`,
`PKI_KEY_ENCRYPTION_UNSUPPORTED`, `PKI_CRYPTO_DECRYPTION_FAILED`, or `ENGINE_VERDICT` with
`data.reasons`; `allowUnverifiedIntegrity` is not available on the signer path).
`limits.maxPkcs12Bags` (4 096), `limits.maxKdfIterations` and `limits.maxPkcs12KdfIterations`
(10 000 000 each, under `PKINATIVE_MCP_MAX_KDF_ITERATIONS`) bound what a hostile file may
declare — a PKCS#12 declaring 2^31 PBKDF2 iterations would otherwise freeze the reader inside
Web Crypto. A PBKDF2 count below 1 000 is reported as `PKI_DIAG_KEY_KDF_ITERATIONS_LOW`.

## OpenSSL on your side

```bash
# a PKCS#8 key, plain and PBES2-encrypted (what inspect_private_key / signer.key open)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key.pem
openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -in leaf.key.pem -out leaf.key.enc.pem
# a PKCS#12 with PBES2 + PBMAC1 (OpenSSL 3.4+; what inspect_pkcs12 / open_pkcs12 / signer.p12 open)
openssl pkcs12 -export -in leaf.crt.pem -inkey leaf.key.pem -certfile inter.crt.pem -pbmac1_pbkdf2 -out leaf.p12
# the legacy conversion, once
openssl pkcs12 -in legacy.p12 -legacy -aes256 -out bundle.pem && openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12 && rm bundle.pem
```

The fixture keys and PKCS#12 files (`leaf.key.{pem,der,enc.pem}`, `rsa.key.*`,
`ed25519.key.pem`, `leaf.p12`, `rsa.p12`, `ed25519.p12`, `legacy.p12`, `plain-keybag.p12`,
`nomac.p12`, `certs-only.p12`) were made exactly this way by OpenSSL 3.5.5
([`tests/fixtures/PROVENANCE.md`](../../tests/fixtures/PROVENANCE.md)); every private key
there is public **TEST-ONLY** material, password `test-only-password`, and the secret-leak
suite proves that none of them ever appears in a result.
