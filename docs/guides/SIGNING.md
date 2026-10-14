# Signing guide — issuing certificates and signing CMS (for AI agents and operators)

Applies to pkinative-mcp v1.0.0 · pkinative 1.0.0.

This guide explains how the four signing tools — `create_csr`, `create_certificate`,
`sign_cms` and `encode_x509_structure signature-algorithm` — take a key, what they derive,
what they verify before the bytes return, and what makes the bytes reproducible. The
server-side recipe is the `issue_certificate` prompt; the time-stamp side continues in
[TIMESTAMPS.md](TIMESTAMPS.md), the verification side in [VERIFICATION.md](VERIFICATION.md).

## TL;DR — the ladder as four tool calls

| Step | What it does | Tool | Verified before the bytes return |
| --- | --- | --- | --- |
| **CA** | A self-signed CA from a key you hold (no `issuerCertificate`) | `create_certificate` | the self-signature |
| **Request** | A PKCS#10 from the subject's key (the public key is the signing key's own) | `create_csr` | the proof of possession |
| **Leaf** | A certificate issued from the request under the CA (`issuerCertificate` + `subjectPublicKey`) | `create_certificate` | the issuer signature |
| **Content** | An RFC 5652 SignedData, attached or detached, with the chain embedded | `sign_cms` | the signer's signature against its certificate |
| check | The trust verdict on what you issued | `verify_certificate_chain` / `verify_cms` | — |

No key is ever generated or exported here: the engine's doctrine (`describe_engine.refusals`).
Bring keys from your HSM, your KMS or `openssl genpkey`, as a PKCS#8 key (plain or
PBES2-encrypted) or a PKCS#12 file. Worked examples:
[`create-certificate-self-signed-ca.json`](../../examples/create-certificate-self-signed-ca.json),
[`create-csr-round-trip.json`](../../examples/create-csr-round-trip.json),
[`create-certificate-issue-leaf.json`](../../examples/create-certificate-issue-leaf.json),
[`sign-cms-detached-then-verify.json`](../../examples/sign-cms-detached-then-verify.json).

```jsonc
// 1. A self-signed CA (serial and dates pinned → reproducible bytes with an Ed25519 key)
{ "tool": "create_certificate", "arguments": {
  "spec": { "serialNumber": 1, "subject": { "C": "FR", "O": "Acme", "CN": "Acme Test CA" },
            "notBefore": "2027-01-01T00:00:00Z", "validityDays": 3650,
            "extensions": { "basicConstraints": { "ca": true, "pathLen": 0 }, "keyUsage": ["keyCertSign", "cRLSign"] } },
  "signer": { "key": { "path": "fixtures/ed25519.key.pem" } }, "encoding": "der" } }
// 2. The subject's request (proof of possession verified)
{ "tool": "create_csr", "arguments": {
  "spec": { "subject": { "C": "FR", "O": "Acme", "CN": "svc.example.test" },
            "extensions": { "subjectAltName": { "dns": ["svc.example.test", "www.svc.example.test"] },
                            "keyUsage": ["digitalSignature"], "extendedKeyUsage": ["serverAuth"] } },
  "signer": { "key": { "path": "fixtures/leaf.key.pem" } }, "encoding": "der" } }
// 3. The leaf, issued from the request (AKI computed from the issuer; issuer signature verified)
{ "tool": "create_certificate", "arguments": {
  "spec": { "serialNumber": "0x1a2b3c", "subject": { "CN": "svc.example.test" },
            "notBefore": "2027-01-01T00:00:00Z", "validityDays": 90,
            "extensions": { "subjectAltName": { "dns": ["svc.example.test"] }, "extendedKeyUsage": ["serverAuth"], "keyUsage": ["digitalSignature"] } },
  "issuerCertificate": { "path": "fixtures/leaf.crt.pem" },
  "subjectPublicKey": { "path": "fixtures/leaf.csr.pem" },
  "signer": { "key": { "path": "fixtures/leaf.key.pem" } }, "encoding": "der" } }
// 4. Prove it
{ "tool": "verify_certificate_chain", "arguments": {
  "leaf": { "derBase64": "<from 3>" }, "trustAnchors": [{ "path": "fixtures/leaf.crt.pem" }], "at": "2027-01-01T00:00:00Z" } }
```

## The `signer` fragment

Every signing tool takes the same `signer` object (`src/signer.ts`):

| Member | Meaning |
| --- | --- |
| `key` | A PKCS#8 private key — `PRIVATE KEY` or `ENCRYPTED PRIVATE KEY`, PEM or DER, inline or a sandbox `path` (`.key` / `.p8` / `.pem`). A SEC1 / PKCS#1 key is converted first: `openssl pkcs8 -topk8 -in ec.key -out key.p8`. Exclusive with `p12`. |
| `p12` | A PKCS#12 file (`.p12` / `.pfx`), PBES2 + PBMAC1 only — a legacy RC2 / 3DES file is refused with the OpenSSL 3.4 conversion remedy ([KEYS.md](KEYS.md)). The key signs; its bag's certificate serves as `certificate` (`sign_cms`) or as the issuer (`create_certificate`) unless one is given. |
| `password` | The password of an encrypted key or a PKCS#12 — **or** set `PKINATIVE_MCP_PASSWORD` in the server environment and omit it (never both: `VALIDATION_ERROR`; neither: `SECRET_REQUIRED`). The value never reaches a result, a message, a log or the cache. |
| `keyType` | `ec-p256` `ec-p384` `ec-p521` `ed25519` `ed448` `rsa` `rsa-pss` — needed for an **encrypted** PKCS#8 key (it reveals its type only once decrypted) unless the tool has the matching certificate or `subjectPublicKey` (`KEY_TYPE_REQUIRED` otherwise). |
| `hash` | `SHA-1` `SHA-256` `SHA-384` `SHA-512`. Default: the curve's hash for ECDSA (P-256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512), SHA-256 for RSA; refused for Ed25519 / Ed448, which hash internally; `SHA-1` only with `allowSha1: true`. |
| `rsaScheme` | **Required for an RSA key**: `'pkcs1'` (RSASSA-PKCS1-v1_5 — what nearly every RSA certificate in use signs with) or `'pss'` (RSA-PSS). pkinative has no default (its ADR 0015) and neither does this server: `RSA_SCHEME_REQUIRED`. An id-RSASSA-PSS key signs `'pss'` only. Refused for non-RSA keys. |
| `saltLength` | RSA-PSS salt length in bytes (`'pss'` only; default: the hash length). |

The key is imported into a **non-extractable** Web Crypto key and never leaves the engine;
the result describes it through `signingKey` (algorithm, handle type, usages) — never a
byte. The algorithm follows the key: ECDSA on the key's curve, Ed25519 / Ed448 without a
hash, RSA under the scheme you name. `encode_x509_structure { structure: 'signature-algorithm', signer }`
returns the AlgorithmIdentifier such a signature would carry without signing anything
([`encode-x509-structure-signature-algorithm.json`](../../examples/encode-x509-structure-signature-algorithm.json)).

## The certificate spec (`create_certificate`, `create_csr`)

The `spec` object (`src/x509-spec.ts`) is closed: an unknown or misspelt member is refused
by name (`VALIDATION_ERROR` naming `spec <path>`), never dropped silently
([`encode-x509-structure-unknown-member.json`](../../examples/encode-x509-structure-unknown-member.json)).

```jsonc
{
  "serialNumber": "0x1001" | "4097" | 4097 | "random",   // default 'random': 127 bits from node:crypto (summary.randomSerial: true)
  "subject": { "C": "FR", "O": "Acme", "CN": "example.test" },   // or explicit RDNs [{ "type": "2.5.4.3", "value": "…" }]
  "issuer": { … },                       // default: the issuer certificate's subject, else the subject (self-signed)
  "notBefore": "2027-01-01T00:00:00Z",   // default PKINATIVE_MCP_AT, else now (whole seconds) — summary.notBeforeSource says which
  "notAfter": "…"  |  "validityDays": 365,
  "extensions": {
    "basicConstraints": { "ca": true, "pathLen": 0, "critical": true },
    "keyUsage": ["digitalSignature", "keyEncipherment"]  |  { "usages": [...], "critical": true },
    "extendedKeyUsage": ["serverAuth", "1.3.6.1.5.5.7.3.2"]  |  { "purposes": [...], "critical": false },
    "subjectAltName" | "issuerAltName": { "dns": [], "email": [], "uri": [], "ip": [], "registeredId": [], "directoryName": [ <name> ], "critical": false },
    "subjectKeyIdentifier": true | false | "hex",   // default true: computed from the subject key
    "authorityKeyIdentifier": true | false | "hex", // default true for an issued certificate: the issuer's SKI
    "raw": [ { "oid": "1.2.3", "critical": false, "value": "hex of the extnValue content" } ]
  }
}
```

Where the public key comes from (`summary.publicKeyFrom`): `signer` (derived from a plain
PKCS#8 key), `pkcs12` (the bag's certificate), or the `subjectPublicKey` input — a
`certificate`, a `csr` or a bare `spki` (`PUBLIC KEY` PEM) — which is **required** for an
issued certificate and for an encrypted signer key (`create-csr-encrypted-key.json`).
`create_csr` carries the requested extensions in `extensionRequest`; `issuerAltName` and
`authorityKeyIdentifier` are refused there as the issuer's business. `notAfter` before
`notBefore` is `VALIDATION_ERROR` (a corpus canary).

The artefact summary tells what happened: `serialNumber` (hex), `randomSerial`, `subject`,
`issuer`, `selfSigned`, `signatureAlgorithm`, `notBefore` / `notAfter` / `notBeforeSource`
(`input` | `pinned` | `clock`), `extensions[]` (the kinds written), `signatureVerified`,
`publicKeyFrom`. `sha256` is the SHA-256 of the DER — the reproducibility proof.

## Signing content (`sign_cms`)

```jsonc
{ "tool": "sign_cms", "arguments": {
  "content": { "path": "fixtures/content.txt" },     // or { "text" } / { "base64" }; or "contentDigest" (detached only — the PDF /ByteRange case)
  "detached": true,                                   // default false (attached: the content travels inside the SignedData)
  "certificate": { "path": "fixtures/leaf.crt.pem" }, // required with signer.key; a PKCS#12 bag's certificate serves otherwise
  "chain": [{ "path": "fixtures/inter.crt.pem" }],    // parsed, then embedded (never embedded unread); "crls" likewise
  "signingTime": "2027-01-01T00:00:00Z",              // default PKINATIVE_MCP_AT, else now; 'none' omits it (PAdES); pin it for reproducible bytes
  "signer": { "key": { "path": "fixtures/leaf.key.pem" } } } }
```

Signed attributes are always written: `contentType`, `messageDigest`, `signingTime` (unless
`'none'`), the ESS `SigningCertificateV2` (RFC 5035) and `CMSAlgorithmProtection`
(RFC 6211) — CAdES, PAdES and RFC 3161 require them; `signingCertificateV2: false` /
`algorithmProtection: false` drop them for a reader that cannot cope. `signedAttributes` /
`unsignedAttributes` add your own (DER `Attribute`s as hex, ≤ 256). `sid` defaults to
`issuerAndSerialNumber` — keep it unless the reader is known: `subjectKeyIdentifier`
(version 3) is refused by some deployed readers and needs the certificate's SKI. `contentType`
defaults to id-data; any other eContentType makes a version 3 SignedData.

The new signature is verified against the signer certificate **before** the bytes are
returned — a key that does not belong to the certificate is `KEY_MISMATCH`, never a silent
bad artefact. Output DER (default, `.p7s`), PEM (label `CMS`) or hex. The summary:
`detached`, `contentType`, `signerSubject`, `signerSerial`, `sid`, `digestAlgorithm`,
`signatureAlgorithm`, `signingTime` / `signingTimeSource`, `certificatesEmbedded`,
`crlsEmbedded`, `signedAttributes`, `unsignedAttributes`, `signatureVerified`, `contentBytes`.
A counter time-stamp is added afterwards with `amend_cms` ([TIMESTAMPS.md](TIMESTAMPS.md)).

## What is verified, and what is not

| Tool | Verified before the bytes return | Not judged here |
| --- | --- | --- |
| `create_certificate` | the new certificate against the issuer's public key (or its own) — `summary.signatureVerified` | whether the issuer is a CA you trust, name constraints, the issuer's own validity: `verify_certificate_chain` |
| `create_csr` | the proof of possession (the request against the key it carries) — always `true`, a mismatch is `KEY_MISMATCH` | nothing else: a CSR carries no trust |
| `sign_cms` | the signer's signature against `certificate` | the chain to an anchor, revocation, the time: `verify_cms` |

The read tools confirm it: `inspect_certificate { checkSelfSignature: true }` /
`{ issuer }`, `inspect_csr` (`signature.valid`), `inspect_cms { signerCertificate }`
(`signerSignature.valid`) — each ONE signature against ONE key, which is a fact, not trust.

## Error codes

| Code | Raised by | Meaning / fix |
| --- | --- | --- |
| `SECRET_REQUIRED` | an encrypted `signer.key`, a `signer.p12` | No password given: the `password` input or `PKINATIVE_MCP_PASSWORD` (never both). |
| `KEY_TYPE_REQUIRED` | an encrypted `signer.key` | Its type is unknown until decrypted: pass `signer.keyType`, or a `certificate` / `subjectPublicKey` that names it. |
| `RSA_SCHEME_REQUIRED` | any RSA key (PKCS#8 or PKCS#12) | `rsaScheme: 'pkcs1'` or `'pss'`; there is no default. |
| `KEY_MISMATCH` | every signing tool | The key does not belong to the certificate, issuer or `subjectPublicKey` it was paired with — the artefact was verified after signing and refused. |
| `UNSUPPORTED_KEY` | every signing tool | A key Web Crypto cannot sign with on this host (DSA, a non-NIST curve, Ed448 where unsupported). |
| `PKI_CRYPTO_DECRYPTION_FAILED` | an encrypted key or PKCS#12 | Wrong password, altered ciphertext, or a key of another algorithm than `keyType`. |
| `PKI_KEY_ENCRYPTION_UNSUPPORTED` / `PKI_KEY_MAC_UNSUPPORTED` | a legacy PKCS#12 or PBES1 key | Convert once with OpenSSL 3.4 ([KEYS.md](KEYS.md)). |
| `ENGINE_VERDICT` | a `signer.p12` | Opening the PKCS#12 came back negative for another reason (`data.reasons`); `allowUnverifiedIntegrity` is not available on the signer path — re-export the file with a PBMAC1 MAC. |
| `VALIDATION_ERROR` | every signing tool | An unknown `spec` member, `notAfter` before `notBefore`, a SHA-1 `hash` without `allowSha1`, a password given twice, `saltLength` without `'pss'`, `issuerAltName` in a CSR spec. |

## Reproducibility

A certificate, a request or a SignedData is byte-identical across runs and hosts when every
input is pinned: `serialNumber` (not `'random'`), `notBefore` (or `PKINATIVE_MCP_AT`),
`signingTime` (or `'none'`), and a **deterministic signer** — Ed25519 or RSA PKCS#1 v1.5.
ECDSA and RSA-PSS draw a fresh random per signature (Web Crypto does not implement
RFC 6979), so their signature value differs on every call while the signed part (the
TBSCertificate, the CertificationRequestInfo, the signed attributes) is identical — which
is what the sample baseline holds in `tbs` mode ([API_STABILITY.md](../API_STABILITY.md) §5).
A `'random'` serial is 127 bits from `node:crypto` and the summary says so
(`randomSerial: true`); such a call is never served from the cache. The annotations say the
same: `create_certificate`, `create_csr` and `sign_cms` are `PRODUCES` (`idempotentHint: false`).

## OpenSSL on the other side

Every artefact these tools write is read and verified by OpenSSL 3 in CI
([CONFORMANCE.md](CONFORMANCE.md)); the same commands check one you produced by hand:

```bash
openssl x509 -inform DER -in ca.der -noout -text                       # dump a certificate
openssl verify -CAfile ca.pem -untrusted inter.pem -purpose sslserver -attime 1798761600 leaf.pem
openssl req -inform DER -in request.der -noout -verify                 # the proof of possession
openssl cms -verify -binary -inform DER -in signed.p7s -content content.txt -CAfile root.pem -purpose any -out /dev/null
```

Keys the other way: `openssl genpkey -algorithm ED25519 -out ca.key.pem` (plain PKCS#8),
`openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -in ca.key.pem -out ca.key.enc.pem`
(PBES2-encrypted, what `signer.key` + `password` opens),
`openssl pkcs12 -export -in leaf.pem -inkey leaf.key.pem -pbmac1_pbkdf2 -out leaf.p12`
(PBES2 + PBMAC1, what `signer.p12` opens). The test fixtures were made exactly this way
([`tests/fixtures/PROVENANCE.md`](../../tests/fixtures/PROVENANCE.md)); every private key
there is public TEST-ONLY material.
