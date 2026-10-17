# Agent contract — pkinative-mcp

The consumer contract for AI agents **using** the server (Copilot, Claude, Cursor,
Cline, …): the tool catalogue, the decision tree, token-frugal responses, output modes
and operator environment, recipes, and the error reference. Section numbers §1–§6 are
stable anchors — tests, prompts and other documents cite them.

Agents **contributing** to this repository read [AGENTS.md](../AGENTS.md) instead.

Verified on 2026-10-13 against pkinative-mcp 1.0.0 and pkinative 1.0.0.

The server also returns the §2 decision tree in `serverInfo.instructions`. Deeper
references: [AI_GUIDE.md](AI_GUIDE.md) (pitfalls + recipes),
[guides/VERIFICATION.md](guides/VERIFICATION.md), [guides/SIGNING.md](guides/SIGNING.md),
[guides/REVOCATION.md](guides/REVOCATION.md), [guides/TIMESTAMPS.md](guides/TIMESTAMPS.md)
and [guides/KEYS.md](guides/KEYS.md) (the workflows in depth),
[guides/REPRODUCIBLE.md](guides/REPRODUCIBLE.md) (what to pin for byte-identical output),
[KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md) (architecture),
[API_STABILITY.md](API_STABILITY.md) (versioning charter). Worked
invocations live under [examples/](../examples/).

---

## 1. Tool catalogue (34 tools)

Registration order, six groups: encodings (5), certificates and requests (8), paths /
CRLs / OCSP (8), CMS and time-stamps (7), keys (3), meta (3).

| # | Tool | Use it for | Read-only |
|---|------|-----------|:---:|
| 1 | `convert_pem` | The RFC 7468 layer. `mode: 'decode'` lists every block of a PEM text (index, label, DER size, offset, SHA-256); `label` keeps one kind, `extractIndex` delivers that block as an artefact (`der` default, `pem`, `hex`). `mode: 'encode'` wraps exactly ONE DER value into one strict PEM block under `label`. A private-key block is listed, never extracted nor produced, and key material anywhere in the input is refused (`SECURITY_VIOLATION`). | ¹ |
| 2 | `resolve_oid` | Object identifiers: `mode` `name` (registered name of each dotted OID, ≤ 1000 per call), `validate` (X.660 grammar, reported never thrown), `list` (the engine registry, filtered, paged ≤ 2000), `encode` (hex per OID, `form` `content` / `tlv`, `relative` — a PEM-wrapped OID is `encode_asn1 { spec: { type: 'oid', value }, encoding: 'pem', label }`), `decode` (dotted form + name, from `hex` or from `input` — a PKI input: pem / derBase64 / path). | ✓ |
| 3 | `compute_fingerprint` | `mode: 'fingerprint'` (SHA-256 default; SHA-1 / 384 / 512; `webcrypto: true`) over the exact DER — what `openssl x509 -fingerprint` prints; `mode: 'key-id'` the RFC 5280 §4.2.1.2 key identifier (SHA-1 default, SHA-256) of the key in a certificate, CSR or PUBLIC KEY; `mode: 'shake256'` with `outputLength` (≤ 1 MiB). `separator` / `letterCase` shape `formatted`. | ✓ |
| 4 | `decode_asn1` | X.690 node tree of any DER (BER with `encodingRules: 'ber'`): offsets, tags, previews (`maxPreviewBytes`, default 32), OID names, ≤ 20 000 nodes. `nodePath` narrows, `read` applies a typed reader (11 readers), `reencode: true` re-encodes the node as an artefact (`label` names its PEM label when the input had none or a sub-node is selected), `sequence: true` reads concatenated values. Refuses a private key or PKCS#12 (`SECURITY_VIOLATION`). | ✓ |
| 5 | `encode_asn1` | A JSON node `spec` (boolean, integer, null, bit-string, named-bits, octet-string, oid, string, time, sequence / set / set-of, explicit / implicit, tlv, der) encoded through the engine's own encoders: DER (default), hex (≤ 64 KiB) or PEM under `label`. Deterministic. | |
| 6 | `inspect_certificate` | The RFC 5280 report of ONE certificate: version, serial, algorithms, issuer / subject (RFC 4514 + RDNs), validity, public key, the 19 decoded extension kinds (`rawExtensions: true` keeps them raw), `fingerprints`, diagnostics. `extension: 'subjectAltName'` returns one. `issuer` / `checkSelfSignature: true` add ONE signature check — facts, never trust. | ✓ |
| 7 | `create_certificate` | Issue an X.509 v3 certificate from `spec` (subject, validity, extensions), signed through `signer` (PKCS#8 key or PKCS#12, non-extractable). Self-signed without `issuerCertificate`; issued with it (`subjectPublicKey` = a certificate, a CSR or a PUBLIC KEY). `serialNumber` `'random'` by default (`summary.randomSerial`), `notBefore` defaults to `PKINATIVE_MCP_AT` or now. Verified against the issuer before the bytes return (`KEY_MISMATCH`). | |
| 8 | `encode_x509_structure` | ONE X.509 building block to DER from a closed `spec`: `name`, `name-attribute`, `validity`, `spki`, `algorithm-identifier`, `attribute`, `extension`, `extensions`, `basic-constraints`, `key-usage`, `extended-key-usage`, `subject-alt-name`, `subject-key-identifier`, `authority-key-identifier`, `signature-algorithm` (takes `signer` instead of a spec). Hex by default; nothing is signed. | |
| 9 | `decode_extension` | ONE extension value by `oid` (`valueHex` or `value` = the extnValue content), decoded as `inspect_certificate` decodes it: the 19 known kinds with members, any other OID as `kind: 'unknown'`; `critical` checked against the RFC 5280 rule (a diagnostic). Malformed → `PKI_X509_EXTENSION_MALFORMED`. | ✓ |
| 10 | `check_certificate_name` | The RFC 6125 identity verdict. Certificate form: `certificate` + `host` or `ip` (SAN dNSName / iPAddress; `allowWildcards` default true; `allowCommonNameFallback` + `chain` for CN-only certificates). Match form: `presented` + `reference`, one name comparison. `valid: false` + `reasons[]` is a verdict, never `isError`. | ✓ |
| 11 | `check_certificate_purpose` | The RFC 5280 §4.2.1.12 purpose verdict: may `certificate` be used for `purpose` (`serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `ocspSigning`, `any`, or an OID) along `[certificate, ...chain]`; `restrictIssuers` (default true), `requireExplicitPurpose` (default false). | ✓ |
| 12 | `inspect_csr` | The RFC 2986 report of ONE PKCS#10 request: subject, public key, attributes, the extensions requested, whether a challengePassword is present (never its text), and — by default (`verify`) — the proof of possession as `signature.valid`. Not trust: no CA signed a CSR. | ✓ |
| 13 | `create_csr` | A PKCS#10 request from `spec` (subject; the extensions to request), signed through `signer`. The public key is the signing key's own (derived from a plain key, taken from the PKCS#12 certificate, or `subjectPublicKey` for an encrypted key). Proof of possession verified before the bytes return (`KEY_MISMATCH`). | |
| 14 | `verify_certificate_chain` | **The** trust verdict: path from `leaf` through `candidates` to one of YOUR `trustAnchors`, every signature, RFC 5280 §6 validation at `at` (validity, constraints, policies via `policy`), `serverName` (RFC 6125), `purposes`, and revocation from the `crls` / `ocspResponses` YOU supply (`requireRevocation: true` demands evidence for the end-entity certificate; an intermediate is judged from the evidence you pass). `valid: false` + `reasons[]` is a verdict; `isError` is for refused inputs. | ✓ |
| 15 | `build_certificate_path` | Path discovery only (RFC 5280 §6 path building): which intermediates link `leaf` to an anchor under the structural rules at `at`. NO signature is verified (`PKI_REASON_SIGNATURE_NOT_CHECKED` on every link, `valid` always false); the verdict is `found` + `structuralReasons`. | ✓ |
| 16 | `validate_certificate_path` | RFC 5280 §6.1 validation of a `path` YOU ordered (leaf first) against `trustAnchors` at `at`; every link signature verified first and reported in `signatures[]`; `checkSignatures: false` gives the structural verdict (`failingReasons`). No revocation here. | ✓ |
| 17 | `inspect_crl` | The RFC 5280 §5 report of ONE CRL: issuer, algorithm, thisUpdate / nextUpdate, CRL number, delta indicator, issuing distribution point, `entryCount` (walked, never all decoded), extensions. `find` looks ONE serial up (`serialHex` or a `certificate`) → `entry`; `issuer` adds ONE signature check. | ✓ |
| 18 | `check_crl_revocation` | The RFC 5280 §6.3 verdict of ONE `certificate` against ONE `crl` you fetched (+ `delta`), evaluated at `at`: scope, freshness (`staleTolerance` ms), signature against `issuer` (pass it for a real verdict — without it the list is not evidence: `PKI_REASON_REVOCATION_UNKNOWN`), the serial not listed. A `delta` whose signature does not verify against `issuer` is not applied (`valid: false`, `PKI_REASON_REVOCATION_UNKNOWN` on `delta`). `PKI_REASON_REVOKED` is a verdict, never `isError`. | ✓ |
| 19 | `create_ocsp_request` | The DER OCSPRequest (RFC 6960) for `certificate` with the CertID computed from `issuer`: `hashAlgorithm` `'SHA-1'` (default) or `'SHA-256'`, `nonce` `'random'` (16 bytes, `summary.randomNonce`) or hex, `certIdOnly: true` for the bare CertID, `label` for the PEM label of `encoding: 'pem'`. You POST the bytes yourself; `summary.certIdHex` / `summary.nonceHex` match the answer. | |
| 20 | `inspect_ocsp_response` | The RFC 6960 §4.2 report of ONE OCSP response: status, responder id, producedAt, every SingleResponse (CertID, status, times, extensions), embedded certificates, whether a nonce is echoed. `responder` adds ONE signature check; omitted, the embedded certificates are tried. | ✓ |
| 21 | `check_ocsp_status` | The RFC 6960 verdict of ONE `response` for ONE `certificate`: CertID recomputed from `issuer`, signature (`responder`, embedded certificates, or the issuer), responder authorisation (RFC 6960 §4.2.2.2; `responderTrusted: true` for out-of-band trust), status, freshness at `at` (`staleTolerance`, `futureTolerance`), `nonce` echoed (`requireNonce: true`). | ✓ |
| 22 | `sign_cms` | An RFC 5652 SignedData over `content` (attached, or `detached: true`) or a precomputed `contentDigest`, ONE signer (`signer` + `certificate`, or the PKCS#12 bag's certificate), `chain` / `crls` parsed then embedded. contentType, messageDigest, `signingTime` (`'none'` omits it), SigningCertificateV2 and CMSAlgorithmProtection are written by default. Verified before the bytes return. A `content.path` naming a key-bearing extension or holding key material is `SECURITY_VIOLATION` — content read from the sandbox is never a key. | |
| 23 | `verify_cms` | **The** CMS verdict: for EVERY signer the signed attributes, the content digest (`content` / `contentDigest` for a detached signature), the signature, the chain to YOUR `trustAnchors` at `at`, every counter time-stamp, and revocation from the bytes YOU supply. `atTimeStamp: true` judges each signer at its verified time-stamp (long-term validation); `requireSigningCertificate` / `requireAlgorithmProtection` enforce CAdES. `signers[i].intact` tells unaltered from untrusted. | ✓ |
| 24 | `inspect_cms` | The RFC 5652 report of ONE SignedData (.p7s / .p7m / .p7b, a PDF /Contents): version, content type, embedded certificates, CRL / OCSP counts, every signer (identifier, algorithms, signing time as CLAIMED, signed / unsigned attributes, counter time-stamp count, **the signature value as hex**). `signerCertificate` (+ `signerIndex`, `content`) adds ONE key check — not the verdict. | ✓ |
| 25 | `amend_cms` | The one legitimate edit of a signed message, every signed octet unchanged: `operation` `'add-unsigned-attribute'` (`attribute`, DER hex) or `'add-timestamp'` (`token`: a TimeStampToken or the whole TimeStampResp) on signer `signerIndex`. A token whose imprint is not over the signer's signature value is refused before anything is written. | |
| 26 | `create_timestamp_request` | The RFC 3161 TimeStampReq you POST to a TSA yourself: imprint `hashAlgorithm` (SHA-256 default, 384, 512) over `data` or `digestHex`; `nonce` `'random'` (63 bits, `summary.randomNonce`) or a value; `policy`; `certReq` (default true); `label` for the PEM label of `encoding: 'pem'`. Keep `summary.imprintHex` and the nonce for `verify_timestamp`. A `data.path` holding key material is `SECURITY_VIOLATION`. | |
| 27 | `inspect_timestamp` | The RFC 3161 report of a TimeStampResp (.tsr), a TimeStampToken (.tst) or a bare TSTInfo (auto-detected, or `as`): status, policy, message imprint, serial, genTime, accuracy, nonce, the TSA name as STATED, the CMS envelope. Parsing proves nothing. | ✓ |
| 28 | `verify_timestamp` | **The** time-stamp verdict: `token` or `response`, judged against what YOU say was stamped (`request`, `data` or `digestHex` — one is required), the TSA signature, its chain to `trustAnchors` at `at` with a critical timeStamping EKU (`allowNonCriticalTimeStampingEku`), revocation from the bytes you supply. `genTime` / `earliest` / `latest` only when valid. | ✓ |
| 29 | `inspect_private_key` | Describe a PKCS#8 key WITHOUT its password: format, version, kind, curve, algorithm, attributes, PBES2 parameters of an encrypted key. `tryImport: true` imports it non-extractable and reports the handle (needs `password` or `PKINATIVE_MCP_PASSWORD`, `keyType`, `rsaScheme` for RSA). No key byte, scalar or password in any result. | ✓ |
| 30 | `inspect_pkcs12` | Describe a PKCS#12 WITHOUT its password (`PKINATIVE_MCP_PASSWORD` unset — the variable counts as one): version, MAC construction (`pbmac1` or the legacy `pkcs12-kdf`), every SafeContents with its scheme, the bags of the plain ones. With `password`: `macVerified` and `opened` (every bag as an allow-list view); a wrong password on an encrypted SafeContents is `isError` `PKI_CRYPTO_DECRYPTION_FAILED` — `macVerified: false` is reported only when nothing is encrypted. | ✓ |
| 31 | `open_pkcs12` | Open a PKCS#12 in one call with `password`: PBMAC1 verified, PBES2 SafeContents decrypted, every key imported NON-EXTRACTABLE (described, never exported), certificates parsed, CRLs counted. The verdict is `valid` + `integrity` + `reasons[]`; `allowUnverifiedIntegrity: true` for a file without a MAC you trust; `rsaScheme` for an RSA key. `exportCertificates: true` attaches a PEM bundle of the certificates only. | ² |
| 32 | `describe_engine` | The offline preflight: server / engine / tool-API versions, Web Crypto `canVerify` / `canSign` / `canDecrypt`, the 22 default limits, the operator ceilings and every cap, the sandbox / cache / pinned-instant state, the 57 / 43 / 97 code vocabularies and the 21 wrapper codes, the doctrine `refusals` and the `unexposed` engine surface. `network` is always `'none'`. | ✓ |
| 33 | `explain_code` | Explain any code this server emits — a `PKI_*` error (class, engine class, when raised, CWE, remedy and the MCP input that lifts it), a `PKI_REASON_*`, a `PKI_DIAG_*` (severity) or a wrapper code; `list: true` enumerates, `kind` filters one vocabulary. | ✓ |
| 34 | `draft_governance_issue` | Draft a governance-compliant GitHub issue for **human** review (`targetRepo` `pkinative` / `pkinative-cli` / `pkinative-mcp`). Produces the markdown + a compliance report; **never submits**, no network. | ³ |

¹ `convert_pem` reads its input but can deliver a block as a sandbox file (`extractIndex` + `outputMode: 'file'`), so it is annotated `readOnlyHint: false` (`WRITES`).
² `open_pkcs12` is a verdict tool, but `exportCertificates: true` with `outputMode: 'file'` writes a PEM bundle into the sandbox, so its `readOnlyHint` is `false`.
³ `draft_governance_issue` is read-only in the default inline mode; `outputMode: 'file'` writes a `.md` into the sandbox, so its `readOnlyHint` is `false`.

The annotations are three fixed sets: `READ_ONLY` (`readOnlyHint: true`, `idempotentHint: true`) on the 23 read, verdict and meta tools marked ✓; `WRITES` (`idempotentHint: true`) on the deterministic producers `encode_asn1`, `encode_x509_structure`, `amend_cms`, `convert_pem`, `open_pkcs12`, `draft_governance_issue`; `PRODUCES` (`idempotentHint: false`) on `create_certificate`, `create_csr`, `sign_cms`, `create_ocsp_request`, `create_timestamp_request` (random serial / nonce, wall-clock instants, randomised ECDSA / RSA-PSS). `destructiveHint` and `openWorldHint` are always `false`.

**Shared fragments (every tool inlines them — no `$ref`).**

- **PKI input** — every certificate, CSR, CRL, OCSP, CMS, token, key or PKCS#12 input is an object with **exactly one** of `pem` (RFC 7468 text, starts with `-----BEGIN`), `derBase64` (the DER as base64, exactly once — no `data:` URI, not PEM) or `path` (relative to the sandbox, PEM or DER sniffed by its first bytes; needs `PKINATIVE_MCP_OUTPUT_DIR`). A single-object input holding several PEM blocks is refused — extract one with `convert_pem` or use a bundle input. Bundles (`trustAnchors`, `candidates`, `crls`, `ocspResponses`, `chain`, `path`) take ≤ 256 items and every PEM block of every item. Key-bearing extensions (`.key` `.p8` `.p12` `.pfx`) are accepted by the key tools only.
- **Content input** — the bytes signed or time-stamped (`content`, `data`): exactly one of `text` (UTF-8), `base64` or `path` (no extension rule), 128 MiB inline / 1 GiB by path.
- **Parse fragment** — `encodingRules` (`'der'` default, `'ber'`), `pemMode` (`'strict'` default, `'lax'`), `strict` (escalate the first warning to `PKI_STRICT_DIAGNOSTIC`) and `limits` (the 22 named `PkiLimits`, integers ≥ 1, never above the operator ceilings — §4) on every engine-touching tool.
- **Signer** (`create_certificate`, `create_csr`, `sign_cms`, `encode_x509_structure signature-algorithm`) — exactly one of `key` (PKCS#8, plain or PBES2-encrypted, PEM or DER) or `p12` (PBES2 + PBMAC1 only), `password` (XOR `PKINATIVE_MCP_PASSWORD`), `keyType` (`ec-p256` `ec-p384` `ec-p521` `ed25519` `ed448` `rsa` `rsa-pss`, for an encrypted key), `hash` (`SHA-1` `SHA-256` `SHA-384` `SHA-512`; refused for Ed25519 / Ed448), `rsaScheme` (`'pkcs1'` | `'pss'`, **required** for RSA), `saltLength` (PSS). `allowSha1` sits beside it.
- **Trust** (the verdict tools) — `trustAnchors` (required), `candidates`, `crls`, `ocspResponses`, `at`, `requireRevocation`, `purposes`, `policy` (`initialPolicySet`, `requireExplicitPolicy`, `inhibitPolicyMapping`, `inhibitAnyPolicy`).
- **Projection** (read and verdict tools) — `verbosity: 'summary'` and `fields` (≤ 16 dot-paths), §3.
- **Output** (artefact tools) — `outputMode` (`'base64'` default | `'file'`), `outputPath`, `encoding` (`'pem'` | `'der'` | `'hex'`), §4.
- **Diagnostics** — every result carries `diagnostics[]` (`{ code, severity, message, standard, path, offset? }`, de-duplicated, ≤ 200), `diagnosticCounts` and `diagnosticsTruncated`.

**Engine diagnostics (97 `PKI_DIAG_*` codes, pkinative 1.0.0).** A diagnostic is a non-fatal concern the engine raises while parsing or verifying (a serial longer than 20 octets, a missing key identifier, an unsorted SET, a low PBKDF2 count, …); the result is still produced. Every tool returns them in `structuredContent.diagnostics[]` with `severity: 'warning' | 'info'`; `strict: true` turns the first warning into `PKI_STRICT_DIAGNOSTIC` instead; an `info` never refuses. `explain_code` explains any of them; the full list with severities is in §6.

**Doctrine (engine-side, pkinative 1.0.0 — `describe_engine.refusals`):** no network, ever (no CRL / OCSP / AIA / TSA fetch — the evidence and the tokens are inputs; `create_ocsp_request` and `create_timestamp_request` produce bytes the caller transports); no key generation (bring keys from your HSM, KMS or `openssl genpkey`); no key export (non-extractable Web Crypto handles, allow-list key views, key-bearing files never written nor served); no writer for PKCS#8, PKCS#12, CRL, OCSP response or time-stamp response; SHA-1 refused by default (`allowSha1: true`); RSA has no default scheme (`rsaScheme` required); PBES2 / PBMAC1 only (a legacy RC2 / 3DES PKCS#12 is refused with the OpenSSL 3.4 conversion remedy); DSA, ML-DSA and unknown key kinds are parsed, never verified or signed (`PKI_REASON_SIGNATURE_NOT_CHECKED`, `UNSUPPORTED_KEY`); diagnostics are not errors; limits raise only by explicit input and never above the ceilings; randomness lives in the wrapper (`node:crypto`, reported as `randomSerial` / `randomNonce`).

## 2. Decision tree

```
What is this object?          → convert_pem (labels of a PEM text) then inspect_certificate / inspect_csr / inspect_crl /
                                inspect_ocsp_response / inspect_cms / inspect_timestamp / inspect_private_key / inspect_pkcs12
                                (facts + diagnostics; verbosity:'summary' for the scalars)
Is this certificate trustworthy? → verify_certificate_chain (RFC 5280 §6 verdict: path, signatures, validity at 'at', name,
                                purposes, policies, offline CRL / OCSP revocation) — NOT inspect_certificate.signature
Does the name / purpose fit?  → check_certificate_name (host name vs SAN, RFC 6125) / check_certificate_purpose (extended key
                                usage) — both run inside verify_certificate_chain when serverName / purposes are given
Why did a path fail / which path? → build_certificate_path (discovery, signatures NOT checked) /
                                validate_certificate_path (a path you ordered, signatures checked)
Is it revoked?                → check_crl_revocation / check_ocsp_status with the bytes YOU fetched
                                (create_ocsp_request builds the request); the engine never fetches
Sign / is this signature good? → sign_cms (CMS SignedData, attached or detached) · verify_cms (the verdict: signatures,
                                chains, time-stamps, revocation) vs inspect_cms (facts; signerSignature is a key check, not trust)
Time-stamps                   → create_timestamp_request / inspect_timestamp / verify_timestamp;
                                counter-stamp a CMS signer with amend_cms add-timestamp
Issue / request               → create_csr / create_certificate (keys come from you; nothing generates or exports a key here)
Keys                          → inspect_private_key / inspect_pkcs12 (no password needed) /
                                open_pkcs12 (password; key handles described, never exported)
Raw bytes                     → decode_asn1 / encode_asn1 / encode_x509_structure / decode_extension / resolve_oid /
                                compute_fingerprint
What can this server do here? → describe_engine (versions, Web Crypto capabilities, limits, ceilings, caps, sandbox,
                                the 57 / 43 / 97 code vocabularies, refusals)
A code you do not understand  → explain_code (PKI_* error, PKI_REASON_*, PKI_DIAG_* or a wrapper code)
Propose an upstream change    → draft_governance_issue (local draft, never submitted)

SECURITY POSTURE
  No network, ever: no CRL / OCSP / AIA / TSA fetch, no telemetry, no URL from any argument. The only filesystem boundary is
  PKINATIVE_MCP_OUTPUT_DIR (path inputs read from it, outputMode:'file' written under it, never overwritten); key-bearing
  files are never written nor served as resources.
  No key leaves: signing keys are non-extractable Web Crypto handles; every key / PKCS#12 report is an allow-list view;
  passwords (input or PKINATIVE_MCP_PASSWORD, never both) are never echoed, logged or cached.
  Doctrine, surfaced not hidden: no key generation or export, no PKCS#8 / PKCS#12 / CRL / OCSP-response writer; RSA needs
  rsaScheme (no default); SHA-1 only with allowSha1:true; PBES2 / PBMAC1 only; DSA / ML-DSA parsed but never verified;
  the 22 engine limits can be raised per call but never above the operator ceilings (LIMIT_CEILING_EXCEEDED names the variable).

COMMON PITFALLS
  Every PKI input is an object with exactly one of pem / derBase64 / path. A single-object input holding several PEM
  blocks is refused — use convert_pem extractIndex or a bundle input.
  Verdict tools (verify_*, check_*, validate_*, build_*, open_pkcs12) return valid:false + reasons[] in structuredContent
  for a negative verdict — never isError. Branch on reasons[].code. isError means the input itself was refused (a PKI_*
  code) or the call was wrong.
  Pin 'at' (ISO 8601) for reproducible, cacheable verdicts; omitted = PKINATIVE_MCP_AT or the wall clock (never cached).
  build_certificate_path never checks signatures (PKI_REASON_SIGNATURE_NOT_CHECKED is always present).
  A counter time-stamp stamps the signer's signature value (inspect_cms fields:['signerInfos.signature']), not the
  content. The OCSP CertID hash defaults to SHA-1 (RFC 6960); ask for 'SHA-256' explicitly.
  An encrypted PKCS#8 key needs its type (signer.keyType, or a certificate / public key input); an RSA key always
  needs rsaScheme.
  verbosity:'summary' keeps the scalar verdict; fields:[…] projects dot-paths — unmatched paths are reported in
  _meta.unmatchedFields.
```

The seven prompts (`prompts/get`) carry the long form: `verify_before_trust`, `issue_certificate`, `sign_and_timestamp`, `offline_revocation`, `open_keys_safely`, and the governance pair `governance_contract` / `draft_issue_workflow`.

## 3. Token-frugal responses

The 25 read, verdict and engine tools — every tool marked ✓ in §1 plus `convert_pem` and `open_pkcs12` — accept two optional inputs (defaults unchanged; `explain_code` accepts them but has no summary of its own, so `verbosity: 'summary'` returns its full result):

- `verbosity: 'summary'` — the tool's canonical scalar subset; drops the heavy arrays (decoded extensions, node trees, per-signer attributes, reason objects) but keeps the scalars you branch on.
- `fields: ['a', 'b.c']` — dot-path projection (≤ 16 paths; an array segment maps over every element), applied **after** `verbosity`. Every path that matched nothing — nested paths included — is omitted, and the result then carries `_meta.unmatchedFields` + `_meta.availableFields` so a typo is visible. A path holding a `__proto__`, `constructor` or `prototype` segment is `VALIDATION_ERROR`.

What `verbosity: 'summary'` keeps (every entry ends with `diagnosticCount`; a member in parentheses is present only when the input asked for it):

| Tool | Summary |
|---|---|
| `inspect_certificate` | `serialNumberHex`, `subjectString`, `issuerString`, `notBefore`, `notAfter`, `publicKey` (kind), `extensionKinds[]`, `selfIssued`, (`signatureValid`) |
| `inspect_csr` | `subjectString`, `publicKey`, `extensionKinds[]`, `challengePassword`, (`signatureValid`) |
| `inspect_crl` | `issuerString`, `thisUpdateIso`, `nextUpdateIso`, `crlNumber`, `entryCount`, `isDelta`, (`revoked`), (`signatureValid`) |
| `inspect_ocsp_response` | `status`, `responses[{ serialNumber, status }]`, `noncePresent`, (`signatureValid`) |
| `inspect_cms` | `version`, `contentTypeOid`, `contentLength`, `signerCount`, `signers[{ index, signingTime, timeStampTokens }]`, (`signerSignatureValid`) |
| `inspect_timestamp` | `as`, (`statusCode`), `genTime`, `serialNumber`, `imprintHex`, `hashAlgorithm` |
| `inspect_private_key` | `format`, `kind`, `curve`, `encrypted`, `scheme`, (`imported` as its `ok` boolean) |
| `inspect_pkcs12` | `version`, `macKind`, (`macVerified`), `contentCount`, `bagCount`, `bagKinds[]` |
| `verify_certificate_chain` | `valid`, `reasonCodes[]`, `pathLength`, `evaluatedAt`, `revocationEvidence` |
| `build_certificate_path` | `found`, `valid`, `reasonCodes[]`, `structuralReasonCodes[]`, `pathLength`, `explored`, `signaturesChecked: false`, `evaluatedAt` |
| `validate_certificate_path` | `valid`, `reasonCodes[]`, `failingReasonCodes[]`, `pathLength`, `signaturesChecked`, `signatureVerdicts[]`, `evaluatedAt` |
| `check_certificate_name` | `form`, `valid`, `reasonCodes[]`, `reference`, (`subject`), (`presented`), (`match`) |
| `check_certificate_purpose` | `valid`, `reasonCodes[]`, `purpose`, `purposeOid`, `subject`, `pathLength` |
| `check_crl_revocation` | `valid`, `reasonCodes[]`, `signatureVerified`, (`deltaSignatureVerified`), `evaluatedAt`, `crlNumber` |
| `check_ocsp_status` | `valid`, `reasonCodes[]`, `status`, `signatureVerified`, `responderAuthorized`, `responder`, `evaluatedAt` |
| `verify_cms` | `valid`, `reasonCodes[]`, `signers[{ index, valid, intact, reasonCodes }]`, `evaluatedAt` |
| `verify_timestamp` | `valid`, `reasonCodes[]`, `genTime`, `evaluatedAt` |
| `open_pkcs12` | `valid`, `integrity`, `reasonCodes[]`, `keyCount`, `certificateCount`, `crlCount` |
| `convert_pem` | `mode`, (`count` + `labels[]`), (`extracted`), (`label`, `sizeBytes`, `sha256`) |
| `resolve_oid` | `mode`, `count`, (`allValid`), (`total`, `hasMore`), (`oid`, `name`) |
| `compute_fingerprint` | `mode`, `algorithm`, `hex` |
| `decode_asn1` | `label`, `sizeBytes`, `nodeCount`, `rootTag`, `truncated`, (`value`), (`identical`) |
| `decode_extension` | `kind`, `oid`, `name`, `critical`, `sizeBytes` |
| `describe_engine` | `server`, `engine`, `capabilities`, `sandbox { enabled, cacheEnabled, pinnedInstant }`, `network` |

Smallest "is this certificate trustworthy?" probe: `verify_certificate_chain { leaf, trustAnchors, at, verbosity: 'summary', fields: ['valid', 'reasonCodes'] }`. The output schemas of these tools declare every property optional (`projectableOutputSchema`), so a projected `structuredContent` always validates against `outputSchema`.

**Artefacts** (the 8 artefact tools `create_certificate`, `create_csr`, `sign_cms`, `amend_cms`, `create_ocsp_request`, `create_timestamp_request`, `encode_asn1`, `encode_x509_structure`, and the attachments of `convert_pem extractIndex`, `decode_asn1 reencode` and `open_pkcs12 exportCertificates`) are delivered **once**: inline as an embedded `resource` content block — PEM as `text` (`application/x-pem-file`), DER as `blob` (`application/pkix-cert`, `application/pkcs10`, `application/pkix-crl`, `application/pkcs7-signature`, `application/pkcs7-mime`, `application/ocsp-request`, `application/timestamp-query`, `application/octet-stream`) — or as a `resource_link` in file mode, never duplicated into `structuredContent`, which carries `{ mode, encoding, sizeBytes, sha256, filePath?, hex?, summary }` plus the diagnostics. `sha256` is the SHA-256 of the DER bytes, the reproducibility proof. `encoding: 'hex'` puts the bytes in `structuredContent.hex` instead (inline only, ≤ 64 KiB).

## 4. Output modes & environment

- `outputMode: 'base64'` (default) — the artefact in the `resource` block (`encoding: 'pem'` → `text`, `'der'` → `blob`, `'hex'` → `structuredContent.hex`).
- `outputMode: 'file'` — writes inside `PKINATIVE_MCP_OUTPUT_DIR`. `outputPath` must be **relative**, no traversal / absolute / drive / UNC paths / NUL bytes, and end in an allowed extension: the PKI extensions minus the key-bearing ones for DER (`.pem .crt .cer .der .csr .p10 .crl .p7s .p7b .p7c .p7m .cms .pub .ocsp .ors .orq .tsq .tsr .tst .bin .asn1`), `.pem` for `encoding: 'pem'`, `.md .txt .json .pem` for text (governance drafts, PEM bundles). The file is written **exclusively** — an existing target is `OUTPUT_EXISTS`, never overwritten — and the result carries a `resource_link` (`pkinative://output/<path>`). File mode is never cached.
- **`PKINATIVE_MCP_OUTPUT_DIR`** — the single sandbox: `path` inputs are read from it, file output written under it, `resources/*` list and serve it. The real path of every file read and of every parent written must stay inside (a planted symlink or junction is `SECURITY_VIOLATION`). Unset = no file I/O at all; every tool works on inline PEM / base64; a relative value refuses to start. Key-bearing files (`.key .p8 .p12 .pfx`) are read by the key and signer tools only, never written, never listed nor served — and `resources/list` / `resources/read` refuse key material by **content** as well (a PEM key after a prefix, hidden among many blocks, a raw DER key behind junk, base64 key material in a text file), whatever the name. The `content.path` of `sign_cms` and the `data.path` of `create_timestamp_request` are content, never a key: a key-bearing extension or key material there is `SECURITY_VIOLATION`.
- **`PKINATIVE_MCP_CACHE_DIR`** — opt-in SHA-256-keyed response cache (1 h TTL, 256 MiB LRU, plaintext at rest; the key namespace carries the tool API, package and engine versions). A hit carries `_meta.cached: true`. **The cache gate** (`isCacheable`): never a `path` input (a path is a reference, not content), never a `password` or a `signer`, never `outputMode: 'file'`, never a `'random'` serial / nonce or a `'now'` instant, never a clock-dependent instant (an omitted `at` / `spec.notBefore` / `signingTime` without `PKINATIVE_MCP_AT`), never `describe_engine` (environment) or `draft_governance_issue` (environment embedded), and never any password-accepting tool while `PKINATIVE_MCP_PASSWORD` is set. Refusals are never persisted.
- **`PKINATIVE_MCP_PORT`** — opt-in Streamable HTTP on `127.0.0.1` (`POST /mcp`, stateless; `GET` / `DELETE` → 405; a foreign `Host` / `Origin` → 403; bodies up to 256 MiB accepted, above → 413). A value outside 1–65535 refuses to start. stdio otherwise.
- **`PKINATIVE_MCP_HTTP_TOKEN`** — opt-in bearer token for HTTP (≥ 16 characters, no whitespace; a weaker value refuses to start). When set, every `/mcp` request must carry `Authorization: Bearer <token>` or is answered `401` + `WWW-Authenticate`; compared constant-time, never logged. Without it HTTP mode has **no authentication** — any local process can reach it.
- **`PKINATIVE_MCP_PASSWORD`** — the operator-side password of the encrypted PKCS#8 key or PKCS#12 file the tools open (keeps the secret out of the model transcript). It counts as the password of **every** password-accepting tool (`inspect_private_key`, `inspect_pkcs12`, `open_pkcs12`, the `signer` of the signing tools), so "describe without a password" needs it unset. Exclusive with the per-call `password` input — both at once is `VALIDATION_ERROR`. Never logged; only its presence is reported at startup. A tool that does not open a key does not accept a `password`.
- **`PKINATIVE_MCP_AT`** — the pinned instant (ISO 8601 or epoch milliseconds, not `'now'`) every omitted `at` / `spec.notBefore` / `signingTime` falls back to, for reproducible verdicts and artefacts. Unset: the wall clock, and such a result is never cached. `evaluatedAtSource` / `notBeforeSource` / `signingTimeSource` say which (`input` | `pinned` | `clock`).
- **`PKINATIVE_MCP_MAX_INPUT_BYTES`** (default 67108864 = 64 MiB, ≥ 1024), **`PKINATIVE_MCP_MAX_KDF_ITERATIONS`** (default 10000000, ≥ 1), **`PKINATIVE_MCP_MAX_PATHS_EXPLORED`** (default 1000, ≥ 1) — the three operator ceilings over `limits.maxInputBytes` (also the decoded size cap of one PKI object), `limits.maxKdfIterations` / `limits.maxPkcs12KdfIterations` (the CPU bound of a hostile PBKDF2) and `limits.maxPathsExplored` (the RFC 5280 §6 work bound). A per-call value above its ceiling is `LIMIT_CEILING_EXCEEDED` with `data.env` naming the variable; a ceiling below the engine default tightens the default silently.

All 9 operator variables are declared in `server.json`, read **once at boot**; an invalid value refuses to start (one `fatal:` line on stderr); only the presence of a secret is logged.

**Caps** (`src/caps.ts`, all in `describe_engine.caps`): stdio frame / HTTP body 256 MiB; inline PKI input 128 MiB per call (sum of decoded `pem` / `derBase64`); inline content 128 MiB, content by path 1 GiB; inline artefact 50 MiB, file output 1 GiB, hex inline 64 KiB; attributes inline 256; bundle items 256; OIDs per call 1000; list limit 200 default / 2000 max; SHAKE output 1 MiB; password 4096 characters; diagnostics 200 per result; `fields` 16 paths; ASN.1 preview 32 bytes, tree 20 000 nodes; resources 1000 listed, walk depth 8, read 50 MiB; cache TTL 3600 s, 256 MiB.

**Limits** — the engine's 22 named `PkiLimits` (`describe_engine.defaultLimits`, [data/limits.json](data/limits.json)): `maxInputBytes` 64 MiB, `maxDepth` 64, `maxNodes` 200 000, `maxIntegerBytes` 8 192, `maxOidBytes` 256, `maxBerSegments` 10 000, `maxPemBlocks` 10 000, `maxExtensions` 256, `maxGeneralNames` 10 000, `maxNameAttributes` 1 024, `maxPolicies` 1 024, `maxChainLength` 10, `maxPolicyNodes` 4 096, `maxRevokedCertificates` 1 000 000, `maxOcspSingleResponses` 256, `maxPathsExplored` 1 000, `maxSignerInfos` 64, `maxAttributes` 256, `maxCmsCertificatesAndCrls` 1 024, `maxKdfIterations` 10 000 000, `maxPkcs12Bags` 4 096, `maxPkcs12KdfIterations` 10 000 000. Raise one through `limits.<name>` for trusted input only; the engine's `PKI_LIMIT_EXCEEDED` carries `data.limit` / `configured` / `observed` (+ `data.env` when a ceiling applies).

**Resources:** with the sandbox enabled, every regular file under it is listed by `resources/list` as `pkinative://output/<relative-path>` (template `pkinative://output/{+path}` from `resources/templates/list`; ≤ 1000 files, depth ≤ 8) and read by `resources/read` (PEM / Markdown / JSON / text as `text`, everything else as a base64 `blob`, ≤ 50 MiB). Key-bearing extensions are never listed and never served, and key material is refused by **content** anywhere in a file — a PEM key after a prefix, a key hidden among many blocks, a raw DER key behind junk, base64 key material inside a text file — not only by name (`SECURITY_VIOLATION`). An unknown URI is JSON-RPC `-32602` carrying `UNKNOWN_RESOURCE`.

**Privacy / network policy:** no telemetry; **no network code path exists** — no CRL, OCSP, AIA or TSA fetch, no GitHub, no URL taken from any argument, no operator-configurable endpoint. Bytes only ever flow back in the JSON-RPC response (or into the sandbox). Passwords and key bytes never reach a message, `_meta.error.data`, stderr, a cache file or a resource (the secret-leak suite holds it with needles computed from the fixtures).

**Protocol:** MCP 2026-07-28 (stateless, `server/discover`, the `_meta` `serverInfo` envelope, `resultType`, `ttlMs` / `cacheScope` hints, `Mcp-Method` / `Mcp-Name` headers over HTTP) on the MCP TypeScript SDK v2 (`@modelcontextprotocol/server` ^2.0.0), with automatic fallback to the legacy `initialize` handshake for 2024-10-07, 2024-11-05, 2025-03-26, 2025-06-18 and 2025-11-25 clients on stdio and HTTP. Cache hints: `tools/list` and `prompts/list` public 24 h, `server/discover` public 1 h, `resources/*` private, `ttlMs: 0`. A `tools/call` naming an unknown tool is a JSON-RPC protocol error (`-32602`, `[UNKNOWN_TOOL] Unknown tool: …`), not an `isError` result. Every tool carries `_meta.apiVersion` (`1.0.0`) and ≤ 2 executable `_meta.examples`. `tools/list` measures 427,850 bytes (budget 448 KiB); `serverInfo.instructions` 5,469 bytes (budget 8 KiB).

## 5. Recipes

Every call below is taken verbatim from [examples/](../examples/); fixture paths resolve under `<PKINATIVE_MCP_OUTPUT_DIR>/fixtures/` (the 42 OpenSSL-made TEST-ONLY files of `tests/fixtures/pki/`, password `test-only-password`, verdicts pinned at `2027-01-01T00:00:00Z`).

- **Verify before trust** (prompt `verify_before_trust`, [guides/VERIFICATION.md](guides/VERIFICATION.md)): `inspect_certificate` is facts, `verify_certificate_chain` is the verdict. [verify-certificate-chain-server.json](../examples/verify-certificate-chain-server.json):

  ```json
  { "tool": "verify_certificate_chain", "arguments": {
    "leaf": { "path": "fixtures/leaf.crt.pem" },
    "candidates": [{ "path": "fixtures/inter.crt.pem" }],
    "trustAnchors": [{ "path": "fixtures/root.crt.pem" }],
    "at": "2027-01-01T00:00:00Z",
    "serverName": { "host": "a.wild.example.test" },
    "purposes": ["serverAuth"],
    "verbosity": "summary" } }
  ```

  → `{ valid: true, reasonCodes: [], pathLength, evaluatedAt, … }`. The same chain at `"at": "2050-01-01T00:00:00Z"` is `valid: false` with `PKI_REASON_EXPIRED` — a verdict, not an error ([verify-certificate-chain-expired.json](../examples/verify-certificate-chain-expired.json)). A verdict without evidence says `revocationEvidence` is empty; add `crls` / `ocspResponses` + `requireRevocation: true` ([verify-certificate-chain-revoked.json](../examples/verify-certificate-chain-revoked.json) → `PKI_REASON_REVOKED`). `build_certificate_path` explains which intermediates a chain needs, signatures NOT checked ([build-certificate-path.json](../examples/build-certificate-path.json)); `validate_certificate_path` judges a path you ordered ([validate-certificate-path.json](../examples/validate-certificate-path.json)).

- **Offline revocation** (prompt `offline_revocation`, [guides/REVOCATION.md](guides/REVOCATION.md)): fetch the CRL (`crlDistributionPoints`) or query the responder (`authorityInfoAccess`) yourself. [create-ocsp-request.json](../examples/create-ocsp-request.json) builds the request you POST (`Content-Type: application/ocsp-request`):

  ```json
  { "tool": "create_ocsp_request", "arguments": {
    "certificate": { "path": "fixtures/leaf.crt.pem" },
    "issuer": { "path": "fixtures/inter.crt.pem" },
    "hashAlgorithm": "SHA-256", "nonce": "random", "encoding": "hex" } }
  ```

  Keep `summary.nonceHex` and `summary.certIdHex`, then judge the answer ([check-ocsp-status.json](../examples/check-ocsp-status.json)):

  ```json
  { "tool": "check_ocsp_status", "arguments": {
    "response": { "path": "fixtures/leaf.ocsp.der" },
    "certificate": { "path": "fixtures/leaf.crt.pem" },
    "issuer": { "path": "fixtures/inter.crt.pem" },
    "nonce": "1538349c433373ed058c291909df5b3e", "requireNonce": true,
    "at": "2027-01-01T00:00:00Z", "verbosity": "summary" } }
  ```

  CRL form: `check_crl_revocation { certificate, crl, issuer, at }` ([check-crl-revocation.json](../examples/check-crl-revocation.json)); a base + delta pair in [check-crl-revocation-delta.json](../examples/check-crl-revocation-delta.json); the facts of a list with `inspect_crl` ([inspect-crl.json](../examples/inspect-crl.json)).

- **Issue certificates** (prompt `issue_certificate`, [guides/SIGNING.md](guides/SIGNING.md)): keys come from the caller. The subject's side makes the request ([create-csr-round-trip.json](../examples/create-csr-round-trip.json)):

  ```json
  { "tool": "create_csr", "arguments": {
    "spec": { "subject": { "C": "FR", "O": "Acme", "CN": "svc.example.test" },
              "extensions": { "subjectAltName": { "dns": ["svc.example.test", "www.svc.example.test"] },
                              "keyUsage": ["digitalSignature"], "extendedKeyUsage": ["serverAuth"] } },
    "signer": { "key": { "path": "fixtures/leaf.key.pem" } }, "encoding": "der" } }
  ```

  The CA issues from it ([create-certificate-issue-leaf.json](../examples/create-certificate-issue-leaf.json)); the public key comes from the request, the AKI from the issuer, and the issuer signature is verified before the bytes return (`summary.signatureVerified`):

  ```json
  { "tool": "create_certificate", "arguments": {
    "spec": { "serialNumber": "0x1a2b3c", "subject": { "CN": "svc.example.test" },
              "notBefore": "2027-01-01T00:00:00Z", "validityDays": 90,
              "extensions": { "subjectAltName": { "dns": ["svc.example.test"] },
                              "extendedKeyUsage": ["serverAuth"], "keyUsage": ["digitalSignature"] } },
    "issuerCertificate": { "path": "fixtures/leaf.crt.pem" },
    "subjectPublicKey": { "path": "fixtures/leaf.csr.pem" },
    "signer": { "key": { "path": "fixtures/leaf.key.pem" } }, "encoding": "der" } }
  ```

  A self-signed CA omits `issuerCertificate` ([create-certificate-self-signed-ca.json](../examples/create-certificate-self-signed-ca.json), serial and dates pinned → reproducible bytes). Prove it: `verify_certificate_chain { leaf, trustAnchors: [the CA], at }`.

- **Sign and time-stamp** (prompt `sign_and_timestamp`, [guides/TIMESTAMPS.md](guides/TIMESTAMPS.md)): [sign-cms-detached-then-verify.json](../examples/sign-cms-detached-then-verify.json):

  ```json
  { "tool": "sign_cms", "arguments": {
    "content": { "path": "fixtures/content.txt" }, "detached": true,
    "certificate": { "path": "fixtures/leaf.crt.pem" }, "chain": [{ "path": "fixtures/inter.crt.pem" }],
    "signingTime": "2027-01-01T00:00:00Z", "signer": { "key": { "path": "fixtures/leaf.key.pem" } } } }
  ```

  A counter time-stamp stamps the **signature value**, not the document: `inspect_cms { signedData, fields: ["signerInfos.signature", "signerInfos.sid", "signerSignature"] }` ([inspect-cms-signature-value.json](../examples/inspect-cms-signature-value.json)) → hash it → `create_timestamp_request { digestHex, nonce: "random" }` ([create-timestamp-request-digest-hex.json](../examples/create-timestamp-request-digest-hex.json)) → POST the `.tsq` to your TSA yourself → `amend_cms { signedData, operation: "add-timestamp", token: { the .tsr } }` — a token over anything else is refused before a byte is written ([amend-cms-add-timestamp-refused.json](../examples/amend-cms-add-timestamp-refused.json)). Then the one verdict:

  ```json
  { "tool": "verify_cms", "arguments": {
    "signedData": { "derBase64": "<base64 from step 1>" }, "content": { "path": "fixtures/content.txt" },
    "trustAnchors": [{ "path": "fixtures/root.crt.pem" }],
    "requireSigningCertificate": true, "requireAlgorithmProtection": true,
    "at": "2027-01-01T00:00:00Z", "verbosity": "summary" } }
  ```

  A TSA response is judged with `verify_timestamp { response, request, data, trustAnchors, at }` ([verify-timestamp-response-request.json](../examples/verify-timestamp-response-request.json)); a bare token against the digest it stamps in [verify-timestamp-token-digest.json](../examples/verify-timestamp-token-digest.json).

- **Open keys safely** (prompt `open_keys_safely`, [guides/KEYS.md](guides/KEYS.md)): describe first, without a password (and with `PKINATIVE_MCP_PASSWORD` unset — the variable counts as one) — `inspect_private_key { key: { path: "fixtures/leaf.key.enc.pem" } }` ([inspect-private-key-describe.json](../examples/inspect-private-key-describe.json)) tells the scheme and PBKDF2 parameters; `inspect_pkcs12 { pkcs12: { path: "fixtures/leaf.p12" }, verbosity: "summary" }` ([inspect-pkcs12-describe.json](../examples/inspect-pkcs12-describe.json)) tells the MAC kind and lists the bags. Then open ([open-pkcs12-export.json](../examples/open-pkcs12-export.json)):

  ```json
  { "tool": "open_pkcs12", "arguments": {
    "pkcs12": { "path": "fixtures/leaf.p12" }, "password": "test-only-password", "exportCertificates": true } }
  ```

  → `integrity: 'verified'`, the key as a non-extractable handle (described, never exported), the certificates as a PEM bundle. Without a password the call is `SECRET_REQUIRED` ([open-pkcs12-no-password.json](../examples/open-pkcs12-no-password.json)); an RSA key needs `rsaScheme` ([open-pkcs12-rsa.json](../examples/open-pkcs12-rsa.json)); a legacy file is described before anyone types a password ([inspect-pkcs12-legacy.json](../examples/inspect-pkcs12-legacy.json)). Prefer `PKINATIVE_MCP_PASSWORD` to keep the password out of the transcript.

- **Names, purposes and fingerprints:** `check_certificate_name { certificate, host }` ([check-certificate-name-wildcard.json](../examples/check-certificate-name-wildcard.json)) and `check_certificate_purpose { certificate, chain, purpose }` ([check-certificate-purpose-server-auth.json](../examples/check-certificate-purpose-server-auth.json)) — both run inside `verify_certificate_chain` when `serverName` / `purposes` are given; `compute_fingerprint { input }` ([compute-fingerprint-sha256.json](../examples/compute-fingerprint-sha256.json)), `mode: 'key-id'` for the subjectKeyIdentifier a CSR's key will carry ([compute-fingerprint-key-id.json](../examples/compute-fingerprint-key-id.json)).
- **Raw bytes:** `decode_asn1 { input, fields: ["nodes.path", "nodes.tagName", "nodes.oidName", "nodeCount"] }` to find a `nodePath` ([decode-asn1-tree.json](../examples/decode-asn1-tree.json)), then `read` a typed value ([decode-asn1-read.json](../examples/decode-asn1-read.json)); `encode_asn1` from a JSON spec ([encode-asn1-algorithm-identifier.json](../examples/encode-asn1-algorithm-identifier.json)); `encode_x509_structure` for one building block ([encode-x509-structure-san.json](../examples/encode-x509-structure-san.json)); `decode_extension` for one extnValue ([decode-extension-basic-constraints.json](../examples/decode-extension-basic-constraints.json)); `resolve_oid` ([resolve-oid-name.json](../examples/resolve-oid-name.json)); `convert_pem` to list or extract blocks ([convert-pem-decode.json](../examples/convert-pem-decode.json), [convert-pem-extract-hex.json](../examples/convert-pem-extract-hex.json)).
- **Preflight and codes:** `describe_engine { verbosity: "summary" }` once per session ([describe-engine.json](../examples/describe-engine.json)); `explain_code { code }` for any code ([explain-code.json](../examples/explain-code.json)); `explain_code { list: true, kind: "reason" }` for a vocabulary ([explain-code-list-reasons.json](../examples/explain-code-list-reasons.json)).
- **Propose an upstream change:** `draft_governance_issue` ([draft-governance-issue.json](../examples/draft-governance-issue.json)) → review the draft + compliance report → a **human** submits it to GitHub (the server never does). See [guides/AI_GOVERNANCE.md](guides/AI_GOVERNANCE.md).

## 6. Error reference

A refused call is `isError: true` with `content[0].text` = `<tool> failed [CODE]: message` and `_meta.error = { code, message, data }`. `data` carries the machine-readable detail: for an engine refusal `errorClass` (the coarse class), `engineError` (the `PkiError` subclass), `path` / `offset` / `algorithm` / `limit` / `configured` / `observed` / `env` where the engine knows them, and `remedy` phrased as an MCP input. Branch on `code`, never on the message. Three vocabularies never appear as `code`: a `PKI_REASON_*` is returned in `reasons[]` of a verdict (`valid: false`, never `isError`), a `PKI_DIAG_*` in `diagnostics[]`, and a tool name that does not exist is a JSON-RPC `-32602` protocol error. Machine-readable registries: [data/errors.json](data/errors.json), [data/reasons.json](data/reasons.json), [data/diagnostics.json](data/diagnostics.json).

### 6.1 Wrapper codes (21)

The server boundary: validation, sandbox, caps, secrets, output (`src/wrapper-codes.ts`; `explain_code` serves the same table).

| `code` | Meaning | Fix |
|--------|---------|-----|
| `VALIDATION_ERROR` | The input failed the schema: wrong type / bound / enum, an unknown or misspelt key (top-level or nested — every object is strict), none or several of the exclusive members (`pem` / `derBase64` / `path`; `text` / `base64` / `path`; `signer.key` / `signer.p12`), a spec member the structure does not define, SHA-1 without `allowSha1`, a password given twice (input and `PKINATIVE_MCP_PASSWORD`), a `delta` that is not a delta CRL, a counter time-stamp whose imprint is not over the signature value (`data.detail` `PKI_REASON_TSP_IMPRINT_MISMATCH`), `encoding: 'hex'` with file output, a `fields` path holding a `__proto__` / `constructor` / `prototype` segment, `resolve_oid decode` with both `hex` and `input` | Re-read the field schema (the message names the path); pass exactly one input form. |
| `INPUT_TOO_LARGE` | A decoded inline input, the sum of inline inputs, or a sandbox file exceeds a cap (the effective `maxInputBytes` for a PKI object, 128 MiB per call inline, 1 GiB for a content path) | Pass the bytes through a sandbox path, split the input, or raise `PKINATIVE_MCP_MAX_INPUT_BYTES` for trusted input only. |
| `INPUT_NOT_FOUND` | A `path` input does not exist in the sandbox (a dangling link too) or is not a regular file | Check the relative path (`resources/list` shows the sandbox); drop the file into `PKINATIVE_MCP_OUTPUT_DIR`. |
| `INVALID_PATH` | A path member is empty or not a string | Pass a non-empty relative path. |
| `INVALID_EXTENSION` | A `path` input or `outputPath` does not end in an allowed extension (PKI inputs: `.pem .crt .cer .der .csr .p10 .crl .p7s .p7b .p7c .p7m .cms .p12 .pfx .key .p8 .pub .ocsp .ors .orq .tsq .tsr .tst .bin .asn1`; outputs: the same minus the key-bearing ones; `.pem` for `encoding: 'pem'`; `.md .txt .json .pem` for text) | Fix the extension (`content.path` is not subject to it). |
| `SECURITY_VIOLATION` | File I/O requested with `PKINATIVE_MCP_OUTPUT_DIR` unset; a path with a NUL byte; an absolute / drive / UNC path; a path escaping the sandbox; a real path (symlink or junction) outside it on a read or a write; an `outputPath` naming a key-bearing extension; an attempt to extract, dump, wrap or serve private-key material (`convert_pem extractIndex` / `encode`, `decode_asn1`, `encode_asn1`, `resources/list` / `resources/read` — by content anywhere in the file, not only by name); a `content.path` of `sign_cms` or `data.path` of `create_timestamp_request` naming a key-bearing extension or holding key material | Set `PKINATIVE_MCP_OUTPUT_DIR`; pass relative paths only; remove the link; open keys with `inspect_private_key` / `inspect_pkcs12` / `open_pkcs12` instead; sign content, never a key file. |
| `OUTPUT_TOO_LARGE` | An inline artefact above 50 MiB, a hex artefact above 64 KiB, a file output above 1 GiB, a resource above the 50 MiB read cap, or a text artefact above 50 MiB | `outputMode: 'file'` with `PKINATIVE_MCP_OUTPUT_DIR` set; `encoding: 'der'` or `'pem'` instead of `'hex'`. |
| `OUTPUT_EXISTS` | The target file already exists in the sandbox — the server never overwrites | Choose another `outputPath`, or remove the file yourself. |
| `MISSING_OUTPUT_PATH` | `outputMode: 'file'` without `outputPath` | Pass a relative `outputPath`. |
| `IO_ERROR` | A filesystem operation failed (permissions, disk full, …); the message carries the errno, never an absolute path or an OS message | Fix the sandbox directory; a partial file was removed. |
| `LIMIT_CEILING_EXCEEDED` | A `limits.*` value above its operator ceiling: `maxInputBytes` above `PKINATIVE_MCP_MAX_INPUT_BYTES`, `maxKdfIterations` / `maxPkcs12KdfIterations` above `PKINATIVE_MCP_MAX_KDF_ITERATIONS`, `maxPathsExplored` above `PKINATIVE_MCP_MAX_PATHS_EXPLORED` (`data.env` names the variable) | Lower the value (or omit it), or the operator raises the ceiling in the server environment for trusted input only. |
| `UNKNOWN_RESOURCE` | `resources/read` with a URI outside `pkinative://output/`, an empty path, or a file that does not exist — surfaced as JSON-RPC error **`-32602`** (Invalid params), the code carried in the message | List URIs with `resources/list`. |
| `GOVERNANCE_VIOLATION` | A `draft_governance_issue` draft breaks the AI-governance contract (proposes a runtime dependency, embeds a private key or a password, has no reproduction code block, or `duplicateSearchPerformed: false`) | Remove the dependency proposal or the secret, include the reproduction, confirm the duplicate search. |
| `SECRET_REQUIRED` | An encrypted PKCS#8 key, a PKCS#12 file or a MAC check needs a password and none was given | Pass the `password` input, or set `PKINATIVE_MCP_PASSWORD` in the server environment (never both). |
| `KEY_TYPE_REQUIRED` | An encrypted PKCS#8 key reveals its type only once decrypted, and neither `signer.keyType` nor a certificate / public key input names it | Pass `signer.keyType` (`ec-p256` \| `ec-p384` \| `ec-p521` \| `ed25519` \| `ed448` \| `rsa` \| `rsa-pss`), or the matching certificate / `subjectPublicKey` input. |
| `RSA_SCHEME_REQUIRED` | An RSA key (PKCS#8 or inside a PKCS#12) was given without `rsaScheme`: pkinative has no default RSA signature scheme (its ADR 0015) | `rsaScheme: 'pkcs1'` (RSASSA-PKCS1-v1_5) or `'pss'` (RSA-PSS). |
| `KEY_MISMATCH` | The signing key does not belong to the certificate, the issuer or the subject public key it was paired with (the artefact was verified after signing and refused) | Pair the key with its own certificate / public key. |
| `UNSUPPORTED_KEY` | A key algorithm Web Crypto cannot sign with on this host (an unknown OID, a non-NIST curve, Ed448 where unsupported) | Use an EC P-256 / 384 / 521, RSA, Ed25519 or (where supported) Ed448 key. |
| `NOT_FOUND` | A named element is absent: an extension kind the certificate lacks, a `nodePath` step, a `signerIndex` out of range, an `extractIndex` past the last block, an unknown code in `explain_code` | Inspect the object first (the message names what exists). |
| `ENGINE_VERDICT` | A one-call engine operation (opening a PKCS#12 to sign) came back negative for a reason that is neither a wrong password nor a scheme or cipher refusal (`data.reasons` carries the `PKI_REASON_*` codes) | Read `data.reasons`; `allowUnverifiedIntegrity: true` for a file whose origin you trust. |
| `ENGINE_ERROR` | The engine threw something that is not a `PkiError` (a bug — `data.errorClass: internal`); also the call stack exhausted inside a raised `limits.maxDepth`, coded with the remedy in the message | Lower `limits.maxDepth` for the stack case; otherwise report it with a reproduction via `draft_governance_issue` (`targetRepo: 'pkinative'`). |
| `UNKNOWN_TOOL` | **Protocol error, not a tool result:** `tools/call` named a tool that does not exist — JSON-RPC error **`-32602`** with message `[UNKNOWN_TOOL] Unknown tool: <name>` (MCP classifies unknown tools as protocol errors; `isError: true` is reserved for execution failures) | List tools with `tools/list`; names are lower-snake-case. |

### 6.2 Engine error codes (57 `PKI_*`)

Passed through verbatim from pkinative 1.0.0 (frozen vocabulary: removal or renaming is semver-major upstream), with `data.errorClass` (the coarse class an agent branches on second) and `data.engineError` (the subclass). The remedy column names the MCP input that lifts the refusal when one does; otherwise the input itself must change (`explain_code` carries the engine's full remedy text).

| `code` | Class | Engine class | Raised when | Remedy |
|---|---|---|---|---|
| `PKI_INVALID_INPUT` | input | PkiError | A value of the wrong type reached the engine (not reachable through the schemas in normal use) | Pass the input in one of the documented forms. |
| `PKI_INVALID_OPTION` | usage | PkiError | An option value is outside its documented domain (an unknown encoding rule, PEM mode, fingerprint algorithm, curve, SHAKE length, freshness tolerance) | Correct the option; the schemas refuse most of these as `VALIDATION_ERROR` first. |
| `PKI_API_MISUSE` | usage | PkiError | A documented precondition is broken: DER re-encoding of an indefinite-length BER value, an OCSP nonce outside 1–32 octets, a `subjectPublicKey` that is not one SubjectPublicKeyInfo, an extension value that is not one DER value, a signed-only attribute added as unsigned | The tool description (the inputs given are incomplete or inconsistent for this input). |
| `PKI_STRICT_DIAGNOSTIC` | check | PkiError | `strict: true` and the operation reported a warning; the message carries the diagnostic code | `strict: false`, or fix the producer the diagnostic names. |
| `PKI_INTERNAL` | internal | PkiError | An engine invariant broke (a pkinative bug) | Report it with the input that triggers it (`draft_governance_issue`, `targetRepo: 'pkinative'`). |
| `PKI_ASN1_TRUNCATED` | parse | PkiEncodingError | A tag, length or content runs past the end of the input or of its enclosing value | Obtain the whole DER object. |
| `PKI_ASN1_TAG_INVALID` | parse | PkiEncodingError | A high-tag-number identifier is non-minimal or does not fit in 31 bits | The encoder is broken (X.690 requires the shortest form). |
| `PKI_ASN1_LENGTH_INVALID` | parse | PkiEncodingError | The initial length octet is 0xFF | The input is corrupt or is not ASN.1. |
| `PKI_ASN1_LENGTH_NON_MINIMAL` | parse | PkiEncodingError | Under DER, a length uses more octets than necessary | `encodingRules: 'ber'` (the producer wrote BER, not DER). |
| `PKI_ASN1_LENGTH_OVERFLOW` | parse | PkiEncodingError | A declared length exceeds the bytes remaining | The input is truncated or crafted; trust no part of it. |
| `PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN` | parse | PkiEncodingError | Under DER, a constructed value uses the indefinite length form | `encodingRules: 'ber'` (indefinite lengths are BER; common in CMS). |
| `PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN` | parse | PkiEncodingError | Under DER, a BIT STRING, OCTET STRING or character string is constructed | `encodingRules: 'ber'` (constructed strings are BER). |
| `PKI_ASN1_CONSTRUCTED_FORM_INVALID` | parse | PkiEncodingError | A universal type appears in a form its definition forbids (a primitive SEQUENCE, a constructed INTEGER, …) | The input is corrupt, or is not the ASN.1 it claims to be. |
| `PKI_ASN1_EOC_UNEXPECTED` | parse | PkiEncodingError | An end-of-contents marker outside an indefinite-length value, or malformed | The input is corrupt. |
| `PKI_ASN1_TRAILING_DATA` | parse | PkiEncodingError | Bytes remain after the outermost value | Pass exactly one object; `decode_asn1 sequence: true` for concatenated objects; `allowTrailingData: true` (`decode_asn1`, `inspect_cms`, `verify_cms`) when the container defines what follows. |
| `PKI_ASN1_UNEXPECTED_TAG` | parse | PkiEncodingError | A reader or parser received a value of another type than its definition requires | Check that the input is the structure the tool expects. |
| `PKI_ASN1_BOOLEAN_INVALID` | parse | PkiEncodingError | A BOOLEAN with content other than one octet, or under DER a TRUE other than 0xFF | `encodingRules: 'ber'` (a non-0xFF TRUE is BER). |
| `PKI_ASN1_INTEGER_INVALID` | parse | PkiEncodingError | An INTEGER / ENUMERATED with no content or a non-minimal two's complement | The encoder is broken. |
| `PKI_ASN1_INTEGER_UNREPRESENTABLE` | parse | PkiEncodingError | A number reader received an INTEGER outside ±(2^53 − 1), or a small field holds an oversized value | `decode_asn1 read: 'integer'` returns big values as decimal strings. |
| `PKI_ASN1_BIT_STRING_INVALID` | parse | PkiEncodingError | A BIT STRING with no content, unused bits above 7, or under DER non-zero padding bits | The encoder is broken. |
| `PKI_ASN1_NULL_INVALID` | parse | PkiEncodingError | A NULL has content octets | The input is corrupt. |
| `PKI_ASN1_STRING_INVALID` | parse | PkiEncodingError | A string's octets are outside its type (invalid UTF-8, a surrogate BMPString, a non-ASCII IA5String, …) | The issuer encoded the value wrongly; `decode_asn1` still shows the raw bytes. |
| `PKI_ASN1_TIME_INVALID` | parse | PkiEncodingError | A UTCTime / GeneralizedTime off its DER form or naming an impossible instant | The issuer encoded the time wrongly; RFC 5280 leaves no lenient reading. |
| `PKI_ASN1_VALUE_OUT_OF_RANGE` | input | PkiEncodingError | An encoder received a value its type cannot represent (a tag above 2^31 − 1, a year outside 0000–9999, a character outside the string type) | Pass a value within the encoder's range (`encode_asn1`, `encode_x509_structure`). |
| `PKI_OID_INVALID` | parse | PkiEncodingError | An OID is empty, malformed, or a dotted string is not two or more arcs with a first arc of 0, 1 or 2 | `resolve_oid mode: 'validate'` reports the fault instead of failing. |
| `PKI_PEM_NO_BLOCK` | parse | PkiEncodingError | The text contains no `-----BEGIN` line on a line of its own | Pass the PEM text itself (or `derBase64` for DER); `pemMode: 'lax'` for boundary lines with surrounding whitespace. |
| `PKI_PEM_LABEL_INVALID` | input | PkiEncodingError | A BEGIN / END label contains characters outside the RFC 7468 grammar | Fix the label (`convert_pem mode: 'encode' label`). |
| `PKI_PEM_LABEL_MISMATCH` | parse | PkiEncodingError | The END label differs from the BEGIN label | The text was spliced or corrupted. |
| `PKI_PEM_UNEXPECTED_LABEL` | input | PkiEncodingError | A block's label is not the one the tool asked for (PRIVATE KEY where CERTIFICATE is expected) | `convert_pem mode: 'decode'` (lists the labels present). |
| `PKI_PEM_UNTERMINATED` | parse | PkiEncodingError | A BEGIN line has no matching END line | Obtain the complete PEM; `pemMode: 'lax'` when the END line carries whitespace. |
| `PKI_PEM_BASE64_INVALID` | parse | PkiEncodingError | The block body is not canonical base64 (alphabet, padding, or in strict mode lines longer than 64 characters) | `pemMode: 'lax'` (whitespace, line length, headers); a missing `=` padding must be restored first. |
| `PKI_PEM_HEADERS_FORBIDDEN` | unsupported | PkiEncodingError | Strict mode met RFC 1421 headers (`Proc-Type`, …) inside a block | `pemMode: 'lax'` reads them. |
| `PKI_X509_STRUCTURE_INVALID` | parse | PkiCertificateError | Well-formed DER that is not the structure the reader expects (certificate, CSR, CRL and key are four different ones) | Pass the right object to the right tool. |
| `PKI_X509_VERSION_INVALID` | parse | PkiCertificateError | A certificate version other than v1 / v2 / v3, or a request version other than v1 | The input is not a version RFC 5280 / RFC 2986 defines. |
| `PKI_X509_NAME_INVALID` | parse | PkiCertificateError | A Name is not a SEQUENCE OF SET OF AttributeTypeAndValue, an RDN is empty, or a value is not one ASN.1 value | The issuer encoded the name wrongly. |
| `PKI_X509_VALIDITY_INVALID` | parse | PkiCertificateError | Validity is not two times | The issuer encoded the validity wrongly. |
| `PKI_X509_SPKI_INVALID` | parse | PkiCertificateError | SubjectPublicKeyInfo is malformed, or a recognised key does not match its definition | The issuer encoded the public key wrongly. |
| `PKI_X509_UNIQUE_ID_INVALID` | parse | PkiCertificateError | An issuerUniqueID / subjectUniqueID is malformed or out of order | The issuer encoded the certificate wrongly. |
| `PKI_X509_EXTENSIONS_EMPTY` | parse | PkiCertificateError | An extensions field (or extensionRequest) is present but empty | The issuer encoded the certificate wrongly (RFC 5280 requires at least one). |
| `PKI_X509_EXTENSION_DUPLICATE` | parse | PkiCertificateError | Two extensions (or two request attributes) share one OID | The structure is refused: which instance a verifier reads is undefined. |
| `PKI_X509_EXTENSION_MALFORMED` | parse | PkiCertificateError | A recognised extension's value does not match its ASN.1 definition | `inspect_certificate rawExtensions: true` (keeps every extension undecoded), or `decode_asn1` on the value. |
| `PKI_X509_GENERAL_NAME_INVALID` | parse | PkiCertificateError | A GeneralName with an unknown tag, an iPAddress of the wrong length, or a non-ASCII IA5String name | The issuer encoded the name wrongly. |
| `PKI_LIMIT_EXCEEDED` | limit | PkiLimitError | An input exceeds one of the 22 `PkiLimits` (`data.limit`, `configured`, `observed`, and `data.env` when a ceiling applies) | `limits.<limit>` for trusted input only, never above the operator ceiling. |
| `PKI_LIMIT_INVALID` | usage | PkiLimitError | `limits` names an unknown bound or a value that is not a positive integer (unreachable: the schema refuses it first) | Use the 22 documented keys with integers ≥ 1. |
| `PKI_CRYPTO_UNAVAILABLE` | crypto | PkiCryptoError | Web Crypto has no `importKey` / `verify` on this runtime | Run on Node 22 or later (`describe_engine.capabilities`). |
| `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` | unsupported | PkiCryptoError | A signature algorithm outside the set pkinative verifies (MD2 / MD5, exotic PSS parameters); `data.algorithm` carries the OID | Verify it with another tool; MD2 / MD5 are refused by design. |
| `PKI_CRYPTO_KEY_UNSUPPORTED` | unsupported | PkiCryptoError | A key family Web Crypto cannot verify or sign with here (a non-NIST curve, DSA, X25519, Ed448 on some runtimes, an id-RSASSA-PSS key under PBES2 on Node 22); `data.algorithm` carries the OID | Use EC P-256 / 384 / 521, RSA, Ed25519 (or Ed448 where supported); try another runtime before concluding the key is at fault. |
| `PKI_CRYPTO_ALGORITHM_REFUSED` | security | PkiCryptoError | The signature is over SHA-1 (refused by policy) | `allowSha1: true` (only for legacy material you already trust; an archival fact, not an authentication decision). |
| `PKI_CRYPTO_DECRYPTION_FAILED` | password | PkiCryptoError | A PBES2 payload or shrouded key did not decrypt with the key derived from the password (wrong password, altered ciphertext, or a key of another algorithm); also a PKCS#12 MAC mismatch on the signer path | Check the password (the `password` input or `PKINATIVE_MCP_PASSWORD`); then the algorithm named for the key. |
| `PKI_CMS_STRUCTURE_INVALID` | parse | PkiCmsError | Well-formed DER that does not match the RFC 5652 / RFC 3161 module (`data.path` names the field) | Pass the whole ContentInfo (a `.p7s`, `.p7m` or a PDF /Contents sliced to its DER length), not a bare SignedData. |
| `PKI_CMS_CONTENT_TYPE_UNEXPECTED` | input | PkiCmsError | A ContentInfo of another type than the one read (enveloped / encrypted / authenticated data, a SignedData that is not a time-stamp) | Use the reader for the type you have; enveloped data is never opened here. |
| `PKI_CMS_VERSION_UNSUPPORTED` | unsupported | PkiCmsError | A SignedData version outside 1, 3, 4, 5, or a TSTInfo / TimeStampReq version other than 1 | Regenerate the structure with a conforming producer. |
| `PKI_CMS_CONTENT_NOT_OCTET_STRING` | unsupported | PkiCmsError | The encapsulated content is not an OCTET STRING (Authenticode-style PKCS #7) | Use a tool built for that profile. |
| `PKI_KEY_STRUCTURE_INVALID` | parse | PkiKeyError | Well-formed DER that does not match the RFC 5958 PKCS#8 / RFC 7292 PKCS#12 module (`data.path` names the field) | Decode the right PEM label (PRIVATE KEY / ENCRYPTED PRIVATE KEY); read a `.p12` as binary. |
| `PKI_KEY_VERSION_UNSUPPORTED` | unsupported | PkiKeyError | A PrivateKeyInfo version other than 0 / 1, or a PFX version other than 3 | Re-export the key from the tool that owns it. |
| `PKI_KEY_ENCRYPTION_UNSUPPORTED` | security | PkiKeyError | A key or bag encrypted with a scheme other than PBES2 + PBKDF2 + AES-CBC (RFC 7292 Appendix C RC2 / 3DES, PBES1, another KDF or cipher, public-key privacy mode) | Convert once with OpenSSL 3.4 or later: `openssl pkcs12 -in legacy.p12 -legacy -aes256 -out bundle.pem`, then `openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12` (delete `bundle.pem` afterwards); for a key alone `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256`. |
| `PKI_KEY_MAC_UNSUPPORTED` | security | PkiKeyError | A PKCS#12 MAC that is not RFC 9579 PBMAC1 (the RFC 7292 Appendix B KDF, or public-key integrity mode) was asked to be verified | `allowUnverifiedIntegrity: true` (`open_pkcs12`; only for a file whose origin you trust), or re-export it with `openssl pkcs12 -export -pbmac1_pbkdf2`. |

### 6.3 Verdict reasons (43 `PKI_REASON_*`)

Returned in `reasons[]` (`{ code, message, standard, path, errorCode?, limit? }`) of a verdict tool — never thrown, never `isError`. The remedy of a reason comes from `explain_code` (and `open_pkcs12` appends the MCP remedy to its PKCS#12 reasons). `verbosity: 'summary'` keeps them as `reasonCodes[]`.

| `code` | Returned when | Remedy |
|---|---|---|
| `PKI_REASON_INPUT_MALFORMED` | The bytes are not the structure they claim to be (`errorCode` carries the `PKI_*` the parser would have thrown) | Read `errorCode`; fix or replace the input. |
| `PKI_REASON_NOT_YET_VALID` | `at` is before a certificate's notBefore | Validate inside the window, or obtain a certificate already valid. |
| `PKI_REASON_EXPIRED` | `at` is after a certificate's notAfter | Renew the certificate; an earlier `at` is only correct when checking a signature made then. |
| `PKI_REASON_NAME_MISMATCH` | No subjectAltName entry matches the host / address asked about (RFC 6125) | The certificate is not for that host; a matching CN counts only under `allowCommonNameFallback`. |
| `PKI_REASON_PURPOSE_NOT_PERMITTED` | A certificate on the path does not name the purpose (or carries no extKeyUsage under `requireExplicitPurpose`) | Ask the issuer for the purpose; `restrictIssuers: false` is the literal-RFC reading for an internal PKI. |
| `PKI_REASON_UNKNOWN_CRITICAL_EXTENSION` | A certificate carries a critical extension the engine does not recognise | RFC 5280 requires refusal; the issuer must drop or document the extension. |
| `PKI_REASON_NAME_NOT_PERMITTED` | A name falls outside the permitted subtrees a CA above set | The certificate names the wrong host or was issued under the wrong CA. |
| `PKI_REASON_NAME_EXCLUDED` | A name falls inside a subtree a CA above excluded | An exclusion wins over every permission; no CA below can grant it back. |
| `PKI_REASON_REVOKED` | A covering, authenticated CRL or OCSP response says revoked (the message carries the revocation date) | A signature made before that instant may still be good; decide with the date. |
| `PKI_REASON_REVOCATION_STALE` | The list or answer has no nextUpdate, or it passed beyond `staleTolerance`, or thisUpdate lies beyond `futureTolerance` | Fetch a current list / response. |
| `PKI_REASON_REVOCATION_WRONG_ISSUER` | The list names a different issuer than the certificate | Use the list published by the certificate's issuer. |
| `PKI_REASON_REVOCATION_OUT_OF_SCOPE` | The list's issuingDistributionPoint excludes this certificate | Fetch the list published at the distribution point the certificate names. |
| `PKI_REASON_REVOCATION_PARTIAL` | The list covers only some reasons | Supply the other lists the CA publishes; `verify_certificate_chain` accumulates them. |
| `PKI_REASON_REVOCATION_UNKNOWN` | No authenticated evidence covers the end-entity certificate (`requireRevocation: true`), a list passed without its `issuer`, or a `delta` whose signature does not verify against `issuer` (the delta is not applied) | This is not "not revoked": pass `crls` / `ocspResponses` and the `issuer`, or decide the soft-fail deliberately. |
| `PKI_REASON_REVOCATION_MISMATCH` | The OCSP answer is about another certificate, or does not echo the nonce sent | Do not retry the same response: suspect a cache or a substitution. |
| `PKI_REASON_NO_VALID_POLICY` | No policy survives the path while an explicit policy was required | The only policy failure; an empty tree with nobody requiring a policy is not one. |
| `PKI_REASON_POLICY_MAPPING_INVALID` | A policyMappings names anyPolicy | The mapping is ignored; the path may still fail for want of a policy. |
| `PKI_REASON_ISSUER_NOT_FOUND` | No supplied certificate has a subject equal to this certificate's issuer | Supply the intermediates in `candidates` (a server that sends only its leaf is the usual cause). |
| `PKI_REASON_SIGNATURE_INVALID` | The issuer's key does not verify the signature | A verdict, not an incident: these bytes were not signed by that key. |
| `PKI_REASON_SIGNATURE_NOT_CHECKED` | The signature could not be checked here: `build_certificate_path` (by design), `checkSignatures: false`, SHA-1 without `allowSha1`, or an algorithm this runtime refuses | Not a rejection; use `validate_certificate_path` / `verify_certificate_chain`, `allowSha1: true`, or another runtime. |
| `PKI_REASON_NO_TRUST_ANCHOR` | The chain ends at none of the supplied anchors | Supply the root in `trustAnchors`; a signature that verifies is not trust. |
| `PKI_REASON_NOT_A_CA` | A certificate issued another without cA / keyCertSign | Only a CA may issue (the 2008 basicConstraints lesson). |
| `PKI_REASON_PATH_TOO_LONG` | A pathLenConstraint or the caller's bound is exceeded | Shorten the chain or use a CA whose constraint permits it. |
| `PKI_REASON_PATH_LOOPS` | The same certificate appears twice in the chain | Remove the duplicate. |
| `PKI_REASON_CMS_NO_SIGNERS` | The SignedData has no SignerInfo (a `.p7b` bundle) | Nothing to verify; read its certificates with `inspect_cms`. |
| `PKI_REASON_CMS_SIGNER_NOT_FOUND` | No embedded or supplied certificate matches the signer's identifier | Supply the signer's certificate in `candidates`. |
| `PKI_REASON_CMS_CONTENT_MISSING` | The signature is detached and neither `content` nor `contentDigest` was given | Pass the content (never treated as empty). |
| `PKI_REASON_CMS_DIGEST_MISMATCH` | The content does not hash to the messageDigest attribute | The content was altered or is not what was signed (PDF: exactly the /ByteRange; S/MIME: CRLF canonical form). |
| `PKI_REASON_CMS_ATTRIBUTE_INVALID` | A signed attribute breaks RFC 5652 §11 / RFC 5035 (missing, repeated, misplaced) | The signer's software is non-conforming, or the attributes were tampered with. |
| `PKI_REASON_CMS_ALGORITHM_MISMATCH` | digestAlgorithm, signatureAlgorithm and CMSAlgorithmProtection disagree, or an algorithm refused outright (MD5) | Treat the signature as unverifiable (RFC 6211 substitution shape). |
| `PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH` | The ESS signing-certificate attribute commits to another certificate than the one whose key verified | Supply the certificate the signer committed to. |
| `PKI_REASON_TSP_NOT_GRANTED` | The TimeStampResp status is neither granted nor grantedWithMods (the message carries the failure codes) | Act on the codes (badAlg, unacceptedPolicy, …); ask again or ask another TSA. |
| `PKI_REASON_TSP_TOKEN_INVALID` | The token breaks an RFC 3161 token rule (several signers, a tsa name its certificate does not hold, an unknown imprint digest) | Not evidence of a time; the TSA is non-conforming or the token altered. |
| `PKI_REASON_TSP_IMPRINT_MISMATCH` | The token's messageImprint differs from the hash of the request, data or signature value expected | The token stamps something else; for a signature time-stamp hash the SignerInfo signature value octets. |
| `PKI_REASON_TSP_REQUEST_MISMATCH` | The token does not echo the request's nonce or policy | Send a new request with a new nonce; never retry the same response. |
| `PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED` | A key or bag is encrypted with a scheme other than PBES2 / AES-CBC, or one this runtime cannot run (the message says which); the rest of the file is still read | Convert once with OpenSSL 3.4 or later (`openssl pkcs12 -legacy … -aes256`, then `-export -pbmac1_pbkdf2`). |
| `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED` | The MAC is the RFC 7292 Appendix B kind, absent, or public-key mode, and `allowUnverifiedIntegrity` was not set | Re-export with `openssl pkcs12 -export -pbmac1_pbkdf2`, or `allowUnverifiedIntegrity: true` for a file you trust by other means. |
| `PKI_REASON_PKCS12_MAC_MISMATCH` | The PBMAC1 MAC does not match under the password given | Check the password; a file that fails with the right password was altered. |
| `PKI_REASON_PKCS12_DECRYPTION_FAILED` | A key or bag would not decrypt, or a key would not unwrap as its certificate's algorithm | Check the password; if the MAC verified, the key is not of the certificate's algorithm. |
| `PKI_REASON_PKCS12_KEY_UNMATCHED` | A key bag shares its localKeyId with no certificate, so its algorithm is unknown | Re-export the container with the key's certificate (`openssl pkcs12 -export` writes the localKeyId on both). |
| `PKI_REASON_PKCS12_KEY_UNSUPPORTED` | A key of a kind Web Crypto does not import as a signing key (DSA, X25519 / X448, a non-NIST curve) or this runtime refused | Such a key cannot sign through Web Crypto here; try another runtime before blaming the file. |
| `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED` | An rsaEncryption key without `rsaScheme` (Web Crypto binds a key to one scheme and hash; pkinative does not guess) | `rsaScheme: 'pkcs1'` for nearly every RSA certificate in use, `'pss'` when the key is to sign with PSS. |
| `PKI_REASON_LIMIT_EXCEEDED` | A named `PkiLimits` bound stopped the search (the `limit` field names it) | Raise it only for trusted input; path building is exponential in the candidate set. |

### 6.4 Diagnostics (97 `PKI_DIAG_*`)

Returned in `diagnostics[]` with their severity; `strict: true` escalates the first `warning` to `PKI_STRICT_DIAGNOSTIC`, an `info` never refuses. `explain_code` gives the standard and the remedy of each.

| `code` | Severity | Raised when |
|---|---|---|
| `PKI_DIAG_SERIAL_TOO_LONG` | warning | A serial number is longer than 20 octets. |
| `PKI_DIAG_SERIAL_NOT_POSITIVE` | warning | A serial number is zero or negative. |
| `PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH` | warning | The outer signatureAlgorithm differs from tbsCertificate.signature. |
| `PKI_DIAG_RSA_PARAMETERS_NOT_NULL` | warning | An RSA PKCS#1 v1.5 algorithm identifier has absent or non-NULL parameters. |
| `PKI_DIAG_EXTENSIONS_REQUIRE_V3` | warning | A certificate carries extensions but declares version 1 or 2. |
| `PKI_DIAG_UNIQUE_ID_REQUIRES_V2` | warning | A certificate carries a unique identifier but declares version 1. |
| `PKI_DIAG_GENERALIZED_TIME_BEFORE_2050` | warning | A validity date before 2050 is encoded as a GeneralizedTime. |
| `PKI_DIAG_GENERALIZED_TIME_FRACTION` | warning | A GeneralizedTime in a certificate carries fractional seconds. |
| `PKI_DIAG_VALIDITY_INVERTED` | warning | notBefore is later than notAfter. |
| `PKI_DIAG_EMPTY_ISSUER` | warning | The issuer name is an empty sequence. |
| `PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL` | warning | The subject is empty and subjectAltName is absent or not critical. |
| `PKI_DIAG_SAN_EMPTY` | warning | A subjectAltName or issuerAltName contains no GeneralName. |
| `PKI_DIAG_RDN_SET_NOT_SORTED` | warning | A multi-valued RDN is not in DER SET OF order. |
| `PKI_DIAG_PRINTABLE_STRING_CHARSET` | warning | A PrintableString contains a character outside the PrintableString alphabet. |
| `PKI_DIAG_TELETEX_AS_LATIN1` | info | A TeletexString is decoded as Latin-1. |
| `PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION` | warning | A critical extension has an OID the engine does not decode. |
| `PKI_DIAG_PATHLEN_WITHOUT_CA` | warning | basicConstraints sets pathLenConstraint while cA is false. |
| `PKI_DIAG_KEY_USAGE_EMPTY` | warning | keyUsage asserts no bit. |
| `PKI_DIAG_NAMED_BITS_TRAILING_ZERO` | warning | A named bit list keeps trailing zero bits. |
| `PKI_DIAG_NAME_CONSTRAINTS_NOT_CRITICAL` | warning | nameConstraints is not marked critical. |
| `PKI_DIAG_NAME_CONSTRAINTS_IN_END_ENTITY` | warning | nameConstraints appears in a non-CA certificate. |
| `PKI_DIAG_BASIC_CONSTRAINTS_NOT_CRITICAL` | warning | basicConstraints asserts cA without being critical. |
| `PKI_DIAG_POLICY_CONSTRAINTS_NOT_CRITICAL` | warning | policyConstraints is present and not critical. |
| `PKI_DIAG_KEY_CERT_SIGN_WITHOUT_CA` | warning | keyUsage asserts keyCertSign while basicConstraints does not assert cA. |
| `PKI_DIAG_AKI_MISSING` | warning | A v3 certificate issued by another subject carries no authorityKeyIdentifier. |
| `PKI_DIAG_SKI_MISSING` | warning | A v3 CA certificate carries no subjectKeyIdentifier. |
| `PKI_DIAG_COMMON_NAME_NOT_IN_SAN` | warning | The subject commonName is not among the subjectAltName entries. |
| `PKI_DIAG_DNS_NAME_NOT_PREFERRED_SYNTAX` | warning | A dNSName falls outside RFC 1034's preferred name syntax. |
| `PKI_DIAG_GENERAL_NAME_CONTROL_CHARACTER` | warning | A dNSName, rfc822Name or URI holds a control character. |
| `PKI_DIAG_AKI_ISSUER_SERIAL_UNPAIRED` | warning | authorityKeyIdentifier carries only one of authorityCertIssuer / authorityCertSerialNumber. |
| `PKI_DIAG_POLICY_DUPLICATE` | warning | certificatePolicies lists one policy OID more than once. |
| `PKI_DIAG_POLICY_CONSTRAINTS_EMPTY` | warning | policyConstraints sets neither requireExplicitPolicy nor inhibitPolicyMapping. |
| `PKI_DIAG_DEFAULT_ENCODED` | warning | A DEFAULT value is encoded explicitly (version v1, critical FALSE, cA FALSE, a subtree minimum of 0). |
| `PKI_DIAG_BER_CONSTRUCT_ACCEPTED` | info | `encodingRules: 'ber'` and the input uses a construct DER forbids. |
| `PKI_DIAG_PEM_LAX_ACCEPTED` | info | `pemMode: 'lax'` and a block deviates from the strict grammar. |
| `PKI_DIAG_CMS_VERSION_MISMATCH` | warning | A SignedData / SignerInfo version is not the one RFC 5652 derives from its content. |
| `PKI_DIAG_CMS_SET_NOT_SORTED` | warning | An unsigned SET OF (digestAlgorithms, certificates, crls, signerInfos) is not in DER order (OpenSSL tokens carry it). |
| `PKI_DIAG_CMS_SIGNED_ATTRIBUTES_NOT_DER` | warning | A signer's signed attributes are not in DER SET OF order (verified over the bytes as signed). |
| `PKI_DIAG_CMS_DIGEST_ALGORITHM_NOT_LISTED` | warning | A signer uses a digest algorithm SignedData.digestAlgorithms does not list. |
| `PKI_DIAG_KEY_KDF_ITERATIONS_LOW` | warning | A PBKDF2 iteration count is below the 1 000 RFC 8018 recommends. |
| `PKI_DIAG_CRL_EXTENSION_MALFORMED` | warning | A CRL's cRLNumber, deltaCRLIndicator, reasonCode or invalidityDate is malformed (ignored). |
| `PKI_DIAG_NAME_ATTRIBUTE_STRING_TYPE` | warning | A name attribute is encoded outside its RFC 5280 syntax. |
| `PKI_DIAG_COUNTRY_NAME_SIZE` | warning | A countryName is not exactly two characters. |
| `PKI_DIAG_NAME_ATTRIBUTE_TOO_LONG` | info | A name attribute exceeds its X.520 upper bound. |
| `PKI_DIAG_NAME_COUNTRY_UNKNOWN` | info | A countryName is not an assigned ISO 3166-1 alpha-2 code. |
| `PKI_DIAG_STRING_SIGNATURE` | warning | A BMPString / UniversalString starts with a byte-order signature. |
| `PKI_DIAG_STRING_ESCAPE_SEQUENCE` | warning | A string contains an ISO/IEC 2022 code-extension control. |
| `PKI_DIAG_SUBJECT_DIRECTORY_ATTRIBUTES_CRITICAL` | warning | subjectDirectoryAttributes is marked critical. |
| `PKI_DIAG_SPKI_RSA_EXPONENT_WEAK` | warning | An RSA public exponent below 3 or even. |
| `PKI_DIAG_SPKI_EC_PARAMETERS_INVALID` | warning | An EC key names no known curve (implicit / specified parameters, or a non-NIST curve). |
| `PKI_DIAG_UNIQUE_ID_PRESENT` | warning | A certificate carries an issuerUniqueID or subjectUniqueID. |
| `PKI_DIAG_AKI_CRITICAL` | warning | authorityKeyIdentifier is marked critical. |
| `PKI_DIAG_SKI_CRITICAL` | warning | subjectKeyIdentifier is marked critical. |
| `PKI_DIAG_SKI_MISSING_END_ENTITY` | info | A v3 end-entity certificate carries no subjectKeyIdentifier. |
| `PKI_DIAG_KEY_USAGE_NOT_CRITICAL` | info | keyUsage is present and not critical. |
| `PKI_DIAG_ANY_POLICY_QUALIFIER` | warning | The anyPolicy entry carries a qualifier other than a CPS pointer or a user notice. |
| `PKI_DIAG_NOTICE_REF_USED` | info | A user notice qualifier carries a noticeRef. |
| `PKI_DIAG_EXPLICIT_TEXT_STRING_TYPE` | warning | A user notice's explicitText is a VisibleString or a BMPString. |
| `PKI_DIAG_EXPLICIT_TEXT_CONTROL_CHARACTER` | info | A user notice's explicitText contains a control character. |
| `PKI_DIAG_EXPLICIT_TEXT_NOT_NFC` | info | A UTF8String explicitText changes under NFC. |
| `PKI_DIAG_POLICY_MAPPING_NOT_ASSERTED` | info | An issuerDomainPolicy is not among the certificate's own policies. |
| `PKI_DIAG_POLICY_MAPPINGS_NOT_CRITICAL` | info | policyMappings is present and not critical. |
| `PKI_DIAG_SAN_CRITICAL` | info | subjectAltName is critical in a certificate whose subject is not empty. |
| `PKI_DIAG_ALT_NAME_URI_INVALID` | warning | A uniformResourceIdentifier is not an RFC 3986 URI. |
| `PKI_DIAG_ALT_NAME_URI_SCHEME_MISSING` | warning | A uniformResourceIdentifier has no scheme. |
| `PKI_DIAG_ALT_NAME_URI_HOST_INVALID` | warning | A URI authority's host is neither an FQDN nor an IP address. |
| `PKI_DIAG_ALT_NAME_GENERAL_NAME_EMPTY` | warning | An alt-name entry is empty. |
| `PKI_DIAG_ISSUER_ALT_NAME_CRITICAL` | info | issuerAltName is marked critical. |
| `PKI_DIAG_NAME_CONSTRAINTS_MIN_MAX` | warning | A GeneralSubtree sets a minimum other than 0, or any maximum. |
| `PKI_DIAG_NAME_CONSTRAINTS_URI_NOT_FQDN` | warning | A URI constraint of nameConstraints is not an FQDN. |
| `PKI_DIAG_EKU_ANY_CRITICAL` | info | extKeyUsage is critical and lists anyExtendedKeyUsage. |
| `PKI_DIAG_CRL_DISTRIBUTION_POINTS_CRITICAL` | info | cRLDistributionPoints is marked critical. |
| `PKI_DIAG_DISTRIBUTION_POINT_WITHOUT_NAME` | warning | A DistributionPoint has neither distributionPoint nor cRLIssuer. |
| `PKI_DIAG_DISTRIBUTION_POINT_LDAP_URI_INCOMPLETE` | warning | An ldap distribution-point URI has no dn or not one attrdesc. |
| `PKI_DIAG_DISTRIBUTION_POINT_NO_HTTP_OR_LDAP_URI` | info | A distribution point's name includes no http or ldap URI. |
| `PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME` | info | A distribution point is named by nameRelativeToCRLIssuer. |
| `PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME_AMBIGUOUS` | warning | nameRelativeToCRLIssuer with more than one cRLIssuer directoryName. |
| `PKI_DIAG_INHIBIT_ANY_POLICY_NOT_CRITICAL` | warning | inhibitAnyPolicy is present and not critical. |
| `PKI_DIAG_FRESHEST_CRL_CRITICAL` | warning | freshestCRL is marked critical. |
| `PKI_DIAG_AIA_CRITICAL` | warning | authorityInfoAccess is marked critical. |
| `PKI_DIAG_SIA_CRITICAL` | warning | subjectInfoAccess is marked critical. |
| `PKI_DIAG_INFO_ACCESS_LDAP_URI_INCOMPLETE` | warning | An ldap access-location URI has no dn or no attributes. |
| `PKI_DIAG_CA_ISSUERS_NO_HTTP_OR_LDAP_URI` | info | id-ad-caIssuers has no http or ldap location. |
| `PKI_DIAG_CA_REPOSITORY_NO_HTTP_OR_LDAP_URI` | info | id-ad-caRepository has no http or ldap location. |
| `PKI_DIAG_CMS_CERTS_ONLY_CONTENT` | warning | A certificates-only SignedData with a content it must not have. |
| `PKI_DIAG_CMS_COUNTERSIGNATURE_CONTENT_TYPE` | warning | A countersignature carries a content-type signed attribute. |
| `PKI_DIAG_CMS_COUNTERSIGNATURE_NO_MESSAGE_DIGEST` | warning | A countersignature with signed attributes lacks message-digest. |
| `PKI_DIAG_CMS_COUNTERSIGNATURE_EMPTY` | warning | A countersignature attribute whose SET OF is empty. |
| `PKI_DIAG_CMS_SIGNING_TIME_NOT_UTC` | warning | A signingTime between 1950 and 2049 encoded as GeneralizedTime. |
| `PKI_DIAG_CMS_SIGNING_TIME_FRACTION` | warning | A GeneralizedTime signingTime with fractional seconds. |
| `PKI_DIAG_TSP_CERTREQ_UNMET` | warning | The request set certReq and the token carries no (or not the) TSA certificate. |
| `PKI_DIAG_TSP_CERTS_UNREQUESTED` | warning | The request did not set certReq and the token carries certificates anyway. |
| `PKI_DIAG_OCSP_CERTS_EMPTY` | info | A BasicOCSPResponse certs field present and empty. |
| `PKI_DIAG_OCSP_VERSION_NOT_V1` | warning | A ResponseData explicit version other than v1. |
| `PKI_DIAG_OCSP_RESPONDER_ID_MISMATCH` | warning | The responderID names neither the signer's subject nor its key hash. |
| `PKI_DIAG_OCSP_SINGLE_RESPONSE_UNREQUESTED` | info | The response carries SingleResponse elements about other certificates. |
| `PKI_DIAG_OCSP_NOCHECK_CRITICAL` | info | The signer's id-pkix-ocsp-nocheck is marked critical. |

## 7. Contributing

Agents working **on** this repository — adding a tool, changing a schema, running the gate, preparing a release — follow [AGENTS.md](../AGENTS.md) (the repository rule file), the human-in-the-loop protocol of [.github/AGENT_RULES.md](../.github/AGENT_RULES.md) and the narrative in [guides/AI_GOVERNANCE.md](guides/AI_GOVERNANCE.md). The architecture behind this contract is in [KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md); what may change between releases, in [API_STABILITY.md](API_STABILITY.md).
