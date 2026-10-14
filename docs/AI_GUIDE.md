# AI Agent Guide — pkinative-mcp

> **Read this first if you are an AI agent (Copilot, Claude, Cursor, Continue, Zed, Windsurf, Cline, Roo Code, …) about to call pkinative-mcp.**
> It tells you which of the 34 tools to pick and how to avoid the common retry loops.
> Current for pkinative-mcp 1.0.0 on pkinative 1.0.0 (tool API `1.0.0`).

The server also returns the same decision tree in `serverInfo.instructions`. The consumer contract (catalogue, environment, every code) is [`AGENT_CONTRACT.md`](AGENT_CONTRACT.md); the full reference lives in [`KNOWLEDGE_BASE.md`](KNOWLEDGE_BASE.md); the stability charter in [`API_STABILITY.md`](API_STABILITY.md). Worked invocations are in [`../examples/`](../examples/).

---

## 1. Decision tree — pick the right tool in one step

| You want to… | Tool |
|---|---|
| Know what a PEM text holds (labels, sizes) or extract one block of a bundle | `convert_pem` *(`mode: 'decode'`; `extractIndex` delivers a block; a private-key block is never extracted)* |
| Wrap DER into a PEM block | `convert_pem` *(`mode: 'encode'` + `label`)* |
| The facts of a certificate (subject, issuer, validity, key, extensions, fingerprints) | `inspect_certificate` *(facts, never trust)* |
| **Is this certificate trustworthy?** | `verify_certificate_chain` *(the RFC 5280 §6 verdict: path, signatures, validity at `at`, name, purposes, policies, offline revocation)* |
| Which intermediates does a chain need / why does a path fail | `build_certificate_path` *(discovery, signatures NOT checked)*, then `validate_certificate_path` *(your ordered path, signatures checked)* |
| Is the certificate valid for this host / IP (RFC 6125) | `check_certificate_name` *(or `serverName` on `verify_certificate_chain`)* |
| May it serve TLS / sign code / protect mail / stamp time | `check_certificate_purpose` *(or `purposes` on `verify_certificate_chain`)* |
| Is it revoked, from a CRL you fetched | `check_crl_revocation` *(`crl` + `issuer` + `at`; `delta` for a delta CRL)* — the facts of the list: `inspect_crl` |
| Is it revoked, from an OCSP response you fetched | `create_ocsp_request` *(the DER you POST)* → `check_ocsp_status` — the facts of the answer: `inspect_ocsp_response` |
| The facts of a CSR, and did its key sign it | `inspect_csr` *(proof of possession, not trust)* |
| Request a certificate (PKCS#10) | `create_csr` *(your PKCS#8 key or PKCS#12; nothing generates a key here)* |
| Issue a certificate — self-signed CA or a leaf from a CSR | `create_certificate` *(`issuerCertificate` + `subjectPublicKey` for a leaf; verified before the bytes return)* |
| Sign content (CMS SignedData, attached or detached, a PDF /ByteRange digest) | `sign_cms` |
| **Is this signature good?** | `verify_cms` *(every signer: digest, signature, chain, time-stamps, revocation)* — the facts only: `inspect_cms` |
| Add a counter time-stamp or an unsigned attribute to a signed message | `amend_cms` *(`'add-timestamp'` / `'add-unsigned-attribute'`)* |
| Build the request a TSA answers | `create_timestamp_request` *(you POST the `.tsq` yourself)* |
| What a TSA answered / what a token asserts | `inspect_timestamp` *(proves nothing)* |
| **Is this time-stamp good?** | `verify_timestamp` *(against the request, the data or the digest it stamps)* |
| What is this key protected with, and is it usable | `inspect_private_key` *(no password to describe; `tryImport: true` + password to prove)* |
| What is in this `.p12` and how is it protected | `inspect_pkcs12` *(no password to describe; with one, `macVerified` + `opened`)* |
| Open a `.p12` (MAC, decryption, non-extractable key import, certificates as PEM) | `open_pkcs12` *(password required; `exportCertificates: true` for the PEM bundle; never a key byte)* |
| Decode any DER to a node tree, read one value, re-encode a subtree | `decode_asn1` |
| Encode arbitrary ASN.1 from a JSON spec | `encode_asn1` |
| Encode one X.509 building block (a Name, a SAN, an AlgorithmIdentifier, …) | `encode_x509_structure` |
| Decode one extension value by OID | `decode_extension` |
| Name / validate / list / encode / decode OIDs | `resolve_oid` |
| A fingerprint, a key identifier, SHAKE256 | `compute_fingerprint` |
| What this server can do here (versions, Web Crypto, limits, ceilings, caps, sandbox, refusals) | `describe_engine` *(call it first in a session)* |
| A code you do not understand (`PKI_*`, `PKI_REASON_*`, `PKI_DIAG_*`, a wrapper code) | `explain_code` |
| Draft a GitHub issue for a human to submit | `draft_governance_issue` |

Ambiguities resolved: `inspect_certificate` with `issuer` / `checkSelfSignature` checks ONE signature against ONE key — facts, not trust; `verify_certificate_chain` is the only trust verdict. `inspect_cms.signerSignature` is a key check, `verify_cms` is the verdict. `build_certificate_path` never verifies a signature. `inspect_csr.signature` is the proof of possession, not a CA's signature. `inspect_timestamp` parses; `verify_timestamp` judges.

Input validation is strict: unknown top-level or nested keys are rejected with `VALIDATION_ERROR` ("Unrecognized key"), matching `additionalProperties: false`. Calling a tool name that does not exist is a JSON-RPC protocol error (`-32602`, `[UNKNOWN_TOOL] Unknown tool: <name>`), not an `isError` result.

---

## 2. Common pitfalls (these cause the most retries)

### Inputs: one object, one form
- Every PKI object (certificate, CSR, CRL, OCSP response, CMS, token, key, PKCS#12) is an object with **exactly one** of `pem` (RFC 7468 text, starts with `-----BEGIN`), `derBase64` (the DER as base64, **exactly once** — no `data:` URI, not PEM text) or `path` (relative to the sandbox). Two forms, or none, is `VALIDATION_ERROR`.
- A single-object input holding **several** PEM blocks is refused — not silently reduced to its first block. Extract one with `convert_pem { mode: 'decode', extractIndex }`, or use a bundle input (`trustAnchors`, `candidates`, `crls`, `ocspResponses`, `chain`, `path`), which takes every block of every item (≤ 256 items).
- `path` needs the operator's `PKINATIVE_MCP_OUTPUT_DIR`; the extension must be one of the PKI extensions (`.pem .crt .cer .der .csr .p10 .crl .p7s .p7b .p7c .p7m .cms .p12 .pfx .key .p8 .pub .ocsp .ors .orq .tsq .tsr .tst .bin .asn1`); key-bearing ones (`.key .p8 .p12 .pfx`) are accepted by the key and signer tools only. A `path` call is **never cached** (a path is a reference, not content).
- The bytes to sign or time-stamp (`content`, `data`) are a different object: exactly one of `text`, `base64` or `path` (no extension rule).
- BER producers (legacy CMS with indefinite lengths) need `encodingRules: 'ber'` — the default is strict DER and refuses them with `PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN` / `PKI_ASN1_LENGTH_NON_MINIMAL`; the remedy is in `_meta.error.data.remedy`. Lax PEM (whitespace, long lines, RFC 1421 headers) needs `pemMode: 'lax'`.

### Verdict vs error
- The verdict tools (`verify_*`, `check_*`, `validate_certificate_path`, `build_certificate_path`, `open_pkcs12`) return `valid: false` + `reasons[]` (`PKI_REASON_*` codes) in `structuredContent` for a negative verdict — **never `isError`**. A revoked certificate, an expired chain, a wrong trust anchor, a token over other data: all verdicts. Branch on `reasons[].code` (or `reasonCodes[]` under `verbosity: 'summary'`), never on message text.
- `isError: true` means the input itself was refused (a `PKI_*` engine code such as `PKI_ASN1_TRUNCATED` or `PKI_PEM_UNEXPECTED_LABEL`) or the call was wrong (a wrapper code such as `VALIDATION_ERROR`, `SECRET_REQUIRED`, `RSA_SCHEME_REQUIRED`). Read `_meta.error.code`, then `_meta.error.data.errorClass` and `data.remedy`.
- `build_certificate_path` is **always** `valid: false` (every link carries `PKI_REASON_SIGNATURE_NOT_CHECKED`); its verdict is `found` + `structuralReasons`. `validate_certificate_path { checkSignatures: false }` is the same shape: `valid` stays false, `failingReasons` carries what actually fails.
- `verify_cms` tells unaltered from untrusted: `signers[i].intact` (digest and signature hold) is true while `valid` is false when the signer does not chain to your anchor.

### Pin `at`
- Every verdict depends on an instant. Pass `at` (ISO 8601, `2027-01-01T00:00:00Z`; a date-time without a zone is read as UTC; an impossible date is refused) — the verdict is then reproducible **and cacheable**. Omitted, `at` falls back to the operator's `PKINATIVE_MCP_AT`, else the wall clock, and the result is never cached; `evaluatedAt` / `evaluatedAtSource` (`input` | `pinned` | `clock`) say which.
- The same applies to `spec.notBefore` (`create_certificate`) and `signingTime` (`sign_cms`): pin them for reproducible bytes. `signingTime: 'none'` omits the attribute (PAdES style).

### Trust is yours to name
- `trustAnchors` is required on every trust verdict: the verdict is relative to the anchors **you** name. No system store is consulted. A signature that verifies against an issuer you did not anchor is `PKI_REASON_NO_TRUST_ANCHOR`.
- Intermediates go in `candidates`; a CMS message's embedded certificates are candidates too. A server that sends only its leaf is the usual `PKI_REASON_ISSUER_NOT_FOUND`.

### Revocation is offline
- This server never fetches. `verify_certificate_chain` / `verify_cms` / `verify_timestamp` judge the `crls` and `ocspResponses` **you** pass; without evidence they say `revocationEvidence` is empty and the verdict is "not revoked as far as the evidence goes" — `requireRevocation: true` turns that into `PKI_REASON_REVOCATION_UNKNOWN`.
- Where to fetch: `inspect_certificate` → `crlDistributionPoints` (the CRL URL) and `authorityInfoAccess` (the OCSP responder). `create_ocsp_request` builds the request bytes; you POST them (`Content-Type: application/ocsp-request`) and bring the answer to `check_ocsp_status`.
- **The OCSP CertID hash defaults to SHA-1** (RFC 6960, what every responder answers). Ask for `hashAlgorithm: 'SHA-256'` explicitly where the responder supports it; `check_ocsp_status` recomputes the CertID with the hash the response used.
- `check_crl_revocation` without `issuer` has no verified signature and the engine refuses the unverified list: pass the CRL issuer certificate for a real verdict. A `delta` must carry a deltaCRLIndicator (`VALIDATION_ERROR` otherwise).

### Signing keys
- Keys come from you, as a PKCS#8 key (`signer.key`, plain or PBES2-encrypted, PEM or DER) or a PKCS#12 file (`signer.p12`). Nothing here generates or exports a key; a SEC1 / PKCS#1 key must be converted first (`openssl pkcs8 -topk8`).
- **RSA needs `rsaScheme: 'pkcs1' | 'pss'`** — there is no default (`RSA_SCHEME_REQUIRED`, also from `open_pkcs12` and `inspect_private_key tryImport`). `'pkcs1'` is what nearly every RSA certificate in use signs with; an id-RSASSA-PSS key signs `'pss'` only.
- **An encrypted PKCS#8 key reveals its type only once decrypted.** Pass `signer.keyType` (`ec-p256` `ec-p384` `ec-p521` `ed25519` `ed448` `rsa` `rsa-pss`) or a certificate / `subjectPublicKey` input that names it (`KEY_TYPE_REQUIRED` otherwise).
- **Two password channels, never both:** the `password` input (it lands in the host's transcript) or the operator's `PKINATIVE_MCP_PASSWORD` (it does not). Both at once is `VALIDATION_ERROR`; neither when one is needed is `SECRET_REQUIRED`; a wrong one is `PKI_CRYPTO_DECRYPTION_FAILED` and the value is never echoed. A call carrying a password is never cached, and no password-accepting tool is cached while the variable is set.
- **SHA-1 is refused by default**: `PKI_CRYPTO_ALGORITHM_REFUSED` on read, `VALIDATION_ERROR` on write. `allowSha1: true` only for legacy material you already trust — treat the result as an archival fact, not an authentication decision.
- The artefact is verified against its own key before the bytes return: a key that does not match the certificate, issuer or `subjectPublicKey` is `KEY_MISMATCH`, never a silent bad artefact.
- ECDSA and RSA-PSS signatures are randomised: two calls give different bytes for the same inputs (the signed part is identical). Ed25519 and RSA PKCS#1 v1.5 are deterministic.

### Counter time-stamps
- **A counter time-stamp stamps the signer's SIGNATURE VALUE, not the document.** Get it with `inspect_cms { signedData, fields: ['signerInfos.signature'] }`, hash it with the TSA's algorithm, `create_timestamp_request { digestHex }`, POST the `.tsq` yourself, then `amend_cms { operation: 'add-timestamp', token }`. A token over anything else is refused with `VALIDATION_ERROR` (`data.detail` `PKI_REASON_TSP_IMPRINT_MISMATCH`) before anything is written.
- `verify_timestamp` needs what was stamped: `request` (the `.tsq` — the only way to catch a replay: imprint, nonce and policy are all checked), `data` or `digestHex`. A token verified without them proves nothing, so the call is `VALIDATION_ERROR`.
- The TSA certificate must carry a **critical** timeStamping EKU; `allowNonCriticalTimeStampingEku: true` for deployed TSAs that are not. `signingTime` is a claim; only a verified time-stamp is proof of time (`verify_cms atTimeStamp: true` judges each signer at it).

### Keys and PKCS#12 doctrine
- Describe before opening: `inspect_private_key` / `inspect_pkcs12` need no password and tell you the scheme, the PBKDF2 parameters and the MAC kind. A legacy file (RC2 / 3DES, the RFC 7292 Appendix B MAC — `macKind: 'pkcs12-kdf'`) is refused by policy with the OpenSSL 3.4 conversion remedy (`openssl pkcs12 -legacy … -aes256`, then `-export -pbmac1_pbkdf2`); run it before anyone types a password.
- A PKCS#12 without a MAC is a negative verdict (`PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED`); `allowUnverifiedIntegrity: true` opens it only when you trust its origin — the report still says `integrity: 'unverified'`.
- No report ever carries a key byte, a scalar, a bag value or the password: every key view is an allow-list, keys are non-extractable Web Crypto handles (described: type, algorithm, usages). `convert_pem`, `decode_asn1`, `encode_asn1` and `resources/read` refuse private-key material with `SECURITY_VIOLATION` — the remedy names `inspect_private_key`.

### Diagnostics are not errors
- Every result carries `diagnostics[]` (`PKI_DIAG_*`, `severity: 'warning' | 'info'`, ≤ 200, de-duplicated) — a serial longer than 20 octets, a missing key identifier, an unsorted SET, a low PBKDF2 count. They never fail the call. `strict: true` escalates the **first warning** to `PKI_STRICT_DIAGNOSTIC`; an `info` never refuses. OpenSSL-made tokens carry `PKI_DIAG_CMS_SET_NOT_SORTED`.

### Limits and ceilings
- The 22 engine bounds (`limits.maxDepth`, `limits.maxChainLength`, `limits.maxPathsExplored`, …) are raised per call for trusted input only; three of them are capped by operator ceilings (`PKINATIVE_MCP_MAX_INPUT_BYTES`, `PKINATIVE_MCP_MAX_KDF_ITERATIONS`, `PKINATIVE_MCP_MAX_PATHS_EXPLORED`) — a value above the ceiling is `LIMIT_CEILING_EXCEEDED` with `data.env` naming the variable. `PKI_LIMIT_EXCEEDED` names the bound that fired in `data.limit`. `describe_engine` lists the defaults and the ceilings in force.
- Inline payloads: 128 MiB of decoded PKI input per call, 50 MiB of inline artefact, 64 KiB of inline hex (`encoding: 'hex'` is inline only). Larger objects go through a sandbox `path` and `outputMode: 'file'`.

### Token-frugal reads
The 25 read, verdict and engine tools (`inspect_*`, `verify_*`, `check_*`, `validate_certificate_path`, `build_certificate_path`, `open_pkcs12`, `convert_pem`, `resolve_oid`, `compute_fingerprint`, `decode_asn1`, `decode_extension`, `describe_engine`, `explain_code`) accept two **optional** inputs that shrink the response without losing the fields you branch on:

- `verbosity: 'summary'` returns the tool's scalar subset — e.g. `verify_certificate_chain` → `{ valid, reasonCodes, pathLength, evaluatedAt, revocationEvidence, diagnosticCount }`; `inspect_certificate` → `{ serialNumberHex, subjectString, issuerString, notBefore, notAfter, publicKey, extensionKinds, selfIssued, signatureValid?, diagnosticCount }`; `verify_cms` → `{ valid, reasonCodes, signers[{ index, valid, intact, reasonCodes }], evaluatedAt, diagnosticCount }`. The full table is [AGENT_CONTRACT.md](AGENT_CONTRACT.md) §3.
- `fields: ['a', 'b.c']` projects the structured result to named dot-paths (≤ 16; an array segment maps over every element, e.g. `['reasons.code']`, `['signerInfos.signature']`). It composes **after** `verbosity`; unknown paths are omitted, and the result then carries `_meta.unmatchedFields` + `_meta.availableFields` so you can correct the path.

Defaults are unchanged: omit both and you get the full result. Smallest "is it trustworthy?" probe: `{ leaf, trustAnchors, at, verbosity: 'summary', fields: ['valid', 'reasonCodes'] }`.

> **Artefact delivery:** a produced certificate, CSR, signature, request or encoding is returned **once** as an embedded `resource` content block (PEM as `text`, DER as `blob`), not duplicated into `structuredContent` (which is `{ mode, encoding, sizeBytes, sha256, summary, diagnostics… }`). `encoding: 'hex'` puts the bytes in `structuredContent.hex` instead (≤ 64 KiB). In file mode the result carries a `resource_link` and the file is listed as `pkinative://output/<path>`; an existing file is never overwritten (`OUTPUT_EXISTS`).

### Response cache
With `PKINATIVE_MCP_CACHE_DIR` set, a repeated identical call may be answered from cache — the result then carries `_meta.cached: true` (1 h TTL, 256 MiB). The gate is strict: never a `path` input, never a `password` or a `signer`, never `outputMode: 'file'`, never a `'random'` serial / nonce or a `'now'` instant, never an unpinned `at` / `notBefore` / `signingTime`, never `describe_engine` or `draft_governance_issue`, and never any password-accepting tool while `PKINATIVE_MCP_PASSWORD` is set. Refusals are never cached. The key is namespaced by the tool API, package and engine versions, so an upgrade never serves old bytes.

### Protocol
- The server speaks MCP 2026-07-28 (stateless, `server/discover`, `resultType`, cache hints) and falls back automatically to the 2025-era `initialize` handshake. Whatever your host negotiates, the `tools/call` payload is the same.
- `tools/list` and `prompts/list` are safe to cache for 24 h (`cacheScope: 'public'`); `resources/*` results are private and must not be cached.
- Seven MCP prompts are advertised: `verify_before_trust`, `issue_certificate`, `sign_and_timestamp`, `offline_revocation`, `open_keys_safely`, `governance_contract`, `draft_issue_workflow` — read the one matching your workflow before the first call.
- Over HTTP (`PKINATIVE_MCP_PORT`), the operator may require a bearer token (`PKINATIVE_MCP_HTTP_TOKEN`): send `Authorization: Bearer <token>` or every `/mcp` request is answered 401. Without it HTTP mode has no authentication (loopback bind + Host / Origin guard only). stdio is unaffected.
- Operator environment, for reference (an agent never sets these): `PKINATIVE_MCP_OUTPUT_DIR` (the one sandbox: path inputs, file output, resources), `PKINATIVE_MCP_CACHE_DIR` (opt-in response cache), `PKINATIVE_MCP_PORT` / `PKINATIVE_MCP_HTTP_TOKEN` (HTTP transport), `PKINATIVE_MCP_PASSWORD` (operator-side password, exclusive with the input), `PKINATIVE_MCP_AT` (the pinned instant), `PKINATIVE_MCP_MAX_INPUT_BYTES` / `PKINATIVE_MCP_MAX_KDF_ITERATIONS` / `PKINATIVE_MCP_MAX_PATHS_EXPLORED` (the three ceilings). Read once at boot; an invalid value refuses to start. Full table: [AGENT_CONTRACT.md](AGENT_CONTRACT.md) §4.
- **`tools/list` is 427,106 bytes** (budgeted at 448 KiB by the gate) because every shared fragment — the PKI input on 70 properties, the 22 named limits and the parse fragment on 31 tools, the signer, the trust fragment, the diagnostics report — is spelled out inline in every tool that carries it (no `$ref`, for host compatibility). If your host has a tight context budget: read the `description` strings and the `_meta.examples` first (≤ 2 per tool, every one executable), keep `limits` / `policy` for the rare call that needs them, and lean on `serverInfo.instructions` (5,469 bytes) and the prompts for the workflows; `describe_engine { verbosity: 'summary' }` is the cheap preflight.

### File output mode
- `outputMode: 'file'` only works if the host process set `PKINATIVE_MCP_OUTPUT_DIR`. Otherwise the call fails with `SECURITY_VIOLATION`.
- `outputPath` must be **relative**, end in an allowed extension (`.pem` for `encoding: 'pem'`; `.der .crt .cer .csr .p10 .crl .p7s .p7b .p7c .p7m .cms .pub .ocsp .ors .orq .tsq .tsr .tst .bin .asn1` for DER; `.md .txt .json .pem` for text), never a key-bearing one, and contain no traversal segments. `encoding: 'hex'` is inline only.
- Files written this way are listed as MCP resources (`pkinative://output/{+path}`); the result also carries a `resource_link`. Key-bearing files (`.key .p8 .p12 .pfx`) dropped into the sandbox are read by the key tools, never listed, never served.

### Drafting a GitHub issue (human-in-the-loop)
- `draft_governance_issue` produces a **local** draft `.md` + a machine-readable compliance report. It **never** submits to GitHub and makes **no** network call — you are a draftsman; a human is the only gate that submits. (The server has no network code path at all.)
- Always set `duplicateSearchPerformed: true` (after actually searching) and include a `reproduction: { command, result }` with TEST material only. Proposing a runtime dependency, embedding a private key or a password, omitting the reproduction, or `duplicateSearchPerformed: false` is rejected with `GOVERNANCE_VIOLATION`. `targetRepo` records where it goes: `pkinative` for engine behaviour (parsing, verification, limits, refusals), `pkinative-cli`, `pkinative-mcp` for wrapper behaviour (schemas, sandbox, transport).
- Read the `governance_contract` and `draft_issue_workflow` MCP prompts first; the full contract is in [`guides/AI_GOVERNANCE.md`](guides/AI_GOVERNANCE.md).

---

## 3. Recipes (multi-tool workflows)

### Verify before trust
1. `inspect_certificate { certificate, verbosity: 'summary' }` — subject, issuer, validity, SAN, EKU, diagnostics. A `signatureValid` from `issuer` / `checkSelfSignature` is ONE signature against ONE key: it is not trust.
2. `verify_certificate_chain { leaf, candidates: [intermediates], trustAnchors: [your roots], at, serverName: { host }, purposes: ['serverAuth'] }` — the RFC 5280 §6 verdict ([`verify-certificate-chain-server.json`](../examples/verify-certificate-chain-server.json)).
3. Add the revocation evidence you fetched: `crls: […]`, `ocspResponses: […]`, `requireRevocation: true` ([`verify-certificate-chain-revoked.json`](../examples/verify-certificate-chain-revoked.json)).
4. Branch on `valid` and `reasons[].code`. A failing path: `build_certificate_path` ([`build-certificate-path.json`](../examples/build-certificate-path.json)) then `validate_certificate_path` ([`validate-certificate-path.json`](../examples/validate-certificate-path.json)). Guide: [`guides/VERIFICATION.md`](guides/VERIFICATION.md).

### Offline revocation
1. `inspect_certificate` → `crlDistributionPoints` / `authorityInfoAccess`; fetch the CRL yourself.
2. `create_ocsp_request { certificate, issuer, hashAlgorithm: 'SHA-256', nonce: 'random' }` ([`create-ocsp-request.json`](../examples/create-ocsp-request.json)) → POST the bytes → keep `summary.nonceHex`.
3. `check_crl_revocation { certificate, crl, issuer, at }` ([`check-crl-revocation.json`](../examples/check-crl-revocation.json)) or `check_ocsp_status { response, certificate, issuer, nonce, requireNonce: true, at }` ([`check-ocsp-status.json`](../examples/check-ocsp-status.json)); `PKI_REASON_REVOKED` is a verdict. Guide: [`guides/REVOCATION.md`](guides/REVOCATION.md).

### Issue a CA, a CSR and a leaf
1. `create_certificate { spec: { subject, validityDays, extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] } }, signer: { key } }` — self-signed because no `issuerCertificate` is given ([`create-certificate-self-signed-ca.json`](../examples/create-certificate-self-signed-ca.json)).
2. The subject's side: `create_csr { spec: { subject, extensions: { subjectAltName } }, signer: { key } }` ([`create-csr-round-trip.json`](../examples/create-csr-round-trip.json)); `inspect_csr` shows what it asks for.
3. `create_certificate { spec, issuerCertificate, subjectPublicKey: { the CSR }, signer: { the CA key } }` ([`create-certificate-issue-leaf.json`](../examples/create-certificate-issue-leaf.json)) — the AKI is computed from the issuer, the result verified before it returns.
4. Prove it: `verify_certificate_chain { leaf, trustAnchors: [the CA], at }` → `valid: true`. Guide: [`guides/SIGNING.md`](guides/SIGNING.md).

### Sign and time-stamp (CAdES-T)
1. `sign_cms { content, detached: true, certificate, chain, signingTime, signer }` ([`sign-cms-detached-then-verify.json`](../examples/sign-cms-detached-then-verify.json)).
2. `inspect_cms { signedData, fields: ['signerInfos.signature'] }` → hash the signature value → `create_timestamp_request { digestHex, nonce: 'random' }` → POST to your TSA → `amend_cms { signedData, operation: 'add-timestamp', token }`.
3. `verify_cms { signedData, content, trustAnchors, candidates, at, atTimeStamp: true }` — one verdict for signatures, chains, time-stamps and revocation. Guide: [`guides/TIMESTAMPS.md`](guides/TIMESTAMPS.md).

### Open keys safely
1. `inspect_private_key { key }` / `inspect_pkcs12 { pkcs12 }` without a password ([`inspect-private-key-describe.json`](../examples/inspect-private-key-describe.json), [`inspect-pkcs12-describe.json`](../examples/inspect-pkcs12-describe.json)).
2. `open_pkcs12 { pkcs12, password, exportCertificates: true }` ([`open-pkcs12-export.json`](../examples/open-pkcs12-export.json)) — or `inspect_private_key { key, tryImport: true, password, keyType }` to prove an encrypted key is usable ([`inspect-private-key-import.json`](../examples/inspect-private-key-import.json)). Guide: [`guides/KEYS.md`](guides/KEYS.md).

### Raw bytes
1. `decode_asn1 { input, fields: ['nodes.path', 'nodes.tagName', 'nodes.oidName'] }` to find a `nodePath` ([`decode-asn1-tree.json`](../examples/decode-asn1-tree.json)), then `{ nodePath, read: 'integer' }` ([`decode-asn1-read.json`](../examples/decode-asn1-read.json)).
2. `encode_asn1 { spec }` ([`encode-asn1-round-trip.json`](../examples/encode-asn1-round-trip.json)) and `encode_x509_structure { structure, spec }` ([`encode-x509-structure-san.json`](../examples/encode-x509-structure-san.json)) build bytes; `decode_extension { oid, valueHex }` and `resolve_oid { mode, oids }` name them.

### Propose an upstream change (human submits)
1. Search existing issues, then `draft_governance_issue` with a reproduction and `duplicateSearchPerformed: true` ([`draft-governance-issue.json`](../examples/draft-governance-issue.json)).
2. Review the returned `draftMarkdown` + `compliance`; a **human** copies the draft into GitHub and submits it. The server never does.

---

## 4. Self-documenting metadata

Every tool ships:
- `_meta.apiVersion` = `'1.0.0'` — see [`API_STABILITY.md`](API_STABILITY.md).
- `_meta.examples`   — one or two executable worked examples per tool (the rest live in [`../examples/`](../examples/)). Inspect the `tools/list` response to discover them.
- Read and verdict tools declare a projectable `outputSchema` (every property optional, `additionalProperties: false`) so `structuredContent` validates under `verbosity` / `fields` as well.
- `describe_engine` returns the live manifest: versions, `capabilities` (`canVerify` / `canSign` / `canDecrypt`), `defaultLimits`, `ceilings`, `caps`, `sandbox`, the `registries` (57 / 43 / 97 codes, the wrapper codes, the purposes, the key-usage names), `refusals` and `unexposed`.

You can rely on these fields when negotiating capabilities before calling a tool.

---

## 5. When things still fail

The MCP error response always includes a `code` and a message. The wrapper codes:

| `code` | Meaning | Fix |
|---|---|---|
| `VALIDATION_ERROR` | Zod rejected the input: wrong type / enum / bound, unknown key (strict, at any depth), none or several of `pem` / `derBase64` / `path`, a spec member the structure does not define, SHA-1 without `allowSha1`, a password given twice, a counter time-stamp over something else than the signature value | Re-read the field schema (the message names the path); pass exactly one input form. |
| `INPUT_TOO_LARGE` / `OUTPUT_TOO_LARGE` | An input over a cap (128 MiB inline per call, the effective `maxInputBytes`, 1 GiB by path) / an artefact over 50 MiB inline, 64 KiB hex, 1 GiB file | Use a sandbox `path` / `outputMode: 'file'`; `encoding: 'der'` instead of `'hex'`. |
| `INPUT_NOT_FOUND` / `INVALID_PATH` / `INVALID_EXTENSION` | A `path` that does not exist, is empty, or has the wrong extension | `resources/list` shows the sandbox; fix the extension. |
| `SECURITY_VIOLATION` | File I/O without the sandbox, a path escaping it, a key-bearing `outputPath`, or private-key material fed to `convert_pem extractIndex` / `decode_asn1` / `encode_asn1` / `resources/read` | Relative paths under `PKINATIVE_MCP_OUTPUT_DIR`; open keys with `inspect_private_key` / `inspect_pkcs12` / `open_pkcs12`. |
| `OUTPUT_EXISTS` / `MISSING_OUTPUT_PATH` / `IO_ERROR` | The target exists (never overwritten) / no `outputPath` / a filesystem failure (errno only) | Another `outputPath`; pass one; fix the directory. |
| `LIMIT_CEILING_EXCEEDED` | A `limits.*` value above its operator ceiling (`data.env` names the variable) | Lower it, or the operator raises the ceiling. |
| `SECRET_REQUIRED` / `KEY_TYPE_REQUIRED` / `RSA_SCHEME_REQUIRED` | A password, a `keyType` or an `rsaScheme` is missing | `password` or `PKINATIVE_MCP_PASSWORD`; `signer.keyType` or a public-key input; `rsaScheme: 'pkcs1' \| 'pss'`. |
| `KEY_MISMATCH` / `UNSUPPORTED_KEY` | The key does not belong to the certificate / public key it was paired with; a key Web Crypto cannot sign with here | Pair the key with its own certificate; use EC P-256 / 384 / 521, RSA, Ed25519 (Ed448 where supported). |
| `NOT_FOUND` | An extension kind, a `nodePath` step, a `signerIndex`, an `extractIndex` or an unknown code | Inspect the object first; the message names what exists. |
| `ENGINE_VERDICT` | Opening a PKCS#12 to sign came back negative (`data.reasons`) | Read the reasons; `allowUnverifiedIntegrity: true` for a trusted file. |
| `ENGINE_ERROR` | The engine threw something that is not a `PkiError` (a bug) | Report it with a reproduction via `draft_governance_issue` (`targetRepo: 'pkinative'`). |
| `GOVERNANCE_VIOLATION` | The draft proposes a runtime dependency, embeds a secret, lacks a reproduction block, or `duplicateSearchPerformed: false` | Fix the draft and call again. |
| `UNKNOWN_RESOURCE` | **Protocol error:** `resources/read` with an unknown `pkinative://` URI → JSON-RPC `-32602` | List URIs with `resources/list`. |
| `UNKNOWN_TOOL` | **Protocol error, not a tool result:** `tools/call` with a tool name that does not exist → JSON-RPC `-32602`, message `[UNKNOWN_TOOL] Unknown tool: <name>` | Pick a name from `tools/list` (34 tools). |

A `PKI_*` code (57 of them) is the engine's own refusal, passed through verbatim with `data.errorClass` (`usage` `input` `parse` `security` `limit` `unsupported` `crypto` `password` `check` `internal`) and `data.remedy` — the most frequent: `PKI_PEM_UNEXPECTED_LABEL` (the wrong object for the tool), `PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN` (BER: `encodingRules: 'ber'`), `PKI_ASN1_TRAILING_DATA` (`allowTrailingData: true` or `decode_asn1 sequence: true`), `PKI_CRYPTO_ALGORITHM_REFUSED` (SHA-1: `allowSha1: true`), `PKI_CRYPTO_DECRYPTION_FAILED` (wrong password), `PKI_KEY_ENCRYPTION_UNSUPPORTED` / `PKI_KEY_MAC_UNSUPPORTED` (legacy PKCS#12: convert with OpenSSL 3.4), `PKI_LIMIT_EXCEEDED` (`limits.<name>`), `PKI_X509_EXTENSION_MALFORMED` (`rawExtensions: true`). `explain_code { code }` explains any of them.

The authoritative tables — the 21 wrapper codes, the 57 `PKI_*` codes with class and remedy, the 43 `PKI_REASON_*` and the 97 `PKI_DIAG_*` — are [AGENT_CONTRACT.md](AGENT_CONTRACT.md) §6.

If a tool seems to return correct artefacts that downstream readers reject, feed the bytes back to the matching `inspect_*` / `verify_*` tool, and compare with `openssl x509 -text` / `openssl verify` / `openssl cms -verify`: every artefact this server writes is held to OpenSSL in CI ([`guides/CONFORMANCE.md`](guides/CONFORMANCE.md)).
