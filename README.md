# pkinative-mcp

> **MCP server for PKI — inspect and verify X.509 certificates, CSRs, CRLs, OCSP responses, CMS SignedData and RFC 3161 time-stamps; build and validate certificate chains (RFC 5280 path validation, name and purpose checks, offline CRL and OCSP revocation); create certificates, CSRs, CMS signatures, OCSP and time-stamp requests; open PKCS#8 and PKCS#12 without ever returning a key byte; decode ASN.1, PEM and OIDs** — 34 tools and 7 prompts on the [pkinative](https://github.com/Nizoka/pkinative) engine (zero-dependency, pure TypeScript, Web Crypto for every signature; OpenSSL 3 interoperability validated in CI), for Claude Desktop, Cursor, ChatGPT and any Model Context Protocol client. No network, ever.

[![npm version](https://img.shields.io/npm/v/pkinative-mcp.svg?logo=npm&color=cb3837)](https://www.npmjs.com/package/pkinative-mcp)
[![npm downloads](https://img.shields.io/npm/dm/pkinative-mcp.svg?logo=npm)](https://www.npmjs.com/package/pkinative-mcp)
[![Node version](https://img.shields.io/node/v/pkinative-mcp.svg?logo=node.js)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Nizoka/pkinative-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Nizoka/pkinative-mcp/actions/workflows/ci.yml)
[![OpenSSL interoperability](https://github.com/Nizoka/pkinative-mcp/actions/workflows/interop.yml/badge.svg)](https://github.com/Nizoka/pkinative-mcp/actions/workflows/interop.yml)
[![MCP](https://img.shields.io/badge/MCP-2026--07--28-6f42c1.svg)](https://modelcontextprotocol.io)
[![pkinative](https://img.shields.io/badge/pkinative-1.0-0a7e8c.svg)](https://github.com/Nizoka/pkinative)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Nizoka/pkinative-mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/Nizoka/pkinative-mcp)
[![CodeQL](https://github.com/Nizoka/pkinative-mcp/actions/workflows/codeql.yml/badge.svg)](https://github.com/Nizoka/pkinative-mcp/actions/workflows/codeql.yml)

---

## ✨ Features

`pkinative-mcp` exposes **34 tools** to any MCP host, in six groups. The **kind** says how the result is shaped: a *read* tool returns facts (`structuredContent`, projectable with `verbosity` / `fields`); a *verdict* tool returns `valid` + `reasons[]` and is **never `isError` for a negative verdict**; an *artefact* tool delivers DER or PEM once, inline or into the sandbox. The last column names the refusal codes an agent branches on (the full table is in [`docs/AGENT_CONTRACT.md`](docs/AGENT_CONTRACT.md#6-error-reference)).

### Encodings

| Tool | Kind | What it does | Key refusal codes |
| ---- | ---- | ------------ | ----------------- |
| `convert_pem` | read | `mode: 'decode'` lists every block of a PEM text (label, DER size, offset, SHA-256) and `extractIndex` delivers one as DER / PEM / hex; `mode: 'encode'` wraps DER into one strict RFC 7468 block under `label`. A private-key block is listed, **never extracted and never produced**. | `SECURITY_VIOLATION`, `NOT_FOUND`, `VALIDATION_ERROR`, `PKI_PEM_UNEXPECTED_LABEL`, `PKI_PEM_*` |
| `resolve_oid` | read | Object identifiers in one call: `name` (registered names, ≤ 1000 per call), `validate` (X.660 grammar, reported never thrown), `list` (the engine registry, paged 200 / 2000), `encode` (dotted → hex, content or whole TLV, RELATIVE-OID), `decode` (hex → dotted + name). | `VALIDATION_ERROR`, `PKI_OID_INVALID`, `PKI_ASN1_*` |
| `compute_fingerprint` | read | `fingerprint` of the exact DER (SHA-256 default; SHA-1 / 384 / 512), `key-id` (the RFC 5280 §4.2.1.2 identifier of the public key of a certificate, CSR or PUBLIC KEY), `shake256` (`outputLength` bytes, the Ed448 CMS digest). Any object may be digested; no input byte is returned. | `VALIDATION_ERROR`, `PKI_X509_*`, `PKI_ASN1_*` |
| `decode_asn1` | read | The X.690 node tree of any DER (BER with `encodingRules: 'ber'`): offsets, tags, previews, OID names, ≤ 20 000 nodes; `nodePath` narrows to a subtree, `read` applies a typed reader, `reencode: true` re-encodes the node as an artefact. **Refuses a private key or a PKCS#12** (by label, or when the DER parses as one). | `SECURITY_VIOLATION`, `NOT_FOUND`, `PKI_ASN1_UNEXPECTED_TAG`, `PKI_API_MISUSE`, `PKI_ASN1_*` |
| `encode_asn1` | artefact | A JSON node `spec` (boolean, integer, bit-string, octet-string, oid, string, time, sequence / set / set-of, explicit / implicit, tlv, der) encoded to DER through the engine's own encoders — deterministic; the inverse of `decode_asn1`. | `VALIDATION_ERROR` (naming the JSON path), `SECURITY_VIOLATION`, `PKI_LIMIT_EXCEEDED`, `PKI_ASN1_*`, `PKI_OID_INVALID` |

### Certificates and requests

| Tool | Kind | What it does | Key refusal codes |
| ---- | ---- | ------------ | ----------------- |
| `inspect_certificate` | read | The RFC 5280 report of one certificate: serial, algorithms, issuer / subject (RFC 4514 + RDNs), validity, public key, the 19 extension kinds decoded (`rawExtensions: true` keeps them raw), fingerprints, diagnostics; `extension` returns one; `issuer` / `checkSelfSignature` adds **one** signature check — which is not trust. | `NOT_FOUND`, `PKI_PEM_UNEXPECTED_LABEL`, `PKI_X509_*`, `PKI_CRYPTO_ALGORITHM_REFUSED` |
| `create_certificate` | artefact | Issue an X.509 v3 certificate from `spec` (subject, validity, extensions), signed by `signer` (a PKCS#8 key or a PKCS#12 file imported as a **non-extractable** Web Crypto key): self-signed CA, or a leaf issued from a certificate / CSR / PUBLIC KEY. Serial `'random'` by default; verified against the issuer **before** the bytes return. | `KEY_MISMATCH`, `RSA_SCHEME_REQUIRED`, `KEY_TYPE_REQUIRED`, `SECRET_REQUIRED`, `UNSUPPORTED_KEY`, `VALIDATION_ERROR` |
| `encode_x509_structure` | artefact | One X.509 building block (name, validity, spki, algorithm-identifier, extension(s), basic-constraints, key-usage, extended-key-usage, subject-alt-name, SKI / AKI, signature-algorithm) encoded deterministically from a closed `spec`; hex by default. Nothing here signs. | `VALIDATION_ERROR` (naming the member), `KEY_TYPE_REQUIRED`, `SECRET_REQUIRED`, `RSA_SCHEME_REQUIRED` |
| `decode_extension` | read | One `extnValue` content (hex or DER) decoded by its OID exactly as `inspect_certificate` would; `critical` is checked against the kind's RFC 5280 rule (a diagnostic, not a refusal). | `PKI_X509_EXTENSION_MALFORMED`, `VALIDATION_ERROR` |
| `check_certificate_name` | verdict | The RFC 6125 identity verdict: `certificate` + `host` / `ip` (SAN dNSName / iPAddress, wildcards, an opt-in CN fallback held to the chain's name constraints), or the match form `presented` + `reference` with no certificate. | `PKI_REASON_NAME_MISMATCH` (in `reasons[]`), `VALIDATION_ERROR` |
| `check_certificate_purpose` | verdict | May `certificate` be used for `purpose` (serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, ocspSigning, any, or an OID) along `[certificate, ...chain]`? `restrictIssuers` (default true) applies a CA's own EKU to what it issued. | `PKI_REASON_PURPOSE_NOT_PERMITTED` (in `reasons[]`), `VALIDATION_ERROR` |
| `inspect_csr` | read | The RFC 2986 report of one PKCS#10 request: subject, key, attributes, the extensions requested, whether a challengePassword is present (never its text), and by default the **proof of possession** (`signature.valid`). | `PKI_REASON_SIGNATURE_NOT_CHECKED` (in `reasons[]`), `PKI_X509_*`, `PKI_PEM_UNEXPECTED_LABEL` |
| `create_csr` | artefact | A PKCS#10 request from `spec` (subject, the extensions to request) signed by `signer`; the public key is derived from a plain key, taken from the PKCS#12 certificate or given as `subjectPublicKey`; the proof of possession is verified **before** the bytes return. | `KEY_MISMATCH`, `RSA_SCHEME_REQUIRED`, `SECRET_REQUIRED`, `KEY_TYPE_REQUIRED`, `VALIDATION_ERROR` |

### Paths, CRLs and OCSP

| Tool | Kind | What it does | Key refusal codes |
| ---- | ---- | ------------ | ----------------- |
| `verify_certificate_chain` | verdict | **The one-call trust verdict**: a path from `leaf` through `candidates` to one of your `trustAnchors`, every signature verified, RFC 5280 §6 validation at `at` (validity, constraints, key usage, names, policies), `serverName` (RFC 6125) and `purposes`, and revocation from the CRL / OCSP bytes **you** supply (`requireRevocation` demands evidence). | `PKI_REASON_*` in `reasons[]` (`NO_TRUST_ANCHOR`, `EXPIRED`, `NOT_YET_VALID`, `REVOKED`, `REVOCATION_UNKNOWN`, `NAME_MISMATCH`, …), `VALIDATION_ERROR` |
| `build_certificate_path` | verdict | Path discovery only: which intermediates lead from `leaf` to an anchor under the structural rules at `at`. **No signature is checked** — `valid` is always false, the verdict is `found` and `structuralReasons`. | `PKI_REASON_SIGNATURE_NOT_CHECKED` (always), `PKI_REASON_NO_TRUST_ANCHOR` |
| `validate_certificate_path` | verdict | RFC 5280 §6.1 validation of a path **you** ordered (leaf first) against your anchors at `at`; every link signature verified first (`checkSignatures: false` gives the structural verdict with `failingReasons`). No revocation here. | `PKI_REASON_SIGNATURE_INVALID`, `PKI_REASON_SIGNATURE_NOT_CHECKED`, `VALIDATION_ERROR` |
| `inspect_crl` | read | The RFC 5280 §5 report of one CRL: issuer, updates, CRL number, delta indicator, IDP, entry count (walked, never all decoded), extensions; `find` looks one serial up; `issuer` adds one signature check. | `VALIDATION_ERROR`, `PKI_X509_*`, `PKI_CRYPTO_ALGORITHM_REFUSED` |
| `check_crl_revocation` | verdict | One `certificate` against one base `crl` (and an optional `delta`) you fetched, at `at`: scope, freshness (`staleTolerance`), the signature verified against `issuer`, the serial looked up. | `PKI_REASON_REVOKED` (in `reasons[]`), `VALIDATION_ERROR` (a delta without `deltaCRLIndicator`) |
| `create_ocsp_request` | artefact | The DER OCSPRequest (RFC 6960) for `certificate` under `issuer`: CertID with SHA-1 (default) or SHA-256, an RFC 8954 `nonce` (`'random'` or hex), `certIdOnly`. **You** POST the bytes to the responder; `summary.nonceHex` / `certIdHex` match the answer. | `VALIDATION_ERROR` |
| `inspect_ocsp_response` | read | The RFC 6960 report of one response: status, responder id, producedAt, every SingleResponse (CertID, status, updates), extensions, embedded certificates, nonce presence; `responder` adds one signature check. | `PKI_*` (`PKI_ASN1_*`, `PKI_X509_*`), `VALIDATION_ERROR` |
| `check_ocsp_status` | verdict | One `response` for one `certificate`: the CertID recomputed from `issuer`, the signature verified (`responder`, the embedded certificates or the issuer), the signer **authorised** (RFC 6960 §4.2.2.2), status, freshness at `at`, nonce (`nonce`, `requireNonce`). | `PKI_REASON_REVOKED` and the other `PKI_REASON_*` in `reasons[]`, `VALIDATION_ERROR` |

### CMS and time-stamps

| Tool | Kind | What it does | Key refusal codes |
| ---- | ---- | ------------ | ----------------- |
| `sign_cms` | artefact | An RFC 5652 SignedData over `content` (attached or `detached`) or a precomputed `contentDigest`, one `signer` (PKCS#8 key or PKCS#12), `certificate`, `chain` and `crls` parsed then embedded; signed attributes always written (contentType, messageDigest, signingTime, SigningCertificateV2, CMSAlgorithmProtection); verified against the signer certificate **before** the bytes return. | `KEY_MISMATCH`, `RSA_SCHEME_REQUIRED`, `SECRET_REQUIRED`, `VALIDATION_ERROR`, `PKI_API_MISUSE`, `ENGINE_ERROR` |
| `verify_cms` | verdict | **The one-call verdict** on a SignedData: for every signer the signed attributes, the content digest (attached, or `content` / `contentDigest`), the signature, the chain to your `trustAnchors` at `at`, every counter time-stamp, and revocation from the bytes you supply plus those the message carries; `atTimeStamp: true` is long-term validation. | `PKI_REASON_*` in `reasons[]` (per signer too; `intact` tells unaltered from untrusted), `PKI_ASN1_TRAILING_DATA`, `VALIDATION_ERROR` |
| `inspect_cms` | read | The RFC 5652 report: content type and length, digest algorithms, embedded certificates, CRL / OCSP counts, every signer (identifier, algorithms, signing time as *claimed*, attributes, time-stamp count, **the signature value** a counter time-stamp stamps); `signerCertificate` adds one key check. | `NOT_FOUND` (`signerIndex`), `PKI_ASN1_TRAILING_DATA`, `PKI_*` |
| `amend_cms` | artefact | The one edit a signed message legitimately receives afterwards: `add-unsigned-attribute` (a DER Attribute as hex) or `add-timestamp` (a TimeStampToken or the whole TimeStampResp) on signer `signerIndex`, every signed octet unchanged; the token's imprint is checked against the signature value **before** anything is written. | `VALIDATION_ERROR` (`data.detail` `PKI_REASON_TSP_IMPRINT_MISMATCH`), `NOT_FOUND`, `PKI_API_MISUSE` |
| `create_timestamp_request` | artefact | The RFC 3161 TimeStampReq you POST to a TSA yourself: imprint over `data` or `digestHex` (SHA-256 / 384 / 512), `nonce` (`'random'`, decimal or hex), `policy`, `certReq`. | `VALIDATION_ERROR` (a digest of the wrong length) |
| `inspect_timestamp` | read | A TimeStampResp, a TimeStampToken or a bare TSTInfo (auto-detected, or `as`): status, policy, imprint, serial, genTime, accuracy, nonce, the TSA name as *stated*, the CMS envelope. Parsing proves nothing. | `PKI_*`, `PKI_STRICT_DIAGNOSTIC` (with `strict: true`) |
| `verify_timestamp` | verdict | `token` or `response` judged against what **you** say was stamped (`request`, `data` or `digestHex` — at least one), the TSA signature, its chain to your anchors at `at` with a critical timeStamping EKU, and revocation from the bytes you supply. | `PKI_REASON_TSP_IMPRINT_MISMATCH`, `PKI_REASON_TSP_NOT_GRANTED` and the other `PKI_REASON_*` in `reasons[]`, `VALIDATION_ERROR` |

### Private keys and PKCS#12

| Tool | Kind | What it does | Key refusal codes |
| ---- | ---- | ------------ | ----------------- |
| `inspect_private_key` | read | Describe a PKCS#8 key **without its password**: format, kind, curve, algorithm, the PBES2 parameters of an encrypted key (or the legacy scheme pkinative refuses); `tryImport: true` imports it as a non-extractable Web Crypto key and reports the handle. No result ever carries a key byte. | `SECRET_REQUIRED`, `KEY_TYPE_REQUIRED`, `RSA_SCHEME_REQUIRED`, `PKI_CRYPTO_DECRYPTION_FAILED`, `PKI_KEY_ENCRYPTION_UNSUPPORTED` |
| `inspect_pkcs12` | read | Describe a `.p12` / `.pfx` **without its password**: MAC construction (PBMAC1, or the legacy RFC 7292 MAC), every SafeContents and its scheme, the bags of the plain ones; with a password, `macVerified` and `opened` (allow-list views of every bag). | `PKI_CRYPTO_DECRYPTION_FAILED`, `PKI_KEY_MAC_UNSUPPORTED`, `PKI_KEY_ENCRYPTION_UNSUPPORTED` |
| `open_pkcs12` | verdict | Open a PKCS#12 in one call: MAC verified, PBES2 SafeContents decrypted, every key unwrapped straight into a non-extractable Web Crypto key (described, never exported), certificates parsed, CRLs counted; `exportCertificates: true` attaches a PEM bundle of the certificates and CRLs — never a key. | `SECRET_REQUIRED`; in `reasons[]`: `PKI_REASON_PKCS12_MAC_MISMATCH`, `PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED`, `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED`, `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED` |

### Meta

| Tool | Kind | What it does | Key refusal codes |
| ---- | ---- | ------------ | ----------------- |
| `describe_engine` | engine | Offline preflight: versions, the host's Web Crypto capabilities, the engine's 22 default limits, the operator ceilings, every server cap, sandbox / cache / pinned-instant state, the 57 `PKI_*` / 43 `PKI_REASON_*` / 97 `PKI_DIAG_*` vocabularies, the 21 wrapper codes, the doctrine refusals and the deliberately unexposed engine surface. `network` is always `'none'`. Never cached. | `VALIDATION_ERROR` |
| `explain_code` | explain | Any code this server can emit, explained from the registries vendored at the pkinative v1.0.0 tag (class, standard, CWE, remedy, the MCP input that lifts it); `list: true` enumerates one vocabulary. | `NOT_FOUND` |
| `draft_governance_issue` | governance | A **local** GitHub issue draft plus a compliance report for pkinative, pkinative-cli or pkinative-mcp — never submitted; a human files it under their own identity. | `GOVERNANCE_VIOLATION`, `MISSING_OUTPUT_PATH`, `INVALID_EXTENSION`, `OUTPUT_EXISTS`, `SECURITY_VIOLATION` |

**What every tool guarantees:**

- 🌐 **No network, ever** — no CRL / OCSP / AIA / TSA fetch, no telemetry, no GitHub, no URL from any argument, no operator-configurable endpoint. Revocation evidence and time-stamp tokens are **inputs**; `create_ocsp_request` and `create_timestamp_request` produce bytes **you** transport. Every tool advertises `openWorldHint: false`.
- 🔑 **No key byte leaves** — signing keys are non-extractable Web Crypto handles; every key / PKCS#12 report is an allow-list view; key-bearing files (`.key .p8 .p12 .pfx`) are never written and never served as resources; `convert_pem`, `decode_asn1` and `encode_asn1` refuse private-key material. There is no key generation and no key export.
- 🧭 **Verdicts are reports, errors are refusals** — a negative verdict is `valid: false` + `reasons[]` with the engine's `PKI_REASON_*` codes (43 of them); `isError` is reserved for an input the engine refuses (one of the 57 `PKI_*` codes, passed through verbatim with `data.errorClass` and a remedy) or a wrapper refusal (21 codes, each with a remedy). Branch on the code, never on the message.
- 📐 **Doctrine, surfaced not hidden** — SHA-1 only with `allowSha1: true`; RSA needs an explicit `rsaScheme` (`'pkcs1'` | `'pss'`, no default); PBES2 and PBMAC1 only (a legacy RC2 / 3DES PKCS#12 is refused with the OpenSSL 3.4 conversion remedy); DSA and ML-DSA are parsed, never verified; diagnostics (97 `PKI_DIAG_*` codes) are not errors unless `strict: true`; the engine's 22 limits raise per call and never above the operator ceilings.
- 🪙 **Token-frugal** — read and verdict tools accept `verbosity: 'summary'` and `fields: [...]`; artefacts arrive **once** as an embedded `resource` block or a `resource_link`, never duplicated into `structuredContent`.
- 🔁 **Reproducible on request** — pin `at`, `notBefore`, `signingTime`, `serialNumber` and `nonce` (or let the operator pin the instant with `PKINATIVE_MCP_AT`) and an artefact or a verdict is a pure function of its inputs; `structuredContent.sha256` is the proof.
- 🧪 **OpenSSL 3 is the judge** — every artefact the server writes is read back by OpenSSL 3.x in CI (23 conformant artefacts, 5 refused canaries, 12 command families), blocking on Linux and Windows.

All artefact-producing tools support two output modes and three encodings:

- **`base64`** *(default)* — the artefact is returned **once** as an embedded `resource` content block (PEM as `text`, DER as `blob`, with its MIME type: `application/pkix-cert`, `application/pkcs10`, `application/pkcs7-signature`, `application/pkix-crl`, `application/ocsp-request`, `application/timestamp-query`, …); `structuredContent` carries `{ mode, encoding, sizeBytes, sha256, summary, diagnostics }` — with `encoding: 'hex'` the bytes land in `structuredContent.hex` instead (inline only, ≤ 64 KiB).
- **`file`** — the artefact is written inside the sandbox configured by `PKINATIVE_MCP_OUTPUT_DIR` (exclusive create, never overwritten → `OUTPUT_EXISTS`; ≤ 1 GiB) and the result carries a `resource_link`. File I/O is disabled unless this variable is set; absolute paths, traversal, NUL bytes, a key-bearing or unknown extension and a symlink or junction whose real path leaves the sandbox are all rejected. The same sandbox serves every `path` **input**, so a `create_csr → create_certificate → verify_certificate_chain` chain never re-sends the bytes.

**Token-frugal reads.** The read and verdict tools (and `describe_engine`, `explain_code`) accept two optional inputs:

- `verbosity: 'summary'` — a compact scalar-only verdict. E.g. `verify_certificate_chain` → `{ valid, reasonCodes, pathLength, evaluatedAt, diagnosticCount }`; `inspect_certificate` → subject, issuer, serial, validity, key, extension kinds.
- `fields: ['a', 'b.c']` — projects the structured result to named dot-paths (≤ 16; arrays map over elements); composes after `verbosity`. Unmatched paths are omitted and reported in `_meta.unmatchedFields` (with `_meta.availableFields`).

Smallest "can I trust this server certificate?" probe: `{ "leaf": {…}, "trustAnchors": [{…}], "at": "2027-01-01T00:00:00Z", "serverName": { "host": "example.test" }, "verbosity": "summary", "fields": ["valid", "reasonCodes"] }` on `verify_certificate_chain`.

The server also ships **seven MCP prompts** — `governance_contract`, `draft_issue_workflow`, `verify_before_trust`, `issue_certificate`, `sign_and_timestamp`, `offline_revocation`, `open_keys_safely` — and exposes every non-secret file in the sandbox as a `pkinative://output/{+path}` **resource**.

### Why pkinative?

`pkinative-mcp` inherits every guarantee of the underlying engine:

- **Zero runtime dependencies in the engine** — pure TypeScript, no native bindings; Web Crypto for every signature, so no secret-dependent arithmetic runs in JavaScript (this server adds only the MCP SDK and zod: three runtime dependencies in total).
- **RFC 5280 path validation** (building, §6.1 validation, name constraints, policies), **RFC 6125 names**, **RFC 6960 OCSP**, **RFC 5652 CMS**, **RFC 3161 time-stamps**, **RFC 2986 CSRs**, **RFC 5958 / 8018 PKCS#8 with PBES2**, **RFC 7292 / 9579 PKCS#12 with PBMAC1**, strict X.690 DER with opt-in BER.
- **22 named, CWE-tagged limits** on every parser loop — raised only by explicit input, never silently.
- **A frozen vocabulary** — 57 `PKI_*` error codes, 43 `PKI_REASON_*` verdict reasons and 97 `PKI_DIAG_*` diagnostics, vendored at the v1.0.0 tag and passed through verbatim.
- **What it will NOT do:** no key generation, no key export, no writer for PKCS#8 / PKCS#12 / CRL / OCSP response / time-stamp response, no DSA / ML-DSA verification, **no network access, ever**.

---

## 🚀 Installation

```bash
# Run directly with npx (recommended for MCP clients)
npx -y pkinative-mcp

# Or install globally
npm install -g pkinative-mcp
pkinative-mcp
```

Requirements: **Node.js ≥ 22** (the engine's floor is `^22.22.2 || ^24.14.1 || >=25.8.2`; `describe_engine.capabilities.nodeFloorSatisfied` tells you). From source: `git clone https://github.com/Nizoka/pkinative-mcp.git && cd pkinative-mcp && npm ci --ignore-scripts && npm run build && node dist/cli.js`.

---

## ⚙️ Configuration

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "pkinative": {
      "command": "npx",
      "args": ["-y", "pkinative-mcp"],
      "env": {
        "PKINATIVE_MCP_OUTPUT_DIR": "/Users/you/Documents/mcp-pki"
      }
    }
  }
}
```

### Claude Code

`.mcp.json` at the root of the project (the repository ships one that drives the **built** server from `dist/cli.js`):

```json
{
  "mcpServers": {
    "pkinative": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "pkinative-mcp"],
      "env": { "PKINATIVE_MCP_OUTPUT_DIR": "${CLAUDE_PROJECT_DIR}/.mcp-pki" }
    }
  }
}
```

### Cursor / Continue / Zed / Windsurf / Cline / Roo Code

Any MCP-compatible client that supports stdio servers will work. Use the same `command` + `args` + `env` triple. Example for **Cursor** (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "pkinative": {
      "command": "npx",
      "args": ["-y", "pkinative-mcp"],
      "env": { "PKINATIVE_MCP_OUTPUT_DIR": "/Users/you/Documents/mcp-pki" }
    }
  }
}
```

**Windsurf / Cline / Roo Code** use the same shape inside their respective MCP config files.

### VS Code

`.vscode/mcp.json`:

```json
{
  "servers": {
    "pkinative": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "pkinative-mcp"],
      "env": { "PKINATIVE_MCP_OUTPUT_DIR": "${workspaceFolder}/.mcp-pki" }
    }
  }
}
```

### 🌐 Supported AI Ecosystem & Clients

`pkinative-mcp` is designed for MCP-native environments and works with clients that support MCP over stdio or Streamable HTTP: Claude Desktop, Claude Code, Cursor, Continue, Zed, Windsurf, Cline, Roo Code, VS Code, ChatGPT (Streamable HTTP), the MCP Inspector, and any client built on the MCP TypeScript / Python SDKs. Because the server never opens a socket of its own, it is also safe to run inside air-gapped or egress-restricted hosts — which is where PKI material usually lives.

It is the third server of the "native" family, after [pdfnative-mcp](https://github.com/Nizoka/pdfnative-mcp) (PDF) and [zipnative-mcp](https://github.com/Nizoka/zipnative-mcp) (ZIP): the same thin-wrapper architecture, the same sandbox, cache, projection and governance conventions, the same human-in-the-loop rules. The same engine is on the command line as [pkinative-cli](https://github.com/Nizoka/pkinative-cli).

### 🔌 MCP protocol compliance

The server is built on the MCP TypeScript SDK v2 (`@modelcontextprotocol/server`) and speaks **MCP 2026-07-28**:

- **Stateless serving** — `server/discover` replaces the session handshake; every result carries `resultType` and the `_meta` `serverInfo` envelope. Over HTTP, 2026-07-28 clients send `Mcp-Method` / `Mcp-Name` headers with each `POST /mcp`.
- **Cache hints** — `tools/list` and `prompts/list` are `public` with a 24 h `ttlMs`, `server/discover` is `public` for 1 h, and `resources/list` / `resources/templates/list` / `resources/read` are `private` with `ttlMs: 0` (sandbox files are per-host user data).
- **Protocol errors** — `tools/call` with an unknown tool name is a JSON-RPC error (`-32602`, `[UNKNOWN_TOOL] Unknown tool: …`) rather than an `isError` result, and an unknown resource URI is `-32602` (Invalid params), as the specification requires; `isError: true` is reserved for execution failures.
- **Automatic legacy fallback** — a client that opens with `initialize` is served through the SDK's legacy path on both stdio and HTTP for every revision the SDK negotiates: **2024-10-07, 2024-11-05, 2025-03-26, 2025-06-18 and 2025-11-25** (legacy) next to **2026-07-28** (modern). Nothing changes for existing hosts.
- **HTTP** — `POST /mcp` only; `GET` / `DELETE /mcp` answer **405** (no SSE resumability; the server is stateless). Bound to `127.0.0.1` with a `Host` / `Origin` guard (foreign values → 403); `PKINATIVE_MCP_HTTP_TOKEN` adds an opt-in bearer-token gate (`401` + `WWW-Authenticate` without it); bodies above 256 MiB → 413.
- **stdio** — the frame cap is **256 MiB** so a multi-MiB base64 CMS message or PKCS#12 fits in one `tools/call`; as in every SDK release, a request sent before `initialize` is dropped without a reply on the legacy path.
- **Output schemas** — every `structuredContent` validates against the tool's `outputSchema` (a 2026-07-28 MUST), including `verbosity: 'summary'` and `fields` projections: the read and verdict tools declare projectable schemas (all properties optional, `additionalProperties: false` kept). Input schemas carry no `$schema` keyword and no `$ref` by policy (some hosts forward `inputSchema` to function-calling APIs that reject unknown keywords). `serverInfo` carries `websiteUrl`; the resource template is `pkinative://output/{+path}`.

The `tools/call` payload (`content`, `structuredContent`, `isError`) is identical between the 2026-07-28 path and the legacy path; `tests/http-modern.test.ts` asserts it, and `tests/schema-conformance.test.ts` validates `structuredContent` with the SDK's JSON Schema 2020-12 validator.

| Client                                                   | Transport        | Protocol negotiated                                 |
| -------------------------------------------------------- | ---------------- | --------------------------------------------------- |
| Claude Desktop, Cursor, Continue, Zed, Windsurf, Cline   | stdio            | legacy `initialize` (2024-xx / 2025-xx) — unchanged |
| ChatGPT and other Streamable HTTP hosts                  | HTTP `POST /mcp` | legacy stateless streamable HTTP — unchanged        |
| MCP 2026-07-28 clients (SDK v2 `Client`, current MCP Inspector) | stdio / HTTP | `server/discover`, cache hints, `_meta` envelope |

Compatibility matrix — every negotiated revision, on both transports, with the test that proves it:

| Revision | Era | stdio | HTTP `POST /mcp` | Proven by |
| -------- | --- | :---: | :--------------: | --------- |
| 2024-10-07 | legacy `initialize` | ✓ | ✓ | `tests/protocol-revisions.test.ts` |
| 2024-11-05 | legacy `initialize` | ✓ | ✓ | `tests/protocol-revisions.test.ts` |
| 2025-03-26 | legacy `initialize` | ✓ | ✓ | `tests/protocol-revisions.test.ts` |
| 2025-06-18 | legacy `initialize` | ✓ | ✓ | `tests/protocol-revisions.test.ts`, `tests/http-transport.test.ts` |
| 2025-11-25 | legacy `initialize` | ✓ | ✓ | `tests/protocol-revisions.test.ts`, `tests/cli-stdio.test.ts`, `tests/autonomy.test.ts` |
| 2026-07-28 | modern (`server/discover`, `_meta` envelope, cache hints) | ✓ | ✓ (+ bearer token) | `tests/stdio-modern.test.ts`, `tests/http-modern.test.ts`, `tests/autonomy.test.ts` |

### Environment variables

All nine are declared in [`server.json`](server.json), read **once** at boot; an invalid value refuses to start — never a silent fallback. Only the *presence* of a secret is logged.

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `PKINATIVE_MCP_OUTPUT_DIR` | *(unset)* | Absolute path of the **one** sandbox directory: every `path` input (PKI objects, content, keys) is read from it and `outputMode: 'file'` outputs are written under it (exclusive create — never overwritten). The **real** path of every file read and of every parent written must stay inside it: a symlink or junction planted in the sandbox is `SECURITY_VIOLATION` on both sides. Key-bearing files (`.key .p8 .p12 .pfx`) are read by the key tools only, never written, never served as resources. Unset ⇒ every tool works on inline PEM / base64 only. |
| `PKINATIVE_MCP_CACHE_DIR` | *(unset)* | Opt-in content-addressed response cache (SHA-256 keyed, 1 h TTL, 256 MiB LRU, plaintext at rest; key namespaced by tool API, package and engine version). Never caches a `path` input, file output, a call carrying a `password` or a `signer`, a `'random'` serial or nonce, a `'now'` or unpinned instant, `describe_engine` or `draft_governance_issue` — nor any password-accepting tool while `PKINATIVE_MCP_PASSWORD` is set; a hit carries `_meta.cached: true`. |
| `PKINATIVE_MCP_PORT` | *(unset → stdio)* | When set to a valid port (1–65535), serves Streamable HTTP on `http://127.0.0.1:<port>/mcp` instead of stdio. Loopback only, DNS-rebinding protection (foreign `Host` / `Origin` → **403**), `GET` / `DELETE` → 405. **No authentication unless `PKINATIVE_MCP_HTTP_TOKEN` is set** — other local processes can reach the endpoint. |
| `PKINATIVE_MCP_HTTP_TOKEN` | *(unset)* | *(secret)* Opt-in bearer token for the HTTP transport (≥ 16 characters, no whitespace — a weaker value aborts startup). When set, every `/mcp` request must carry `Authorization: Bearer <token>`; otherwise **401** + `WWW-Authenticate: Bearer realm="pkinative-mcp"` (with `error="invalid_token"` only when credentials were sent — RFC 6750 §3.1). Compared constant-time, never logged. |
| `PKINATIVE_MCP_PASSWORD` | *(unset)* | *(secret)* The operator-side password of the encrypted PKCS#8 key or PKCS#12 file the tools open — it keeps the secret out of the model transcript. Exclusive with the per-call `password` input (both at once is `VALIDATION_ERROR`). Never logged; only its presence is reported at startup. |
| `PKINATIVE_MCP_AT` | *(unset → wall clock)* | Pinned instant (ISO 8601, or epoch milliseconds) every omitted `at` / `notBefore` / `signingTime` falls back to, for reproducible verdicts and artefacts. Unset: the wall clock — and a clock-dependent result is never cached. |
| `PKINATIVE_MCP_MAX_INPUT_BYTES` | `67108864` (64 MiB) | Operator ceiling for `limits.maxInputBytes` and the decoded size of one PKI object (the engine default). Integer ≥ 1024. A per-call value above it is `LIMIT_CEILING_EXCEEDED`; a ceiling below the engine default tightens the default silently. |
| `PKINATIVE_MCP_MAX_KDF_ITERATIONS` | `10000000` | Operator ceiling for `limits.maxKdfIterations` and `limits.maxPkcs12KdfIterations` (the engine default): the CPU bound of a hostile PBES2 key or PKCS#12 file. Integer ≥ 1. |
| `PKINATIVE_MCP_MAX_PATHS_EXPLORED` | `1000` | Operator ceiling for `limits.maxPathsExplored` (the engine default): the RFC 5280 §6 path-building work bound. Integer ≥ 1. |

**The operator ceilings.** The engine's 22 named `PkiLimits` (`maxInputBytes`, `maxDepth`, `maxNodes`, `maxIntegerBytes`, `maxOidBytes`, `maxBerSegments`, `maxPemBlocks`, `maxExtensions`, `maxGeneralNames`, `maxNameAttributes`, `maxPolicies`, `maxChainLength`, `maxPolicyNodes`, `maxRevokedCertificates`, `maxOcspSingleResponses`, `maxPathsExplored`, `maxSignerInfos`, `maxAttributes`, `maxCmsCertificatesAndCrls`, `maxKdfIterations`, `maxPkcs12Bags`, `maxPkcs12KdfIterations`) can be raised **per call** through the `limits` fragment for trusted input only. Three of them are bounded by the three operator ceilings above: a value above the ceiling is refused with `LIMIT_CEILING_EXCEEDED` and `data.env` names the variable an operator would raise. There is no "unbounded" and no ceiling a tool argument can move. `describe_engine` reports the defaults, the ceilings and every cap in force.

---

## 🛠 Tool reference

Every PKI object input is an object with **exactly one** of `pem` (RFC 7468 text), `derBase64` (the DER as base64, exactly once — no `data:` URI, not PEM) or `path` (relative, inside the sandbox; `.pem .crt .cer .der .csr .p10 .crl .p7s .p7b .p7c .p7m .cms .p12 .pfx .key .p8 .pub .ocsp .ors .orq .tsq .tsr .tst .bin .asn1`). Every engine-touching tool takes the `PARSE` fragment (`encodingRules`, `pemMode`, `strict`, `limits`); the read and verdict tools take `verbosity` and `fields`; the artefact tools take `outputMode`, `outputPath` and `encoding`. The fragments are described in [Shared input fragments](#-shared-input-fragments). Error results: `content[0].text = "<tool> failed [CODE]: message"`, `isError: true`, `_meta.error = { code, message, data? }`. Full input / output schemas are advertised by `tools/list`; the consumer contract — catalogue, decision tree, recipes and the complete error table — is [`docs/AGENT_CONTRACT.md`](docs/AGENT_CONTRACT.md). Every example below is an executable call from [`examples/`](examples/) or a tool's `_meta.examples` (the `fixtures/…` paths are the TEST-ONLY PKI the examples runner copies into the sandbox; `test-only-password` is their published password).

### `convert_pem`

The RFC 7468 layer ([catalogue](docs/AGENT_CONTRACT.md#1-tool-catalogue-34-tools)). **Inputs:** `mode` (`decode` | `encode`), `input` (PKI_INPUT), `label`, `extractIndex`, PARSE, PROJECTION, OUTPUT (`encoding` der / pem / hex). **Output:** `blocks[]` (index, label, sizeBytes, offset, sha256), `count`, `extracted`, and the `artefact` when a block is extracted or DER is wrapped. **Codes:** `SECURITY_VIOLATION` (a private-key block or DER that parses as a key or a PKCS#12, under any label), `NOT_FOUND` (an index past the last block), `VALIDATION_ERROR`, `PKI_PEM_UNEXPECTED_LABEL`, `PKI_PEM_*`.

```jsonc
{ "mode": "decode", "input": { "path": "fixtures/leaf.crt.pem" }, "label": "CERTIFICATE", "extractIndex": 0, "encoding": "hex", "fields": ["extracted", "artefact"] }
```

### `resolve_oid`

Object identifiers in one call. **Inputs:** `mode` (`name` | `validate` | `list` | `encode` | `decode`), `oids[]` (≤ 1000), `filter`, `offset` / `limit` (200 default, 2000 max), `form` (`content` | `tlv`), `relative`, `hex`, PARSE, PROJECTION. **Output:** per mode — `oids[]` with names or validity, `entries[]` + `total` / `hasMore`, or one `oid` + `name`. **Codes:** `VALIDATION_ERROR` (a member outside its mode, `relative` without `form: 'tlv'`), `PKI_OID_INVALID` (encode / decode; `validate` reports it instead), `PKI_ASN1_*`.

```jsonc
{ "mode": "name", "oids": ["1.2.840.10045.4.3.2", "2.5.29.17", "1.3.6.1.5.5.7.3.1", "1.2.3.4"] }
```

### `compute_fingerprint`

The digest of one object. **Inputs:** `input` (PKI_INPUT, any label or DER; a bundle is refused), `mode` (`fingerprint` | `key-id` | `shake256`), `algorithm`, `webcrypto`, `outputLength` (≤ 1 MiB), `separator`, `letterCase`, PARSE, PROJECTION. **Output:** `hex`, `formatted`, `algorithm`, `sizeBytes`, `label`, `from` (where the public key came from in `key-id`). **Codes:** `VALIDATION_ERROR` (an algorithm outside its mode, SHA-384 / 512 for a key identifier), `PKI_X509_*` / `PKI_ASN1_*` (`key-id` on an object without a public key).

```jsonc
{ "input": { "path": "fixtures/leaf.csr.pem" }, "mode": "key-id", "fields": ["formatted", "from"] }
```

### `decode_asn1`

The X.690 node tree. **Inputs:** `input` (PKI_INPUT — never a private key or a PKCS#12), `sequence`, `nodePath` (`'0.2.1'`), `read` (boolean | integer | small-integer | enumerated | null | bit-string | octet-string | oid | relative-oid | string | time), `stringType`, `timeType`, `reencode`, `allowTrailingData`, `maxPreviewBytes` (default 32), PARSE, PROJECTION, OUTPUT. **Output:** `nodes[]` (path, offset, lengths, tag, constructed, children, preview, oid + oidName), `nodeCount`, `truncated` (past 20 000 nodes), `value` (the typed read), `reencode.identical`, `artefact`. **Codes:** `SECURITY_VIOLATION`, `NOT_FOUND` (a missing `nodePath` step, naming the range), `PKI_ASN1_UNEXPECTED_TAG` (a wrong reader), `PKI_API_MISUSE` (an IMPLICIT string / time without `stringType` / `timeType`), `PKI_ASN1_*`.

```jsonc
{ "input": { "path": "fixtures/leaf.crt.der" }, "nodePath": "0.1", "read": "integer", "verbosity": "summary" }
```

### `encode_asn1`

A JSON node spec to DER. **Inputs:** `spec` (one node `{ type, … }`), `label` (for `encoding: 'pem'`), PARSE, OUTPUT (`encoding` der / hex / pem; default der). **Output:** the artefact (`sizeBytes`, `sha256`, `hex` or the resource) and `summary` (root tag, node count). **Codes:** `VALIDATION_ERROR` naming the JSON path (`$.children[1].value …`), `SECURITY_VIOLATION` (a private-key label, or a value that parses as a key or a PKCS#12), `PKI_LIMIT_EXCEEDED` (nesting past `limits.maxDepth`), `PKI_ASN1_*`, `PKI_OID_INVALID`.

```jsonc
{ "spec": { "type": "sequence", "children": [{ "type": "oid", "value": "1.2.840.10045.4.3.2" }] }, "encoding": "hex" }
```

### `inspect_certificate`

The RFC 5280 report. **Inputs:** `certificate` (PKI_INPUT), `extension` (one of the 19 kinds), `rawExtensions`, `issuer` (PKI_INPUT) or `checkSelfSignature`, `requireAlgorithmMatch`, `fingerprints[]`, `allowSha1`, PARSE, PROJECTION. **Output:** `version`, `serialNumber`, `signatureAlgorithm`, `issuer` / `subject` (+ `issuerString` / `subjectString`), `validity`, `subjectPublicKeyInfo`, `extensions[]`, `selfIssued`, `fingerprints`, `signature` (valid / algorithm, when checked), `diagnostics[]`. **Codes:** `NOT_FOUND` (an `extension` the certificate lacks), `PKI_PEM_UNEXPECTED_LABEL` (a key given as a certificate — refused by label before any byte is parsed), `PKI_X509_*`, `PKI_CRYPTO_ALGORITHM_REFUSED` (SHA-1 without `allowSha1`).

```jsonc
{ "certificate": { "path": "fixtures/leaf.crt.pem" }, "issuer": { "path": "fixtures/inter.crt.pem" }, "fingerprints": ["SHA-256", "SHA-1"], "fields": ["signature", "extensions.kind", "subjectString", "fingerprints"] }
```

### `create_certificate`

Issue a certificate. **Inputs:** `spec` (`serialNumber` — integer, hex string or `'random'`, `subject`, `issuer`, `notBefore`, `notAfter` / `validityDays`, `extensions` — basicConstraints, keyUsage, extendedKeyUsage, subjectAltName, issuerAltName, SKI / AKI, raw), `issuerCertificate` (PKI_INPUT; omitted = self-signed), `subjectPublicKey` (a certificate, a CSR or a PUBLIC KEY), `signer` (SIGNER), `allowSha1`, PARSE, OUTPUT (default pem). **Output:** the artefact and `summary` (`serialNumber`, `randomSerial`, subject, issuer, `selfSigned`, `signatureAlgorithm`, `notBefore` / `notAfter` with `notBeforeSource`, the extension kinds, `signatureVerified`, `publicKeyFrom`). **Codes:** `KEY_MISMATCH` (the new certificate did not verify against the issuer or itself), `RSA_SCHEME_REQUIRED`, `KEY_TYPE_REQUIRED`, `SECRET_REQUIRED`, `UNSUPPORTED_KEY`, `VALIDATION_ERROR` (an unknown spec member, SHA-1 without `allowSha1`, `notAfter` before `notBefore`).

```jsonc
{
  "spec": {
    "serialNumber": 1,
    "subject": { "C": "FR", "O": "Acme", "CN": "Acme Test CA" },
    "notBefore": "2027-01-01T00:00:00Z",
    "validityDays": 3650,
    "extensions": { "basicConstraints": { "ca": true, "pathLen": 0 }, "keyUsage": ["keyCertSign", "cRLSign"] }
  },
  "signer": { "key": { "path": "fixtures/ed25519.key.pem" } }
}
```

### `encode_x509_structure`

One building block to DER. **Inputs:** `structure` (name | name-attribute | validity | spki | algorithm-identifier | attribute | extension | extensions | basic-constraints | key-usage | extended-key-usage | subject-alt-name | subject-key-identifier | authority-key-identifier | signature-algorithm), `spec` (a closed object), `signer` (`signature-algorithm` only — the key is imported non-extractable and only its algorithm is read), `label`, `allowSha1`, PARSE, OUTPUT (default hex). **Output:** the artefact (`hex` by default) and `summary`. **Codes:** `VALIDATION_ERROR` naming `spec <member>` (an unknown or missing member is never dropped silently), `KEY_TYPE_REQUIRED`, `SECRET_REQUIRED`, `RSA_SCHEME_REQUIRED`.

```jsonc
{ "structure": "subject-alt-name", "spec": { "dns": ["svc.example.test", "*.wild.example.test"], "ip": ["192.0.2.1"] } }
```

### `decode_extension`

One `extnValue` by OID. **Inputs:** `oid`, `valueHex` or `value` (PKI_INPUT — the DER inside the OCTET STRING), `critical`, PARSE, PROJECTION. **Output:** `kind`, `oid`, `name`, `critical`, `sizeBytes`, `decoded` (the kind's members), `diagnostics[]` (the criticality check). **Codes:** `PKI_X509_EXTENSION_MALFORMED` (remedy: `decode_asn1`), `VALIDATION_ERROR`.

```jsonc
{ "oid": "2.5.29.19", "valueHex": "30030101ff", "critical": true }
```

### `check_certificate_name`

The RFC 6125 identity verdict. **Inputs:** certificate form — `certificate` (PKI_INPUT) + `host` or `ip`, `chain[]` (PKI_BUNDLE, for the CN fallback), `allowCommonNameFallback` (default false), `allowWildcards` (default true); match form — `presented` + `reference`; PARSE, PROJECTION. **Output:** `form`, `valid`, `reasons[]`, `reference`, `subject` / `presented`, `match`. **Codes:** `PKI_REASON_NAME_MISMATCH` and friends in `reasons[]` (a verdict, never `isError`); `VALIDATION_ERROR` (both forms at once).

```jsonc
{ "certificate": { "path": "fixtures/leaf.crt.pem" }, "host": "a.wild.example.test", "verbosity": "summary" }
```

### `check_certificate_purpose`

The RFC 5280 §4.2.1.12 purpose verdict. **Inputs:** `certificate`, `chain[]` (leaf's issuer first), `purpose` (serverAuth | clientAuth | codeSigning | emailProtection | timeStamping | ocspSigning | any | a dotted OID), `restrictIssuers` (default true), `requireExplicitPurpose` (default false), PARSE, PROJECTION. **Output:** `valid`, `reasons[]`, `purposeOid`, `purposeName`, `subject`, `pathLength`. **Codes:** `PKI_REASON_PURPOSE_NOT_PERMITTED` (with the `path[i]` element) in `reasons[]`; `VALIDATION_ERROR` (an unknown purpose name).

```jsonc
{ "certificate": { "path": "fixtures/leaf.crt.pem" }, "purpose": "codeSigning" }
```

### `inspect_csr`

The RFC 2986 report. **Inputs:** `request` (PKI_INPUT), `rawExtensions`, `verify` (default true — the proof of possession, one Web Crypto verification), `allowSha1`, PARSE, PROJECTION. **Output:** `subject` (+ `subjectString`), `subjectPublicKeyInfo`, `attributes[]`, `extensions[]`, `challengePassword` (present or not, never its text), `signatureAlgorithm`, `signature` (`valid`, `reasons[]`). **Codes:** `PKI_REASON_SIGNATURE_NOT_CHECKED` in `signature.reasons[]` (SHA-1 without `allowSha1`), `PKI_X509_*`, `PKI_PEM_UNEXPECTED_LABEL`.

```jsonc
{ "request": { "path": "fixtures/leaf.csr.pem" }, "verbosity": "summary" }
```

### `create_csr`

A PKCS#10 request. **Inputs:** `spec` (`subject`, `extensions` — subjectAltName, keyUsage, extendedKeyUsage, basicConstraints, subjectKeyIdentifier, raw; the issuer's extensions are refused), `subjectPublicKey` (required for an encrypted PKCS#8 key), `signer` (SIGNER), `allowSha1`, PARSE, OUTPUT (default pem). **Output:** the artefact and `summary` (subject, `signatureAlgorithm`, the requested extension kinds, `signatureVerified`, `publicKeyFrom`). **Codes:** `KEY_MISMATCH` (the key does not match the public key named), `RSA_SCHEME_REQUIRED`, `SECRET_REQUIRED`, `KEY_TYPE_REQUIRED`, `VALIDATION_ERROR`.

```jsonc
{
  "spec": {
    "subject": { "C": "FR", "O": "Acme", "CN": "svc.example.test" },
    "extensions": { "subjectAltName": { "dns": ["svc.example.test", "www.svc.example.test"] }, "keyUsage": ["digitalSignature"], "extendedKeyUsage": ["serverAuth"] }
  },
  "signer": { "key": { "path": "fixtures/leaf.key.pem" } }
}
```

### `verify_certificate_chain`

The RFC 5280 §6 verdict. **Inputs:** `leaf` (PKI_INPUT), TRUST (`trustAnchors[]`, `candidates[]`, `crls[]`, `ocspResponses[]`, `at`, `requireRevocation`, `purposes[]`, `policy`), `serverName` (`host` | `ip`), `ocspNonce`, `requireOcspNonce`, `allowSha1`, PARSE, PROJECTION. **Output:** `valid`, `reasons[]`, `path[]` (leaf first up to the anchor), `pathLength`, `explored`, `signatureVerifications[]`, `evaluatedAt` + `evaluatedAtSource`, `revocationEvidence`. **Codes:** `PKI_REASON_*` in `reasons[]` — `NO_TRUST_ANCHOR`, `EXPIRED`, `NOT_YET_VALID`, `REVOKED`, `REVOCATION_UNKNOWN`, `REVOCATION_STALE`, `NAME_MISMATCH`, `PURPOSE_NOT_PERMITTED`, … (a verdict, never `isError`); `VALIDATION_ERROR`, `PKI_*` for inputs the engine refuses.

```jsonc
{
  "leaf": { "path": "fixtures/revoked.crt.pem" },
  "candidates": [{ "path": "fixtures/inter.crt.pem" }],
  "trustAnchors": [{ "path": "fixtures/root.crt.pem" }],
  "crls": [{ "path": "fixtures/inter.crl.pem" }],
  "ocspResponses": [{ "path": "fixtures/revoked.ocsp.der" }],
  "requireRevocation": true,
  "at": "2027-01-01T00:00:00Z",
  "fields": ["valid", "reasons.code", "revocation", "pathLength"]
}
```

### `build_certificate_path`

Path discovery, signatures **not** checked. **Inputs:** `leaf`, `candidates[]`, `trustAnchors[]`, `at`, `purposes[]`, `policy`, PARSE, PROJECTION. **Output:** `found`, `structuralReasons[]`, `path[]`, `pathLength`, `explored`, `valid` (always false), `reasons[]`, `signaturesChecked: false`. **Codes:** `PKI_REASON_SIGNATURE_NOT_CHECKED` (always present), `PKI_REASON_NO_TRUST_ANCHOR` (in `structuralReasons[]` when no path reached an anchor).

```jsonc
{ "leaf": { "path": "fixtures/leaf.crt.pem" }, "candidates": [{ "path": "fixtures/inter.crt.pem" }], "trustAnchors": [{ "path": "fixtures/root.crt.pem" }], "at": "2027-01-01T00:00:00Z", "verbosity": "summary" }
```

### `validate_certificate_path`

RFC 5280 §6.1 on an ordered path. **Inputs:** `path[]` (PKI_BUNDLE, leaf first), `trustAnchors[]`, `at`, `checkSignatures` (default true), `policy`, `allowSha1`, PARSE, PROJECTION. **Output:** `valid`, `reasons[]`, `failingReasons[]`, `path[]`, `signaturesChecked`, `signatures[]` (one verdict per link), `evaluatedAt`. **Codes:** `PKI_REASON_SIGNATURE_INVALID`, `PKI_REASON_SIGNATURE_NOT_CHECKED` (`checkSignatures: false`), `VALIDATION_ERROR`.

```jsonc
{ "path": [{ "path": "fixtures/leaf.crt.pem" }, { "path": "fixtures/inter.crt.pem" }], "trustAnchors": [{ "path": "fixtures/root.crt.pem" }], "at": "2027-01-01T00:00:00Z" }
```

### `inspect_crl`

The RFC 5280 §5 report. **Inputs:** `crl` (PKI_INPUT), `find` (`serialHex` | `certificate`), `issuer` (PKI_INPUT, one signature check), `allowSha1`, PARSE, PROJECTION. **Output:** `issuer` (+ `issuerString`), `signatureAlgorithm`, `thisUpdate` / `nextUpdate`, `crlNumber`, `isDelta`, `baseCrlNumber`, `issuingDistributionPoint`, `entryCount`, `extensions[]`, `entry` (revoked, revocationDate, reason, invalidityDate), `signature`. **Codes:** `VALIDATION_ERROR`, `PKI_X509_*`, `PKI_CRYPTO_ALGORITHM_REFUSED`.

```jsonc
{ "crl": { "path": "fixtures/inter.crl.der" }, "find": { "certificate": { "path": "fixtures/revoked.crt.pem" } }, "fields": ["entry", "issuerString", "crlNumber", "nextUpdate.iso"] }
```

### `check_crl_revocation`

One certificate against one CRL. **Inputs:** `certificate`, `crl`, `delta`, `issuer` (the CRL issuer — without it the engine refuses the unverified list), `at`, `staleTolerance` (ms), `allowSha1`, PARSE, PROJECTION. **Output:** `valid`, `reasons[]`, `signatureVerified`, `deltaSignatureVerified`, `crlNumber`, `isDelta`, `deltaCrlNumber`, `evaluatedAt`. **Codes:** `PKI_REASON_REVOKED` (with the reason) and the freshness / scope reasons in `reasons[]`; `VALIDATION_ERROR` (a `delta` without a `deltaCRLIndicator`).

```jsonc
{ "certificate": { "path": "fixtures/ed25519.crt.pem" }, "crl": { "path": "fixtures/ed25519.crl.der" }, "delta": { "path": "fixtures/ed25519-delta.crl.der" }, "issuer": { "path": "fixtures/ed25519.crt.pem" }, "at": "2027-01-01T00:00:00Z" }
```

### `create_ocsp_request`

The RFC 6960 request you POST yourself. **Inputs:** `certificate`, `issuer`, `hashAlgorithm` (`SHA-1` default | `SHA-256`), `nonce` (`'random'` or 1–32 bytes of hex), `certIdOnly`, PARSE, OUTPUT (default der, `.orq`). **Output:** the artefact and `summary` (`certIdHex`, `nonceHex`, `randomNonce`, serial). **Codes:** `VALIDATION_ERROR`.

```jsonc
{ "certificate": { "path": "fixtures/leaf.crt.pem" }, "issuer": { "path": "fixtures/inter.crt.pem" }, "hashAlgorithm": "SHA-256", "nonce": "random", "encoding": "hex" }
```

### `inspect_ocsp_response`

The RFC 6960 report. **Inputs:** `response` (PKI_INPUT), `responder` (PKI_INPUT, one signature check; omitted = the embedded certificates are tried), PARSE, PROJECTION. **Output:** `status`, `basicResponse` (responder id, producedAt, `responses[]` with CertID / status / updates, extensions, certificates, signature algorithm), `noncePresent`, `signature` (valid, source). **Codes:** `PKI_ASN1_*`, `PKI_X509_*`, `VALIDATION_ERROR`.

```jsonc
{ "response": { "path": "fixtures/revoked.ocsp.der" }, "responder": { "path": "fixtures/ocsp.crt.pem" }, "fields": ["signature", "basicResponse.responses.status", "basicResponse.responses.certId.serialNumber", "noncePresent"] }
```

### `check_ocsp_status`

One response for one certificate. **Inputs:** `response`, `certificate`, `issuer`, `responder`, `responderTrusted`, `hashAlgorithm`, `nonce` (hex), `requireNonce`, `at`, `staleTolerance`, `futureTolerance`, `allowSha1`, PARSE, PROJECTION. **Output:** `valid`, `reasons[]`, `status` (good | revoked | unknown | null), `signatureVerified`, `responderAuthorized`, `responder`, `responderSource`, `hashAlgorithm`, `certIdHex`, `evaluatedAt`. **Codes:** `PKI_REASON_REVOKED`, the freshness, nonce and authorisation reasons in `reasons[]` (a non-successful response status is a negative verdict with `status: null`); `VALIDATION_ERROR`.

```jsonc
{ "response": { "path": "fixtures/leaf.ocsp.der" }, "certificate": { "path": "fixtures/leaf.crt.pem" }, "issuer": { "path": "fixtures/inter.crt.pem" }, "nonce": "1538349c433373ed058c291909df5b3e", "requireNonce": true, "at": "2027-01-01T00:00:00Z", "verbosity": "summary" }
```

### `sign_cms`

An RFC 5652 SignedData. **Inputs:** `content` (CONTENT_INPUT) or `contentDigest` (HEX, `detached` only), `detached`, `contentType` (OID), `certificate`, `chain[]`, `crls[]`, `sid` (`issuerAndSerialNumber` default | `subjectKeyIdentifier`), `signingTime` (an instant, `'now'`, `'none'`), `signingCertificateV2`, `algorithmProtection`, `signedAttributes[]` / `unsignedAttributes[]` (DER Attributes as hex), `signer` (SIGNER), `allowSha1`, PARSE, OUTPUT (default der, `.p7s`). **Output:** the artefact and `summary` (`detached`, `contentType`, `signerSubject` / `signerSerial`, `sid`, digest and signature algorithms, `signingTime` with `signingTimeSource`, `certificatesEmbedded`, `crlsEmbedded`, attribute counts, `signatureVerified`). **Codes:** `KEY_MISMATCH` (the new signature did not verify against the signer certificate), `RSA_SCHEME_REQUIRED`, `SECRET_REQUIRED`, `KEY_TYPE_REQUIRED`, `VALIDATION_ERROR` (`contentDigest` without `detached`, `certificate` missing with `signer.key`), `PKI_API_MISUSE` (a repeated or builder-owned attribute type), `ENGINE_ERROR`.

```jsonc
{
  "content": { "path": "fixtures/content.txt" },
  "detached": true,
  "certificate": { "path": "fixtures/leaf.crt.pem" },
  "chain": [{ "path": "fixtures/inter.crt.pem" }],
  "signingTime": "2027-01-01T00:00:00Z",
  "signer": { "key": { "path": "fixtures/leaf.key.pem" } }
}
```

### `verify_cms`

The RFC 5652 verdict. **Inputs:** `signedData` (PKI_INPUT), `content` (CONTENT_INPUT) or `contentDigest` (detached signatures), TRUST (`trustAnchors[]`, `candidates[]`, `crls[]`, `ocspResponses[]`, `at`, `requireRevocation`, `purposes[]`), `atTimeStamp`, `requireSigningCertificate`, `requireAlgorithmProtection`, `allowTrailingData`, `allowSha1`, PARSE, PROJECTION. **Output:** `valid`, `reasons[]`, `signers[]` (per signer: `valid`, `intact`, `reasons[]`, chain, time-stamps, revocation), `signerCount`, `signatureVerifications[]`, `evaluatedAt`, `atTimeStamp`. **Codes:** `PKI_REASON_*` in `reasons[]` (`NO_TRUST_ANCHOR`, `SIGNATURE_INVALID`, `REVOKED`, `TSP_*`, …); `VALIDATION_ERROR` (content given for an attached message, both `content` and `contentDigest`), `PKI_ASN1_TRAILING_DATA` (the zero padding of a PDF `/Contents` without `allowTrailingData`).

```jsonc
{ "signedData": { "path": "fixtures/attached.p7s" }, "trustAnchors": [{ "path": "fixtures/root.crt.pem" }], "crls": [{ "path": "fixtures/inter.crl.pem" }], "ocspResponses": [{ "path": "fixtures/leaf.ocsp.der" }], "requireRevocation": true, "purposes": ["emailProtection"], "at": "2027-01-01T00:00:00Z" }
```

### `inspect_cms`

The RFC 5652 report. **Inputs:** `signedData`, `allowTrailingData`, `signerCertificate` (one key check), `signerIndex`, `content` (for a signer without signed attributes), `allowSha1`, PARSE, PROJECTION. **Output:** `version`, `contentType`, `contentLength` (null = detached), `digestAlgorithms[]`, `certificates[]`, `crlCount`, `ocspResponseCount`, `signerInfos[]` (sid, algorithms, signing time as claimed, attributes, time-stamp count, `signature` as hex), `signerSignature`. **Codes:** `NOT_FOUND` (a `signerIndex` past the last signer), `PKI_ASN1_TRAILING_DATA`, `PKI_*`.

```jsonc
{ "signedData": { "path": "fixtures/detached.p7s" }, "signerCertificate": { "path": "fixtures/leaf.crt.pem" }, "content": { "path": "fixtures/content.txt" }, "fields": ["signerInfos.signature", "signerInfos.sid", "signerSignature"] }
```

### `amend_cms`

The one legitimate edit. **Inputs:** `signedData`, `signerIndex`, `operation` (`add-unsigned-attribute` | `add-timestamp`), `attribute` (HEX), `token` (PKI_INPUT — a `.tst` or a whole `.tsr`), `allowSha1`, PARSE, OUTPUT (default der). **Output:** the artefact and `summary`. **Codes:** `VALIDATION_ERROR` with `data.detail` `PKI_REASON_TSP_IMPRINT_MISMATCH` (a token over anything but the signer's signature value — the remedy names the `inspect_cms → create_timestamp_request → amend_cms` sequence), `NOT_FOUND`, `PKI_API_MISUSE` (a signed-only attribute type), `PKI_*`.

```jsonc
{ "signedData": { "path": "fixtures/attached.p7s" }, "operation": "add-unsigned-attribute", "attribute": "300d06032a0304310606042a030405" }
```

### `create_timestamp_request`

The RFC 3161 request you POST yourself. **Inputs:** `data` (CONTENT_INPUT) or `digestHex` (HEX), `hashAlgorithm` (`SHA-256` default | `SHA-384` | `SHA-512`), `nonce` (`'random'`, decimal or `0x` hex), `policy` (OID), `certReq` (default true), PARSE, OUTPUT (default der, `.tsq`). **Output:** the artefact and `summary` (`imprintHex`, `hashAlgorithm`, `nonce`, `randomNonce`, `policy`, `certReq`). **Codes:** `VALIDATION_ERROR` (a digest whose length does not match the algorithm).

```jsonc
{ "data": { "path": "fixtures/content.txt" }, "nonce": "random" }
```

### `inspect_timestamp`

The RFC 3161 report. **Inputs:** `input` (PKI_INPUT), `as` (`response` | `token` | `tstinfo`), PARSE, PROJECTION. **Output:** `as`, `status` (statusStrings, failInfo), `token` (CMS envelope: signer count, certificates), `tstInfo` (policy, messageImprint, serialNumber, genTime, accuracy, ordering, nonce, tsa, extensions). **Codes:** `PKI_*` (the bytes are none of the three structures), `PKI_STRICT_DIAGNOSTIC` (with `strict: true` — OpenSSL tokens carry `PKI_DIAG_CMS_SET_NOT_SORTED`).

```jsonc
{ "input": { "path": "fixtures/content.tst" }, "as": "token", "fields": ["token.tstInfo.genTime.iso", "token.tstInfo.messageImprint", "token.certificates.subject"] }
```

### `verify_timestamp`

The RFC 3161 verdict. **Inputs:** `token` or `response`, `request` (the `.tsq` you sent — imprint, nonce and policy all checked), `data` (CONTENT_INPUT) or `digestHex`, TRUST (`trustAnchors[]`, `candidates[]`, `crls[]`, `ocspResponses[]`, `at`, `requireRevocation`), `allowNonCriticalTimeStampingEku`, `allowSha1`, PARSE, PROJECTION. **Output:** `valid`, `reasons[]`, `genTime`, `earliest` / `latest` (accuracy applied), `tsa`, `chain[]`, `signatureVerifications[]`, `evaluatedAt`. **Codes:** `PKI_REASON_TSP_IMPRINT_MISMATCH`, `PKI_REASON_TSP_NOT_GRANTED`, `PKI_REASON_TSP_REQUEST_MISMATCH`, `PKI_REASON_TSP_TOKEN_INVALID` and the chain reasons in `reasons[]`; `VALIDATION_ERROR` (nothing stamped was given — a token verified without what it stamps proves nothing).

```jsonc
{ "response": { "path": "fixtures/content.tsr" }, "request": { "path": "fixtures/content.tsq" }, "data": { "path": "fixtures/content.txt" }, "trustAnchors": [{ "path": "fixtures/root.crt.pem" }], "candidates": [{ "path": "fixtures/inter.crt.pem" }], "at": "2027-01-01T00:00:00Z" }
```

### `inspect_private_key`

A PKCS#8 key described, no key byte. **Inputs:** `key` (PKI_INPUT), `tryImport`, `password` (or `PKINATIVE_MCP_PASSWORD`), `keyType` (ec-p256 | ec-p384 | ec-p521 | ed25519 | ed448 | rsa | rsa-pss), `hash`, `rsaScheme`, `saltLength`, `allowSha1`, PARSE, PROJECTION. **Output:** `format` (`pkcs8` | `encrypted-pkcs8`), `kind`, `curve`, `algorithm` + `algorithmName`, `attributes`, `publicKey` (embedded or not), `encryption` (scheme, PBKDF2 iterations, PRF, AES key size, salt length), `encryptedBytes`, `imported` (handle type, algorithm, usages). **Codes:** `SECRET_REQUIRED`, `KEY_TYPE_REQUIRED`, `RSA_SCHEME_REQUIRED`, `PKI_CRYPTO_DECRYPTION_FAILED` (a wrong password), `PKI_KEY_ENCRYPTION_UNSUPPORTED` (a legacy cipher, with the `openssl pkcs8` remedy), `PKI_*` (a PUBLIC KEY or a non-PKCS#8 DER).

```jsonc
{ "key": { "path": "fixtures/leaf.key.enc.pem" }, "tryImport": true, "password": "test-only-password", "keyType": "ec-p256", "fields": ["imported", "encryption.scheme"] }
```

### `inspect_pkcs12`

A PKCS#12 described, no key byte. **Inputs:** `pkcs12` (PKI_INPUT; BER with `encodingRules: 'ber'` for a Windows-written PFX), `password` (optional), PARSE, PROJECTION. **Output:** `version`, `mac` (kind `pbmac1` | `pkcs12-kdf` | null, parameters), `contents[]` (path, encryption scheme and parameters, bags of the plain ones), `bagCount`, `macVerified` (with a password; a wrong password or an altered file is a report), `opened[]` (allow-list views: certBags by subject / issuer / serial, key bags by algorithm, curve and encryption parameters, crlBags by size). **Codes:** `PKI_CRYPTO_DECRYPTION_FAILED` (a wrong password on an encrypted SafeContents), `PKI_KEY_MAC_UNSUPPORTED`, `PKI_KEY_ENCRYPTION_UNSUPPORTED` (each with the OpenSSL 3.4 conversion remedy).

```jsonc
{ "pkcs12": { "path": "fixtures/legacy.p12" }, "fields": ["mac.kind", "contents.path", "contents.encryption.scheme"] }
```

### `open_pkcs12`

A PKCS#12 opened in one call. **Inputs:** `pkcs12`, `password` (or `PKINATIVE_MCP_PASSWORD`), `allowUnverifiedIntegrity`, `rsaScheme` (`pkcs1` | `pss`), `hash`, `exportCertificates`, PARSE, PROJECTION, OUTPUT (pem only — a bundle has no DER form). **Output:** `valid`, `integrity` (`verified` | `unverified` | `mismatch`), `reasons[]`, `keys[]` (algorithm, handle type, usages — never a byte), `certificates[]`, `keyCount` / `certificateCount` / `crlCount`, `exportSkipped`, `artefact` (the PEM bundle). **Codes:** `SECRET_REQUIRED` (no password from either channel); in `reasons[]`: `PKI_REASON_PKCS12_MAC_MISMATCH` (a wrong password or an altered file — nothing is decrypted), `PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED`, `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED`, `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED`; `MISSING_OUTPUT_PATH`, `OUTPUT_TOO_LARGE`.

```jsonc
{ "pkcs12": { "path": "fixtures/leaf.p12" }, "password": "test-only-password", "exportCertificates": true }
```

### `describe_engine`

The offline preflight. **Inputs:** PROJECTION only. **Output:** `server` (name, version, toolApiVersion, protocol, toolCount), `engine` (name, version, nodeFloor), `capabilities` (canVerify, canSign, canDecrypt, node, nodeFloorSatisfied, platform), `randomness`, `defaultLimits`, `ceilings`, `caps`, `sandbox` (enabled, cacheEnabled, pinnedInstant, the extension allow-lists), `network: 'none'`, `registries` (the 57 / 43 / 97 codes, the wrapper codes, purposes, key-usage bits, the OID registry count), `refusals` (the doctrine), `unexposed`. **Codes:** `VALIDATION_ERROR`.

```jsonc
{ "fields": ["defaultLimits", "ceilings", "sandbox", "capabilities"] }
```

### `explain_code`

Any code, explained. **Inputs:** `code`, or `list: true` with `kind` (`error` | `reason` | `diagnostic` | `wrapper`), PROJECTION. **Output:** `code`, `kind`, `summary`, `standard`, `severity`, `errorClass`, `engineClass`, `cwe`, `since`, `remedy` — or `codes[]` + `count`. **Codes:** `NOT_FOUND` (an unknown code).

```jsonc
{ "code": "PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED" }
```

### `draft_governance_issue`

Draft a governance-compliant GitHub issue **locally** for a human to review and submit — for `pkinative` (engine behaviour: parsing, verification, limits, refusals), `pkinative-cli` or `pkinative-mcp` (wrapper behaviour: schemas, sandbox, transport). The server never contacts GitHub — it has no network code path at all; it returns the draft Markdown plus a machine-readable compliance report. Present both to the user, then STOP: they review and submit under their own identity. **Inputs:** `title`, `summary`, `issueType` (bug | feature | security | docs | performance), `targetRepo`, `reproduction` (`{ command, result }`), `expectedBehavior`, `actualBehavior`, `affectedPackages[]`, `duplicateSearchPerformed` (must be `true`), `outputMode` (`inline` | `file`) + `outputPath` (a relative `.md` in the sandbox). **Output:** `draftMarkdown`, `warnings[]`, `compliance` (the eight keys of [`.github/AGENT_RULES.md`](.github/AGENT_RULES.md)). **Codes:** `GOVERNANCE_VIOLATION` (a runtime dependency proposed, an embedded private key or password, no reproduction, `duplicateSearchPerformed: false`), `MISSING_OUTPUT_PATH`, `INVALID_EXTENSION`, `OUTPUT_EXISTS`, `SECURITY_VIOLATION`.

```jsonc
{
  "title": "parseCertificateList refuses a delta CRL with an empty revokedCertificates list",
  "summary": "A delta CRL (deltaCRLIndicator present) whose revokedCertificates SEQUENCE is absent is refused with PKI_X509_STRUCTURE_INVALID although RFC 5280 makes the field OPTIONAL.",
  "issueType": "bug",
  "targetRepo": "pkinative",
  "reproduction": { "command": "inspect_crl { crl: { path: \"fixtures/empty-delta.crl\" } }", "result": "PKI_X509_STRUCTURE_INVALID at revokedCertificates" },
  "expectedBehavior": "The delta CRL parses with entryCount 0.",
  "affectedPackages": ["pkinative", "pkinative-mcp"],
  "duplicateSearchPerformed": true
}
```

See the `governance_contract` and `draft_issue_workflow` prompts and [`docs/guides/AI_GOVERNANCE.md`](docs/guides/AI_GOVERNANCE.md) for the full human-in-the-loop contract.

---

## 🧩 Shared input fragments

The same ten fragments appear across the catalogue; a tool's description names the ones it carries. Every object schema is closed (`additionalProperties: false`, Zod `.strict()` at every depth): an unknown or misspelt key is `VALIDATION_ERROR` naming the path, never silently dropped.

| Fragment | Shape | Rules |
| -------- | ----- | ----- |
| `PKI_INPUT` | `{ pem }` \| `{ derBase64 }` \| `{ path }` | Exactly one. `pem` is RFC 7468 text starting with `-----BEGIN` (a PEM text holding several blocks where **one** object is expected is refused — use `convert_pem extractIndex` or a bundle); `derBase64` is the DER as base64 exactly once (no `data:` URI, not PEM); `path` is relative to the sandbox, PEM or DER sniffed by its first bytes, extension allow-listed, never cached. The label is checked before any byte is parsed (`PKI_PEM_UNEXPECTED_LABEL`). |
| `PKI_BUNDLE` | `PKI_INPUT[]` (1–256 items) | `trustAnchors`, `candidates`, `crls`, `ocspResponses`, `chain`, `path`: every PEM block of every item is taken, in order. |
| `CONTENT_INPUT` | `{ text }` \| `{ base64 }` \| `{ path }` | The bytes to sign, verify or time-stamp: UTF-8 text, base64 (≤ 128 MiB decoded) or a sandbox file (any extension, ≤ 1 GiB — it is content, not a PKI object). |
| `HEX` | string | `contentDigest`, `digestHex`, `valueHex`, `attribute`, `nonce`, `ocspNonce`, `serialHex`: hexadecimal; an `0x` prefix, colons and spaces are tolerated (`^(?:0x)?(?:[0-9a-fA-F]{2}[:\s]?)+$`). |
| `PARSE` | `encodingRules`, `pemMode`, `strict`, `limits` | `encodingRules` `'der'` (strict X.690, default) or `'ber'` (indefinite / non-minimal lengths, as legacy CMS producers write); `pemMode` `'strict'` (RFC 7468 exactly) or `'lax'` (whitespace, line length, RFC 1421 headers); `strict: true` escalates the first engine warning to `PKI_STRICT_DIAGNOSTIC`; `limits` below. |
| `LIMITS` | `{ maxInputBytes, maxDepth, … }` (the 22 keys) | Raise the engine's named bounds for this call, trusted input only; absent keys keep the engine defaults; every value is an integer ≥ 1; `maxInputBytes`, `maxKdfIterations` / `maxPkcs12KdfIterations` and `maxPathsExplored` are bounded by the operator ceilings (`LIMIT_CEILING_EXCEEDED`). |
| `SIGNER` | `{ key }` \| `{ p12 }`, + `password`, `keyType`, `hash`, `rsaScheme`, `saltLength` | Exactly one of `key` (a PKCS#8 private key, plain or PBES2-encrypted, PEM or DER — SEC1 / PKCS#1 keys must be converted with `openssl pkcs8 -topk8` first) or `p12` (PBES2 + PBMAC1 only). The key is imported into a **non-extractable** Web Crypto key and never leaves the engine. The algorithm follows the key: ECDSA on the key's curve (SHA-256 / 384 / 512 by curve), Ed25519 / Ed448 (no hash), RSA **requires** `rsaScheme` (`'pkcs1'` \| `'pss'`, optional `saltLength`); an encrypted key needs `password` (or `PKINATIVE_MCP_PASSWORD`) and `keyType` unless a certificate or public key input names it. A call carrying a signer is never cached. |
| `TRUST` | `trustAnchors`, `candidates`, `crls`, `ocspResponses`, `at`, `requireRevocation`, `purposes`, `policy` | A verdict is relative to the anchors **you** name (at least one). `at` is an ISO 8601 date-time (UTC unless zoned), epoch milliseconds, or `'now'`; omitted = `PKINATIVE_MCP_AT`, else the wall clock (never cached). `requireRevocation: true` demands fresh evidence for every certificate below the anchor (`PKI_REASON_REVOCATION_UNKNOWN` otherwise). `purposes` (≤ 16) are EKU names or OIDs; `policy` holds the RFC 5280 §6.1.1 inputs (`initialPolicySet`, `requireExplicitPolicy`, `inhibitPolicyMapping`, `inhibitAnyPolicy`). |
| `PROJECTION` | `verbosity`, `fields` | `'full'` (default) or `'summary'`; up to 16 dot-paths kept after `verbosity` (arrays map over elements); unmatched paths are reported in `_meta.unmatchedFields` with `_meta.availableFields`. |
| `OUTPUT` | `outputMode`, `outputPath`, `encoding` | `'base64'` (default, ≤ 50 MiB inline) or `'file'` (a relative `outputPath` whose extension matches the encoding — `.pem` for pem; `.der .crt .cer .csr .p10 .crl .p7s .p7m .p7b .cms .orq .tsq .bin .asn1 …` for der; key-bearing extensions refused; never overwritten; ≤ 1 GiB). `encoding` `'pem'`, `'der'` or `'hex'` (inline only, ≤ 64 KiB; the hex lands in `structuredContent.hex`). |

Every result also carries `diagnostics[]` (de-duplicated by code and path, capped at 200 with `diagnosticsTruncated`) and `diagnosticCounts`; the password input, when a tool has one, is a plain string (≤ 4096 characters) that is never echoed, logged or cached.

---

## 🔐 Security model

`pkinative-mcp` runs **inside the host process** and exposes a stdio MCP server (or a loopback-only HTTP endpoint). It treats every certificate, request, list, response, message, token, key and PKCS#12 as untrusted input and performs no I/O outside the configured sandbox other than the opt-in response cache under `PKINATIVE_MCP_CACHE_DIR`.

- **Secrets: two channels, never a third.** A password reaches the server through the per-call `password` input or the operator-side `PKINATIVE_MCP_PASSWORD` — one source per call (both at once is `VALIDATION_ERROR`); `SECRET_REQUIRED` when neither is present. A password is never echoed in a result or an error text, never logged (only the presence of the variable is reported at boot), never written to a cache file, never served as a resource. Private keys are imported into **non-extractable** Web Crypto handles; every key and PKCS#12 report is an allow-list view built field by field (`src/key-views.ts`), and the test suite proves with a needle table computed from the fixtures that no key byte, scalar, JWK member, encrypted-key body or password is printed by any result, on stderr, in a cache file or on the stdio transcript (`tests/secret-leak.test.ts`).
- **The sandbox** (`PKINATIVE_MCP_OUTPUT_DIR`) is the one filesystem boundary for reads (every `path` input, `resources/read`) and writes (`outputPath`, governance drafts). Paths must be relative; absolute / drive / UNC paths, `..`, NUL bytes and non-allow-listed extensions are rejected; the **real** path of the file read and of the parent written must stay inside (a symlink or junction planted in the sandbox is `SECURITY_VIOLATION` on both sides); files are opened exclusively (`OUTPUT_EXISTS` — never overwritten); a failed write removes the partial file. Key-bearing extensions (`.key .p8 .p12 .pfx`) are read by the key tools only, never written, never listed nor served by `resources/*`. Unset ⇒ inline PEM / base64 only.
- **Caps** — every byte and count bound is a constant in `src/caps.ts` and advertised by `describe_engine.caps`:

| Cap | Value |
| --- | ----- |
| stdio frame / HTTP body | 256 MiB |
| decoded inline PKI inputs per call / inline `content` | 128 MiB / 128 MiB |
| `content.path` read fully into memory | 1 GiB |
| inline output (an artefact, a resource read) | 50 MiB |
| file output | 1 GiB |
| inline hex artefact | 64 KiB |
| bundle items / DER attributes inline / OIDs per call | 256 / 256 / 1000 |
| `resolve_oid` list page | 200 default / 2000 max |
| SHAKE256 output / password / `fields` paths / `decode_asn1` preview / tree nodes | 1 MiB / 4096 / 16 / 32 bytes / 20 000 |
| diagnostics per result | 200 (de-duplicated by code and path) |
| `resources/list` entries / walk depth / `resources/read` | 1000 / 8 / 50 MiB |
| response cache TTL / size | 3600 s / 256 MiB |
| engine defaults (`limits`) | the 22 `PkiLimits` of pkinative 1.0.0 — `maxInputBytes` 64 MiB, `maxKdfIterations` 10 000 000, `maxPathsExplored` 1000, … (`describe_engine.defaultLimits`) |

- **The cache gate** (`isCacheable`, `src/server.ts`) — with `PKINATIVE_MCP_CACHE_DIR` set, a result is served from the cache only when nothing about it depends on the environment, a secret, the clock or randomness: never a `path` input (a path is a reference, not content), never `outputMode: 'file'`, never a call carrying a `password` or a `signer`, never a `'random'` serial or nonce, never a `'now'` or unpinned instant, never `describe_engine` or `draft_governance_issue`, and never any password-accepting tool while `PKINATIVE_MCP_PASSWORD` is set (the operator password may have been used without any secret in the input). The key namespace carries the tool API, package and engine versions, so an engine upgrade never serves bytes the previous engine wrote.
- **Doctrine refusals** (`describe_engine.refusals`) — the lines the server will not cross, each with its remedy: no network, no key generation (bring keys from your HSM, KMS or `openssl genpkey`), no key export, no writer for PKCS#8 / PKCS#12 / CRL / OCSP response / time-stamp response (use the issuing software or OpenSSL and verify the result here), SHA-1 refused by default, no default RSA scheme, legacy PKCS#12 and PBES1 keys refused (convert once with OpenSSL 3.4+: `openssl pkcs12 -legacy … ` then `-export -pbmac1_pbkdf2`), DSA / ML-DSA parsed but never verified or signed, diagnostics are not errors, limits raise only explicitly and under the ceilings, randomness lives in the wrapper and is reported (`randomSerial`, `randomNonce`).
- **Inputs** are validated against strict JSON Schemas + Zod at the boundary of every tool — unknown or misspelt keys at any depth are `VALIDATION_ERROR`; base64 is sanity-checked (`data:` URIs, PEM where DER is expected, double-encoded or empty payloads refused with a remedy) before any parser runs; specs are built prototype-pollution-safe (`tests/prototype-pollution.test.ts`).
- **HTTP transport** (`PKINATIVE_MCP_PORT`) binds loopback only with a Host / Origin guard; it has **no authentication** unless `PKINATIVE_MCP_HTTP_TOKEN` is set (then `401` without a valid bearer token).

### Network & egress: none

**None, ever.** The server has no network code path: no CRL, OCSP, AIA or TSA fetch, no telemetry, no GitHub, no update check, no URL from any tool argument, and — unlike its PDF sibling — no operator-configurable endpoint of any kind. `describe_engine` reports `network: 'none'` and every tool advertises `openWorldHint: false`. Revocation evidence and time-stamp tokens are **inputs** you fetched out of band; `create_ocsp_request` and `create_timestamp_request` produce the bytes **you** transport (`application/ocsp-request`, `application/timestamp-query`). The engine itself never opens a socket, never touches the filesystem and never evals.

See [SECURITY.md](SECURITY.md) for the responsible disclosure process and the threat model, and [`docs/guides/SECURITY.md`](docs/guides/SECURITY.md) for the defences with their CWE ids.

---

## 🧪 Conformance (OpenSSL 3)

OpenSSL 3.x is the external judge of this server — the role veraPDF plays for pdfnative-mcp: what the tools write, a foreign implementation must read and verify. `npm run corpus:pki` drives the **built** server (`scripts/generate-pki-corpus.ts`, corpus table in `scripts/lib/pki-corpus.ts`) under a pinned instant to write the interoperability corpus into `test-output/pki/` with a `manifest.json` (status, SHA-256, the second digest of every deterministic entry): **23 conformant artefacts** — self-signed CAs and leaves for every signature family (Ed25519, RSA PKCS#1 v1.5, RSA-PSS, ECDSA P-256), a pathLen-0 intermediate and a leaf under it, three CSRs, attached and detached CMS messages (the Ed25519 signer included), two time-stamp requests, two OCSP requests, PEM re-encodings of the DER fixtures — and **5 refused canaries** that must be refused with their declared code (a SHA-1 signature, a legacy PKCS#12 signer, an RSA key without a scheme, a `notAfter` before `notBefore`, a URL member in a spec). A canary that writes bytes is an **XPASS** and fails the run.

`npm run validate:pki` (`scripts/validate-pki.ts`) then checks every artefact at two levels:

- **Level 0 — engine round trip**, in-process through `dist/server.js`: every certificate inspected and verified to the corpus CA at the pinned instant (`verify_certificate_chain` with `serverName` and `purposes` for the leaves), every request read with its proof of possession, every CMS message verified with the anchors (and the detached content), every OCSP and time-stamp request decoded and recomputed independently with `node:crypto` (CertID hashes, serial, message imprint, nonce), and every deterministic entry produced twice hashing the same. It needs no external tool and always runs.
- **Level 1 — OpenSSL**, `openssl` 3.x on `PATH` (`OPENSSL_BIN` overrides; LibreSSL and OpenSSL < 3.0 are refused with the reason): **12 command families** — `x509 -text` over every certificate (DER and PEM), `verify` to each corpus CA (`-purpose sslserver` for the leaves, `-untrusted` for the intermediate, `-attime` the pinned instant), `req -verify`, `crl -text`, `cms -verify` (attached and detached, `-CAfile` the fixture root), `asn1parse`, `ocsp -req_text`, `ts -query -text` — with the raw transcripts under `test-output/pki/reports/`. Skipped with the reason when OpenSSL is absent; a failure under `PKINATIVE_INTEROP_REQUIRED=1` or the gate's `--require-all`.

A coverage canary holds the corpus to `declared.conformant` / `declared.refused` in [`docs/data/interop.json`](docs/data/interop.json), so a silent regression cannot shrink the validated set. Per file the validator reports `PASS` / `FAIL` / `XFAIL` / `XPASS` / `INFRA` / `SKIP`; exit codes: 0 every expectation met, 1 a `FAIL` / `XPASS` / canary, 2 the corpus or `dist/` missing, 3 OpenSSL required but absent. The vitest form of the same level-1 checks is `tests/interop/openssl.test.ts` (`npm run test:interop`), and `tests/interop/lint.test.ts` (`npm run test:lint-certs`, publish profile) runs the zlint and pkilint certificate linters over the corpus with the reviewed waivers of `scripts/data/lint-waivers.json` (none today).

The gate is **blocking**: the `ci` workflow runs it with `--require-all` on Linux (Node 22 and 24), Windows and macOS, and the `interop` workflow repeats it on four OS legs (`ubuntu-22.04`, `ubuntu-24.04`, `windows-latest`, `macos-latest`), two of which — `interop (ubuntu-24.04)` and `interop (windows-latest)` — are required status checks. OpenSSL is a runner tool, never a dependency. A PASS is validation evidence against a specific OpenSSL revision (3.5.5 on the development host), not a certification. See [`docs/guides/CONFORMANCE.md`](docs/guides/CONFORMANCE.md).

### Autonomy proof

`tests/autonomy.test.ts` replays one scripted agent scenario (S0–S18: the handshake → the catalogue → `describe_engine` → `inspect_certificate` and the cache hit over the wire → the chain verdicts with CRL and OCSP evidence → name and purpose → a CA, a CSR and an issued leaf in file mode → a CMS signature signed, verified and then tampered → a time-stamp request built and a response verified → a PKCS#12 opened without a key byte in the transcript → `resources/*` → hostile inputs refused with a code and a remedy → the ceilings → protocol errors → `draft_governance_issue` → `prompts/get` → `explain_code` → a clean shutdown) against the built `dist/cli.js` on four transport × era pairs — stdio legacy, stdio modern, HTTP legacy, HTTP modern with `PKINATIVE_MCP_HTTP_TOKEN` — under a sandbox holding the fixtures, a cache directory, `PKINATIVE_MCP_AT` pinned and the three ceilings set, asserting no interaction, no unexpected `isError`, a code and a remedy on every refusal, a cache hit over the wire, no secret needle anywhere (stdout, stderr, the cache, the sandbox), a JSON-only stdout and a clean exit. To replay it by hand from Claude Code, Claude Desktop or the MCP Inspector, see [`docs/guides/LOCAL_TESTING.md`](docs/guides/LOCAL_TESTING.md) (the repository ships a ready `.mcp.json`).

---

## 🧪 Local development

```bash
git clone https://github.com/Nizoka/pkinative-mcp.git
cd pkinative-mcp
npm ci --ignore-scripts   # .npmrc sets ignore-scripts=true: nothing builds on install
npm run gate:fast         # before every commit: typecheck:all, lint, test, code-tables, server-json, verify:docs
npm run gate              # the CI profile: + build, dist checks, stdio smoke test, tool shape, samples, coverage, docs, the OpenSSL corpus and interop
npx tsx scripts/gate.ts --publish --require-all   # release branches: everything incl. lint:certs (zlint / pkilint); a skipped step fails
```

`npm run gate` ([`scripts/gate.ts`](scripts/gate.ts)) is the single definition of green — 2263 tests across 106 files, the coverage thresholds of `vitest.config.ts` (94 / 90 / 95 / 94), and the **built** server driven over stdio, where stdout must carry JSON-RPC frames only and `dist/` must hold no byte of a test key. It prints one line per step and writes the logs to `test-output/.gate/<step>.log`; `--only <step>` runs one step, `--from <step>` resumes, `--json` gives machine output (call the script directly to pass flags: PowerShell swallows a bare `--` after `npm run`). The individual steps are ordinary npm scripts:

| Script | What it does |
| ------ | ------------ |
| `npm run typecheck:all` | `tsc --noEmit` over `src/` + `tests/`, then `scripts/` |
| `npm run lint` | `eslint src --max-warnings 0` — a warning fails |
| `npm test` / `npm run test:coverage` | vitest (dot reporter) / with v8 coverage — thresholds in `vitest.config.ts` |
| `npm run build` | `tsc -p tsconfig.build.json` → `dist/` |
| `npm run examples:check` | runs the 89 `examples/*.json` live through the `tools/call` handler (multi-step examples chained) |
| `npm run test:generate` / `npm run verify:samples` | the 98-sample baseline: the built server under the hermetic env → `test-output/samples/`, held to `tests/_fixtures/samples.sha256.json` (10 byte-exact, 3 by their TBS structure, 85 semantic) |
| `npm run corpus:pki` / `npm run validate:pki` | the OpenSSL corpus (23 + 5) written to `test-output/pki/` and validated at levels 0 and 1 |
| `npm run test:interop` / `npm run test:lint-certs` | the vitest form of level 1 (`PKINATIVE_INTEROP_REQUIRED=1` fails instead of skipping) / the zlint + pkilint linters |
| `npm run verify:tool-shape` | the built `tools/list` structure against `tests/_fixtures/tool-shape.json`, under the 448 KiB catalogue and 8 KiB instructions budgets (`npx tsx scripts/tool-shape.ts --write` after a deliberate schema change only) |
| `npm run verify:docs` | every count, version, tool, code, operator variable, link and anchor in the docs held to `docs/assets/ecosystem.json` and the source tree |
| `npm run agents:rules` | regenerates `.claude/rules/*.md` from `.github/instructions/*.instructions.md` |
| `npm run release:prepare` | the mechanical version bump (never commits, tags or publishes) |
| `npm run hooks:install` / `hooks:uninstall` | opt-in git hooks (pre-commit: lint + a CRLF guard; pre-push: the fast gate) |

Every script, its flags and its exit codes are listed in [`scripts/README.md`](scripts/README.md). The 42 fixtures under `tests/fixtures/pki/` were made by OpenSSL 3.5.5 ([`tests/fixtures/PROVENANCE.md`](tests/fixtures/PROVENANCE.md)), are pinned by `SHA256SUMS`, and are never regenerated in place: every private key there is public TEST-ONLY material (password `test-only-password`).

**OpenSSL on your machine.** Level 1 needs `openssl` 3.x on `PATH` (or `OPENSSL_BIN`). Linux: the distribution package. macOS: `brew install openssl@3` (the system `/usr/bin/openssl` is LibreSSL and is refused with the reason). Windows: an OpenSSL 3 build on `PATH`, or the one that ships with Git for Windows (`usr/bin/openssl.exe`); point `OPENSSL_BIN` at it when it is not first on `PATH`. Without it, `validate:pki` and `interop` SKIP with the reason — and fail under `--require-all`.

Smoke-test the server over stdio:

```bash
node dist/cli.js
# In another terminal, send a JSON-RPC initialize request via stdin (e.g. with the MCP Inspector).
npx @modelcontextprotocol/inspector --cli node dist/cli.js --method tools/list
```

Run it over HTTP with a bearer token and a sandbox:

```bash
PKINATIVE_MCP_PORT=3000 PKINATIVE_MCP_HTTP_TOKEN=change-me-to-a-real-secret PKINATIVE_MCP_OUTPUT_DIR=/tmp/pki npx pkinative-mcp
# POST http://127.0.0.1:3000/mcp with Authorization: Bearer …
```

> **Contributors:** start at [`AGENTS.md`](AGENTS.md) (the repository rules shared by every coding agent and contributor) and see [`docs/guides/LOCAL_TESTING.md`](docs/guides/LOCAL_TESTING.md) for the full local-verification workflow — the quality gate, examples-as-tests, the sample baseline, the OpenSSL corpus, and driving the built server from Claude Code or the MCP Inspector.

## 📣 Release process

`pkinative-mcp` follows the same release formalism as `pkinative`, `pdfnative-mcp` and `zipnative-mcp`:

- One release note file per tag in `release-notes/vX.Y.Z.md`
- `CHANGELOG.md` mirrors each release bullet list
- GitHub Release body is copied from `release-notes/vX.Y.Z.md`
- `npx tsx scripts/release-prepare.ts --version X.Y.Z` applies the mechanical part of a version bump (it never commits, tags or publishes); the version moves in lock-step across `package.json`, `src/version.ts`, `server.json`, `CITATION.cff` and [`docs/assets/ecosystem.json`](docs/assets/ecosystem.json) (`tests/metadata.test.ts`)
- A release branch must pass `npx tsx scripts/gate.ts --publish --require-all` — every step, OpenSSL included, with no skip (the certificate linters run when zlint and pkilint are installed)
- npm publication is handled by GitHub Actions Trusted Publishing (OIDC), without `NPM_TOKEN`, from the protected `npm-publish` environment: the workflow checks that the tag equals the package version, runs the publish gate and publishes with `--provenance`; a second job attests the tarball (build provenance) together with a CycloneDX SBOM and attaches both to the GitHub Release
- Every Linux and Windows job starts with `step-security/harden-runner` (the action does not support macOS; the macOS job is the one documented exemption), checks out with `persist-credentials: false`, installs with `npm ci --ignore-scripts` and runs under least-privilege `permissions`; actions are pinned by commit SHA; the OpenSSL interoperability gate is **blocking**
- Human-in-the-loop: coding agents prepare and verify; the maintainer pushes, opens the pull request, tags and publishes ([`.github/AGENT_RULES.md`](.github/AGENT_RULES.md))

See `release-notes/TEMPLATE.md` for the canonical structure and publication checklist, and [CONTRIBUTING.md](CONTRIBUTING.md#release) for the release procedure.

---

## 📚 Project structure

```
src/
├── cli.ts                      # entrypoint: stdio (default, 256 MiB frames) or Streamable HTTP (PKINATIVE_MCP_PORT); reads the operator knobs once
├── http.ts                     # Node http <-> Web Request/Response bridge, 256 MiB body cap, Host/Origin loopback guard
├── auth.ts                     # opt-in HTTP bearer token (PKINATIVE_MCP_HTTP_TOKEN)
├── server.ts                   # Server factory, dispatch by tool kind, cache hints, the cache gate, SERVER_INSTRUCTIONS, 7 prompts, resources
├── caps.ts                     # every byte / count cap + the three operator ceilings
├── limits.ts                   # the 22 PkiLimits as the `limits` fragment; LIMIT_CEILING_EXCEEDED
├── sandbox.ts                  # the single filesystem boundary (PKINATIVE_MCP_OUTPUT_DIR): extension allow-lists, realpath checks, wx writes
├── pki-input.ts                # pem XOR derBase64 XOR path; PEM sniffing, label discipline, bundles
├── content-input.ts            # text XOR base64 XOR path for the bytes to sign / verify / time-stamp; the HEX grammar
├── parse-context.ts            # the PARSE fragment (encodingRules, pemMode, strict, limits) and the per-call input budget
├── signer.ts                   # PKCS#8 / PKCS#12 -> non-extractable SigningKey; the algorithm rules (rsaScheme, hashes)
├── secrets.ts                  # the two password channels (input XOR PKINATIVE_MCP_PASSWORD), redaction
├── key-views.ts                # allow-list views of keys and PKCS#12 bags (never a key byte)
├── trust.ts                    # the TRUST fragment (anchors, candidates, evidence, at, purposes, policy) and reasons[]
├── time.ts                     # ISO 8601 instants, PKINATIVE_MCP_AT, clock-dependence
├── random.ts                   # serialNumber:'random' / nonce:'random' (node:crypto), reported in summaries
├── x509-spec.ts, asn1-spec.ts  # the closed JSON specs of create_certificate / create_csr / encode_* (depth-bounded, pollution-safe)
├── names.ts, spki.ts           # host / IP identity inputs; public-key kinds and curves
├── pki-errors.ts               # PkiError -> ToolError (the 57 PKI_* codes verbatim, classes, remedies), guard()
├── wrapper-codes.ts            # the 21 wrapper codes with meaning and remedy (served by explain_code)
├── diagnostics.ts              # engine diagnostic sink (de-duplicated, capped at 200) -> diagnostics[]; strict escalation
├── projection.ts               # verbosity / fields projection for the read and verdict tools
├── output.ts                   # artefact emitter: embedded resource (pem / der / hex) or exclusive sandbox file
├── resources.ts                # pkinative://output/{+path} over the sandbox (key-bearing files never listed nor served)
├── cache.ts                    # opt-in SHA-256 response cache (PKINATIVE_MCP_CACHE_DIR)
├── views.ts, wire.ts, base64.ts  # wire views (no raw DER echoes), hex helpers, base64 boundary diagnostics
├── engine.ts                   # engine version and Node floor, the Web Crypto capability probe
├── governance.ts               # AI-governance / HITL contract text + draft validation
├── errors.ts, version.ts, index.ts
├── data/pkinative/             # the registries vendored at the pkinative v1.0.0 tag: errors, reasons, diagnostics, limits, core-exports + generated code-tables.ts
└── tools/                      # one file per tool (34), _definition.ts (kinds, annotations), _registry.ts + _group-*.ts (catalogue order), _shared.ts
scripts/                        # TypeScript run by tsx — the full table is in scripts/README.md
├── gate.ts                     # THE quality gate (npm run gate / gate:fast; --publish --require-all on release branches)
├── generate-samples.ts         # npm run test:generate — the examples through the built server -> test-output/samples/
├── verify-samples.ts           # npm run verify:samples — the 98-sample baseline (tests/_fixtures/samples.sha256.json)
├── generate-pki-corpus.ts      # npm run corpus:pki — the OpenSSL interoperability corpus (23 + 5)
├── validate-pki.ts             # npm run validate:pki — level 0 (engine round trip) + level 1 (OpenSSL 3.x); exit 0 / 1 / 2 / 3
├── tool-shape.ts               # structural tools/list fingerprint and size budgets (--write refreshes the fixture)
├── verify-docs.ts              # npm run verify:docs — the docs held to docs/assets/ecosystem.json and the source tree
├── release-prepare.ts          # mechanical version bump (never commits, tags or publishes)
├── build-claude-rules.ts       # npm run agents:rules — .github/instructions/ -> .claude/rules/
├── build-code-tables.mjs       # regenerates src/data/pkinative/code-tables.ts from the vendored registries
├── verify-issue.mjs            # governance draft checker (npm run verify:issue)
├── lib/                        # pki-corpus, interop-tools (OpenSSL), sample-fingerprint, tool-shape, mcp-surface, markdown-anchors, agent-config, prose-language, json-schema-lite
└── helpers/, data/, validators/  # hermetic env, I/O, the lint waivers, the pkilint driver
docs/
├── AGENT_CONTRACT.md           # the consumer contract for agents that USE the server (catalogue, decision tree, recipes, error reference)
├── AI_GUIDE.md, KNOWLEDGE_BASE.md, API_STABILITY.md
├── guides/                     # AI_GOVERNANCE, LOCAL_TESTING, SECURITY, SIGNING, VERIFICATION, REVOCATION, TIMESTAMPS, KEYS, CONFORMANCE
├── data/                       # errors, reasons, diagnostics, limits, core-exports (mirrors of src/data/pkinative/), interop.json (the corpus counts)
└── assets/ecosystem.json       # the single source of every count and version quoted in the docs
examples/                       # 89 executable tools/call sequences (npm run examples:check)
AGENTS.md, CLAUDE.md            # repository rules for coding agents; .github/instructions/ holds the per-area rules
.claude/                        # shared agent settings, the fail-closed guard hook, generated rules, the release-audit skill
.github/workflows/              # ci (Linux Node 22 / 24, Windows, macOS — the gate with --require-all), interop (4 OS legs, blocking),
                                #   sample-regression, publish (Trusted Publishing + SBOM + attestation), docs, codeql, scorecard,
                                #   dependency-review, audit, node-current
.github/rulesets/               # branch and tag rulesets to import
tests/                          # vitest suites (one per tool / module), _fixtures/ (tool shape, sample baseline, the registry schema),
                                #   fixtures/pki/ (42 OpenSSL-made TEST-ONLY files, SHA256SUMS, PROVENANCE.md), interop/ (OpenSSL, linters), tools/ (repository tooling)
```

---

## 🗺 Roadmap

v1.0.0 is the first release, on pkinative 1.0.0: the whole runtime surface of the engine (117 / 117 runtime exports reached by a named tool), offline. The full plan — the released milestone, what is blocked upstream, next steps and the long-term direction — lives in [ROADMAP.md](ROADMAP.md).

**Blocked upstream, by design** (the engine does not have it, and a thin wrapper will not fake it):

- **Key generation** — pkinative generates nothing; keys come from your HSM, KMS or `openssl genpkey`.
- **Writers for PKCS#8, PKCS#12, CRL, OCSP response and time-stamp response** — the engine has none; issue them with your CA software or OpenSSL and verify them here.
- **DSA and ML-DSA verification** — parsed, reported, never verified or signed (`PKI_REASON_SIGNATURE_NOT_CHECKED` / `UNSUPPORTED_KEY`).

Have a feature idea? Open an issue or PR — or let an agent draft one with `draft_governance_issue` and submit it yourself.

---

## ⭐ Star the project

If `pkinative-mcp` is useful to you, please ⭐ this repository — and consider also starring the underlying engine [Nizoka/pkinative](https://github.com/Nizoka/pkinative). Stars help others discover the project and motivate continued development.

---

## 🤝 Contributing

Contributions are very welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md), check the [open issues](https://github.com/Nizoka/pkinative-mcp/issues), and follow the [code of conduct](CODE_OF_CONDUCT.md).

---

## 📄 License

[MIT](LICENSE) © 2026 Nizoka. Third-party material: [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

`pkinative-mcp` is built on top of [`pkinative`](https://github.com/Nizoka/pkinative) and the [Model Context Protocol TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk).
