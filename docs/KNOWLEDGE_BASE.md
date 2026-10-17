# pkinative-mcp — Knowledge Base

> Reference for AI assistants (GitHub Copilot, Claude, Cursor, Continue, Zed, Windsurf, Cline, Roo Code)
> and human contributors. Captures the full context needed to understand, extend, and debug
> pkinative-mcp **v1.0.0** without reading every source file.
>
> Verified on 2026-10-13 against pkinative-mcp 1.0.0 and pkinative 1.0.0: 34 tools, 7 prompts, 21 wrapper codes,
> 57 `PKI_*` engine codes, 43 `PKI_REASON_*` reasons, 97 `PKI_DIAG_*` diagnostics, 9 operator variables.
> Every count and version quoted here comes from [`assets/ecosystem.json`](assets/ecosystem.json)
> and is held to it by `npm run verify:docs`.

> If you are an AI agent calling pkinative-mcp from a chat session, also read
> [`AI_GUIDE.md`](AI_GUIDE.md) — the short, action-oriented decision tree — and the consumer
> contract [`AGENT_CONTRACT.md`](AGENT_CONTRACT.md).

---

## 1. Context

**What is pkinative-mcp?**
An MCP (Model Context Protocol) server that bridges the zero-dependency
[`pkinative`](https://github.com/Nizoka/pkinative) PKI engine (v1.0.x, pure TypeScript, Web
Crypto for every signature) to AI clients (Claude Desktop, ChatGPT, Cursor, Continue, Zed,
Windsurf, Cline, Roo Code, …). It exposes **34** tools over a stdio (or Streamable HTTP)
transport so AI agents can **inspect** X.509 certificates, CSRs, CRLs, OCSP responses, CMS
SignedData, RFC 3161 time-stamps, PKCS#8 keys and PKCS#12 files; **verify** certification
paths (RFC 5280 §6 with name, purpose, policy and offline CRL / OCSP revocation), CMS
signatures and time-stamps; **issue** certificates and requests, **sign** CMS, build OCSP and
time-stamp **requests**; **open** PKCS#12 files without a key byte leaving; decode and encode
ASN.1, PEM and OIDs; and draft governance-compliant GitHub issues for human review. Files in
the sandbox are also exposed as native MCP resources.

**Philosophy:**
- Three runtime dependencies (`pkinative`, the MCP SDK `@modelcontextprotocol/server`, `zod`) — every PKI decision lives in `pkinative`; the wrapper never parses a byte of DER on its own.
- The MCP server is a thin, secure dispatch layer: validate inputs with Zod → call the engine through `guard` → shape the result through allow-list views → deliver an artefact once, inline or into the sandbox.
- Every tool is fully self-contained (its own file in [src/tools/](../src/tools)), registered through its group file.
- Security at every boundary: strict Zod on every input, one filesystem boundary with realpath checks, byte caps on every exchange, operator ceilings no argument can exceed, a secrets policy enforced by needle tests.
- Honest doctrine, surfaced not hidden: no network ever, no key generation or export, no writer for PKCS#8 / PKCS#12 / CRL / OCSP response / time-stamp response, SHA-1 opt-in, RSA scheme explicit, PBES2 / PBMAC1 only, DSA / ML-DSA parsed but never verified — every refusal carries a frozen code and a remedy, and `describe_engine.refusals` lists them.
- Every tool ships `_meta.apiVersion = '1.0.0'` and ≤ 2 executable `_meta.examples` (the rest live in `examples/*.json`) — see [`API_STABILITY.md`](API_STABILITY.md).
- Reproducible by decision: a pinned instant (`PKINATIVE_MCP_AT` or the call's own), an explicit serial / nonce and a deterministic signer make an artefact a pure function of its inputs (`sha256` in every artefact result).
- Interoperable by proof: OpenSSL 3 is the external judge of every artefact the tools write ([`guides/CONFORMANCE.md`](guides/CONFORMANCE.md)).

**Runtime:** Node.js ≥ 22 (ESM, strict TypeScript; the engine floor is `^22.22.2 || ^24.14.1 || >=25.8.2`). Transport: stdio (default) or Streamable HTTP. Protocol: MCP 2026-07-28 with automatic 2024 / 2025-era fallback.

**Repositories**
- MCP server: <https://github.com/Nizoka/pkinative-mcp>
- Core engine: <https://github.com/Nizoka/pkinative>
- CLI companion: <https://github.com/Nizoka/pkinative-cli>
- npm: <https://www.npmjs.com/package/pkinative-mcp>

---

## 2. Architecture

### Request path

```
host ──stdio frame / POST /mcp──► src/cli.ts (boot: ceilings, pinned instant, password presence, token; TZ-independent)
   ► src/http.ts (loopback guard: Host / Origin → 403, body > 256 MiB → 413) ► src/auth.ts (bearer → 401)
   ► src/server.ts  tools/call → TOOL_INDEX.get(name) ?? ProtocolError -32602 [UNKNOWN_TOOL]
        ► isCacheable(tool, input) ? getCached : miss
        ► tool.handler(input)
             parseInput(z.strictObject)             → VALIDATION_ERROR (the path named, secrets redacted)
             readPkiInput / readContentInput        → pem | derBase64 | path through src/sandbox.ts, caps, PEM sniffing, secret-label refusal
             createParseContext(input)              → engine options + diagnostics sink + effective limits (ceilings applied)
             guard / guardAsync(engine call)        → PKI_* verbatim + errorClass + remedy, IO_ERROR, ENGINE_ERROR
             views (src/views.ts, src/key-views.ts) → the wire form, raw DER echoes stripped, key views allow-listed
             emitArtefact (src/output.ts)           → base64 resource | resource_link after an exclusive write | hex
        ► dispatchOutput by tool.kind (artefact | governance | read / verdict / engine / explain → projection)
        ► setCached (only when cacheable) ► server.projectCallToolResult(result, outputSchema)
   ◄── CallToolResult { content[], structuredContent, isError?, _meta { cached?, unmatchedFields?, error? } }
```

### Modules

```
src/
├── cli.ts            # Entry point: stdio (serveStdio) or HTTP (createMcpHandler + node:http bridge); boot-time knobs read once; SIGINT / SIGTERM
├── http.ts           # node:http <-> web Request / Response bridge, 256 MiB body cap (413), loopback Host / Origin guard (403), keep-alive-safe abort
├── auth.ts           # opt-in HTTP bearer token (PKINATIVE_MCP_HTTP_TOKEN, ≥ 16 chars), constant-time compare, 401 + WWW-Authenticate
├── server.ts         # createServer(): low-level Server + setRequestHandler, SERVER_INSTRUCTIONS (5,469 bytes), PROMPTS (7), cache hints, isCacheable, dispatchOutput, callToolDirect
├── version.ts        # the package version constant and TOOL_API_VERSION ('1.0.0')
├── engine.ts         # engine identity (version read from pkinative's package.json), the Node floor, probeRuntime (canVerify / canSign / canDecrypt)
├── errors.ts         # ToolError (code + data) and SecurityError (SECURITY_VIOLATION)
├── wrapper-codes.ts  # the 21 wrapper codes with meaning and remedy (served by explain_code)
├── pki-errors.ts     # PkiError → ToolError: PKI_ERROR_CLASS (57 → 10 classes), PKI_REMEDY (MCP inputs), guard / guardAsync, pkcs12Failure
├── caps.ts           # every byte / count cap (CAPS record) + the three operator ceilings (read once; invalid → refuse to start)
├── limits.ts         # the 22 PkiLimits by name (LIMITS_INPUT_SCHEMA / LimitsSchema), resolveCallLimits under the ceilings → LIMIT_CEILING_EXCEEDED
├── sandbox.ts        # the one filesystem boundary: PKINATIVE_MCP_OUTPUT_DIR, extension allow-lists, traversal / NUL / UNC / realpath guards, exclusive writes
├── secrets.ts        # the two password channels (input XOR PKINATIVE_MCP_PASSWORD), redact(), carriesSecret()
├── time.ts           # ISO 8601 instants parsed from fields (never Date.parse), PKINATIVE_MCP_AT, resolveInstant, isClockDependent
├── random.ts         # the wrapper's CSPRNG ('random' serial / nonce from node:crypto), RANDOMNESS manifest
├── cache.ts          # opt-in SHA-256-keyed response cache (1 h TTL, 256 MiB LRU), transparent miss on any I/O error
├── resources.ts      # pkinative://output/{+path}: sandbox listing (≤ 1000, depth ≤ 8) and reads (≤ 50 MiB); key-bearing files never listed nor served
├── output.ts         # artefact emission: base64 resource / resource_link / hex, encoding pem | der | hex, MIME per artefact, text artefacts
├── projection.ts     # verbosity 'summary' + fields dot-path projection (≤ 16), PROJECTION_INPUT_PROPERTIES
├── diagnostics.ts    # the diagnostics sink installed on every engine call (never console.warn), ≤ 200 rows, strict → PKI_STRICT_DIAGNOSTIC
├── parse-context.ts  # PARSE fragment (encodingRules, pemMode, strict, limits) → engine options + sink + effective limits + inline byte budget
├── base64.ts         # base64 boundary diagnostics (data: URI, PEM text, double encoding, empty payload named in the remedy)
├── pki-input.ts      # PKI_INPUT: pem | derBase64 | path, PEM sniffing, label discipline, bundles (≤ 256), secret-label / secret-DER refusal
├── content-input.ts  # CONTENT_INPUT: text | base64 | path (128 MiB / 1 GiB), hex schema
├── signer.ts         # SIGNER fragment: PKCS#8 (plain / PBES2) or PKCS#12 → non-extractable SigningKey; algorithm follows the key; rsaScheme required
├── spki.ts           # a public key from a certificate, a CSR or a PUBLIC KEY; key type from the SPKI algorithm
├── trust.ts          # TRUST fragment: trustAnchors, candidates, crls, ocspResponses, at, requireRevocation, purposes, policy; reasonsView
├── names.ts          # distinguished names and IP addresses as an agent writes them → engine descriptions
├── x509-spec.ts      # the JSON spec of create_certificate / create_csr / encode_x509_structure (serialNumber, subject, validity, extensions)
├── asn1-spec.ts      # the JSON node spec of encode_asn1 (18 node types) through the engine encoders
├── views.ts          # wire views of parsed objects (certificate, CSR, name, SPKI, extension, time, algorithm, reasons), raw DER echoes dropped
├── key-views.ts      # allow-list views of keys, encrypted keys, MACs, bags and CryptoKey handles — the only door for key material
├── wire.ts           # pkinative ADR 0018 wire form: bigint → decimal string, bytes → hex, epochMilliseconds kept, CryptoKey described
├── governance.ts     # the HITL contract: validateIssueMarkdown (dependency / secret / reproduction policy), prompt texts, HUMAN_GATE
├── index.ts          # public library entry (createServer, types)
├── data/pkinative/   # vendored registries of the pkinative v1.0.0 tag: errors.json, reasons.json, diagnostics.json, limits.json, core-exports.json; code-tables.ts generated from them
└── tools/
    ├── _definition.ts            # ToolDefinition, ToolKind, the three annotation sets (READ_ONLY / WRITES / PRODUCES), defineTool, projectableOutputSchema
    ├── _shared.ts                # ProjectionShape, AllowSha1Shape, parseInput (secret-redacting), withDiagnostics, diagnosticCount, sha256Hex
    ├── _registry.ts              # TOOLS = encodings + certificates + paths + cms + keys + meta (registration order = tools/list order)
    ├── _group-encodings.ts       # convert_pem, resolve_oid, compute_fingerprint, decode_asn1, encode_asn1
    ├── _group-certificates.ts    # inspect_certificate, create_certificate, encode_x509_structure, decode_extension, check_certificate_name, check_certificate_purpose, inspect_csr, create_csr
    ├── _group-paths.ts           # verify_certificate_chain, build_certificate_path, validate_certificate_path, inspect_crl, check_crl_revocation, create_ocsp_request, inspect_ocsp_response, check_ocsp_status
    ├── _group-cms.ts             # sign_cms, verify_cms, inspect_cms, amend_cms, create_timestamp_request, inspect_timestamp, verify_timestamp
    ├── _group-keys.ts            # inspect_private_key, inspect_pkcs12, open_pkcs12
    └── <kebab-name>.ts           # one module per tool (34): <NAME>_NAME, <NAME>_INPUT_SCHEMA, the Zod twin, <NAME>_OUTPUT_SCHEMA, <NAME>_SUMMARY_PROPERTIES, handler, <NAME>_TOOL
```

Catalogue parity gate: `scripts/lib/tool-shape.ts` computes a structural fingerprint of the built `tools/list` (description strings stripped; `npx tsx scripts/tool-shape.ts --write` refreshes `tests/_fixtures/tool-shape.json`, `npm run verify:tool-shape` is the gate step that checks it) and `tests/catalogue-parity.test.ts` fails on any structural drift (types, enums, defaults, constraints, `required`, `additionalProperties`, example count). Wording — descriptions, examples, `SERVER_INSTRUCTIONS` — may change freely; a structural change needs a deliberate fixture refresh reviewed under `API_STABILITY.md` §5. The frozen published catalogue `tests/_fixtures/tool-shape.v1.0.0.json` (created at the release commit, never regenerated) is the compatibility floor. `tests/schema-lockstep.test.ts` holds every JSON Schema to its Zod twin (same keys, same enums, same defaults, no `$ref` / `$defs` / `$schema`); `tests/schema-conformance.test.ts` validates every `structuredContent` (full, summary, `fields`, file mode) and every `_meta.examples[].input` with the SDK's Ajv 2020-12 validator.

Catalogue size: `tools/list` is 427,106 bytes and `SERVER_INSTRUCTIONS` 5,469 bytes; `scripts/tool-shape.ts --check` fails above 448 KiB / 8 KiB and when `declared.toolsListBytes` in `docs/assets/ecosystem.json` drifts more than 2 % from the measurement. The size is the price of host compatibility: no `$ref` / `$defs` (some hosts forward `inputSchema` to function-calling APIs that reject references) and no `$schema` keyword, so the parse fragment with its 22 named limits rides on 31 tools, the PKI input on 70 properties, the projection inputs on 25 tools and the diagnostics report on every output schema. The descriptions of the shared fragments are terse on purpose; the long form lives in `describe_engine`, the prompts and the contract.

### Shared fragments (import, never redeclare)

| Fragment | Module | JSON Schema / Zod | What it gives a tool |
|---|---|---|---|
| PKI input | `src/pki-input.ts` | `pkiInputSchema(kind)` / `PkiInputSchema`, `pkiBundleSchema` / `PkiBundleSchema` | exactly one of `pem` / `derBase64` / `path`; PEM sniffed by `-----BEGIN `; one object expected ⇒ several matching blocks refused; bundles ≤ 256 items; a private-key label or a DER that parses as PKCS#8 / PKCS#12 refused where keys are not expected (`refuseSecretDer`) |
| Content input | `src/content-input.ts` | `contentInputSchema` / `ContentInputSchema`, `hexSchema` / `HexSchema` | `text` / `base64` / `path` for the signed or stamped bytes; hex values (serials, nonces, attributes) |
| Parse | `src/parse-context.ts` | `PARSE_INPUT_PROPERTIES` / `ParseShape` | `createParseContext(input)` → engine options with the sink, effective limits, the inline byte budget — built once per call |
| Limits | `src/limits.ts` | `LIMITS_INPUT_SCHEMA` / `LimitsSchema` | the 22 `PkiLimits` by name; `resolveCallLimits` applies the ceilings |
| Signer | `src/signer.ts` | `SIGNER_INPUT_SCHEMA` / `SignerSchema`, `ALLOW_SHA1_INPUT_PROPERTY` | a non-extractable `SigningKey` from PKCS#8 or PKCS#12; `signatureAlgorithm` follows the key; `SIGNING_KEY_VIEW_SCHEMA` in results |
| Trust | `src/trust.ts` | `TRUST_INPUT_PROPERTIES` / `TrustShape`, `REASONS_OUTPUT_PROPERTY` | anchors, candidates, evidence, `at`, policy inputs; `reasonsView` rows `{ code, message, remedy, … }` |
| Projection | `src/projection.ts` | `PROJECTION_INPUT_PROPERTIES` / `ProjectionShape` | `verbosity`, `fields` |
| Output | `src/output.ts` | `outputInputProperties` / `outputShape`, `ARTEFACT_OUTPUT_PROPERTIES` | `outputMode`, `outputPath`, `encoding`; `emitArtefact` |
| Password | `src/secrets.ts` | `PASSWORD_INPUT_PROPERTY` / `PasswordSchema` | `resolvePassword` (input XOR environment), `secretRequired`, `redact` |
| Diagnostics | `src/diagnostics.ts` | `DIAGNOSTICS_OUTPUT_PROPERTIES` | `diagnostics[]`, `diagnosticCounts`, `diagnosticsTruncated` on every result |

---

## 3. Tool registry ([src/tools/_registry.ts](../src/tools/_registry.ts))

`TOOLS` is the concatenation, in registration order, of the five group lists and `META_TOOLS` (`describe_engine`, `explain_code`, `draft_governance_issue`); `tools/list` is that order. Each `ToolDefinition` carries:

| Member | Role |
|---|---|
| `name`, `title`, `description` | the catalogue entry; the description states what the tool does, when to prefer another, the caps and the codes it raises |
| `kind` | how `server.ts` shapes the result: `read` (a report, projectable), `verdict` (`valid` + `reasons[]`, never `isError` for a negative verdict), `artefact` (a produced DER, delivered once), `engine` (`describe_engine`), `explain` (`explain_code`), `governance` (`draft_governance_issue`) |
| `inputSchema`, `outputSchema`, `rawOutputSchema` | hand-written JSON Schema 2020-12 (`additionalProperties: false` everywhere); read / verdict tools advertise `projectableOutputSchema(raw, summaryProperties)`, keeping `rawOutputSchema` for the lock-step tests |
| `annotations` | `READ_ONLY` (23 tools), `WRITES` (`convert_pem`, `encode_asn1`, `encode_x509_structure`, `amend_cms`, `open_pkcs12`, `draft_governance_issue`), `PRODUCES` (`create_certificate`, `create_csr`, `sign_cms`, `create_ocsp_request`, `create_timestamp_request`) |
| `examples` | ≤ 2 `_meta.examples`, each a self-contained input validated against the schema in tests |
| `cacheable`, `instantInputs` | the cache gate's static part: `cacheable: false` for `create_certificate`, `create_csr`, `sign_cms`, `open_pkcs12`, `describe_engine`, `draft_governance_issue`; `instantInputs` (`at`, `spec.notBefore`, `signingTime`) checked for clock dependence |
| `handler`, `text`, `summary` | the async handler `(args: unknown) => result`, the one-line `content[0].text`, the `verbosity: 'summary'` projection |

Kinds by tool: read — `convert_pem`, `resolve_oid`, `compute_fingerprint`, `decode_asn1`, `inspect_certificate`, `decode_extension`, `inspect_csr`, `inspect_crl`, `inspect_ocsp_response`, `inspect_cms`, `inspect_timestamp`, `inspect_private_key`, `inspect_pkcs12` (13); verdict — `check_certificate_name`, `check_certificate_purpose`, `verify_certificate_chain`, `build_certificate_path`, `validate_certificate_path`, `check_crl_revocation`, `check_ocsp_status`, `verify_cms`, `verify_timestamp`, `open_pkcs12` (10); artefact — `encode_asn1`, `create_certificate`, `encode_x509_structure`, `create_csr`, `create_ocsp_request`, `sign_cms`, `amend_cms`, `create_timestamp_request` (8); engine, explain, governance (1 each).

**Dispatch (`dispatchOutput`):** an `artefact` result splits into the content block (the bytes, once) and `structuredContent` (`mode`, `encoding`, `sizeBytes`, `sha256`, `filePath?`, `hex?`, `summary`, diagnostics); a `governance` result adds the draft markdown as a second text block; a `read` / `verdict` / `engine` / `explain` result goes through `projectStructured` (summary, then `fields`) and `projectionMeta` (`_meta.unmatchedFields` + `availableFields`), with one optional artefact attachment delivered as a block. A `ToolError` becomes `isError: true` with `<tool> failed [CODE]: message` and `_meta.error { code, message, data }`; anything else becomes a code-less `isError` (the tests assert it never happens).

**MCP resources** (`src/resources.ts`): `resources/list` walks the sandbox (≤ 1000 files, depth ≤ 8, key-bearing extensions skipped) into `pkinative://output/<relative>` descriptors with a MIME type per extension; `resources/templates/list` advertises `pkinative://output/{+path}`; `resources/read` re-validates the path (sandbox, realpath, secret extension, the private-key PEM label) and returns `text` for PEM / Markdown / JSON / text, a `blob` otherwise, ≤ 50 MiB.

**MCP prompts** (`src/server.ts` `PROMPTS`): `governance_contract`, `draft_issue_workflow` (from `src/governance.ts`), `verify_before_trust`, `issue_certificate`, `sign_and_timestamp`, `offline_revocation`, `open_keys_safely` — read-only text, no arguments.

---

## 4. Error mapping ([src/pki-errors.ts](../src/pki-errors.ts), [src/wrapper-codes.ts](../src/wrapper-codes.ts))

`src/pki-errors.ts` is the **only** module that reads `err.code`. Every engine call runs through `guard(context, fn, remedies?)` / `guardAsync`, and `mapPkiError` turns:

- a `PkiError` into `ToolError(code)` with the frozen `PKI_*` code verbatim, `data.errorClass` from `PKI_ERROR_CLASS` (57 codes → `usage` `input` `parse` `security` `limit` `unsupported` `crypto` `password` `check` `internal`), `data.engineError` (the subclass name), the detail the subclass carries (`path`, `offset`, `algorithm`, `limit` / `configured` / `observed`, and `env` when a ceiling backs the limit), and `data.remedy` — the call site's override, else the `PKI_REMEDY` table (the MCP input that lifts the refusal: `encodingRules: 'ber'`, `pemMode: 'lax'`, `allowTrailingData: true`, `allowSha1: true`, `rawExtensions: true`, `limits.<limit>`, the OpenSSL 3.4 conversion, the password channels);
- a Node filesystem error (`ENOENT`, `EACCES`, `EEXIST`, …) into `IO_ERROR` carrying the errno only;
- anything else into `ENGINE_ERROR` (`errorClass: internal`).

`pkcs12Failure(report)` is the one shared translation of a negative `openPkcs12` result on the signer path: `RSA_SCHEME_REQUIRED`, `PKI_KEY_ENCRYPTION_UNSUPPORTED` (legacy cipher, security), `PKI_CRYPTO_DECRYPTION_FAILED` (MAC mismatch, password), or `ENGINE_VERDICT` with `data.reasons`. `tests/pki-errors.test.ts` and `tests/error-codes.test.ts` hold the table, the contract's §6 and the tests together; `tests/wrapper-codes.test.ts` asserts every `ToolError('CODE'` literal under `src/` is one of the 21.

The three vocabularies that are **not** errors: `PKI_REASON_*` (43) are rows of `reasons[]` in a verdict (`reasonsView`), `PKI_DIAG_*` (97) are rows of `diagnostics[]` (the sink of `src/diagnostics.ts`, `severity` from `PKI_DIAGNOSTIC_SEVERITY`), and the registries behind `explain_code` are `src/data/pkinative/code-tables.ts`, generated from the vendored JSON by `scripts/build-code-tables.mjs` (gate step `code-tables`).

---

## 5. Sandbox, output and cache

**The sandbox** ([src/sandbox.ts](../src/sandbox.ts)) is the single filesystem boundary. `PKINATIVE_MCP_OUTPUT_DIR` unset ⇒ every `path` input, every `outputMode: 'file'` and every resource is disabled. Set ⇒ `resolveSandboxPath` (reads) and `resolveOutputFile` (writes) refuse a NUL byte, an absolute, drive or UNC path (also on POSIX), `..` traversal, an extension outside the allow-list (`PKI_INPUT_EXTENSIONS` for reads; `OUTPUT_EXTENSIONS` = the same minus `SECRET_EXTENSIONS` `.key .p8 .p12 .pfx` for artefacts; `.pem` for PEM; `TEXT_OUTPUT_EXTENSIONS` `.md .txt .json .pem` for text), and — after resolution — a **real path** outside the sandbox (`assertRealpathInside` on the file for reads, on the parent for writes). Writes are exclusive (`wx` → `OUTPUT_EXISTS`), a partial file is removed on failure, and no absolute path ever leaves in a message (`relativeLabel`). Key material is never written: the engine has no writer and `resolveOutputFile` refuses a key-bearing `outputPath` before any work.

**Output** ([src/output.ts](../src/output.ts)): `emitArtefact(der, { encoding, pemLabel, mimeType, outputMode, outputPath, summary })` → `OutputResult { mode, encoding, sizeBytes, sha256, base64? | filePath? | hex?, mimeType, summary }`. `encoding: 'pem'` wraps through the engine's `encodePem` under the artefact's label (`CERTIFICATE`, `CERTIFICATE REQUEST`, `CMS`, `OCSP REQUEST`, `TIMESTAMP QUERY`, …) and is delivered as `text` with `application/x-pem-file`; `'der'` as `blob` with the artefact's MIME; `'hex'` inline only (≤ 64 KiB, `VALIDATION_ERROR` with file mode). `writeSandboxedText` serves governance drafts and PEM bundles. `src/server.ts` turns the result into the content block (`artefactBlocks`) and the structured part (`artefactStructured`) — the bytes are never duplicated.

**The cache** ([src/cache.ts](../src/cache.ts)): opt-in through `PKINATIVE_MCP_CACHE_DIR`; key = SHA-256 of the canonical JSON `{ tool, apiVersion, input }` with `apiVersion` = `TOOL_API_VERSION/<package version>/<engine version>`; entries `<key>.json` with a 1 h TTL and a 256 MiB LRU by mtime; every I/O error degrades to a miss. **The gate** `isCacheable(tool, input)` (`src/server.ts`): `tool.cacheable`, no `outputMode: 'file'`, no `path` anywhere in the input (`isPathInput`), no secret (`carriesSecret`: a `password` at the top level or inside `signer`, or a `signer` at all), no `'random'` / `'now'` string anywhere (`hasVolatileValue`), no password-accepting tool while `PKINATIVE_MCP_PASSWORD` is set, and every `instantInputs` path pinned (`isClockDependent`). A hit is re-dispatched through the projection and tagged `_meta.cached: true`; refusals are never stored (`tests/cache-policy.test.ts`, `tests/cache-wire.test.ts`).

---

## 6. Transport & environment

**stdio** (default): one `Server` per process, `serveStdio`; stdout carries JSON-RPC frames only (eslint `no-console`, the `[pkinative-mcp]` logger writes stderr; the gate's `smoke` step and `tests/cli-stdio.test.ts` drive the built binary). **HTTP** (`PKINATIVE_MCP_PORT`): `createMcpHandler` from the SDK behind the `node:http` bridge of `src/http.ts` (no `@modelcontextprotocol/node` adapter — it would pull in an HTTP framework), bound to `127.0.0.1`, a fresh connection-less `Server` per request (2026-07-28 is stateless), `POST /mcp` only. Both transports serve the modern envelope and the legacy `initialize` handshake (`tests/_agent-client.ts` drives the four transport × era pairs: `stdio-legacy`, `stdio-modern`, `http-legacy`, `http-modern`).

**Boot** (`src/cli.ts`): `ensureEngineReady()`, then the operator knobs are read once — the three ceilings (`src/caps.ts` `readCeilings`), the pinned instant (`src/time.ts` `readPinnedInstant`), the password presence (`src/secrets.ts`), the HTTP token (`src/auth.ts` `readHttpToken`) — each logged on stderr by name (never by value for a secret); an invalid value is one `fatal:` line and exit 1. The nine variables (`server.json`, asserted by `tests/metadata.test.ts`):

| Variable | Scope |
|---|---|
| `PKINATIVE_MCP_OUTPUT_DIR` | the sandbox (reads, writes, resources) |
| `PKINATIVE_MCP_CACHE_DIR` | the response cache |
| `PKINATIVE_MCP_PORT` | Streamable HTTP on loopback |
| `PKINATIVE_MCP_HTTP_TOKEN` | bearer token (secret) |
| `PKINATIVE_MCP_PASSWORD` | operator-side key / PKCS#12 password (secret) |
| `PKINATIVE_MCP_AT` | the pinned instant for omitted `at` / `notBefore` / `signingTime` |
| `PKINATIVE_MCP_MAX_INPUT_BYTES` | ceiling of `limits.maxInputBytes` and the decoded size of one PKI object (default 64 MiB) |
| `PKINATIVE_MCP_MAX_KDF_ITERATIONS` | ceiling of `limits.maxKdfIterations` / `maxPkcs12KdfIterations` (default 10 000 000) |
| `PKINATIVE_MCP_MAX_PATHS_EXPLORED` | ceiling of `limits.maxPathsExplored` (default 1 000) |

**Privacy & data handling:** no telemetry, no network code path, no URL from any argument. Inputs stay in memory for the call; the only persistence is the opt-in cache (plaintext, never a password-bearing or signer-bearing input, never a path input) and the files a caller asks for in the sandbox. Secrets never reach a message, `_meta.error.data`, stderr, a cache file, a resource or the stdio transcript — `tests/secret-leak.test.ts` sweeps every result of every key-taking tool, stderr, the cache directory and the transcript with needles computed from the fixtures (`tests/_secrets.ts`: PEM bodies, DER hex / base64, private scalars in every encoding, encrypted-key bodies, the password), and `assertResultClean` is called on every such result in every suite.

---

## 7. Testing architecture

vitest, `pool: 'forks'`, `TZ=UTC`, `sequence.shuffle: false`, 30 s per test; coverage thresholds 94 / 90 / 95 / 94 (statements / branches / functions / lines, `vitest.config.ts`, `src/cli.ts` and `src/index.ts` excluded). One `tests/<tool>.test.ts` per tool and per module, `_`-prefixed helpers (`_pki-fixtures.ts` — `fixture`, `fixtureBytes`, `fixtureInput`, `AT = '2027-01-01T00:00:00Z'`, `PASSWORD`; `_pki-assert.ts` — `assertResultClean`, `assertNoSecret`, `assertValidDer`, `codeOf`, `errorCodeOf`, `artefactBytes`; `_secrets.ts`; `_sandbox.ts`; `_mcp-harness.ts` `connectLegacy`; `_http-fixture.ts`; `_agent-client.ts` `openAgent`; `_fuzz.ts`).

**Fixtures:** `tests/fixtures/pki/` holds **42 files** made by OpenSSL 3.5.5 (`tests/fixtures/make-test-pki.sh`, kept for provenance, never run in CI), pinned by `tests/fixtures/SHA256SUMS` and described row by row in [`tests/fixtures/PROVENANCE.md`](../tests/fixtures/PROVENANCE.md): a P-256 root → intermediate (pathLen 0) → leaf chain with SAN / EKU / CRL DP / AIA, a revoked leaf, an RSA leaf, an Ed25519 root, a delegated OCSP responder and a TSA, keys (plain, PBES2-encrypted, DER), a CSR, PKCS#12 files (PBMAC1, RSA, Ed25519, legacy, plain keyBag, no MAC, certs-only), CRLs (base, delta), OCSP request and responses, CMS attached / detached, a TSP request / response / token. Foreign provenance: neither the server nor the engine wrote them, so a defect cannot be baked into both a fixture and its reading. Every private key is public TEST-ONLY material (password `test-only-password`); validity 2026-01-01 → 2046-01-01; verdicts are pinned at `at: 2027-01-01T00:00:00Z`. `tests/fixtures.test.ts` fails on a changed checksum, a missing or an unlisted file.

**Suites of note:**

| Suite | What it proves |
|---|---|
| `tests/<tool>.test.ts` (34) | success and error paths of every tool: `isError` + `[CODE]` + `_meta.error.code`, unknown keys at any depth, `pem` XOR `derBase64` XOR `path`, the summary and `fields` projections, `assertResultClean` on every key-taking result |
| `autonomy` | scenarios S0–S18: a scripted client with no human in the loop drives every workflow over stdio / HTTP × legacy / 2026-07-28 with an operator environment (sandbox + fixtures, cache, a lowered ceiling): no unexpected `isError`, every error coded with a remedy, cache hits visible on the wire, verdicts never errors, no secret anywhere, clean shutdown |
| `secret-leak` | three campaigns: every key / PKCS#12 / signer tool on every key fixture and password situation; a private key or PKCS#12 fed to every PKI input of every tool; stderr, the console and the cache sweep |
| `pki-fuzz` | seeded mutation of every DER fixture against every reader and verdict tool, and hostile values on every top-level input of every tool — nothing escapes a handler uncoded |
| `prototype-pollution` | a poisoned object at every nesting (PKI input, bundle, limits, signer, projection, the loose specs) is refused without touching `Object.prototype` |
| `coverage-matrix` | the 294-export registry is the frozen 1.0.0 surface; **117 / 117 runtime exports** are imported by name under `src/` and every tool reaches the engine; `UNEXPOSED_EXPORTS` are members, never exports |
| `schema-lockstep`, `schema-conformance`, `catalogue-parity` | JSON Schema ≡ Zod; `structuredContent` and every example validate; the catalogue equals `tests/_fixtures/tool-shape.json` |
| `examples` | every `examples/*.json` (89 files) runs live through `callToolDirect`, multi-step examples chained, `expectError` asserted, `documentationOnly` schema-checked |
| `cache-policy`, `cache-wire`, `cache` | the gate, the namespace, `_meta.cached`, never a secret or a path in a cache file |
| `protocol-revisions`, `stdio-modern`, `http-modern`, `http-hardening`, `http-transport`, `http-shutdown`, `auth` | both eras on both transports, the loopback guard, the body cap, the bearer token, keep-alive abort, graceful shutdown |
| `sandbox`, `resources`, `output`, `limits`, `caps`, `secrets`, `time`, `diagnostics` | the boundary modules: traversal, UNC, NUL, extension lists, symlinked parent or file, never-overwrite, key-bearing names, the 22 limits under their ceilings, the password channels, instants, the sink |
| `governance`, `draft-governance-issue`, `tools/guard` | `src/governance.ts` ≡ `scripts/verify-issue.mjs`; the Claude Code guard hook denies every GitHub write |
| `interop/openssl`, `interop/lint` | level 1 of the conformance gate as vitest (OpenSSL 3 reads and verifies what the tools write, the tools read what OpenSSL wrote); zlint / pkilint over the corpus certificates (publish profile, `REQUIRE_LINT=1`) |
| `tools/*` | the pure parts of the scripts: gate, tool-shape, interop-tools, pki-corpus, json-schema-lite, markdown-anchors, hermetic-env, release-prepare, agent-config, build-claude-rules, workflows |
| `metadata`, `version`, `describe-engine`, `explain-code` | version lock-step (package, `server.json`, `src/version.ts`), the nine variables, every cap advertised, every registry served |

The sample baseline (`tests/_fixtures/samples.sha256.json`, 98 samples: 10 `bytes`, 3 `tbs`, 85 `semantic`) and the OpenSSL corpus are described in [`API_STABILITY.md`](API_STABILITY.md) §5 and [`guides/CONFORMANCE.md`](guides/CONFORMANCE.md); how to run all of it locally, in [`guides/LOCAL_TESTING.md`](guides/LOCAL_TESTING.md).

---

## 8. Engine export ledger

Every runtime export of pkinative 1.0.0 — the **117** entries with `reach: "capability"` of [`data/core-exports.json`](data/core-exports.json) (294 exports in all, 177 type-only; the registry is vendored from the engine's frozen `api.frozen.json` at the v1.0.0 tag and mirrored byte-identical from `src/data/pkinative/core-exports.json`) — with the `src/` module that imports it by name and the tools that reach that module through their relative imports, transitively (the derivation `tests/coverage-matrix.test.ts` runs: `engineImports()` × `reachableModules()`). 117 / 117 are reached; kinds: 104 functions, 7 classes, 6 constants.

The wide reaches are named sets, measured from the import closure:

- **all 34 tools** — through `src/limits.ts` (every tool spreads the limits fragment or `describe_engine` reports them), `src/pki-errors.ts` (every handler guards its engine calls) and `src/output.ts` (every tool module imports the output helpers).
- **the 29 PKI-input tools** — through `src/pki-input.ts`: every tool but `create_timestamp_request`, `describe_engine`, `draft_governance_issue`, `explain_code` and `resolve_oid`.
- **the 26 view tools** — through `src/views.ts` / `src/key-views.ts`: the 29 minus `compute_fingerprint`, `convert_pem` and `encode_x509_structure`.
- **the 25 ASN.1-reading tools** — through `src/spki.ts` / `src/asn1-spec.ts` / `src/tools/decode-asn1.ts`: the 29 minus `convert_pem`, `decode_extension`, `inspect_ocsp_response`, `inspect_pkcs12` and `open_pkcs12`, plus `resolve_oid`.
- **the 25 certificate-parsing tools** — through `src/spki.ts` / `src/key-views.ts`: the 29 minus `convert_pem`, `decode_asn1`, `decode_extension` and `encode_asn1`.
- **the 22 SPKI tools** — through `src/spki.ts`: the 25 certificate-parsing tools minus `inspect_ocsp_response`, `inspect_pkcs12` and `open_pkcs12`.
- **the 21 signer tools** — through `src/signer.ts`: the 22 SPKI tools minus `compute_fingerprint`.
- **the 18 trust-fragment tools** — through `src/trust.ts`: `amend_cms`, `build_certificate_path`, `check_certificate_name`, `check_certificate_purpose`, `check_crl_revocation`, `check_ocsp_status`, `create_certificate`, `create_csr`, `create_ocsp_request`, `describe_engine`, `encode_x509_structure`, `inspect_csr`, `open_pkcs12`, `sign_cms`, `validate_certificate_path`, `verify_certificate_chain`, `verify_cms`, `verify_timestamp`.

| Export | Kind | Imported by | Reached by (tools) |
|---|---|---|---|
| `ANY_EXTENDED_KEY_USAGE` | constant | `src/trust.ts`, `src/tools/describe-engine.ts` | the 18 trust-fragment tools (18) |
| `DEFAULT_PKI_LIMITS` | constant | `src/asn1-spec.ts`, `src/limits.ts`, `src/tools/describe-engine.ts` | all 34 tools (34) |
| `KEY_PURPOSES` | constant | `src/trust.ts`, `src/tools/check-ocsp-status.ts`, `src/tools/describe-engine.ts` | the 18 trust-fragment tools (18) |
| `KEY_USAGE_BITS` | constant | `src/x509-spec.ts`, `src/tools/describe-engine.ts` | `create_certificate`, `create_csr`, `describe_engine`, `encode_x509_structure` (4) |
| `OCSP_NONCE_OID` | constant | `src/tools/describe-engine.ts`, `src/tools/inspect-ocsp-response.ts` | `check_ocsp_status`, `describe_engine`, `inspect_ocsp_response` (3) |
| `OID_REGISTRY` | constant | `src/names.ts`, `src/tools/describe-engine.ts`, `src/tools/resolve-oid.ts` | `amend_cms`, `build_certificate_path`, `check_certificate_name`, `check_certificate_purpose`, `check_ocsp_status`, `create_certificate`, `create_csr`, `create_ocsp_request`, `describe_engine`, `encode_x509_structure`, `resolve_oid`, `sign_cms`, `validate_certificate_path`, `verify_certificate_chain`, `verify_cms`, `verify_timestamp` (16) |
| `PkiCertificateError` | class | `src/pki-errors.ts` | all 34 tools (34) |
| `PkiCmsError` | class | `src/pki-errors.ts` | all 34 tools (34) |
| `PkiCryptoError` | class | `src/pki-errors.ts` | all 34 tools (34) |
| `PkiEncodingError` | class | `src/pki-errors.ts` | all 34 tools (34) |
| `PkiError` | class | `src/pki-errors.ts` | all 34 tools (34) |
| `PkiKeyError` | class | `src/pki-errors.ts` | all 34 tools (34) |
| `PkiLimitError` | class | `src/pki-errors.ts` | all 34 tools (34) |
| `addTimeStampToken` | function | `src/tools/amend-cms.ts` | `amend_cms` (1) |
| `addUnsignedAttribute` | function | `src/tools/amend-cms.ts` | `amend_cms` (1) |
| `buildCertificatePath` | function | `src/tools/build-certificate-path.ts` | `build_certificate_path`, `validate_certificate_path` (2) |
| `canDecrypt` | function | `src/engine.ts` | `describe_engine` (1) |
| `canSign` | function | `src/engine.ts` | `describe_engine` (1) |
| `canVerify` | function | `src/engine.ts` | `describe_engine` (1) |
| `checkExtendedKeyUsage` | function | `src/tools/check-certificate-purpose.ts`, `src/tools/check-ocsp-status.ts` | `check_certificate_purpose`, `check_ocsp_status` (2) |
| `checkOcspStatus` | function | `src/tools/check-ocsp-status.ts` | `check_ocsp_status` (1) |
| `checkRevocation` | function | `src/tools/check-crl-revocation.ts` | `check_crl_revocation`, `check_ocsp_status` (2) |
| `checkServerName` | function | `src/tools/check-certificate-name.ts` | `check_certificate_name` (1) |
| `computeFingerprint` | function | `src/tools/compute-fingerprint.ts`, `src/tools/create-timestamp-request.ts`, `src/tools/inspect-certificate.ts` | `compute_fingerprint`, `create_timestamp_request`, `inspect_certificate` (3) |
| `computeFingerprintAsync` | function | `src/tools/compute-fingerprint.ts` | `compute_fingerprint` (1) |
| `computeKeyIdentifier` | function | `src/x509-spec.ts`, `src/tools/compute-fingerprint.ts`, `src/tools/create-certificate.ts`, `src/tools/encode-x509-structure.ts` | `compute_fingerprint`, `create_certificate`, `create_csr`, `encode_x509_structure` (4) |
| `createCertificate` | function | `src/tools/create-certificate.ts` | `create_certificate` (1) |
| `createCertificationRequest` | function | `src/tools/create-csr.ts` | `create_csr` (1) |
| `createOcspRequest` | function | `src/tools/create-ocsp-request.ts` | `check_ocsp_status`, `create_ocsp_request` (2) |
| `createSignedData` | function | `src/tools/sign-cms.ts` | `amend_cms`, `sign_cms` (2) |
| `createTimeStampRequest` | function | `src/tools/create-timestamp-request.ts` | `create_timestamp_request` (1) |
| `decodeAsn1` | function | `src/asn1-spec.ts`, `src/spki.ts`, `src/tools/check-ocsp-status.ts`, `src/tools/decode-asn1.ts`, `src/tools/encode-asn1.ts`, `src/tools/resolve-oid.ts` | the 25 ASN.1-reading tools (25) |
| `decodeAsn1Sequence` | function | `src/tools/decode-asn1.ts` | `decode_asn1`, `encode_asn1` (2) |
| `decodeExtensionValue` | function | `src/tools/decode-extension.ts` | `decode_extension` (1) |
| `decodeOid` | function | `src/tools/resolve-oid.ts` | `resolve_oid` (1) |
| `decodePem` | function | `src/pki-input.ts` | the 29 PKI-input tools (29) |
| `decryptPrivateKey` | function | `src/signer.ts` | the 21 signer tools (21) |
| `encodeAlgorithmIdentifier` | function | `src/tools/encode-x509-structure.ts` | `encode_x509_structure` (1) |
| `encodeAsn1Node` | function | `src/tools/decode-asn1.ts` | `decode_asn1`, `encode_asn1` (2) |
| `encodeAttribute` | function | `src/tools/encode-x509-structure.ts` | `encode_x509_structure` (1) |
| `encodeAuthorityKeyIdentifier` | function | `src/x509-spec.ts`, `src/tools/encode-x509-structure.ts` | `create_certificate`, `create_csr`, `encode_x509_structure` (3) |
| `encodeBasicConstraints` | function | `src/x509-spec.ts`, `src/tools/encode-x509-structure.ts` | `create_certificate`, `create_csr`, `encode_x509_structure` (3) |
| `encodeBitString` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeBoolean` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeDistinguishedName` | function | `src/x509-spec.ts`, `src/tools/encode-x509-structure.ts` | `create_certificate`, `create_csr`, `encode_x509_structure` (3) |
| `encodeEnumerated` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeExplicit` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeExtendedKeyUsage` | function | `src/x509-spec.ts`, `src/tools/encode-x509-structure.ts` | `create_certificate`, `create_csr`, `encode_x509_structure` (3) |
| `encodeExtension` | function | `src/tools/encode-x509-structure.ts` | `encode_x509_structure` (1) |
| `encodeExtensions` | function | `src/tools/encode-x509-structure.ts` | `encode_x509_structure` (1) |
| `encodeImplicit` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeInteger` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeKeyUsage` | function | `src/x509-spec.ts`, `src/tools/encode-x509-structure.ts` | `create_certificate`, `create_csr`, `encode_x509_structure` (3) |
| `encodeNameAttribute` | function | `src/tools/encode-x509-structure.ts` | `encode_x509_structure` (1) |
| `encodeNamedBits` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeNull` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeObjectIdentifier` | function | `src/asn1-spec.ts`, `src/tools/resolve-oid.ts` | `encode_asn1`, `resolve_oid` (2) |
| `encodeOcspCertId` | function | `src/tools/check-ocsp-status.ts`, `src/tools/create-ocsp-request.ts` | `check_ocsp_status`, `create_ocsp_request` (2) |
| `encodeOctetString` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeOid` | function | `src/tools/resolve-oid.ts` | `resolve_oid` (1) |
| `encodePem` | function | `src/output.ts`, `src/tools/open-pkcs12.ts` | all 34 tools (34) |
| `encodeRelativeOid` | function | `src/asn1-spec.ts`, `src/tools/resolve-oid.ts` | `encode_asn1`, `resolve_oid` (2) |
| `encodeSequence` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeSet` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeSetOf` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeSignatureAlgorithm` | function | `src/tools/encode-x509-structure.ts` | `encode_x509_structure` (1) |
| `encodeString` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeSubjectAltName` | function | `src/x509-spec.ts`, `src/tools/encode-x509-structure.ts` | `create_certificate`, `create_csr`, `encode_x509_structure` (3) |
| `encodeSubjectKeyIdentifier` | function | `src/x509-spec.ts`, `src/tools/encode-x509-structure.ts` | `create_certificate`, `create_csr`, `encode_x509_structure` (3) |
| `encodeSubjectPublicKeyInfo` | function | `src/tools/encode-x509-structure.ts` | `encode_x509_structure` (1) |
| `encodeTime` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeTlv` | function | `src/asn1-spec.ts` | `encode_asn1` (1) |
| `encodeValidity` | function | `src/tools/encode-x509-structure.ts` | `encode_x509_structure` (1) |
| `findRevocation` | function | `src/tools/inspect-crl.ts` | `check_crl_revocation`, `check_ocsp_status`, `inspect_crl` (3) |
| `formatDistinguishedName` | function | `src/key-views.ts`, `src/views.ts` | the 26 view tools (26) |
| `formatFingerprint` | function | `src/tools/compute-fingerprint.ts`, `src/tools/inspect-certificate.ts` | `compute_fingerprint`, `inspect_certificate` (2) |
| `getExtension` | function | `src/tools/create-certificate.ts`, `src/tools/encode-x509-structure.ts`, `src/tools/inspect-certificate.ts` | `create_certificate`, `encode_x509_structure`, `inspect_certificate` (3) |
| `getOidName` | function | `src/key-views.ts`, `src/views.ts`, `src/tools/check-certificate-purpose.ts`, `src/tools/decode-asn1.ts`, `src/tools/decode-extension.ts`, `src/tools/inspect-cms.ts`, `src/tools/inspect-private-key.ts`, `src/tools/inspect-timestamp.ts`, `src/tools/resolve-oid.ts` | the 26 view tools + `resolve_oid` (27) |
| `importPrivateKey` | function | `src/signer.ts` | the 21 signer tools (21) |
| `isValidOid` | function | `src/tools/resolve-oid.ts` | `resolve_oid` (1) |
| `matchDnsName` | function | `src/tools/check-certificate-name.ts` | `check_certificate_name` (1) |
| `openPkcs12` | function | `src/signer.ts`, `src/tools/open-pkcs12.ts` | the 21 signer tools + `open_pkcs12` (22) |
| `openSafeContents` | function | `src/tools/inspect-pkcs12.ts` | `inspect_pkcs12` (1) |
| `parseCertificate` | function | `src/key-views.ts`, `src/spki.ts`, `src/tools/build-certificate-path.ts`, `src/tools/check-certificate-name.ts`, `src/tools/check-certificate-purpose.ts`, `src/tools/check-crl-revocation.ts`, `src/tools/check-ocsp-status.ts`, `src/tools/create-certificate.ts`, `src/tools/create-ocsp-request.ts`, `src/tools/encode-x509-structure.ts`, `src/tools/inspect-certificate.ts`, `src/tools/inspect-cms.ts`, `src/tools/inspect-crl.ts`, `src/tools/inspect-ocsp-response.ts`, `src/tools/inspect-timestamp.ts`, `src/tools/sign-cms.ts`, `src/tools/verify-certificate-chain.ts` | the 25 certificate-parsing tools (25) |
| `parseCertificateList` | function | `src/tools/inspect-crl.ts`, `src/tools/sign-cms.ts` | `amend_cms`, `check_crl_revocation`, `check_ocsp_status`, `inspect_crl`, `sign_cms` (5) |
| `parseCertificationRequest` | function | `src/spki.ts`, `src/tools/create-csr.ts`, `src/tools/inspect-csr.ts` | the 22 SPKI tools (22) |
| `parseEncryptedPrivateKeyInfo` | function | `src/pki-input.ts`, `src/signer.ts`, `src/tools/inspect-private-key.ts` | the 29 PKI-input tools (29) |
| `parseOcspResponse` | function | `src/tools/check-ocsp-status.ts`, `src/tools/inspect-ocsp-response.ts` | `check_ocsp_status`, `inspect_ocsp_response` (2) |
| `parsePkcs12` | function | `src/pki-input.ts`, `src/tools/inspect-pkcs12.ts` | the 29 PKI-input tools (29) |
| `parsePrivateKeyInfo` | function | `src/pki-input.ts`, `src/signer.ts`, `src/tools/inspect-private-key.ts` | the 29 PKI-input tools (29) |
| `parseSignedData` | function | `src/tools/amend-cms.ts`, `src/tools/inspect-cms.ts`, `src/tools/sign-cms.ts`, `src/tools/verify-cms.ts` | `amend_cms`, `inspect_cms`, `inspect_timestamp`, `sign_cms`, `verify_cms` (5) |
| `parseTimeStampResponse` | function | `src/tools/amend-cms.ts`, `src/tools/inspect-timestamp.ts` | `amend_cms`, `inspect_timestamp` (2) |
| `parseTimeStampToken` | function | `src/tools/amend-cms.ts`, `src/tools/inspect-timestamp.ts` | `amend_cms`, `inspect_timestamp` (2) |
| `parseTstInfo` | function | `src/tools/inspect-timestamp.ts` | `inspect_timestamp` (1) |
| `readBitString` | function | `src/spki.ts`, `src/tools/decode-asn1.ts` | the 25 ASN.1-reading tools minus `resolve_oid` (24) |
| `readBoolean` | function | `src/tools/decode-asn1.ts` | `decode_asn1`, `encode_asn1` (2) |
| `readEnumerated` | function | `src/tools/decode-asn1.ts` | `decode_asn1`, `encode_asn1` (2) |
| `readInteger` | function | `src/tools/decode-asn1.ts` | `decode_asn1`, `encode_asn1` (2) |
| `readNull` | function | `src/tools/decode-asn1.ts` | `decode_asn1`, `encode_asn1` (2) |
| `readObjectIdentifier` | function | `src/spki.ts`, `src/tools/decode-asn1.ts`, `src/tools/resolve-oid.ts` | the 25 ASN.1-reading tools (25) |
| `readOctetString` | function | `src/tools/check-ocsp-status.ts`, `src/tools/decode-asn1.ts` | `check_ocsp_status`, `decode_asn1`, `encode_asn1` (3) |
| `readRelativeOid` | function | `src/tools/decode-asn1.ts`, `src/tools/resolve-oid.ts` | `decode_asn1`, `encode_asn1`, `resolve_oid` (3) |
| `readSmallInteger` | function | `src/tools/decode-asn1.ts` | `decode_asn1`, `encode_asn1` (2) |
| `readString` | function | `src/tools/decode-asn1.ts` | `decode_asn1`, `encode_asn1` (2) |
| `readTime` | function | `src/tools/decode-asn1.ts` | `decode_asn1`, `encode_asn1` (2) |
| `shake256` | function | `src/tools/compute-fingerprint.ts` | `compute_fingerprint` (1) |
| `validateCertificatePath` | function | `src/tools/validate-certificate-path.ts` | `validate_certificate_path` (1) |
| `verifyCertificateChain` | function | `src/tools/verify-certificate-chain.ts` | `amend_cms`, `build_certificate_path`, `check_certificate_name`, `check_certificate_purpose`, `check_ocsp_status`, `create_ocsp_request`, `sign_cms`, `validate_certificate_path`, `verify_certificate_chain`, `verify_cms`, `verify_timestamp` (11) |
| `verifyCertificateSignature` | function | `src/tools/check-ocsp-status.ts`, `src/tools/create-certificate.ts`, `src/tools/inspect-certificate.ts`, `src/tools/validate-certificate-path.ts` | `check_ocsp_status`, `create_certificate`, `inspect_certificate`, `validate_certificate_path` (4) |
| `verifyCertificationRequest` | function | `src/tools/create-csr.ts`, `src/tools/inspect-csr.ts` | `create_csr`, `inspect_csr` (2) |
| `verifyCrlSignature` | function | `src/tools/check-crl-revocation.ts`, `src/tools/inspect-crl.ts` | `check_crl_revocation`, `check_ocsp_status`, `inspect_crl` (3) |
| `verifyOcspSignature` | function | `src/tools/inspect-ocsp-response.ts` | `check_ocsp_status`, `inspect_ocsp_response` (2) |
| `verifyPkcs12Mac` | function | `src/tools/inspect-pkcs12.ts` | `inspect_pkcs12` (1) |
| `verifySelfSignature` | function | `src/tools/create-certificate.ts`, `src/tools/inspect-certificate.ts` | `create_certificate`, `inspect_certificate` (2) |
| `verifySignedData` | function | `src/tools/verify-cms.ts` | `verify_cms` (1) |
| `verifySignerInfoSignature` | function | `src/tools/inspect-cms.ts`, `src/tools/sign-cms.ts` | `amend_cms`, `inspect_cms`, `inspect_timestamp`, `sign_cms`, `verify_cms` (5) |
| `verifyTimeStampToken` | function | `src/tools/amend-cms.ts`, `src/tools/verify-timestamp.ts` | `amend_cms`, `verify_cms`, `verify_timestamp` (3) |

The CLI invocation that reaches each export (pkinative-cli 1.0.0, 18 command groups) is the `via` member of the same registry; `tests/coverage-matrix.test.ts` asserts every CLI group has a tool carrying its noun. Two CLI conveniences have no tool-level twin by design: the CLI's `--config` file (an MCP call carries every member of its arguments; the host passes them — the nine operator variables are the whole environment surface), and a PEM-wrapped OID from the CLI's OID command (`resolve_oid encode` answers hex per OID; the artefact form is `encode_asn1 { spec: { type: 'oid', value }, encoding: 'pem', label }`, while `decode_asn1 reencode`, `create_ocsp_request` and `create_timestamp_request` take `label` for theirs and `resolve_oid decode` reads `input` — pem / derBase64 / path — as well as `hex`).

---

## 9. Conformance architecture

OpenSSL 3 is the external judge of this server — the role veraPDF plays for pdfnative-mcp. `scripts/lib/pki-corpus.ts` is one table of **23 conformant entries and 5 refused canaries** (`docs/data/interop.json` declares the counts and the 12 OpenSSL command families; `tests/tools/pki-corpus.test.ts` holds the two together); `npm run corpus:pki` writes every artefact through the **built** server (`dist/server.js`, `callToolDirect`) under the pinned instant into `test-output/pki/` with a manifest; `npm run validate:pki` runs level 0 (every artefact fed back to its read / verify tool in-process, an independent `node:crypto` reckoning of the OCSP CertID and the TSP imprint / nonce, a deterministic entry hashed twice) and level 1 (OpenSSL 3.x on PATH; LibreSSL and OpenSSL < 3.0 refused; `PKINATIVE_INTEROP_REQUIRED=1` fails instead of skipping; an XPASS canary is fatal). The read direction — OpenSSL wrote the 42 fixtures, the tools read and verify them — is `tests/interop/openssl.test.ts`; the certificate linters zlint and pkilint judge the corpus certificates in `tests/interop/lint.test.ts` (publish profile). Blocking in CI on `interop (ubuntu-24.04)` and `interop (windows-latest)`. The full story: [`guides/CONFORMANCE.md`](guides/CONFORMANCE.md).

---

## 10. Development quick reference

```bash
npm ci --ignore-scripts        # what CI runs
npm run build                  # tsc -p tsconfig.build.json → dist/
npm run gate:fast              # typecheck:all, lint, test, code-tables, server-json, verify:docs — the loop while you work
npm run gate                   # the CI profile: + build, dist-check, dist-probe, smoke, verify:tool-shape, test:generate, test:coverage, verify:samples, corpus:pki, validate:pki, interop
npx tsx scripts/gate.ts --publish --require-all   # + lint:certs; a SKIP fails — what publish.yml runs
npm run test:watch · npx vitest run tests/<name>.test.ts · npm run examples:check · npm run test:interop
```

| Loop | Commands |
|---|---|
| The gate (`scripts/gate.ts`) | one line per step, logs under `test-output/.gate/<step>.log`; `--only <step>`, `--from <step>`, `--json`; hermetic (TZ pinned, every inherited `PKINATIVE_MCP_*` scrubbed) |
| Catalogue fingerprint | `npm run build && npx tsx scripts/tool-shape.ts --write` after a deliberate schema change; `npm run verify:tool-shape` checks it and the 448 KiB / 8 KiB budgets |
| Sample baseline | `npm run build && npm run test:generate && npm run verify:samples` (`--strict` fails on an unbaselined sample; `--update` only with a declared rebaseline) |
| Conformance corpus | `npm run build && npm run corpus:pki && npm run validate:pki` (`OPENSSL_BIN` overrides the binary; `PKINATIVE_INTEROP_REQUIRED=1` fails closed) |
| Engine-surface matrix, fuzz, autonomy | `npx vitest run tests/coverage-matrix.test.ts tests/pki-fuzz.test.ts tests/autonomy.test.ts` |
| Docs as code | `npm run verify:docs` (every count, version, tool, code, variable, link and anchor against `docs/assets/ecosystem.json` and the tree); `npm run agents:rules` regenerates `.claude/rules/` from `.github/instructions/` |
| Governance | `npm run verify:issue -- .github/drafts/<draft>.md`; `npm run hooks:install` sets `core.hooksPath` to `.githooks/` (lint on commit, the fast gate on push) |
| Release | `npm run release:prepare -- --version X.Y.Z` bumps the manifests and scaffolds the notes; the maintainer pushes, tags and publishes (`publish.yml`: Trusted Publishing, SBOM, attestation) |

**Adding a tool:** `src/tools/<kebab>.ts` exporting `<NAME>_NAME`, `<NAME>_INPUT_SCHEMA` (JSON Schema `as const`), the Zod `z.strictObject` twin, `<NAME>_OUTPUT_SCHEMA`, `<NAME>_SUMMARY_PROPERTIES` for a read tool, the handler through `parseInput` / `createParseContext` / `guard`, and `<NAME>_TOOL = defineTool({ kind, annotations, cacheable, instantInputs, examples, text, summary })`; register it in the right `_group-*.ts`; add `tests/<kebab>.test.ts`, an `examples/<kebab>.json`, a corpus entry for any new write-side option; refresh the fingerprint; update `SERVER_INSTRUCTIONS`, the README, `llms.txt`, `AGENTS.md` and the contract's §1 / §2 / §3 — `verify:docs` holds the counts.

---

## 11. Security design notes

- **Trust boundaries:** the host process and the operator are trusted; the model and every input byte are not; the filesystem outside the sandbox and the network do not exist for this server. The threat model and the defence table are [`guides/SECURITY.md`](guides/SECURITY.md); the reporting policy and release integrity, [`SECURITY.md`](../SECURITY.md) at the root.
- **Keys never cross:** the engine imports keys non-extractable; `src/key-views.ts` builds every key / PKCS#12 report from an allow-list; `convert_pem`, `decode_asn1`, `encode_asn1` and `resources/read` refuse private-key material; nothing writes a key-bearing file; `assertResultClean` guards every result.
- **Bounds everywhere:** `src/caps.ts` (the JSON-RPC envelope), the 22 engine limits (what a DER structure may declare) under three ceilings an argument cannot exceed, `pool: 'forks'` tests for the ceilings, `src/http.ts` for the body.
- **No silent fallback:** an invalid operator value, a weak token, a legacy cipher, a missing password, a BER construct under DER rules — every one is a coded refusal with a remedy, never a guess.
- **Supply chain:** three runtime dependencies, SHA-pinned actions, harden-runner, CodeQL, OpenSSF Scorecard, dependency review, `npm audit`, OIDC Trusted Publishing with provenance, a CycloneDX SBOM and a build attestation; the gate's `dist-probe` step proves `dist/` holds no `console.log` and no byte of a test key.
