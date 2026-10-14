# API Stability — pkinative-mcp

> Stability charter for the **tool API** (tool names, input/output schemas, error codes, runtime semantics, the bytes of the artefacts).
> The server binary itself follows standard SemVer for npm releases.

---

## 1. Versioning

Every tool emits `_meta.apiVersion` in the `tools/list` response.

Current value: **`1.0.0`** (stable, since pkinative-mcp 1.0.0; `TOOL_API_VERSION` in `src/version.ts`).

The tool API version is **independent of the npm release version**.
Server releases that ship only documentation, refactoring, or non-breaking ergonomic improvements (richer descriptions, additional `_meta.examples`, new optional output fields) **do not** bump `_meta.apiVersion`.

A bump of `_meta.apiVersion` happens **only** in the cases listed in §3 — and whenever a cached response would become unsafe to serve: the response-cache key is namespaced by `TOOL_API_VERSION`, the package version and the engine version, so a bump invalidates every entry.

> **MCP protocol alignment.** The tool API version above is orthogonal to the MCP
> wire-protocol revision. The server runs on the MCP TypeScript SDK v2
> (`@modelcontextprotocol/server` ^2.0.0) and speaks **MCP 2026-07-28** — stateless
> serving, `server/discover`, `resultType`, `ttlMs` / `cacheScope` cache hints, the `_meta`
> `serverInfo` envelope, `Mcp-Method` / `Mcp-Name` headers over HTTP — with automatic
> fallback to the legacy `initialize` handshake for `2025-11-25`, `2025-06-18`,
> `2025-03-26`, `2024-11-05` and `2024-10-07` clients on both stdio and HTTP
> (`tests/protocol-revisions.test.ts`, `tests/stdio-modern.test.ts`, `tests/http-modern.test.ts`).
> The `tools/call` payload (`content`, `structuredContent`, `isError`) is identical on both
> paths. Tool schemas are JSON Schema **2020-12**, `serverInfo` advertises `title` +
> `description` + `websiteUrl`, and input-validation failures are returned as
> tool-execution errors (`isError: true`) — none of which affect `_meta.apiVersion`.
>
> **Protocol-level error codes, outside the §2 matrix:** `resources/read` on an unknown URI
> answers the JSON-RPC error code **`-32602`** (Invalid params), which the 2026-07-28
> specification mandates for resource-not-found on every protocol revision (the
> `UNKNOWN_RESOURCE` code is carried in the message); `tools/call` naming a tool that does
> not exist is a JSON-RPC **`-32602`** protocol error with the message
> `[UNKNOWN_TOOL] Unknown tool: <name>`, because the specification classifies unknown tools
> as protocol errors and reserves `isError` for execution failures (the in-process
> `callToolDirect` helper keeps returning `isError`). `UNKNOWN_TOOL` is a message marker,
> never a `ToolError` code.
>
> **Output-schema conformance:** `structuredContent` always validates against the tool's
> `outputSchema` — a 2026-07-28 MUST — including `verbosity: 'summary'` and `fields`
> projections and file mode. To make that true the read and verdict tools declare
> **projectable** output schemas (`projectableOutputSchema` in `src/tools/_definition.ts`):
> every property optional, no `required`, `additionalProperties: false` kept, and the
> summary-only scalars (`reasonCodes`, `diagnosticCount`, `serialNumberHex`, `extensionKinds`,
> `signatureValid`, `structuralReasonCodes`, `failingReasonCodes`, `signatureVerdicts`, …)
> declared. Default (`'full'`) output is unchanged; only the schema metadata is relaxed
> (`tests/schema-conformance.test.ts`, SDK Ajv 2020-12 validator, every `_meta.examples[].input`
> validated against its `inputSchema` too).
>
> **Transport facts that are SDK behaviour:** on **stdio**, a request sent before
> `initialize` is dropped without a reply (the specification requires the client to
> initialise first), and JSON-RPC **batch arrays** (2025-03-26) are not accepted on stdio —
> they are accepted over HTTP. Input schemas declare **no `$schema` keyword** by policy:
> MCP ≥ 2025-11-25 defaults to JSON Schema 2020-12, and some hosts forward `inputSchema`
> verbatim to LLM function-calling APIs that reject unknown keywords. Likewise there is no
> `$ref` / `$defs` (`tests/schema-lockstep.test.ts`), which is why every shared fragment —
> the PKI input, the signer, the trust fragment, the parse fragment with its 22 named
> limits, the projection inputs, the diagnostics report — is repeated inline, and
> `tools/list` weighs **427,106 bytes**, under a **448 KiB budget** enforced by
> `scripts/tool-shape.ts --check` (gate step `verify:tool-shape`, §5).

---

## 2. What is covered

| Surface | Scope |
|---------|-------|
| Tool **name** | Stable. Renaming a tool is a major bump. |
| Required **input fields** | Stable. Removing or renaming is a major bump. |
| Required **output fields** | Stable. Removing or renaming is a major bump. |
| Field **types** (string/number/bool/enum) | Stable. Narrowing accepted values is a major bump. |
| **Wrapper error codes** (the 21 `code` values of `src/wrapper-codes.ts`) | Stable. Removing or renaming is a major bump. |
| **Engine codes** (57 `PKI_*` errors, 43 `PKI_REASON_*` reasons, 97 `PKI_DIAG_*` diagnostics) | Passed through verbatim from pkinative's frozen vocabulary (`src/data/pkinative/*.json`, vendored from the v1.0.0 tag; removal or renaming is semver-major upstream, addition semver-minor). The class table of `src/pki-errors.ts` is typed `satisfies Record<PkiErrorCode, …>`: an engine minor that adds a code fails `tsc` here instead of leaking as `ENGINE_ERROR`. |
| `data.errorClass` (the 10 classes) and `data.remedy` | Stable classes; the remedy wording is not covered. |
| **Artefact bytes** for deterministic inputs | Stable (§5, the determinism promise). Changing them is a major bump. |
| `_meta.examples` | **Not** covered. May change at any time (at most two per tool; every one is executable against its `inputSchema`). |
| `description` strings, `serverInfo.instructions`, prompt texts | **Not** covered. May be reworded at any time — the `tools/list` *wording* is outside the structural charter; tool-result `structuredContent` defaults are inside it. |
| `tools/list` **structure** (types, enums, bounds, defaults, `required`, `additionalProperties`, annotations, example count) | Covered, and enforced by two gates. *Drift:* `scripts/lib/tool-shape.ts` fingerprints the catalogue with every description string stripped; `tests/catalogue-parity.test.ts` and the gate step `npm run verify:tool-shape` compare it with `tests/_fixtures/tool-shape.json` — any structural change is a deliberate `npm run build && npx tsx scripts/tool-shape.ts --write` refresh reviewed under §3 / §5. *Compatibility:* the frozen **published 1.0.0** catalogue, `tests/_fixtures/tool-shape.v1.0.0.json`, is created at the release commit and never regenerated; the live catalogue must stay a superset of it — no tool, input property, enum value or default removed, no `required` added, no `additionalProperties` tightened, no numeric / length bound made stricter (`.github/AGENT_RULES.md`, "What agents must NOT do"). |
| Schema **`default`** values | Documented; changes are minor unless they alter produced bytes silently. |
| Unknown input keys | Rejected with `VALIDATION_ERROR` at every nesting level (Zod `z.strictObject`), exactly as the published `additionalProperties: false` declares. |
| Annotations (`readOnlyHint`, `idempotentHint`, `destructiveHint`, `openWorldHint`) | Hints, part of the fingerprint but not of the §3 matrix; `openWorldHint` is always `false` (no network code path exists). |

---

## 3. Bump rules

### Patch (`1.0.x`)
- New optional output fields added to existing tools (additive only).
- Looser input validation (e.g. accept a previously rejected payload).
- Internal hardening or cache changes that do not alter response shape.
- Documentation, examples, and description refreshes.
- A new `PKI_DIAG_*` diagnostic reported by an engine patch (diagnostics are additions-only upstream and never errors here).

### Minor (`1.x.0`)
- New tool added.
- New optional input field with a backward-compatible default.
- New value added to an existing enum (when older clients can safely ignore it).
- A new wrapper code, or a new `PKI_*` / `PKI_REASON_*` code inherited from an engine minor (additive; the contract's §6 gains a row).

### Major (`x.0.0`)
- Tool removed or renamed.
- Required field added or removed.
- Field type narrowed or semantics changed.
- Wrapper code removed, renamed, or repurposed; an engine code removed upstream.
- Default value change that alters produced byte output for the same input.
- **The bytes `create_certificate`, `create_csr`, `sign_cms`, `amend_cms`, `create_ocsp_request`, `create_timestamp_request`, `encode_asn1` or `encode_x509_structure` write for deterministic inputs changing** — a fixture key, a pinned instant, an explicit serial / nonce (`.github/AGENT_RULES.md` rule 5; the sample baseline of §5 is the evidence).
- A security default weakened (a cap or ceiling raised by default, SHA-1 accepted, a legacy PKCS#12 scheme opened) — never without an explicit human decision, and never silently.

---

## 4. Deprecation policy

When a tool, field or error code is scheduled for removal:

1. Mark it deprecated in `description` and in this document.
2. Keep it functional for **at least one minor release** before removal.
3. Provide a migration note in the next `release-notes/vX.Y.Z.md`.
4. Drop only on the next major bump.

---

## 5. Per-tool stability matrix

All 34 tools shipped through pkinative-mcp 1.0.0 are at `_meta.apiVersion = '1.0.0'` and are considered **stable**:

`convert_pem`, `resolve_oid`, `compute_fingerprint`, `decode_asn1`, `encode_asn1`,
`inspect_certificate`, `create_certificate`, `encode_x509_structure`, `decode_extension`,
`check_certificate_name`, `check_certificate_purpose`, `inspect_csr`, `create_csr`,
`verify_certificate_chain`, `build_certificate_path`, `validate_certificate_path`,
`inspect_crl`, `check_crl_revocation`, `create_ocsp_request`, `inspect_ocsp_response`,
`check_ocsp_status`, `sign_cms`, `verify_cms`, `inspect_cms`, `amend_cms`,
`create_timestamp_request`, `inspect_timestamp`, `verify_timestamp`,
`inspect_private_key`, `inspect_pkcs12`, `open_pkcs12`, `describe_engine`, `explain_code`,
`draft_governance_issue`.

> **v1.0.0 rationale:** the first release, on pkinative 1.0.0 (the engine's first frozen
> API: 294 exports, 117 runtime, 177 type-only). Every one of the 117 runtime exports is
> reached by a named tool (`tests/coverage-matrix.test.ts`); the engine surface deliberately
> not exposed as a tool input — `ExternalSigner.produceSignature` (executable code cannot
> cross JSON-RPC), `PkiParseOptions.onDiagnostic` (always installed), `password: Uint8Array`
> (JSON carries UTF-8 only), the raw `der` / `tbsDer` / `valueDer` echoes, the 177 types — is
> enumerated with its rationale by `describe_engine.unexposed`. The catalogue mirrors the 18
> command groups of pkinative-cli 1.0.0 (`docs/data/core-exports.json` `via`), so an agent
> that knows one surface reads the other.
>
> **Catalogue budget (448 KiB).** `tools/list` measures 427,106 bytes and
> `serverInfo.instructions` 5,469 bytes; `scripts/tool-shape.ts --check` fails above
> 448 KiB / 8 KiB and when `declared.toolsListBytes` of `docs/assets/ecosystem.json` drifts
> more than 2 % from the measurement. The budget is 448 KiB for 34 tools where
> pdfnative-mcp budgets 320 KiB for its catalogue, because the shared fragments ride on many
> tools and are never `$ref`-ed: the parse fragment with its 22 named limits on 31 tools,
> the PKI input on 70 properties, the signer on 4, the trust fragment on 9, the projection
> inputs on 25, the diagnostics report on every result. Their descriptions are kept terse on
> purpose — the long form lives in `describe_engine`, `serverInfo.instructions`, the
> prompts and [AGENT_CONTRACT.md](AGENT_CONTRACT.md). Raising the budget is a deliberate
> change reviewed here, never a side effect.
>
> **The determinism promise.** With `PKINATIVE_MCP_AT` or a per-call instant pinned, an
> explicit `serialNumber` / `nonce` and a deterministic signer, an artefact is a pure
> function of its inputs: the same `sha256` on every host and every run. What that covers,
> per signature family:
>
> | Producer | Deterministic when | Why not otherwise |
> | --- | --- | --- |
> | `create_certificate`, `create_csr` | Ed25519 or RSA PKCS#1 v1.5 signer, `serialNumber` explicit, `notBefore` pinned | ECDSA and RSA-PSS draw a fresh random per signature (Web Crypto does not implement RFC 6979); `serialNumber: 'random'` is 127 bits from `node:crypto` |
> | `sign_cms` | Ed25519 or RSA PKCS#1 v1.5 signer, `signingTime` pinned or `'none'` | ECDSA / RSA-PSS randomised; a wall-clock `signingTime` |
> | `amend_cms` | always (the input bytes and the attribute / token are the inputs) | — |
> | `create_ocsp_request`, `create_timestamp_request` | `nonce` explicit (or omitted) | `nonce: 'random'` (16 bytes / 63 bits from `node:crypto`) |
> | `encode_asn1`, `encode_x509_structure`, `convert_pem`, `decode_asn1 reencode` | always | — |
>
> The evidence is the sample baseline: `npm run test:generate` drives the built server under
> `TZ=UTC` with every operator variable scrubbed, then `PKINATIVE_MCP_AT=2027-01-01T00:00:00Z`
> and a temporary sandbox holding the 42 OpenSSL fixtures, and `npm run verify:samples` holds
> the **98 samples** to `tests/_fixtures/samples.sha256.json` in the mode the generator
> recorded per sample (`scripts/lib/sample-fingerprint.ts`): **10 in `bytes` mode** (SHA-256 of
> the file — Ed25519 / RSA PKCS#1 artefacts, requests, encodings, PEM re-encodings), **3 in
> `tbs` mode** (SHA-256 of the first element of the outer SEQUENCE — the TBSCertificate /
> CertificationRequestInfo of an ECDSA or RSA-PSS artefact, whose signature value cannot
> repeat but whose signed part is a pure function of the inputs) and **85 in `semantic` mode**
> (SHA-256 of the canonical JSON of `structuredContent` without the volatile members
> `evaluatedAt`, `sha256`, `sizeBytes`, `filePath` — every read / verdict result, and a
> randomised CMS whose SignerInfo cannot be cut out by position). The baseline is a chain:
> each entry records the release whose output it is (`since`), an unchanged entry keeps it,
> and `--update` is used only with a rebaseline declared in the release note. The OpenSSL
> corpus adds the second proof: 13 of its 23 conformant entries claim `deterministic: true`
> and are produced twice by `npm run corpus:pki`; `npm run validate:pki` holds the two
> digests equal.
>
> **Engine lock-step.** The package pins `pkinative ^1.0.0`. An engine patch or minor is
> accepted by `npm ci` only when it keeps the frozen vocabularies (`scripts/build-code-tables.mjs --check`,
> gate step `code-tables`, regenerates `src/data/pkinative/code-tables.ts` from the vendored
> registries; `docs/data/*.json` are byte-identical mirrors, held by the `engine-data-parity`
> rule of `npm run verify:docs` and `tests/coverage-matrix.test.ts`); a code the engine adds
> fails the type check until the class table, the contract's §6 and `explain_code` follow.
> An engine change to the bytes of a deterministic artefact is a rebaseline declared in the
> release note and, per §3, a major bump of this server.

---

## 6. Reporting a breaking change

If you believe a change in a release silently broke a stable contract, please open an issue with:
- the affected tool name,
- the input that worked previously,
- the new response or error,
- the previous release version where it worked.

We treat unintended breaking changes as bugs and fix them in a patch release. A changed
`sha256` of a deterministic artefact is a breaking change even when every reader still
accepts the bytes.
