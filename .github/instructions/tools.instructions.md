---
description: "Use when adding or changing a tool handler, its input/output schema, the shared PKI input / content / parse / limits / signer / trust / projection / output fragments, the wire views or the engine error mapping."
applyTo: "src/tools/**"
---
# Tool Standards

## Thin, faithful wrapper
- No PKI logic in `src/`: every byte-level operation (ASN.1 / DER / PEM decoding, X.509 / CRL / OCSP / CMS / TSP / PKCS#8 / PKCS#12 parsing, path building and validation, signature verification, signing) is an engine call. A tool maps inputs to engine options, wraps EVERY engine call in `guard` / `guardAsync` (`src/pki-errors.ts`), and shapes the result through the views.
- Expose the engine's options by their engine names where the CLI does too (`pkinative-cli` field names), so an agent that knows one surface reads the other.
- The engine's `PKI_*` codes pass through verbatim with the engine's message (which names the remedy) and `data`. Wrapper codes (`src/wrapper-codes.ts`) are the server boundary only — validation, sandbox, caps, secrets, output; a new one needs a doc row in `docs/AGENT_CONTRACT.md` §6, a `PKI_REMEDY`-style remedy and a test.
- Diagnostics are not errors: every engine call takes the sink's options (`createParseContext(...).options`), every result spreads the report (`withDiagnostics`: `diagnostics`, `diagnosticCounts`, `diagnosticsTruncated`, ≤ 200). `strict: true` escalates the first warning (`PKI_STRICT_DIAGNOSTIC`); an `info` never refuses.

## Shape of a tool module
```
export const X_NAME = 'x';
export const X_INPUT_SCHEMA = { type: 'object', additionalProperties: false, properties: {…} } as const;
const InputSchema = z.strictObject({…}).superRefine(…);      // mirrors the JSON Schema exactly
export interface XResult extends DiagnosticsReport { … }
export const X_OUTPUT_SCHEMA = { … } as const;                 // read tools: + X_SUMMARY_PROPERTIES / xSummary()
export async function xTool(rawInput: unknown): Promise<XResult> { const input = parseInput(InputSchema, rawInput); … }
```
- Register with `defineTool` in the right `src/tools/_group-*.ts` (certificates, paths, cms, keys, encodings), with `kind`, `title`, `description`, annotations (`READ_ONLY` / `WRITES` / `PRODUCES`), ≤ 2 `_meta.examples`; update `SERVER_INSTRUCTIONS`, AGENTS.md, README.md, `docs/AGENT_CONTRACT.md`, llms.txt, `tests/_fixtures/tool-shape.json`, and add `tests/<tool>.test.ts` + an `examples/<kebab>.json`.

## The shared fragments (import, never redeclare)
- `PKI_INPUT` — `src/pki-input.ts`: exactly one of `pem` (RFC 7468) / `derBase64` (DER as base64, exactly once) / `path` (a relative sandbox path); `PkiInputSchema` / `pkiInputSchema(kind)` and `PkiBundleSchema` / `pkiBundleSchema` for bundles (≤ 256 items). `path` needs `PKINATIVE_MCP_OUTPUT_DIR`; a key-bearing extension is accepted by the key tools only.
- `CONTENT_INPUT` — `src/content-input.ts`: exactly one of `text` (UTF-8) / `base64` / `path` for the signed or time-stamped content (`ContentInputSchema`, 128 MiB inline / 1 GiB path).
- `HEX` — `HexSchema` / `hexSchema(maxBytes)` (`HEX_PATTERN`, even length, ≤ 64 KiB inline); serials, nonces, raw values.
- `PARSE` — `src/parse-context.ts`: `PARSE_INPUT_PROPERTIES` / `ParseShape` (`encodingRules`, `pemMode`, `strict`, `limits`) → `createParseContext(input)` gives the engine options, the sink and the effective limits; build it once per call.
- `LIMITS` — `src/limits.ts`: `LIMITS_INPUT_SCHEMA` / `LimitsSchema`, the 22 `PkiLimits` by name; `resolveCallLimits` applies the operator ceilings (`LIMIT_CEILING_EXCEEDED` names the variable). Never add a ceiling a tool argument can raise.
- `SIGNER` — `src/signer.ts`: `SIGNER_INPUT_SCHEMA` / `SignerSchema`: a PKCS#8 key (plain or PBES2-encrypted) or a PKCS#12 entry, the password through `password` XOR `PKINATIVE_MCP_PASSWORD`, an explicit RSA scheme, SHA-1 opt-in; the result carries `SIGNING_KEY_VIEW_SCHEMA` (algorithm, key id, subject), never a key byte.
- `TRUST` — `src/trust.ts`: `TRUST_INPUT_PROPERTIES` / `TrustShape` / `TspTrustShape`: trust anchors, intermediates, revocation evidence (CRLs, OCSP responses) as inputs; nothing is fetched.
- `PROJECTION` — `PROJECTION_INPUT_PROPERTIES` / `ProjectionShape` (`verbosity`, `fields`); `OUTPUT` — `outputShape` / `resolveOutputFile` (`outputMode` base64 | file (draft_governance_issue alone: inline | file), `outputPath` in the sandbox, never a key-bearing extension); the instant inputs through `instantSchema` / `resolveInstant` (`src/time.ts`, pinned by `PKINATIVE_MCP_AT`).
- Every cap is a constant in `src/caps.ts`, quoted in the description and advertised by `describe_engine.caps` through the `CAPS` record (tests/describe-engine.test.ts asserts every numeric export appears there).

## Views and results
- Results are built from `src/views.ts` (`certificateView`, `csrView`, `nameView`, `spkiView`, `extensionView`, `timeView`, `algorithmView`, `reasonsView`) and `src/key-views.ts` (allow-list key / PKCS#12 views); the wire form (`src/wire.ts`: bigint → decimal string, bytes → hex or base64, times → `{ epochMilliseconds, iso }`) is the only JSON shape. Never echo the input DER, a `tbsDer`, a `valueDer` or a key byte (`stripRaw`; raw extension values only on an explicit `includeRaw`).
- Verdict tools (`verify_*`, `check_*`, `validate_certificate_path`) return `{ valid, reasons[] }` with `reasonsView` rows (code, message, standard, path, errorCode?, limit? — the remedy lives in `explain_code`) — a negative verdict is NEVER `isError`; `isError` is for a malformed input, a refused algorithm or a wrapper failure. Every verdict depends on `at` (default: `PKINATIVE_MCP_AT`, else the wall clock → not cacheable).
- Artefact tools self-check after signing: the bytes the tool returns are parsed back and verified against the signer's public key before they leave (a signer / content / algorithm mismatch is a coded refusal, never a silent bad artefact). Randomness lives in the wrapper (`src/random.ts`): `serialNumber: 'random'` / `nonce: 'random'` are reported in the summary (`randomSerial`, `randomNonce`), and the baseline compares such samples in `tbs` mode.
- `key` / `p12` views: the password is resolved through `resolvePassword`, decryption failures are the engine's `PKI_CRYPTO_DECRYPTION_FAILED`, and a tool that does not open a key does not accept a `password` (its presence is `VALIDATION_ERROR`).

## Determinism and reproducibility
- Default output must stay byte-identical across releases for the same deterministic inputs; the bytes `create_certificate` / `create_csr` / `sign_cms` write with a fixture key, a pinned instant and an explicit serial changing is semver-major (.github/AGENT_RULES.md rule 5).
- Every artefact a tool writes must be accepted by OpenSSL 3: add a corpus entry (`scripts/generate-pki-corpus.ts`) for any new write-side option and run `npm run corpus:pki && npm run validate:pki`.

## Read tools
- Read-only tools never modify their input and are `READ_ONLY`-annotated; results are projectable (`verbosity`, `fields`) and paged where unbounded (`offset` / `limit`, `hasMore`, `MAX_LIST_LIMIT`).
- `explain_code` and `resolve_oid` are lookups over the vendored registries (`src/data/`); `describe_engine` is the capability manifest (caps, ceilings, refusals, `UNEXPOSED_EXPORTS`) and is never cached.
