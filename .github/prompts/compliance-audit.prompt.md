---
description: "Audit pkinative-mcp for security at the tools/call boundary, the agent contract, the OpenSSL conformance gate, the secrets policy and reproducible artefacts."
agent: "agent"
---
# Compliance Audit

Perform a compliance audit of pkinative-mcp. The server is the untrusted-input boundary
around the pkinative engine: every argument of every `tools/call` comes from a model, and
some of them are passwords and private keys. Every finding is reproduced with a command — a
test, a script, or a request sent to the built server (`node dist/cli.js`, after `npm run build`)
— and cited with `file:line`. Report findings with a severity (blocker / major / minor / note),
the reproduction command and the recommended fix; a finding without a reproducible command is
not a finding. Never paste a key body or a password into the report, even from a TEST-ONLY fixture.

## Audit Areas

### 1. Protocol contract (docs/AGENT_CONTRACT.md, docs/API_STABILITY.md)
- On stdio, stdout carries JSON-RPC frames only; every log goes to stderr (gate steps
  `smoke` and `dist-probe`, `tests/cli-stdio.test.ts`)
- Both protocol eras are served by the same binary: MCP 2026-07-28 (`server/discover`) and
  the 2025-era `initialize` handshake, on stdio and on Streamable HTTP
  (`tests/protocol-revisions.test.ts`, `tests/stdio-modern.test.ts`, `tests/http-modern.test.ts`)
- A tool failure is an `isError` result carrying one documented code (a wrapper code or the
  engine's `PKI_*` code verbatim); a negative verdict is `valid: false` + `reasons[]`, never
  `isError`; an unknown tool name is JSON-RPC `-32602` `[UNKNOWN_TOOL]`. Nothing throws and
  no failure is uncoded
- `structuredContent` validates against the advertised `outputSchema` on the default,
  `verbosity: 'summary'` and `fields` paths (`tests/projection.test.ts`, `tests/schema-lockstep.test.ts`)
- `tools/list` is a superset of the frozen `tests/_fixtures/tool-shape.v1.0.0.json`
  (`tests/catalogue-parity.test.ts`); default artefacts are byte-identical for the same
  deterministic inputs unless the release notes declare the change

### 2. Input boundary
- Every object schema is Zod `strictObject`, at every nesting level, and agrees with the JSON
  Schema advertised for it — send a value at the edge of each new input
- `pem` XOR `derBase64` XOR `path` (`src/pki-input.ts`); base64 through `src/base64.ts`;
  content through `src/content-input.ts`; hex through `HexSchema`
- Size bounds hold (`src/caps.ts`, advertised by `describe_engine.caps`): 128 MiB decoded
  inline input, 64 KiB hex, 256 bundle items, 50 MiB inline output, 1 GiB file output,
  256 MiB frame; the 22 limits are bounded by the three operator ceilings
  (`tests/limits.test.ts`, `LIMIT_CEILING_EXCEEDED`)
- No `__proto__` / `constructor` / `prototype` key of a nested spec (`src/x509-spec.ts`,
  `src/asn1-spec.ts`) reaches an object the server builds; `Object.prototype` is untouched
- Hostile bytes end in a coded `PKI_*` refusal, never an uncoded failure, a stack overflow or
  a hang; a hostile PBES2 key or PKCS#12 is bounded by the KDF ceiling

### 3. Secrets, keys and the sandbox
- No key byte, private scalar, JWK member, encrypted-key body, password,
  `PKINATIVE_MCP_PASSWORD` or `PKINATIVE_MCP_HTTP_TOKEN` in any result, error message,
  diagnostic, cache file, resource, stderr line or stdio transcript — run the needle
  suite (`tests/_secrets.ts`, `assertResultClean`) over every key and password-bearing result
- The key tools return allow-list views (`src/key-views.ts`); no tool generates or exports a
  key; no writer for PKCS#8 / PKCS#12 / CRL / OCSP responses / time-stamp responses exists
- A `password` is accepted ONLY by the tools that open a key or a PKCS#12 file; elsewhere it
  is `VALIDATION_ERROR`; `password` and `PKINATIVE_MCP_PASSWORD` together are `VALIDATION_ERROR`
- There is NO network code path: no `fetch`, `http`, `https`, `net`, `dns` import outside
  `src/http.ts` (loopback listener only); no tool argument supplies a URL; revocation
  evidence and time-stamp tokens are inputs
- `outputMode: 'file'` writes under `PKINATIVE_MCP_OUTPUT_DIR` only, exclusively (`wx`):
  absolute paths, traversal, NUL bytes, a symlinked parent or file, and any key-bearing
  extension are `SECURITY_VIOLATION`; `resources/*` never list or serve `.key .p8 .p12 .pfx`
- HTTP mode binds loopback, checks Host and Origin, and honours the opt-in bearer token
- The response cache never persists a path input, a file output, a call carrying a password
  or a signer, a `'random'` serial or nonce, a `'now'` or clock-dependent instant,
  `describe_engine` or `draft_governance_issue` (`tests/cache-policy.test.ts`)

### 4. Operator knobs
- Every `PKINATIVE_MCP_*` variable (nine) is read once at boot, declared in `server.json`,
  and an invalid value refuses to start (`tests/metadata.test.ts`, `tests/limits.test.ts`,
  `tests/parse-context.test.ts`); `PKINATIVE_MCP_AT` pins every omitted instant and a
  verdict under the wall clock is never cached

### 5. Exactly three runtime dependencies
- `package.json` `dependencies` is `pkinative`, `@modelcontextprotocol/server`, `zod`
  (`tests/tools/workflows.test.ts`); the server reimplements no PKI feature on raw primitives

### 6. Conformance gate (OpenSSL 3)
- The corpus (`scripts/generate-pki-corpus.ts`) validates under OpenSSL with the negative
  canaries rejected (`npm run validate:pki`); the interop suite reads what OpenSSL writes
  (`npm run test:interop`); `PKINATIVE_INTEROP_REQUIRED=1` fails instead of skipping
- OpenSSL version differences are stated, not hidden: 3.0 has no PBMAC1 (ubuntu-22.04),
  3.4+ does, LibreSSL is not OpenSSL (macOS system binary); the manifest's expectations name
  the version they hold on
- The refusal paths hold: SHA-1 without `allowSha1`, PBES1 / RC2 / 3DES, a legacy SHA-1-MAC
  PKCS#12, an implicit RSA scheme — each a coded refusal with a remedy, never a silent accept
- Every artefact tool self-checks after signing; a signer / content / algorithm mismatch is a
  coded refusal

### 7. Reproducible artefacts
- A pinned `at` / `notBefore` / `signingTime` — or `PKINATIVE_MCP_AT` — plus an explicit
  serial / nonce and a fixture key make an artefact byte-identical across hosts and time
  zones; `serialNumber: 'random'` / `nonce: 'random'` are reported in the summary and
  compared in `tbs` mode by the baseline
- The sample baseline (`tests/_fixtures/samples.sha256.json`) holds; a rebaseline is declared
  in the release note; every `tbs`-mode sample is listed for a stated reason
- No `toLocaleString()` without a locale in `src/` or `scripts/`; generators run under
  `TZ=UTC` with the operator knobs scrubbed (`scripts/helpers/hermetic.ts`)

### 8. Documentation truth
- `npm run verify:docs` green: every count and version matches the tree; every tool, code and
  operator variable the docs name exists, and every one that exists is documented; every
  `#fragment` resolves; `.claude/rules/` is in sync with `.github/instructions/`
- Every input the docs and the tool descriptions name exists in the live schema; every
  engine export is reached by a tool or listed in `UNEXPOSED_EXPORTS` with a true rationale
  (`docs/data/core-exports.json`); `describe_engine.refusals` matches what the tools refuse

### 9. Governance
- No `Co-Authored-By` trailer, "Generated with" footer or mention of an AI assistant in the
  branch history, the PR draft or the release notes
- Nothing pushed, tagged, published or opened by an agent (`.claude/hooks/guard.mjs`, wired
  to Bash and PowerShell)
- Issue drafts under `.github/drafts/` pass `npm run verify:issue` and contain no secret
