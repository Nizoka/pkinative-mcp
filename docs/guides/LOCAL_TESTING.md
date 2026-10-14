# Local testing guide (for contributors)

This guide shows how to verify, on your own machine, that pkinative-mcp builds,
passes its quality gate, and — most importantly — that the **artefacts it produces are
actually correct** (not just well-formed DER): OpenSSL 3 must read and verify every one of
them. It complements the [Contributing guide](../../CONTRIBUTING.md) and the testing
rules of [`.github/instructions/testing.instructions.md`](../../.github/instructions/testing.instructions.md).

Applies to pkinative-mcp v1.0.0 · pkinative 1.0.0.

## 1. Prerequisites

- **Node.js ≥ 22** (`node -v`; `.nvmrc` pins 22). The package sets `"engines": { "node": ">=22" }`; the engine's own floor is `^22.22.2 || ^24.14.1 || >=25.8.2` (`describe_engine.engine.nodeFloor`).
- A clean install and a first build:

  ```bash
  git clone https://github.com/Nizoka/pkinative-mcp.git
  cd pkinative-mcp
  npm ci --ignore-scripts      # what CI runs
  npm run build                # nothing builds on install — the gate, the samples and the corpus drive dist/
  ```

There are **no** native build steps and no system PKI tools required for the core suite —
`pkinative` is a zero-dependency pure-TypeScript engine and every signature goes through
Web Crypto. Optional, for the interoperability steps (section 5): **OpenSSL 3.x**
(3.5.5 on the development host); for the publish profile, the certificate linters zlint and
pkilint.

## 2. The quality gate

`npm run gate` is **the** quality gate — the single definition of green, the same command CI
runs (`scripts/gate.ts`). It prints one line per step and a summary of at most 20 lines;
each step's log lands in `test-output/.gate/<step>.log`. The gate is hermetic: `TZ` is
pinned and every inherited `PKINATIVE_MCP_*` variable is scrubbed (`scripts/helpers/hermetic.ts`),
so its verdict is the same on a laptop and on a runner.

```bash
npm run gate:fast     # while you work, and before every commit
npm run gate          # the CI profile — run it before opening a PR
```

| Profile | Command | Steps |
| --- | --- | --- |
| Fast | `npm run gate:fast` | `typecheck:all`, `lint`, `test`, `code-tables`, `server-json`, `verify:docs` |
| CI (default) | `npm run gate` | `typecheck:all`, `lint`, `code-tables`, `build`, `dist-check`, `dist-probe`, `smoke`, `verify:tool-shape`, `server-json`, `test:generate`, `test:coverage`, `verify:docs`, `verify:samples`, `corpus:pki`, `validate:pki`, `interop` |
| Publish (release branches) | `npx tsx scripts/gate.ts --publish --require-all` | everything above + `lint:certs` (zlint / pkilint); `--require-all` turns a skipped step into a failure — CI passes it on every leg, with `PKINATIVE_INTEROP_REQUIRED=1` |

What the main steps check:

| Step | What it checks |
| --- | --- |
| `typecheck:all` | Strict TypeScript over `src/`, `tests/` and `scripts/` — the `PKI_ERROR_CLASS` table is typed against the engine's code union, so an engine minor that adds a code fails here. |
| `lint` | `eslint src --max-warnings 0` — a warning fails; `no-console` keeps stdout clean. |
| `code-tables` | `scripts/build-code-tables.mjs --check`: `src/data/pkinative/code-tables.ts` is in sync with the vendored registries. |
| `test` / `test:coverage` | The full vitest suite; with v8 coverage it must stay above the thresholds in [vitest.config.ts](../../vitest.config.ts) (94 / 90 / 95 / 94). |
| `build`, `dist-check`, `dist-probe` | `dist/` is emitted by `tsc -p tsconfig.build.json`, is complete (`cli.js`, `index.js`, `server.js`, the code tables, the shebang), holds only `src/` output, no `console.log` — and **no byte of a test key**: the needle table of the secret-leak suite is recomputed from the fixtures and swept over the emitted JavaScript. |
| `smoke` | The **built** server over stdio: `initialize`, `tools/list`, `tools/call describe_engine` — stdout carrying JSON-RPC frames only, the tool count read from `dist/server.js`. |
| `verify:tool-shape` | The built `tools/list` against the committed structural fixture (section 3.2b), and the size budgets (448 KiB catalogue, 8 KiB instructions, `declared.toolsListBytes` within 2 %). |
| `server-json` | `server.json` against the vendored MCP registry schema, offline (the nine variables included). |
| `test:generate`, `verify:samples` | The sample set, regenerated and held to the fingerprint baseline (section 3.4). |
| `verify:docs` | Every count, version, tool, code, operator variable, link and anchor the docs quote, against `docs/assets/ecosystem.json` and the source tree. |
| `corpus:pki`, `validate:pki`, `interop` | The OpenSSL conformance corpus, its validator and the vitest interop suite (section 5). |

Useful flags — pass them by calling the script directly:

```bash
npx tsx scripts/gate.ts --fast            # same as npm run gate:fast
npx tsx scripts/gate.ts --only smoke      # one step
npx tsx scripts/gate.ts --from build      # from a step onwards
npx tsx scripts/gate.ts --json            # machine-readable result
```

When a step fails, open **that step's** log under `test-output/.gate/` — not the whole
run. Use `npm run test:watch` for a fast inner loop while developing, and
`npx vitest run tests/<name>.test.ts` for one suite. The opt-in git hooks
(`npm run hooks:install` sets `core.hooksPath` to `.githooks/`) run lint on commit, refuse
CRLF in staged text, and run the fast gate before a push. The full script table, with
flags and exit codes, is in [scripts/README.md](../../scripts/README.md).

### Windows notes

- **PowerShell swallows a bare `--` after `npm run`**, so `npm run gate -- --fast` does
  not do what it says: call the script directly — `npx tsx scripts/<name>.ts <flags>`
  (`npx tsx scripts/gate.ts --fast`, `npx tsx scripts/verify-samples.ts --strict`).
- The Bash one-liners of this guide run under Git Bash.
- Every file the project writes uses LF line endings (`.gitattributes`; the pre-commit hook refuses CRLF).
- OpenSSL 3 ships with Git for Windows but is not on `PATH` (section 5).
- Tests pass on win32, darwin and linux — CI runs all three; use `path` helpers, never a hard-coded separator.

## 3. Verifying produced artefacts are correct

A DER blob that merely starts with `0x30` can still be structurally broken, signed by the
wrong key, or refused by every other implementation. Tests in this repo assert **real
validity** through four complementary layers.

### 3.1 Assertion helpers (in tests)

[tests/_pki-assert.ts](../../tests/_pki-assert.ts) exports:

- `assertValidDer(bytes)` — one well-formed DER value, decoded through the engine;
- `artefactBytes(result)` — the DER of the embedded `resource` block of an artefact result;
- `assertResultClean(result)` / `assertNoSecret(text)` — no needle of `tests/_secrets.ts` (PEM bodies, DER hex / base64, private scalars, encrypted-key bodies, the password) anywhere in a result, on stderr, in a cache file or in a transcript;
- `codeOf(promise)` / `errorCodeOf(result)` — the `[CODE]` of a refusal, so a test asserts both shapes a tool can produce (a coded `isError`, or `valid: false` + `reasons[]`).

The fixtures come through [tests/_pki-fixtures.ts](../../tests/_pki-fixtures.ts) — `fixture(name)`,
`fixtureBytes`, `fixtureBase64`, `fixtureText`, `fixtureInput` (a `{ pem }` or `{ derBase64 }`
fragment), `AT = '2027-01-01T00:00:00Z'`, `PASSWORD` — never by a hard-coded path:

```ts
import { callToolDirect } from '../src/server.js';
import { assertResultClean, artefactBytes, assertValidDer } from './_pki-assert.js';
import { AT, fixtureInput } from './_pki-fixtures.js';

const r = await callToolDirect('verify_certificate_chain', {
    leaf: fixtureInput('leaf.crt.pem'), candidates: [fixtureInput('inter.crt.pem')],
    trustAnchors: [fixtureInput('root.crt.pem')], at: AT, verbosity: 'summary',
});
expect(r.structuredContent).toMatchObject({ valid: true, reasonCodes: [] });   // a verdict is never isError
```

Every verdict test pins `at: AT` (inside the fixtures' 2026–2046 validity) and asserts
`valid` and the `reasons[].code` values, never the prose. The artefact tools verify their own
output before returning it (`summary.signatureVerified`), and the tests parse it back
through the matching `inspect_*` tool.

### 3.2 Examples-as-tests

Every file under [examples/](../../examples) — 89 files — is exercised by
[tests/examples.test.ts](../../tests/examples.test.ts) (`npm run examples:check`):

- the referenced tool name(s) must exist in the live registry;
- each `{ description, tool, arguments }` example is executed end-to-end through
  `callToolDirect()` in a temporary sandbox holding the 42 fixtures under `fixtures/`, with
  `PKINATIVE_MCP_AT=2027-01-01T00:00:00Z`; `expectError: CODE` asserts the refusal;
- `{ steps: [...] }` examples are chained in order with `<base64 from step N>` substituted
  into the next, so they run for real too — with an explicit guard that no example is left
  unexecuted;
- `documentationOnly: true` examples (file mode, the eight that write into the sandbox)
  are schema-checked, not executed.

Placeholders: `<fixture:NAME>` (a PKI input fragment), `<content:NAME>` (a content
fragment), `<base64 from step N>`, `<password:test-only>`. This guarantees the published
examples never drift from the real schemas. A stale field name or a renamed tool fails CI
immediately.

### 3.2b Catalogue parity (tool-shape gate)

The `tools/list` catalogue is fingerprinted structurally — names, titles, annotations,
schema types, enums, defaults, constraints, `required`, `additionalProperties` and the
number of `_meta.examples`, with every `description` string stripped — by
[scripts/lib/tool-shape.ts](../../scripts/lib/tool-shape.ts), and
[tests/catalogue-parity.test.ts](../../tests/catalogue-parity.test.ts) asserts the live
server matches the committed fixture `tests/_fixtures/tool-shape.json`; the gate step
`verify:tool-shape` (`npm run verify:tool-shape`) does the same against the **built**
`tools/list`. Wording (descriptions, examples, server instructions) can change freely; a
structural change fails the suite until you refresh the fixture on purpose:

```bash
npm run build && npx tsx scripts/tool-shape.ts --write
```

Review that diff under [docs/API_STABILITY.md](../API_STABILITY.md) §5 — it may require a
`TOOL_API_VERSION` bump. Never refresh the fixture to silence an accidental change. The
frozen `tests/_fixtures/tool-shape.v1.0.0.json` (created at the release commit) is never
regenerated: nothing published may be removed or narrowed.

### 3.3 Inspecting an artefact you produced by hand

The read tools double as a verification toolkit. After producing an artefact, feed its
bytes back in:

- **`inspect_certificate`** (`checkSelfSignature: true` or `issuer`) / **`inspect_csr`** / **`inspect_crl`** / **`inspect_cms`** / **`inspect_timestamp`** — the facts, one signature check.
- **`verify_certificate_chain`** / **`verify_cms`** / **`verify_timestamp`** — the verdict against the anchors you name at a pinned `at`.
- **`decode_asn1`** — the node tree, when the structure itself is in doubt (`reencode: true` proves the DER is canonical: `reencode.identical`).
- **`compute_fingerprint`** — the SHA-256 OpenSSL prints with `-fingerprint -sha256`.

A quick Node check against the **built** server (`callToolDirect` is what `tools/call` delegates to):

```ts
import { callToolDirect } from './dist/server.js';

const ca = await callToolDirect('create_certificate', {
    spec: { serialNumber: 1, subject: { CN: 'Demo CA' }, notBefore: '2027-01-01T00:00:00Z', validityDays: 365,
            extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] } },
    signer: { key: { path: 'fixtures/ed25519.key.pem' } }, encoding: 'der',
});
const der = ca.content.find((c) => c.type === 'resource').resource.blob;        // base64 DER, delivered once
console.log(await callToolDirect('inspect_certificate', { certificate: { derBase64: der }, checkSelfSignature: true, verbosity: 'summary' }));
```

### 3.4 The sample set and its fingerprint baseline

Structural assertions prove an artefact parses; the **baseline** proves it did not change by
accident. The whole loop is:

```bash
npm run build && npm run test:generate && npm run verify:samples
```

- `npm run test:generate` drives the **built** server (never `src/`) over every hermetic
  `examples/*.json` and writes 98 samples into the git-ignored `test-output/samples/`:
  `<example>.json` (the result without base64 blobs), `<example>.<ext>` (the artefact
  bytes) and `manifest.json` (the fingerprint mode of every file). It runs under `TZ=UTC`,
  with every operator variable scrubbed, then `PKINATIVE_MCP_AT=2027-01-01T00:00:00Z` and a
  temporary sandbox holding the fixtures, so the set is reproducible on any machine.
- `npm run verify:samples` fingerprints the set in the mode the manifest recorded and
  compares it with the committed `tests/_fixtures/samples.sha256.json`: **10 samples byte for
  byte** (`bytes`: Ed25519 / RSA PKCS#1 artefacts, requests, encodings), **3 through their
  signed part** (`tbs`: the TBSCertificate / CertificationRequestInfo of an ECDSA or RSA-PSS
  artefact, whose signature value cannot repeat) and **85 through a semantic projection**
  (`semantic`: the canonical JSON of `structuredContent` without `evaluatedAt`, `sha256`,
  `sizeBytes`, `filePath` — every read / verdict result and a randomised CMS). The modes
  are defined once in `scripts/lib/sample-fingerprint.ts`. Exit 0 match, 1 a changed or
  removed sample, 2 usage or missing samples. `npx tsx scripts/verify-samples.ts --strict`
  also fails on a new, unbaselined sample.
- The baseline is a **chain**: each entry records the release whose output it is
  (`since`), and an unchanged entry keeps it.
- An **intended** output change (an engine bump) is rebaselined with
  `npx tsx scripts/verify-samples.ts --update`, explained in the manifest's `provenance`
  note and declared in the release note. `--update` is never used to silence a surprise:
  an unexplained byte change is a regression until proven otherwise — and per
  [API_STABILITY.md](../API_STABILITY.md) §3 a changed deterministic artefact is semver-major.

`.github/workflows/sample-regression.yml` runs this loop on every push and pull request; it
is a required status check.

## 4. Driving the server with real files

To work with files instead of inline base64, point the sandbox at a directory you own and
drop the material in:

```bash
export PKINATIVE_MCP_OUTPUT_DIR="$PWD/.out"        # PowerShell: $env:PKINATIVE_MCP_OUTPUT_DIR = "$PWD/.out"
mkdir -p .out/fixtures && cp tests/fixtures/pki/* .out/fixtures/
```

Then pass `{ "path": "fixtures/leaf.crt.pem" }` as any PKI input, and call an artefact tool
with `outputMode: 'file'` and a relative `outputPath` (`issued/svc.crt.pem`,
`requests/svc.csr`, `signed/hello.p7m`; absolute paths, `..` traversal, a key-bearing
extension and an existing file are refused by the sandbox). The result carries a
`resource_link`, and `resources/list` shows the file as `pkinative://output/issued/svc.crt.pem`.
Open it with OpenSSL to eyeball it:

```bash
openssl x509 -in .out/issued/svc.crt.pem -noout -text        # Windows: the same under Git Bash
```

Key-bearing files in the sandbox (`.key .p8 .p12 .pfx`) are read by the key and signer
tools, never listed by `resources/list`, never served by `resources/read`, never written.

## 5. External interoperability (OpenSSL)

The built-in read tools are the engine's own reading; the conformance gate asks a **foreign
implementation** — OpenSSL 3.x, intentionally **not** a project dependency — to read and
verify what the tools write, and the tools to read what OpenSSL wrote (the 42 fixtures):

```bash
npm run build            # the corpus is written by the BUILT server
npm run corpus:pki       # → test-output/pki/*.{der,pem,…} + manifest.json (status, sha256, the second digest of a deterministic entry)
npm run validate:pki     # level 0 (engine round trip, in-process) + level 1 (OpenSSL), reports under test-output/pki/reports/
npm run test:interop     # the read direction, as vitest (tests/interop/openssl.test.ts)
```

### OpenSSL setup

Install **OpenSSL 3.x** (3.5.5 is what the fixtures were made with and what the development
host runs; CI runs the runner images' 3.x builds — ubuntu-22.04 carries 3.0, which has no
PBMAC1), then make sure the right binary is found:

| Platform | Where OpenSSL 3 is |
| --- | --- |
| Linux | `openssl` on `PATH` (the distribution package). |
| **Windows** | Git for Windows ships OpenSSL 3 under `C:\Program Files\Git\usr\bin`, which is **not** on `PATH` by default — add it, or set `OPENSSL_BIN` to `C:\Program Files\Git\usr\bin\openssl.exe` (what `.github/workflows/ci.yml` and `interop.yml` do). |
| **macOS** | `openssl` on `PATH` answers **LibreSSL**, which the gate refuses on purpose (`-pbmac1_pbkdf2`, `-attime` on `cms` and the PBES2 defaults are OpenSSL 3 behaviour). Homebrew carries OpenSSL 3: `export PATH="$(brew --prefix openssl@3)/bin:$PATH"`, or `OPENSSL_BIN="$(brew --prefix openssl@3)/bin/openssl"`. |

| Variable | Meaning |
| --- | --- |
| `OPENSSL_BIN` | The binary to use (must exist). Otherwise whatever `openssl` is on `PATH`. |
| `PKINATIVE_INTEROP_REQUIRED=1` | Fail closed: an absent or unusable OpenSSL is exit 3 instead of a skip (set in CI on every leg, and by the gate's `interop` step). |

`scripts/lib/interop-tools.ts` qualifies the binary (`opensslMissing()`: "openssl not on
PATH", "LibreSSL is not OpenSSL", "OpenSSL < 3.0") and records `openssl version` before
any judgement.

### The corpus

The corpus is a **representative sample** of every writer path, not an exhaustive feature
matrix: **23 conformant entries and 5 refused canaries** (`scripts/lib/pki-corpus.ts`,
declared in `docs/data/interop.json`). The conformant entries: a self-signed CA per
signature family (Ed25519, RSA PKCS#1 v1.5, RSA-PSS, EC P-256) and a leaf issued under
each (the subject key from a CSR, a certificate or a PUBLIC KEY), a pathLen-0 intermediate
and a leaf under it, three CSRs (EC with a SAN, RSA-PSS, Ed25519), attached and detached
CMS signatures plus an Ed25519 attached one, two time-stamp requests (SHA-256, SHA-384),
two OCSP requests (the leaf, the revoked leaf), and the PEM re-encodings of the DER
fixtures (the root certificate, the intermediate CRL, the leaf CSR). The five canaries name
the code the server **must** refuse them with: SHA-1 signing (`VALIDATION_ERROR`), a legacy
PKCS#12 signer (`PKI_KEY_ENCRYPTION_UNSUPPORTED`), an RSA key without a scheme
(`RSA_SCHEME_REQUIRED`), notAfter before notBefore and an unknown spec member
(`VALIDATION_ERROR`). A canary that writes bytes is an **XPASS** and fails the run.

What level 0 and level 1 check per entry, the 12 OpenSSL command families and the outcome
vocabulary are in [CONFORMANCE.md](CONFORMANCE.md). Exit codes of `validate:pki`: **0** every
expectation met (level 1 skipped with a reason when OpenSSL is absent and not required),
**1** a conformance FAIL / XPASS / coverage canary (`declared.conformant` / `declared.refused`
no longer match the table), **2** infrastructure — no corpus (run `npm run corpus:pki`
first), `dist/` missing, OpenSSL installed but unusable, **3** OpenSSL required but absent.

When OpenSSL is simply **not installed**, `npm run validate:pki` prints install hints and
exits 0 — explicitly labelled **SKIPPED, not a pass** — so local work never blocks, and the
gate reports the step as skipped. To fail closed, run the publish profile:
`npx tsx scripts/gate.ts --publish --require-all`, or set `PKINATIVE_INTEROP_REQUIRED=1`.

### The certificate linters (publish profile)

`tests/interop/lint.test.ts` (`npm run test:lint-certs`, gate step `lint:certs` under
`--publish`) hands the corpus certificates — a CA per signature family and leaves under two
of them — to **zlint** v3 and DigiCert's **pkilint**, because the mapping from a JSON spec
to extensions (`src/x509-spec.ts`) is wrapper code the engine's own linting never sees. An
ERROR or FATAL fails; a WARNING or NOTICE must be reviewed into
`scripts/data/lint-waivers.json` (none today), and a waiver that matches nothing is stale.
`ZLINT=<path>` and `PKILINT_PYTHON=<python that imports pkilint>` locate the tools;
`REQUIRE_LINT=1` fails instead of skipping.

**CI status:** `.github/workflows/interop.yml` builds, writes the corpus, validates it with
OpenSSL and runs the interop suite on four legs — ubuntu-22.04, ubuntu-24.04, windows-latest,
macos-latest — with `PKINATIVE_INTEROP_REQUIRED=1`; it is **blocking** on
`interop (ubuntu-24.04)` and `interop (windows-latest)` (`.github/rulesets/main.json`), the
other two report. The raw per-entry OpenSSL transcripts are uploaded as artifacts. The
publish workflow runs the whole `--publish --require-all` profile again before the package
is published.

## 6. Smoke-testing the MCP server over stdio

The server speaks JSON-RPC over stdio. **Always drive the built server before claiming a
change works** — source tests alone do not prove the emitted package. After `npm run build`:

```bash
node dist/cli.js
```

On stdio, **stdout is the protocol**: one stray `console.log` in `src/` corrupts every
session, so logs go to stderr (`[pkinative-mcp] …`) — the gate's `smoke` step
(`npx tsx scripts/gate.ts --only smoke`) performs the handshake against `dist/cli.js` and
fails on any stdout line that is not a JSON-RPC frame; `dist-probe` sweeps the emitted
JavaScript for `console.log` and for every secret needle. `tests/cli-stdio.test.ts`,
`tests/stdio-modern.test.ts` and `tests/autonomy.test.ts` spawn the same binary (they skip
locally when `dist/` is absent and fail under CI and the gate).

Operator variables are read once at boot, and an invalid value refuses to start; the boot
lines on stderr name every knob in force (never a secret's value):

```bash
PKINATIVE_MCP_AT=2027-01-01T00:00:00Z PKINATIVE_MCP_MAX_PATHS_EXPLORED=50 node dist/cli.js
# PowerShell: $env:PKINATIVE_MCP_AT = "2027-01-01T00:00:00Z"; node dist/cli.js
```

The cleanest way to drive it interactively is the official
[MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```bash
npx @modelcontextprotocol/inspector node dist/cli.js
```

From the Inspector you can list the 34 tools, inspect each schema and the `_meta.examples`,
read the seven prompts, browse the sandbox resources and issue `tools/call` requests — a fast
way to confirm a new or changed tool behaves before writing assertions.

To exercise the Streamable HTTP transport instead, set `PKINATIVE_MCP_PORT` (the server
binds loopback only and checks `Host` / `Origin`; `GET` / `DELETE` are 405). Without a
token the endpoint has **no authentication** — any local process can reach it — so also
set `PKINATIVE_MCP_HTTP_TOKEN` (≥ 16 characters, no whitespace; a weaker value aborts
startup) and send `Authorization: Bearer <token>` on every request to `/mcp`; a missing or
wrong token gets `401` with `WWW-Authenticate: Bearer`. The startup log tells you which mode
you are in ("bearer token required" vs. "no authentication (loopback only)").
`tests/http-modern.test.ts` and `tests/_http-fixture.ts` show the request shapes;
`tests/_agent-client.ts` drives all four transport × era pairs.

## 7. Interpreting coverage

`npm run test:coverage` prints a per-file table and fails if any metric drops below the
thresholds in [vitest.config.ts](../../vitest.config.ts) — they live there once, the gate
enforces them, and they are never lowered to make a change pass. When you add code, add
tests in the same PR so coverage does not regress on the modules you touched; a test that
closes an audit finding carries the finding id in its name.
