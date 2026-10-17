---
name: release-audit
description: Pre-release audit of pkinative-mcp — two parallel auditors (security, hardening and protocol conformance; API coverage, doctrine and docs parity), an adversarial verifier, an agent-autonomy pass and a GO/NO-GO ledger under .audit/<version>/. Run by the maintainer before every release; never invoked by the model on its own.
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Bash(npm run *), Bash(npx tsx scripts/*), Bash(npx vitest *), Bash(node dist/cli.js*), Bash(git diff*), Bash(git log*), Bash(git show*), Agent
argument-hint: [release-notes/vX.Y.Z.md] [previous-tag]
---

# Release audit

Audit the release described by `$0` (default: the newest `release-notes/v*.md`) against everything that changed since `$1` (default: the previous `v*` tag from `git tag -l`). The audit produces findings, never fixes: every fix goes through the normal edit → gate loop afterwards, and the ledger records what was fixed.

Read `ledger.md` first for the ledger and verdict formats. Each phase below hands a template to the agents it spawns; the agents return findings, you file them.

## Ledger location

`.audit/<version>/` — git-ignored (check `.gitignore` covers it before writing; it is NOT under `test-output/`, which Claude Code is denied to Read), so nothing here is ever committed. One Markdown file per report: auditor-a, auditor-b, verifier-1, auditor-d, verifier-2, then the ledger and the verdict (formats in `ledger.md`). A report never quotes a key body, a private scalar or a password — not even from a TEST-ONLY fixture; it quotes the needle's name and the file:line.

## Phase A and B — two auditors, in parallel

Spawn both with the Agent tool in the same message (distinct angles; neither sees the other's report):

- **Auditor A — security, hardening and protocol conformance.** Template: `auditor-a.md`. The secrets policy at every exit (results, error texts, diagnostics, cache files, resources, stderr, the stdio transcript), the sandbox, the ceilings, the cache gate, the refusal paths, both protocol eras on both transports, the supply chain of the workflows; at least one assertion per claim is *reproduced with a command* (a test, a script, a `tools/call` against the BUILT server), not inferred from reading.
- **Auditor B — API coverage, doctrine and docs parity.** Template: `auditor-b.md`. Every engine export reached by a tool or honestly listed in `UNEXPOSED_EXPORTS` (117/117 of `docs/data/core-exports.json`), the doctrine (no network, no keygen, no key export, no writers, SHA-1 opt-in), the README tool matrix, `docs/AGENT_CONTRACT.md`, `llms.txt`, `docs/API_STABILITY.md`, the live `tools/list` descriptions, `SERVER_INSTRUCTIONS`, `server.json`, the sample baseline, the OpenSSL corpus — every surface an agent or a human reads — compared with the behaviour that actually shipped.

Both write their report in the finding format of `ledger.md` (id, severity, claim, evidence command, observed, expected).

## Phase C — adversarial verifier

Spawn one verifier (template: `verifier.md`) with both reports. It re-derives every finding from scratch — re-runs the evidence command, reads the cited lines — and stamps each one `CONFIRMED | DOWNGRADED | REJECTED | DUPLICATE` with a one-line justification. Auditors have about 10 % false findings; the verifier exists to keep them out of the ledger. A finding the verifier cannot reproduce is `REJECTED`, not "probably fine".

## Phase D — agent-autonomy pass, then verify

Spawn Auditor D (template: `auditor-b.md`, section "Autonomy pass") with one question: *can an agent that has only what an MCP host shows it — `tools/list` (names, descriptions, input schemas, `_meta.examples`), `serverInfo.instructions`, `resources/list`, plus `llms.txt` and `docs/AGENT_CONTRACT.md` — drive every 1.x feature without reading `src/`?* It picks every feature the release note names plus a sample of older ones, writes the `tools/call` it would send from those surfaces alone, and sends it to the built server. Then a second verifier pass (template: `verifier.md`) over its findings.

## Phase E — GO / NO-GO

Merge the confirmed findings into the ledger, then write the verdict file (both formats are in `ledger.md`):

- **GO** — no CONFIRMED finding of severity `blocker`; every `major` has a fix commit or an explicit maintainer waiver in the ledger.
- **NO-GO** — otherwise. List the blockers first, each with its evidence command, so the fix loop starts from the ledger, not from memory.

Report the verdict, the counts per severity and per stamp, and the ledger path. Do not push, tag, open a PR or publish: `scripts/release-prepare.ts` and the maintainer take over from `GO`.

## Driving the built server

The server speaks newline-delimited JSON-RPC on stdio and exits when stdin closes, so one call is one shell command — write the request lines to a file with Write, then `node dist/cli.js < request.jsonl`. Read the frames on stdout; the boot log is on stderr. `tests/_mcp-harness.ts` is the same harness in test form, and `scripts/helpers/server.ts` calls the built `dist/server.js` without a transport. Set `PKINATIVE_MCP_AT` for a reproducible verdict, and pass passwords through `PKINATIVE_MCP_PASSWORD` rather than a request file that could be pasted into a report.

## Known blind spots

Add a check for each of these to the auditor briefs; they are where an audit of this server misses something.

- **Secret leakage through the side doors.** The results are needle-tested, but a secret also leaves through an error text (a `VALIDATION_ERROR` that echoes the offending value), a diagnostic message, a cache file under `PKINATIVE_MCP_CACHE_DIR`, a resource served from the sandbox, and the stdio transcript on stderr. Run the needle table (`tests/_secrets.ts`) over all five for every key and password path the release touched.
- **`at` versus the wall clock.** Every verdict depends on an instant. A test that omits `at` without `PKINATIVE_MCP_AT` passes today and fails the day a fixture expires; a result under the wall clock that reaches the cache is wrong tomorrow. Check `instantInputs` of every verdict tool and the `isClockDependent` path.
- **`valid: false` versus `isError` versus thrown.** Three shapes for "no": a negative verdict (`valid: false` + `reasons[]`), a coded refusal (`isError`), and a throw that escaped `guard`. A refusal reported as a verdict hides a bug; a verdict reported as an error breaks the agent's decision tree; a throw corrupts nothing but is uncoded. Send a malformed, an expired and a revoked input to each verdict tool and check the three shapes.
- **The refusal paths and their remedies.** SHA-1 without `allowSha1`, a PBES1 / RC2 / 3DES key, a legacy SHA-1-MAC PKCS#12, an implicit RSA scheme: each must be a coded refusal whose message names the remedy, never a silent accept and never an uncoded failure — and `describe_engine.refusals` must list the same set.
- **A `password` where none is needed.** A tool that does not open a key must refuse a `password` input (`VALIDATION_ERROR`), or the value is accepted, ignored, and possibly cached or logged. Grep every input schema for `password` and compare with the tools that call `resolvePassword`.
- **OpenSSL version differences.** ubuntu-22.04 carries OpenSSL 3.0 (no PBMAC1), ubuntu-24.04 3.x with PBMAC1, macOS answers `openssl` with LibreSSL unless Homebrew's is first on PATH; the corpus manifest must state the version its expectations hold on, and the interop suite must skip-with-reason, not fail, on a judge that cannot express a feature.
- **Deterministic (`bytes`) versus randomised (`tbs`) baseline modes.** A sample compared in `tbs` mode because it draws a random serial or nonce proves structure, not bytes; a sample silently moved from `bytes` to `tbs` hides a byte change. Diff the mode column of `tests/_fixtures/samples.sha256.json` against the previous tag and demand a reason for every `tbs` row.
- **Prototype pollution through nested specs.** `create_certificate`, `create_csr`, `encode_x509_structure` and `encode_asn1` take deep JSON specs; a `__proto__`, `constructor` or `prototype` key at any depth must be refused by the Zod twin and must leave `Object.prototype` untouched after the call.
- **The 22 limits bounded by the ceilings.** Every `limits.*` key must be clamped by its operator ceiling (`PKINATIVE_MCP_MAX_INPUT_BYTES`, `_MAX_KDF_ITERATIONS`, `_MAX_PATHS_EXPLORED`) with `LIMIT_CEILING_EXCEEDED`; a new limit the engine added is a new row in `src/limits.ts` and a new ceiling check, or it is unbounded.
- **`UNEXPOSED_EXPORTS` honesty.** `describe_engine` lists the engine surface deliberately not reachable as a tool input, with a rationale. An export that is neither reached by a tool nor listed is a coverage gap; a listed rationale that is no longer true (a feature since exposed) is a documentation lie. Reconcile against `docs/data/core-exports.json`.
- **Cache poisoning through an unkeyed input.** `PKINATIVE_MCP_CACHE_DIR` serves earlier bytes for equal arguments; anything that changes a result without appearing in the arguments must gate or namespace the entry — the operator pin (`PKINATIVE_MCP_AT`, which fills every omitted instant), the environment password (`PKINATIVE_MCP_PASSWORD`, which turns a describe call into an open), a ceiling, the engine version. Check `isCacheable` and the cache namespace (`src/server.ts`, `src/cache.ts`) for every new input and knob; a miss here is silent and wrong.
- **`structuredContent` versus `outputSchema` under projection.** The read tools' output schemas are projectable (every property optional), so a `fields` / `verbosity` result always validates — which also means a field that drifted, was renamed or vanished never fails validation. Check every new output member on the default, the `summary` and a projected path, and on the error path; compare `_meta.availableFields` with the schema's property list.
- **A sandbox bypass through a non-PKI input.** The PKI `path` inputs carry an extension allow-list and the key-tool restriction, but `content.path` (`sign_cms`, `verify_cms`), `data.path` (`create_timestamp_request`, `verify_timestamp`) and `resources/read` read *any* file: a key-bearing file or key material read as content leaves in an artefact. Every read path must resolve through `src/sandbox.ts` **and** be tested by content (`isSecretMaterial`), not only by name; plant a key behind a prefix and among many blocks and read it through each of them.
- **Two schemas per tool, kept in step by hand.** Every tool has a JSON Schema (what `tools/list` advertises) and a Zod `strictObject` (what the handler enforces). The tool-shape fixture proves the STRUCTURE of the first only; for each new input, send one value the JSON Schema accepts and check the handler accepts it, and one it rejects.
- **Capability negotiation and the legacy fallback.** The same binary serves MCP 2026-07-28 (`server/discover`) and the 2025-era `initialize` handshake, on stdio and on HTTP. A feature that only works in one era ships silently: the unit tests call handlers directly. `tests/stdio-modern.test.ts`, `tests/protocol-revisions.test.ts` and `tests/http-modern.test.ts` are the only places the eras are exercised.
- **stdout purity.** One `console.log` anywhere under `src/` — or in a dependency — corrupts the stdio framing for every host. The gate's `smoke` and `dist-probe` steps catch the built tree; an engine diagnostic that falls back to `console.warn` (a parse path without the sink) goes to stderr and is invisible to them.
- **`TOOL_API_VERSION`.** A schema or code change that ships without the bump leaves hosts and the response cache on a stale contract. Diff `tests/_fixtures/tool-shape.json` and the code table of `docs/AGENT_CONTRACT.md` against the previous tag.
- Regex-driven `verify:docs` rules are blind to wording: they prove counts, versions, links and presence, never that a sentence is true.
- CI assumptions live outside the repo: Trusted Publishing needs npm ≥ 11.5.1 on the runner (publish.yml installs it), the `npm-publish` environment must exist and be bound on npmjs.com, and the interop legs need OpenSSL 3 exposed on Windows (Git for Windows) and macOS (Homebrew); a green local gate proves nothing about the publish job.
- Auditors have ~10 % false findings — never file an unverified finding, and never let a `REJECTED` one reach the verdict.
- Publish-related strings in a shell command trip the guard hook (`.claude/hooks/guard.mjs`, wired to Bash and PowerShell): anything containing `npm publish`, `gh release`, `git push` or `git tag <name>` inside a segment, a `$( )`, or an interpreter payload is refused. Write such strings into files with Edit or Write, never through `echo` or a heredoc.
