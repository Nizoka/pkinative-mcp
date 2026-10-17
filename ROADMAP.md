# Roadmap

This document outlines the planned development direction for **pkinative-mcp**, the
Model Context Protocol server bridging [pkinative](https://github.com/Nizoka/pkinative)
to AI clients (Claude Desktop, Cursor, Continue, ChatGPT, Zed, …).

Priorities may shift based on community feedback and sponsorship. Engine-level items
live in [pkinative's ROADMAP](https://github.com/Nizoka/pkinative/blob/main/ROADMAP.md);
this server is a faithful thin wrapper and never parses DER, implements a signature or
fetches anything on its own.

---

## Released

### v1.0.0 — First stable release

- [x] **34 tools on pkinative 1.0.0** — encodings (`convert_pem`, `resolve_oid`, `compute_fingerprint`, `decode_asn1`, `encode_asn1`), certificates and requests (`inspect_certificate`, `create_certificate`, `encode_x509_structure`, `decode_extension`, `check_certificate_name`, `check_certificate_purpose`, `inspect_csr`, `create_csr`), paths / CRLs / OCSP (`verify_certificate_chain`, `build_certificate_path`, `validate_certificate_path`, `inspect_crl`, `check_crl_revocation`, `create_ocsp_request`, `inspect_ocsp_response`, `check_ocsp_status`), CMS and time-stamps (`sign_cms`, `verify_cms`, `inspect_cms`, `amend_cms`, `create_timestamp_request`, `inspect_timestamp`, `verify_timestamp`), keys (`inspect_private_key`, `inspect_pkcs12`, `open_pkcs12`), meta (`describe_engine`, `explain_code`, `draft_governance_issue`); every tool with typed input / output schemas, annotations, `_meta.apiVersion = '1.0.0'` and ≤ 2 executable `_meta.examples`.
- [x] **Full engine coverage** — 117 / 117 runtime exports of the frozen pkinative 1.0.0 API reached by a named tool (`tests/coverage-matrix.test.ts`, the ledger in `docs/KNOWLEDGE_BASE.md` §8, `docs/data/core-exports.json`); the surface deliberately not exposed listed with its rationale (`describe_engine.unexposed`); the 57 `PKI_*` error codes passed through verbatim with class, detail and remedy; the 43 `PKI_REASON_*` reasons returned in `reasons[]`, never thrown; the 97 `PKI_DIAG_*` diagnostics on every result, escalated only under `strict: true`.
- [x] **Verify before trust** — `inspect_*` are facts, `verify_certificate_chain` is the RFC 5280 §6 verdict (path, signatures, validity at a pinned instant, RFC 6125 names, purposes, policies, offline CRL / OCSP revocation); `build_certificate_path` discovers without checking signatures, `validate_certificate_path` judges an ordered path; `verify_cms` and `verify_timestamp` are the one-call verdicts on signatures and time-stamps, with long-term validation (`atTimeStamp`).
- [x] **Offline revocation** — CRL (base + delta) and OCSP evidence as inputs; `create_ocsp_request` builds the request the caller transports; the responder's authorisation, freshness and nonce judged by `check_ocsp_status`.
- [x] **Issue, sign, time-stamp** — `create_csr` → `create_certificate` (self-signed CA or issued leaf, proof of possession and issuer signature verified before the bytes return); `sign_cms` (attached / detached, CAdES attributes) → `inspect_cms` → `create_timestamp_request` → the caller's TSA → `amend_cms add-timestamp` (imprint checked) → `verify_cms`.
- [x] **Keys without a byte leaving** — `inspect_private_key` and `inspect_pkcs12` describe without a password, `open_pkcs12` opens with one; non-extractable Web Crypto import, allow-list views, two password channels (`password` input or `PKINATIVE_MCP_PASSWORD`, never both), a needle-table leak test over every result, stderr, the cache and the stdio transcript.
- [x] **Doctrine surfaced** — no network, no key generation, no key export, no PKCS#8 / PKCS#12 / CRL / OCSP-response / time-stamp-response writer, SHA-1 opt-in, explicit RSA scheme, PBES2 / PBMAC1 only, DSA / ML-DSA parsed never verified — each with its remedy in `describe_engine.refusals` and `explain_code`.
- [x] **One sandbox, caps and ceilings** — `PKINATIVE_MCP_OUTPUT_DIR` for every `path` input and every file output (realpath checks, exclusive writes, extension allow-lists, key-bearing files never written nor served); every byte / count cap in `src/caps.ts`; the 22 `PkiLimits` raised per call under the operator ceilings `PKINATIVE_MCP_MAX_INPUT_BYTES` / `_MAX_KDF_ITERATIONS` / `_MAX_PATHS_EXPLORED`.
- [x] **Reproducible on request** — `PKINATIVE_MCP_AT`, pinned instants, explicit serials and nonces (randomness reported as `randomSerial` / `randomNonce`); a 98-sample baseline (10 byte-exact, 3 `tbs`, 85 semantic) held by `sample-regression` on every pull request.
- [x] **MCP 2026-07-28 + legacy fallback** — SDK v2, stateless serving, cache hints, projectable output schemas, `verbosity` / `fields` projections, resources (`pkinative://output/{+path}`), 7 prompts, opt-in response cache with a cache gate that never caches a path, a secret, a file output, randomness or an unpinned instant (and a key that is never derived from a secret, `src/cache.ts`), opt-in HTTP bearer token; every legacy revision (2024-10-07 … 2025-11-25) proven on stdio and HTTP; the S0–S18 autonomy scenario over four transport × era pairs.
- [x] **OpenSSL interoperability gate** — a corpus of 23 conformant artefacts and 5 refused canaries written by the built server, validated at level 0 (engine round trip) and level 1 (OpenSSL 3.x, 12 command families), blocking on Linux and Windows and again before every publish; zlint and pkilint on the publish profile.
- [x] **AI governance / HITL** — `draft_governance_issue`, the `governance_contract` + `draft_issue_workflow` prompts, `.github/ai-governance.json`, `.github/AGENT_RULES.md`, `verify:issue`, the fail-closed Claude Code guard hook; no network code path.
- [x] **Docs as code** — README, AGENTS.md / CLAUDE.md, `llms.txt`, `docs/AGENT_CONTRACT.md`, `docs/AI_GUIDE.md`, `docs/API_STABILITY.md`, `docs/KNOWLEDGE_BASE.md`, nine guides; `docs/assets/ecosystem.json` held by `npm run verify:docs`; the catalogue pinned by `tests/_fixtures/tool-shape.json`.
- [x] **Release integrity** — one gate (`scripts/gate.ts`, profiles fast / CI / publish, `--require-all`), the gate on Linux (Node 22 / 24), Windows and macOS, npm Trusted Publishing (OIDC) with provenance, a CycloneDX SBOM and a build attestation, SHA-pinned actions, harden-runner, CodeQL, Scorecard, dependency review, committed rulesets.

_v1.0.0 is the active release._

---

## Planned

### Blocked upstream

Everything below waits on a pkinative export; implementing it on raw primitives in the wrapper would contradict the faithful-thin-wrapper philosophy and reintroduce PKI logic in `src/`. Each item is a tracked refusal today, with its remedy in `describe_engine.refusals`.

- [ ] **Key generation** — pkinative generates nothing (its ADR 0001): there is no `generate_key` tool and there will be none until the engine ships one. Remedy: bring keys from an HSM, a KMS or `openssl genpkey`.
- [ ] **Writers for PKCS#8, PKCS#12, CRL, OCSP response and time-stamp response** — the engine has no writer for them (its ADR 0003), so the catalogue has no `create_crl`, `create_ocsp_response`, `create_timestamp_response`, `create_pkcs12` or `export_key`. Remedy: issue them with the CA, responder or TSA software (or OpenSSL) and verify them here.
- [ ] **DSA and ML-DSA verification** — parsed and reported, never verified or signed (`PKI_REASON_SIGNATURE_NOT_CHECKED` / `UNSUPPORTED_KEY`); the wrapper follows the engine the day it verifies them through Web Crypto.
- [ ] **A non-UTF-8 password** — JSON carries UTF-8 strings only; the engine's `password: Uint8Array` form cannot be expressed over MCP and stays unexposed.

### By design (CLI parity notes)

- **No `--config` equivalent** — pkinative-cli reads a configuration file for defaults; an MCP call carries every member of its arguments, and the host passes them, so there is nothing for a config file to supply. The nine operator knobs are the whole environment surface. Will not be added.
- **`resolve_oid encode` answers hex per OID, never an artefact** — the CLI's PEM-wrapped OID is `encode_asn1 { spec: { type: 'oid', value }, encoding: 'pem', label }` here; `decode_asn1 reencode`, `create_ocsp_request` and `create_timestamp_request` take `label` for their PEM artefacts, and `resolve_oid decode` takes `input` (pem / derBase64 / path) as an alternative to `hex`.

### Next

- [ ] **Catalogue superset gate** — `tests/catalogue-superset.test.ts` comparing the live `tools/list` with the catalogue frozen at the 1.0.0 tag (`tests/_fixtures/tool-shape.v1.0.0.json`): no removal, no narrowing, no new `required`, no tighter bound; accepted deltas enumerated in the test. The comparison starts with the first release that has something to compare.
- [ ] **Automated MCP registry publication** — publishing `server.json` to the MCP registry is a manual maintainer step after the npm publication; move it into the publish workflow (the gate already validates `server.json` offline against the vendored schema).
- [ ] **`harden-runner` from audit to block mode** — switch the Linux jobs to `egress-policy: block` with an allow-list once the audited egress is known (Windows runners support audit mode only; macOS runners are not supported by the action).
- [ ] **Certificate linters on every CI leg** — zlint and pkilint run on the publish profile today; a pinned install on the `interop` legs would make `lint:certs` a required check.
- [ ] **Transport-layer fuzz** — the fixed cases are pinned (`tests/cli-stdio.test.ts`, `tests/http-hardening.test.ts`, `tests/http-modern.test.ts`); still open: a seeded generator of random frame mutations (the shape of `tests/_fuzz.ts`) over both transports — the current fuzz suite stops at tool arguments.
- [ ] **Upstream findings** — file the engine-side observations recorded in the guides through `draft_governance_issue` (human-submitted).

### Long-term

- [ ] **Resource subscriptions** — `resources/subscribe` on the sandbox listing once hosts consume it.
- [ ] **Per-tool HTTP streaming** — MCP 2026-07-28 still has no partial `structuredContent` envelope (results are `resultType: 'complete'` only), so a large CMS message or CRL report stays single-shot; the token-frugal projections are the mitigation.
- [ ] **Larger inline envelopes behind an operator switch** — the inline caps (128 MiB in, 50 MiB out, 64 KiB hex) are host-friendly defaults; an opt-in ceiling could raise them for hosts that can carry more.

---

## How to influence the roadmap

- **Feature requests:** [open an issue](https://github.com/Nizoka/pkinative-mcp/issues/new?template=feature_request.md) — or let an agent draft one with `draft_governance_issue` and submit it yourself.
- **Pull requests:** community contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
- **Engine features:** open them on [Nizoka/pkinative](https://github.com/Nizoka/pkinative/issues); the wrapper follows the engine within a minor.
- **Sponsorship:** sponsored features get prioritised — see [funding options](https://github.com/sponsors/Nizoka).
- **Discussion:** weigh in on the [open milestones](https://github.com/Nizoka/pkinative-mcp/milestones).
