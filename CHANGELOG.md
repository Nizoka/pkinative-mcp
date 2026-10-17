# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-13

The first stable release — and the first npm publication — of the MCP server for
[pkinative v1.0.0](https://github.com/Nizoka/pkinative), the zero-dependency,
pure-TypeScript PKI engine that signs and verifies through Web Crypto only.
**34 tools** expose the engine's whole runtime surface (117 / 117 runtime exports
reached by a named tool; the 57 `PKI_*` error codes, 43 `PKI_REASON_*` reasons and
97 `PKI_DIAG_*` diagnostics passed through verbatim from the registries vendored at
the engine tag) to any MCP client over stdio or loopback HTTP, speaking
**MCP 2026-07-28** with automatic fallback to every 2024- and 2025-era handshake.
**Three runtime dependencies** (pkinative, the MCP SDK, zod), **no network code
path**, no key byte ever leaving the engine, one sandbox for reads and writes, and
every artefact the server writes read back and verified by **OpenSSL 3** in a
blocking interoperability gate on Linux and Windows and before every publish. It
is the third server of the "native" family, built on the architecture, gate and
governance of pdfnative-mcp 1.7.0 and zipnative-mcp 1.0.0.

### Added

#### Tools — encodings (5)
- **feat(tool): convert_pem** — RFC 7468 decode (every block listed with label, size, offset and SHA-256; `extractIndex` delivers one as der / pem / hex) and encode (DER wrapped into one strict block under `label`); a private-key block is listed, never extracted, never produced (`SECURITY_VIOLATION`, by label and by parsing the DER as PKCS#8 / PKCS#12).
- **feat(tool): resolve_oid** — `name`, `validate` (X.660, reported not thrown), `list` (the engine registry, filtered, paged 200 / 2000), `encode` (content or TLV, RELATIVE-OID), `decode`.
- **feat(tool): compute_fingerprint** — the digest of the exact DER (SHA-1 / 256 / 384 / 512, `webcrypto`), the RFC 5280 key identifier of a certificate / CSR / PUBLIC KEY, SHAKE256 (`outputLength`); `formatted` with separator and case; no input byte returned.
- **feat(tool): decode_asn1** — the X.690 node tree (≤ 20 000 nodes, previews, OID names), `nodePath`, typed `read`, `reencode` as an artefact, `sequence`, `allowTrailingData`, BER; refuses a private key or a PKCS#12.
- **feat(tool): encode_asn1** — a JSON node spec encoded through the engine's own encoders, deterministic, naming the JSON path of a malformed node.

#### Tools — certificates and requests (8)
- **feat(tool): inspect_certificate** — the RFC 5280 report (the 19 extension kinds decoded or raw, fingerprints, diagnostics); `extension`; one signature check against `issuer` or itself, labelled as not trust.
- **feat(tool): create_certificate** — self-signed CA or issued leaf from a closed `spec` (serial integer / hex / `'random'`, validity, basicConstraints, keyUsage, extendedKeyUsage, subjectAltName, issuerAltName, SKI / AKI, raw), `subjectPublicKey` from a certificate / CSR / PUBLIC KEY, the AKI computed from the issuer, the new certificate verified before it is returned (`KEY_MISMATCH`).
- **feat(tool): encode_x509_structure** — fifteen X.509 building blocks from closed specs (`signature-algorithm` reads a signer's algorithm without signing), hex by default.
- **feat(tool): decode_extension** — one extnValue by OID with the RFC 5280 criticality rule as a diagnostic.
- **feat(tool): check_certificate_name** — RFC 6125 host / IP identity (wildcards, an opt-in CN fallback held to the chain's name constraints) or one name match.
- **feat(tool): check_certificate_purpose** — extended key usage along the path (`restrictIssuers`, `requireExplicitPurpose`).
- **feat(tool): inspect_csr** — the RFC 2986 report with the requested extensions decoded, challengePassword presence, and the proof of possession verified by default.
- **feat(tool): create_csr** — a PKCS#10 request from a closed `spec`, the public key derived from the signer, the PKCS#12 certificate or `subjectPublicKey`, the proof of possession verified before the bytes return.

#### Tools — paths, CRLs and OCSP (8)
- **feat(tool): verify_certificate_chain** — the one-call RFC 5280 §6 verdict: path building through `candidates` to the caller's `trustAnchors`, every signature, validation at `at` (validity, constraints, key usage, name constraints, `policy`), `serverName`, `purposes`, offline revocation from `crls` / `ocspResponses` (`requireRevocation`, `ocspNonce`, `requireOcspNonce`); `evaluatedAt` with its source.
- **feat(tool): build_certificate_path** — path discovery without signatures (`found`, `structuralReasons`, `PKI_REASON_SIGNATURE_NOT_CHECKED` always present).
- **feat(tool): validate_certificate_path** — RFC 5280 §6.1 on an ordered path, link signatures verified first, `checkSignatures: false` for the structural verdict with `failingReasons`.
- **feat(tool): inspect_crl** — the RFC 5280 §5 report (entries counted by walking, bounded by `maxRevokedCertificates`), `find` one serial, one signature check.
- **feat(tool): check_crl_revocation** — one certificate against one base CRL with an optional delta, scope, freshness (`staleTolerance`), the signature verified against `issuer`.
- **feat(tool): create_ocsp_request** — RFC 6960 request with a SHA-1 or SHA-256 CertID, an RFC 8954 nonce (`'random'` or hex), `certIdOnly`; `summary.certIdHex` / `nonceHex` to match the answer.
- **feat(tool): inspect_ocsp_response** — the RFC 6960 report (status, responder id, every SingleResponse, extensions, embedded certificates, nonce presence), one signature check.
- **feat(tool): check_ocsp_status** — the CertID recomputed, the signature verified (responder, embedded certificates or issuer), the responder's authorisation (RFC 6960 §4.2.2.2, `responderTrusted`), status, freshness (`staleTolerance`, `futureTolerance`), nonce (`requireNonce`).

#### Tools — CMS and time-stamps (7)
- **feat(tool): sign_cms** — RFC 5652 SignedData, attached or detached, or over a precomputed `contentDigest` (the PDF `/ByteRange` case); one signer from a PKCS#8 key or a PKCS#12; `chain` and `crls` parsed then embedded; contentType, messageDigest, signingTime (pinned, `'now'` or `'none'`), SigningCertificateV2 and CMSAlgorithmProtection; further signed / unsigned attributes as DER; `sid`; verified against the signer certificate before the bytes return.
- **feat(tool): verify_cms** — every signer judged: signed attributes, digest, signature, chain to the caller's anchors at `at`, every counter time-stamp, revocation from the supplied and the embedded evidence; `atTimeStamp` long-term validation; `requireSigningCertificate`, `requireAlgorithmProtection`, `allowTrailingData`; per-signer `intact` next to `valid`.
- **feat(tool): inspect_cms** — the RFC 5652 report with every signer's attributes, the signing time as claimed, the time-stamp count and the signature value to counter-stamp; one key check with `signerCertificate`.
- **feat(tool): amend_cms** — `add-unsigned-attribute` and `add-timestamp` (a token or a whole TSA response, the imprint checked against the signature value before anything is written), every signed octet unchanged.
- **feat(tool): create_timestamp_request** — RFC 3161 request over data or a digest (SHA-256 / 384 / 512), a 63-bit random or pinned nonce, `policy`, `certReq`.
- **feat(tool): inspect_timestamp** — a response, a token or a bare TSTInfo, auto-detected or `as`.
- **feat(tool): verify_timestamp** — a token or a response against the request sent, the data or the digest (at least one), the TSA signature, its chain with a critical timeStamping EKU (`allowNonCriticalTimeStampingEku`), revocation; `genTime`, `earliest`, `latest`.

#### Tools — private keys and PKCS#12 (3)
- **feat(tool): inspect_private_key** — a PKCS#8 key described without its password (kind, curve, algorithm, PBES2 parameters or the refused legacy scheme); `tryImport` into a non-extractable Web Crypto key with the handle described.
- **feat(tool): inspect_pkcs12** — a PKCS#12 described without its password (PBMAC1 or the legacy MAC, every SafeContents and its scheme, the plain bags); with a password, `macVerified` and `opened` as allow-list views — a wrong password on an encrypted SafeContents is `PKI_CRYPTO_DECRYPTION_FAILED`, `macVerified: false` only when nothing is encrypted.
- **feat(tool): open_pkcs12** — MAC verified, SafeContents decrypted, keys unwrapped straight into non-extractable Web Crypto keys and described, certificates parsed, CRLs counted; `integrity` verified / unverified / mismatch with the `PKI_REASON_PKCS12_*` reasons; `exportCertificates` attaches a PEM bundle, never a key.

#### Tools — meta (3)
- **feat(tool): describe_engine** — the offline preflight: versions, Web Crypto capabilities, the 22 default limits, the three operator ceilings, every server cap, sandbox / cache / pinned-instant state, the extension allow-lists, the three code vocabularies plus the wrapper codes, purposes and key-usage names, the doctrine refusals with their remedies, the deliberately unexposed engine surface; `network: 'none'`.
- **feat(tool): explain_code** — every `PKI_*`, `PKI_REASON_*`, `PKI_DIAG_*` and wrapper code explained from the vendored registries (class, standard, CWE, remedy, the MCP input that lifts it); `list` by `kind`.
- **feat(tool): draft_governance_issue** — a local, governance-compliant issue draft plus compliance report for pkinative, pkinative-cli or pkinative-mcp (`targetRepo`); `GOVERNANCE_VIOLATION` on a runtime-dependency proposal, an embedded key or password, a missing reproduction or `duplicateSearchPerformed: false`; optional `.md` output in the sandbox.

#### Shared fragments
- **feat(input):** the PKI input (`pem` XOR `derBase64` XOR `path`, the label checked before any byte is parsed, several blocks where one object is expected refused), bundles of up to 256 items, the content input (`text` XOR `base64` XOR `path`), the hex grammar, the `PARSE` fragment (`encodingRules`, `pemMode`, `strict`, `limits`), the 22 named `PkiLimits` as a per-call input bounded by the operator ceilings, the `SIGNER` fragment (PKCS#8 or PKCS#12, `password`, `keyType`, `hash`, `rsaScheme`, `saltLength`), the `TRUST` fragment (anchors, candidates, evidence, `at`, `requireRevocation`, `purposes`, `policy`), the projection (`verbosity`, `fields` ≤ 16) and the output fragment (`outputMode`, `outputPath`, `encoding` pem / der / hex).
- **feat(views):** wire views of every engine object with the raw DER echoes dropped, instants as epoch milliseconds + ISO, `bigint` as decimal strings, bytes as hex; allow-list key and PKCS#12 views (`src/key-views.ts`).

#### Protocol and transport
- **feat(mcp):** MCP 2026-07-28 on `@modelcontextprotocol/server` ^2.0.0 with automatic legacy `initialize` fallback for every revision the SDK negotiates (2024-10-07, 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25) on stdio and HTTP, proven by `tests/protocol-revisions.test.ts` (legacy) and `tests/stdio-modern.test.ts` / `tests/http-modern.test.ts` (modern); `server/discover`, `resultType`, `SERVER_CACHE_HINTS` (catalogue public 24 h, discover 1 h, resources private); `serverInfo` `title` / `description` / `websiteUrl`; unknown tool / prompt → JSON-RPC `-32602`; deterministic `tools/list` order (the group files); `_meta.apiVersion` + ≤ 2 executable `_meta.examples` per tool; `_meta.error { code, message, data }` on every failure with `data.remedy`.
- **feat(mcp):** projectable output schemas on the read and verdict tools (every property optional, summary scalars declared) so `structuredContent` validates under `verbosity: 'summary'` and `fields`; typed `summary` schemas on every artefact tool; `_meta.unmatchedFields` / `availableFields`.
- **feat(mcp):** native resources — every non-secret file in the sandbox as `pkinative://output/<path>` (`resources/list`, `resources/templates/list` with `{+path}`, `resources/read` ≤ 50 MiB; `.key .p8 .p12 .pfx` never listed nor served) and `resource_link` blocks from the file-producing tools; artefacts delivered once as an embedded `resource` (PEM as text, DER as blob, with their MIME types).
- **feat(mcp):** seven prompts — `governance_contract`, `draft_issue_workflow`, `verify_before_trust`, `issue_certificate`, `sign_and_timestamp`, `offline_revocation`, `open_keys_safely`; `SERVER_INSTRUCTIONS` (a decision tree, the security posture, the pitfalls) under 8 KiB.
- **feat(transport):** stdio with a 256 MiB frame cap; loopback Streamable HTTP (`PKINATIVE_MCP_PORT`) through a dependency-free `node:http` bridge with Host / Origin guard, 405 on GET / DELETE, 413 above 256 MiB, per-response disconnect detection; opt-in bearer token `PKINATIVE_MCP_HTTP_TOKEN` (constant-time, RFC 6750 challenge); graceful shutdown on SIGINT / SIGTERM.
- **feat(cache):** opt-in content-addressed response cache (`PKINATIVE_MCP_CACHE_DIR`, 1 h TTL, 256 MiB LRU, key namespaced by tool API / package / engine version, `_meta.cached: true`) behind a cache gate: never a path input, file output, a password or a signer, `'random'`, `'now'`, an unpinned instant, `describe_engine`, `draft_governance_issue`, nor any password-accepting tool while `PKINATIVE_MCP_PASSWORD` is set (`tests/cache-policy.test.ts`).
- **feat(time):** `PKINATIVE_MCP_AT` pins every omitted `at` / `notBefore` / `signingTime`; instants parsed from their ISO 8601 fields (UTC unless zoned, impossible dates refused); `evaluatedAtSource` / `notBeforeSource` / `signingTimeSource` say where an instant came from.

#### Security posture
- **feat(security):** one filesystem boundary (`PKINATIVE_MCP_OUTPUT_DIR`) for every `path` input, `resources/read` and `outputMode: 'file'` — relative paths only, NUL / absolute / drive / UNC / `..` refused, extension allow-lists for PKI inputs and outputs, realpath re-check of every file read and of every parent written (a planted symlink or junction is `SECURITY_VIOLATION`), `wx` opens (never overwrite), partial files removed; key-bearing extensions never written, never listed, never served; unset = inline PEM / base64 only.
- **feat(security):** two password channels (`password` input XOR `PKINATIVE_MCP_PASSWORD`), never echoed, logged, cached or served; non-extractable Web Crypto import of every signing key; allow-list key views; `convert_pem`, `decode_asn1` and `encode_asn1` refuse private-key material under any label; the needle-table leak test (`tests/secret-leak.test.ts`, `assertResultClean`) over every key-bearing result, stderr, the cache and the stdio transcript; the gate's `dist-probe` refuses a build carrying a fixture key.
- **feat(security):** the `src/caps.ts` envelope (256 MiB frame / body, 128 MiB decoded inline inputs, 128 MiB inline content, 1 GiB content path, 50 MiB inline output, 1 GiB file output, 64 KiB inline hex, 256 bundle items, 1000 OIDs, 4096-byte passwords, 20 000 ASN.1 nodes, 200 diagnostics, the resources and cache bounds — every constant advertised by `describe_engine.caps`); the operator ceilings `PKINATIVE_MCP_MAX_INPUT_BYTES` (64 MiB), `PKINATIVE_MCP_MAX_KDF_ITERATIONS` (10 000 000), `PKINATIVE_MCP_MAX_PATHS_EXPLORED` (1000) — `LIMIT_CEILING_EXCEEDED` names the variable; an invalid value refuses to start; strict Zod at every nesting level; prototype-pollution-safe specs; base64 and PEM boundary diagnostics.
- **feat(errors):** the 21 wrapper codes with a remedy each (`src/wrapper-codes.ts`) and the 57 `PKI_*` codes passed through verbatim by `src/pki-errors.ts` (the only reader of `err.code`, typed against the engine's code union so a new engine code fails `tsc`) with `data.errorClass`, `engineError`, `path`, `offset`, `limit`, `remedy`; a negative verdict is `valid: false` + `reasons[]`, never `isError`; the 97 diagnostics de-duplicated on every result, `strict: true` escalating the first warning to `PKI_STRICT_DIAGNOSTIC`.
- **feat(doctrine):** surfaced by `describe_engine.refusals` with a remedy each — no network, no key generation, no key export, no PKCS#8 / PKCS#12 / CRL / OCSP-response / time-stamp-response writer, SHA-1 opt-in, explicit RSA scheme, PBES2 / PBMAC1 only, DSA / ML-DSA never verified, diagnostics are not errors, limits under the ceilings, randomness reported.

#### Governance
- **feat(governance):** `.github/ai-governance.json` and `.github/AGENT_RULES.md` (eight rules, the eighth the human-in-the-loop gate), the `governance_contract` / `draft_issue_workflow` prompts, `scripts/verify-issue.mjs` (`npm run verify:issue`) mirroring the tool's validation, `.github/drafts/` as the staging area; the no-network charter stated as a property of the code, not a policy.

#### Conformance gate
- **feat(conformance):** the OpenSSL interoperability corpus (`scripts/lib/pki-corpus.ts`): 23 conformant artefacts written by the built server (CAs and leaves for Ed25519, RSA PKCS#1 v1.5, RSA-PSS and ECDSA P-256, a pathLen-0 intermediate, CSRs, attached and detached CMS, time-stamp and OCSP requests, PEM re-encodings) and 5 refused canaries (SHA-1, a legacy PKCS#12 signer, RSA without a scheme, an inverted validity, a URL member); `npm run corpus:pki` / `npm run validate:pki` at level 0 (engine round trip, independent `node:crypto` reckonings, double-run determinism) and level 1 (OpenSSL 3.x, 12 command families: `x509`, `verify`, `req -verify`, `crl`, `cms -verify`, `asn1parse`, `ocsp -req_text`, `ts -query -text`); a coverage canary against `docs/data/interop.json`; XPASS fatal; `PKINATIVE_INTEROP_REQUIRED=1` and the gate's `--require-all` fail closed; the vitest forms `tests/interop/openssl.test.ts` and `tests/interop/lint.test.ts` (zlint, pkilint, reviewed waivers).

#### Documentation
- **docs:** README, AGENTS.md (the repository rules, ≤ 120 lines), CLAUDE.md, `llms.txt`, `server.json`, `CITATION.cff`, CONTRIBUTING, SECURITY, SUPPORT, ROADMAP, THIRD-PARTY-NOTICES; `docs/AGENT_CONTRACT.md` (the consumer contract: catalogue, decision tree, token economy, output modes, recipes, the error reference), `docs/AI_GUIDE.md`, `docs/API_STABILITY.md`, `docs/KNOWLEDGE_BASE.md` (with the 117-export ledger); guides `AI_GOVERNANCE`, `LOCAL_TESTING`, `SECURITY`, `SIGNING`, `VERIFICATION`, `REVOCATION`, `TIMESTAMPS`, `KEYS`, `CONFORMANCE`; `docs/data/` mirrors of the vendored registries and `interop.json`; `docs/assets/ecosystem.json` held by `npm run verify:docs`; 89 worked examples under `examples/` executed by `tests/examples.test.ts`; release notes and the PR draft.

#### CI and release
- **ci:** ten workflows — `ci` (the gate with `--ci --require-all` on Linux Node 22 / 24, Windows and macOS), `interop` (four OS legs, blocking on `ubuntu-24.04` and `windows-latest`), `sample-regression`, `publish` (tag = version check, the publish gate, npm Trusted Publishing with provenance from the `npm-publish` environment, CycloneDX SBOM + build attestation), `docs`, `codeql`, `scorecard`, `dependency-review`, `audit`, `node-current`; `harden-runner` on every Linux and Windows job, `persist-credentials: false`, `npm ci --ignore-scripts`, least-privilege permissions, every action pinned by commit SHA; `.github/rulesets/main.json` (seven required checks) and `tags.json`; Dependabot; CODEOWNERS; issue templates (bug, feature, interop report, maintenance).
- **feat(gate):** `scripts/gate.ts` — profiles `--fast`, `--ci` (default), `--publish`; `--require-all` turns a skip into a failure; inline steps `code-tables`, `dist-check`, `dist-probe` (no `console.log`, only `src/` under `dist/`, no secret needle), `smoke` (the built server over stdio, stdout purity), `server-json` (offline validation against the vendored registry schema); hermetic (`TZ=UTC`, every `PKINATIVE_MCP_*` scrubbed).
- **test:** 2376 tests across 111 files (coverage thresholds 94 / 90 / 95 / 94); `tests/autonomy.test.ts` — the S0–S18 agent scenario replayed against the built CLI on stdio legacy, stdio modern, HTTP legacy and HTTP modern with a bearer token; `tests/protocol-revisions.test.ts`, `tests/stdio-modern.test.ts`, `tests/http-modern.test.ts`, `tests/http-hardening.test.ts`, `tests/http-shutdown.test.ts`; `tests/coverage-matrix.test.ts` (117 / 117), `tests/schema-lockstep.test.ts`, `tests/schema-conformance.test.ts`, `tests/catalogue-parity.test.ts` with `tests/_fixtures/tool-shape.json`, `tests/cache-policy.test.ts`, `tests/secret-leak.test.ts`, `tests/pki-fuzz.test.ts` (seeded), `tests/prototype-pollution.test.ts`, `tests/examples.test.ts`; the 98-sample baseline (`npm run test:generate`, `npm run verify:samples`: 10 byte-exact, 3 `tbs`, 85 semantic); 42 OpenSSL-made TEST-ONLY fixtures pinned by `SHA256SUMS` (`tests/fixtures/PROVENANCE.md`); `.mcp.json` for driving the built server from Claude Code.
- **fix(interop):** the trust files of `openssl verify` (`-CAfile`, `-untrusted`) are handed over as PEM (`scripts/lib/interop-tools.ts` `withPemTrust`): OpenSSL 3.0 reads them as PEM only and answered a DER CA with "no certificate or crl found" on the ubuntu legs, while 3.2+ autodetects DER and passed on the development host; the artefact under test stays DER.
- **fix(samples):** the semantic fingerprint neutralises the host members (`describe_engine.capabilities.node` / `.platform`, `draft_governance_issue.compliance.environment.node` / `.os` and the `- Node:` / `- OS:` lines of the draft; `scripts/lib/sample-fingerprint.ts` `stripHost`), so the baseline made on one machine holds on every CI runner; `describe-engine.json` and `draft-governance-issue.json` rebaselined under the new projection, their `since` unchanged (1.0.0).
- **fix(test):** `tests/autonomy.test.ts` S6 asserted that no result carries the sandbox path, which `filePath` — the one documented absolute path of a file-mode result — does by contract; the assertion now holds the resource link relative and `filePath` inside the sandbox (it passed on Windows only because JSON escapes backslashes); the CodeQL findings on `scripts/verify-docs.ts`, `tests/docs-consistency.test.ts` (version strings escaped as regex literals) and `tests/governance.test.ts` (no overlapping alternatives) resolved.
- **feat(agents):** committed `.claude/settings.json` (no commit attribution, Read denied on the generated bulk files, the human-in-the-loop commands denied for Bash and PowerShell), the fail-closed `PreToolUse` guard hook, `.claude/rules/` generated from `.github/instructions/` (`npm run agents:rules`), the `release-audit` skill; `scripts/release-prepare.ts` (the mechanical bump, never commits, tags or publishes); opt-in git hooks (`npm run hooks:install`).

### Security

- **No network code path** — no CRL / OCSP / AIA / TSA fetch, no telemetry, no GitHub, no URL from any argument; `describe_engine.network` is `'none'` and every tool advertises `openWorldHint: false`.
- **No key byte leaves** — non-extractable Web Crypto import, allow-list views, no key writer, no key resource, private-key material refused by the generic tools; proven by a needle table computed from the fixtures.
- **Engine doctrine never weakened** — SHA-1 opt-in, explicit RSA scheme, PBES2 / PBMAC1 only, DSA / ML-DSA never verified, limits under the operator ceilings; every artefact verified before it is returned.
- **A cache key is never derived from a secret** — `src/cache.ts` refuses to compute a key, on read and on write, for an input holding a `password` or a `signer` at any depth, the local invariant behind the cache gate of `isCacheable` (the key is a content address of the call, never a password hash; the CodeQL `js/insufficient-password-hash` finding on it is a false positive, no secret reaches the hash).
- **Supply chain** — three runtime dependencies; OIDC Trusted Publishing with provenance and a CycloneDX SBOM per release; CodeQL, OpenSSF Scorecard, dependency review, `npm audit --audit-level=high`; secrets (`PKINATIVE_MCP_HTTP_TOKEN`, `PKINATIVE_MCP_PASSWORD`) never logged or echoed.

### Inherited from pkinative 1.0.0

The engine's own guarantees, passed through unchanged: the frozen `PKI_*` / `PKI_REASON_*` / `PKI_DIAG_*` vocabularies with their standards and CWE ids; the 22 named `PkiLimits` on every parser loop; RFC 5280 §6 path building and validation with name constraints and policies; RFC 6125 names; RFC 6960 OCSP with responder authorisation; RFC 5652 CMS with ESS and CMSAlgorithmProtection; RFC 3161; RFC 8018 PBES2 and RFC 9579 PBMAC1; strict DER with opt-in BER; Web Crypto for every signature and decryption (no secret-dependent arithmetic in TypeScript); and the engine's refusals — no key generation (ADR 0001), no PKCS#8 / PKCS#12 / CRL / OCSP-response / time-stamp-response writer (ADR 0003), no default RSA scheme (ADR 0015) — which this server surfaces rather than works around.

### Deferred by design

- **Blocked upstream** (listed in ROADMAP.md, each a tracked refusal with its remedy in `describe_engine.refusals`): key generation, the PKCS#8 / PKCS#12 / CRL / OCSP-response / time-stamp-response writers, DSA and ML-DSA verification, a non-UTF-8 password.
- **Next**: the catalogue superset gate against the catalogue frozen at this tag, automated MCP registry publication, `harden-runner` block mode, the certificate linters on every CI leg, transport-layer fuzz.
- **Long-term**: resource subscriptions, per-tool HTTP streaming (no partial `structuredContent` in MCP 2026-07-28), larger inline envelopes behind an operator switch.

[Unreleased]: https://github.com/Nizoka/pkinative-mcp/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Nizoka/pkinative-mcp/releases/tag/v1.0.0
