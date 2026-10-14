# Security Policy

## Supported versions

The latest published minor on npm receives security patches. Older versions are unsupported once a new minor lands.

| Version  | Supported          |
| -------- | ------------------ |
| `1.0.x`  | :white_check_mark: |
| `< 1.0`  | :x:                |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report suspected vulnerabilities privately via GitHub Security Advisories:
<https://github.com/Nizoka/pkinative-mcp/security/advisories/new> (**Security → Report a vulnerability** on the repository). Include:

- A description of the vulnerability.
- Reproduction steps or a minimal proof of concept — for a PKI-shaped issue, the object itself made from **TEST material only** (never a real private key, a real PKCS#12 or a password) and the tool call.
- The version of `pkinative-mcp`, `pkinative`, Node.js and, when relevant, OpenSSL you tested against.
- Any suggested mitigation.

You will receive an acknowledgement within **7 days**. We aim to ship a fix and a coordinated public advisory within **30 days** of the initial report (or sooner for critical issues). Engine-level findings (parsing, path validation, signatures, revocation, PKCS#12, the limits) belong to [Nizoka/pkinative](https://github.com/Nizoka/pkinative/security/advisories/new) — report to both when unsure.

## Threat model

`pkinative-mcp` is designed to run as a local MCP server, spawned by a trusted host (Claude Desktop, Cursor, etc.) and communicating over stdio (or a loopback-only Streamable HTTP endpoint when `PKINATIVE_MCP_PORT` is set). The threat model assumes:

- The **host process is trusted** (the user installed it themselves).
- The **operator** who sets the environment variables is trusted.
- The **LLM controlling the host is untrusted** — it may send arbitrary, malicious tool arguments (specs, paths, limits, base64, passwords).
- **PKI inputs are untrusted** — every certificate, request, list, response, message, token, key and PKCS#12 may lie, be malformed or be hostile (deep nesting, huge integers, a million KDF iterations, a path explosion).
- The **filesystem outside `PKINATIVE_MCP_OUTPUT_DIR` must remain inaccessible** — for reads as much as for writes; with the variable unset the server performs no file I/O except the opt-in response cache under `PKINATIVE_MCP_CACHE_DIR` (see below).
- **A private key must never leave the engine**, whatever the tool arguments say.

In particular we defend against (details and CWE ids in [docs/guides/SECURITY.md](docs/guides/SECURITY.md)):

- **Secret leakage through the model transcript** — a password reaches the server through the per-call `password` input or the operator-side `PKINATIVE_MCP_PASSWORD` (`src/secrets.ts`): one source per call, both at once is `VALIDATION_ERROR`; it is never echoed in a result or an error text, never logged (only the presence of the variable is reported at boot), never written to a cache file (`carriesSecret` → not cacheable), never served as a resource. Private keys are imported into **non-extractable** Web Crypto handles; `PrivateKeyInfo.der`, keyBag and secretBag values and `authenticatedSafe` hold plaintext, so every key / PKCS#12 report is an allow-list view built field by field (`src/key-views.ts`). `tests/secret-leak.test.ts` and `assertResultClean` prove, with a needle table computed from the fixtures (PEM bodies, DER hex / base64, scalars in every encoding, encrypted-key bodies, the password), that no needle appears in any result, on stderr, in a cache file or on the stdio transcript; the gate's `dist-probe` step refuses a build that carries one.
- **Key material dumped through the generic tools** — `convert_pem` lists a private-key block but never extracts it and never produces one (`SECURITY_VIOLATION`, under any label — DER that parses as a PKCS#8 key or a PKCS#12 is refused too); `decode_asn1` refuses a key or a PKCS#12 (its previews would be key bytes); `encode_asn1` refuses a private-key label and a value that parses as key material; `resources/list` never lists and `resources/read` never serves a key-bearing extension (`.key .p8 .p12 .pfx`); no tool writes one (`resolveOutputFile` refuses them); `open_pkcs12 exportCertificates` exports certificates and CRLs, never a key.
- **Resource exhaustion through hostile DER** — the engine's 22 named, CWE-tagged `PkiLimits` on every parser loop (nesting depth, node count, integer and OID length, BER segments, PEM blocks, extensions, names, policies, chain length, policy nodes, revoked entries, OCSP responses, paths explored, signers, attributes, CMS certificates and CRLs, KDF iterations, PKCS#12 bags), raised only by explicit per-call `limits` and never above the operator ceilings `PKINATIVE_MCP_MAX_INPUT_BYTES`, `PKINATIVE_MCP_MAX_KDF_ITERATIONS`, `PKINATIVE_MCP_MAX_PATHS_EXPLORED` (`LIMIT_CEILING_EXCEEDED` names the variable; an invalid ceiling refuses to start). A hostile PBES2 key or PKCS#12 is bounded by the KDF ceiling; a hostile chain by the path ceiling; `decode_asn1` stops at 20 000 nodes.
- **Resource exhaustion through the exchange** — 256 MiB stdio frame / HTTP body cap (413), 128 MiB decoded inline PKI inputs and 128 MiB inline content per call, 1 GiB content path, 256 bundle items, 1000 OIDs per call, 4096-byte passwords, 16 `fields` paths, 50 MiB inline output, 64 KiB inline hex, 1 GiB file output, 200 diagnostics per result — every bound a constant in `src/caps.ts`, advertised by `describe_engine.caps`.
- **Sandbox escape through tool arguments** — every path (`path` of a PKI input, of a content input, of a signer; `outputPath`; a `resources/read` URI) resolves through one module (`src/sandbox.ts`): relative only, NUL / absolute / drive / UNC / `..` rejected, an extension allow-list on PKI inputs and outputs, the real path of the file read or of the parent written checked against the real sandbox (a planted symlink or junction is `SECURITY_VIOLATION`; a dangling link is `INPUT_NOT_FOUND`), absolute paths never echoed.
- **Arbitrary file overwrite** — every write opens with `wx` (`OUTPUT_EXISTS`); partial files are removed on failure; input files are never touched.
- **Weak cryptography slipping through** — SHA-1 signatures are refused on read (`PKI_CRYPTO_ALGORITHM_REFUSED`) and on write (`VALIDATION_ERROR`) unless the call says `allowSha1: true`; an RSA key has no default signature scheme (`RSA_SCHEME_REQUIRED` — `'pkcs1'` or `'pss'` must be named); only PBES2 (PBKDF2 + AES-CBC) and PBMAC1 are opened — PBES1, RC2, 3DES and the RFC 7292 Appendix B MAC are refused with the OpenSSL 3.4 conversion remedy; a PKCS#12 without a verifiable MAC is a negative verdict unless the caller states `allowUnverifiedIntegrity: true`; DSA and ML-DSA signatures are never verified (`PKI_REASON_SIGNATURE_NOT_CHECKED`), never reported valid.
- **Artefacts that do not verify** — every certificate, request and CMS signature the server produces is verified against the issuer, the subject key or the signer certificate **before** the bytes are returned (`KEY_MISMATCH` otherwise); a counter time-stamp is checked against the signer's signature value before `amend_cms` writes it; `sign_cms` parses every certificate and CRL before embedding it.
- **Prototype pollution** — `additionalProperties: false` on every JSON Schema input object; Zod strict objects at every nesting level (unknown keys are `VALIDATION_ERROR`, never silently stripped); the JSON specs of `create_certificate`, `create_csr`, `encode_asn1` and `encode_x509_structure` are depth-bounded and built so that no `__proto__` / `constructor` / `prototype` key reaches an object the server builds (`tests/prototype-pollution.test.ts`).
- **Malformed base64 and PEM at the boundary** — `data:` URIs, PEM where DER is expected, double-encoded or empty payloads are rejected with a coded error before the engine runs; a PEM label is checked before any byte is parsed (`PKI_PEM_UNEXPECTED_LABEL`); several blocks where one object is expected are refused rather than silently reduced to the first.
- **Code injection through the engine's extension points** — `ExternalSigner.produceSignature` and `PkiParseOptions.onDiagnostic` are not exposed; no tool argument can name a module, a script or a callback (`describe_engine.unexposed`).
- **DNS rebinding against the HTTP transport** — bound to `127.0.0.1`, foreign `Host` / `Origin` answered with 403, `GET` / `DELETE` with 405.
- **Unauthenticated local access to the HTTP transport** — *only when the operator opts in:* `PKINATIVE_MCP_HTTP_TOKEN` (≥ 16 characters, no whitespace; a weaker value aborts startup) makes every request to `/mcp` require `Authorization: Bearer <token>`; anything else is answered `401` with `WWW-Authenticate: Bearer realm="pkinative-mcp"` — followed by `, error="invalid_token"` only when the request carried credentials, per RFC 6750 §3.1 — before the MCP handler runs. The comparison is constant-time and the token is never logged or echoed. stdio mode needs no token (the host owns the pipe).
- **Diagnostics corrupting the stdio wire** — a diagnostics sink is installed on every engine call, so the engine's `console.warn` fallback is never reached; the gate's `smoke` step holds stdout to JSON-RPC frames only.

We do **not** currently defend against:

- **Other local processes reaching the HTTP endpoint when `PKINATIVE_MCP_HTTP_TOKEN` is unset.** The default HTTP mode (`PKINATIVE_MCP_PORT` without a token) has **no authentication**: the loopback bind and the Host / Origin guard stop browsers and remote hosts, not a process running on the same machine. Set the token whenever anything untrusted can run locally; the startup log states which mode is active (`bearer token required` / `no authentication (loopback only)`).
- **A password sent through the per-call input.** It is the model's transcript that carries it; the server keeps it out of every output, but a host that logs tool arguments has it. Prefer `PKINATIVE_MCP_PASSWORD` when the operator can set it.
- **Trust decisions the caller delegates.** A verdict is relative to the `trustAnchors` the caller names and the revocation evidence the caller supplies at the instant the caller pins; the server never fetches a CRL, an OCSP response or a chain, so stale or missing evidence is reported (`PKI_REASON_REVOCATION_UNKNOWN`, `PKI_REASON_REVOCATION_STALE`) but cannot be refreshed here. `inspect_*` results are facts, not trust — the server's instructions and every description say so.
- **A maliciously-crafted object causing a crash inside `pkinative`** beyond what its limits and fuzzing cover (the engine is responsible for parser hardening — please report such issues to both projects). Any non-`PkiError` escape is classified `ENGINE_ERROR` with `data.errorClass: internal`, never an uncoded failure.
- **Side channels.** Every signature and decryption runs through the host's Web Crypto (`node:crypto`); the pure-TypeScript hashes of `compute_fingerprint` are not constant-time, and no constant-time claim is made for the engine's parsers.
- **Anything stored in the opt-in response cache** (`PKINATIVE_MCP_CACHE_DIR`) — it writes tool output as plaintext at rest, which is why path inputs, file-mode calls, calls carrying a password or a signer, random or clock-dependent results, `describe_engine` and `draft_governance_issue` are never cached, and nothing password-accepting is cached while `PKINATIVE_MCP_PASSWORD` is set; protect the directory like the output sandbox.
- **A residual window between the realpath check and the exclusive open** in file mode — the documented posture is "use an empty or trusted destination".

## Network egress: none

The server makes **no outbound network call, ever**. There is no network code path: no `fetch`, no socket other than the opt-in loopback listener that *receives* MCP requests. No tool argument, environment variable or certificate extension (AIA, CRL distribution point) can name a URL that is fetched; nothing is sent to GitHub or to a telemetry endpoint; `draft_governance_issue` produces a local draft and stops; `create_ocsp_request` and `create_timestamp_request` produce bytes the **caller** transports. `describe_engine.network` is the constant `'none'` and every tool advertises `openWorldHint: false`.

The nine environment variables carry no egress role: `PKINATIVE_MCP_OUTPUT_DIR` (the sandbox for reads and writes; unset = no file I/O beyond the cache), `PKINATIVE_MCP_CACHE_DIR` (opt-in response cache), `PKINATIVE_MCP_PORT` (loopback HTTP transport), `PKINATIVE_MCP_HTTP_TOKEN` (**secret**, bearer token for that transport), `PKINATIVE_MCP_PASSWORD` (**secret**, the operator-side password channel), `PKINATIVE_MCP_AT` (the pinned instant), `PKINATIVE_MCP_MAX_INPUT_BYTES`, `PKINATIVE_MCP_MAX_KDF_ITERATIONS`, `PKINATIVE_MCP_MAX_PATHS_EXPLORED` (operator ceilings). All nine are declared in `server.json`, read once at boot; an invalid value refuses to start, never a silent fallback.

## Cryptographic verification scope

What the verdict tools establish, with no network access:

- **`verify_certificate_chain`** — a path from the leaf through the candidates to one of the caller's trust anchors, every link signature verified through Web Crypto (ECDSA P-256 / P-384 / P-521, RSA PKCS#1 v1.5 and RSA-PSS, Ed25519, Ed448 where the host supports it), RFC 5280 §6 validation at the pinned instant (validity, basic constraints, key usage, name constraints, policies), RFC 6125 host or IP identity, extended key usage along the path, and revocation from the CRL and OCSP bytes supplied — scope, freshness, the CRL signature, the OCSP responder's authorisation (RFC 6960 §4.2.2.2) and nonce.
- **`verify_cms`** — for every signer: the signed attributes (contentType, messageDigest, ESS signing-certificate, CMSAlgorithmProtection), the content digest, the signature, the chain as above, every counter time-stamp, and revocation from the supplied bytes plus those the message carries; `atTimeStamp: true` judges a signer's chain at its verified time-stamp.
- **`verify_timestamp`** — the imprint against what the caller says was stamped (the request, the data or the digest), the TSA signature, its chain with a critical timeStamping EKU, revocation.
- **`check_crl_revocation`**, **`check_ocsp_status`**, **`check_certificate_name`**, **`check_certificate_purpose`**, **`validate_certificate_path`** — one question each, with the same primitives.

**Out of scope** — stated in the tools' descriptions and in [docs/guides/VERIFICATION.md](docs/guides/VERIFICATION.md); do not rely on a verdict alone for legal or regulatory non-repudiation:

- a verdict is only as good as the anchors and the evidence the caller supplies at the instant the caller pins — nothing is fetched, nothing is refreshed;
- `inspect_certificate.signature`, `inspect_crl.signature`, `inspect_ocsp_response.signature`, `inspect_cms.signerSignature` and `inspect_csr.signature` are **one signature against one key** — a key check, not trust;
- `build_certificate_path` checks no signature (`PKI_REASON_SIGNATURE_NOT_CHECKED` is always present);
- DSA and ML-DSA signatures are parsed and never verified; a certificate on an unsupported curve or algorithm is `UNSUPPORTED_KEY` / `PKI_REASON_SIGNATURE_NOT_CHECKED`, never reported valid;
- a TSA's own revocation status and policy are judged only from the evidence given; a document-level validation policy (ETSI EN 319 102-1) is not implemented.

## Reproducibility

- **Instants.** Every verdict takes `at`; every artefact takes its instants (`notBefore`, `signingTime`); omitted ones fall back to `PKINATIVE_MCP_AT` when the operator pinned it, else to the wall clock — and a clock-dependent result is never cached. Instants are parsed from their ISO 8601 fields (never `Date.parse`), a date-time without a zone is read as UTC, and a date that does not exist is refused, so a verdict never depends on the host's time zone.
- **Randomness** lives in the wrapper and is reported: `serialNumber: 'random'` and `nonce: 'random'` draw from `node:crypto` and the summary says `randomSerial` / `randomNonce`; such a call is never cached. Pass explicit values for reproducible bytes.
- **Not reproducible, by design:** ECDSA and RSA-PSS signatures are randomised (the sample baseline compares those artefacts through their signed structure, `tbs`), and a PKCS#12 or an encrypted key is never written.
- **The engine pin.** `pkinative` is pinned at `^1.0.0`; the pin never moves without a release note that declares every byte change it brings, and the registries vendored under `src/data/pkinative/` move with it (`npm run gate` step `code-tables`).
- **The repository proves the promise on itself.** `npm run test:generate` drives the built server under `TZ=UTC` with every operator variable scrubbed and the instant pinned, and `npm run verify:samples` holds the 98 samples to `tests/_fixtures/samples.sha256.json` — 10 byte for byte, 3 through their TBS structure (randomised signatures), 85 through a semantic projection, each listed with its mode. The check is blocking in CI (`sample-regression` is a required status check).

## Supply chain

- **Exactly three runtime dependencies** — `pkinative` (MIT, zero dependencies), `@modelcontextprotocol/server` (Apache-2.0, see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)) and `zod` (MIT), and no new one, ever. `.npmrc` sets `ignore-scripts=true` and `audit-level=high`; every CI install is `npm ci --ignore-scripts`, so no install-time lifecycle script runs, locally or in CI.
- **Hardened workflows** — every Linux and Windows job starts with `step-security/harden-runner` (the action does not support macOS, so the macOS gate and interop legs are the documented exemption), declares least-privilege `permissions` and a timeout, and checks out with `persist-credentials: false`. Every action is pinned to a full commit SHA, one SHA per action across the tree. `dependency-review` gates every dependency change on a pull request, CodeQL and OpenSSF Scorecard run on a schedule, `npm audit --audit-level=high` runs weekly, and `node-current` runs the gate on the current Node line.
- **External tools, never dependencies** — OpenSSL 3.x (the interoperability judge), zlint and pkilint (the certificate linters of the publish profile) are runner tools found on `PATH`; on the release runner zlint is pinned by the SHA-256 of its release archive and pkilint by `--require-hashes` (`scripts/data/lint-python-requirements.txt`, when present). The 42 fixtures under `tests/fixtures/pki/` are foreign-provenance TEST-ONLY material pinned by `SHA256SUMS` and never regenerated in place; no test ever calls OpenSSL to make a fixture.
- **Trusted Publishing** — `publish.yml` runs from a protected environment (`npm-publish`, approved by the maintainer), checks that the tag equals the package version, re-runs the publish gate (`--publish --require-all`, OpenSSL required; the certificate linters when their pinned requirements file is present), and publishes through npm Trusted Publishing: a short-lived GitHub OIDC token, no long-lived npm token, with provenance. A CycloneDX SBOM (`npm sbom`) and a build-provenance attestation for the tarball and the SBOM are attached to the GitHub release. Verify an install with `npm audit signatures`.
- **One release gate** — `npx tsx scripts/gate.ts --publish --require-all` runs typecheck, lint, the code-table sync, the build, the `dist/` checks (no `console.log` in emitted JavaScript, only `src/` under `dist/`, **no byte of a test key**), the built-server smoke test over stdio (stdout must carry JSON-RPC frames only), the catalogue fingerprint, the offline `server.json` validation, the sample generation, the tests with coverage, the docs verifier, the sample baseline, the OpenSSL corpus and its two-level validation, the interop suite and the certificate linters. A skipped step fails the publish.
- **Branch and tag protection** — `.github/rulesets/main.json` and `tags.json` are the committed copies of the GitHub rulesets (required checks `ci (22)`, `ci (24)`, `os (windows-latest)`, `os (macos-latest)`, `sample-regression`, `interop (ubuntu-24.04)` and `interop (windows-latest)`; release tags are never deleted or moved); the maintainer imports them.
- **Agents never publish** — the human-in-the-loop policy (`.github/AGENT_RULES.md`, `.github/ai-governance.json`) is enforced in Claude Code sessions by `.claude/hooks/guard.mjs`, which refuses publishing, pushing, tagging and every GitHub write; the server itself has no code path that can write to GitHub.

## Compatibility promise

- The **tool API** (34 tool names, input / output schemas, the 21 wrapper codes, the `_meta.error` envelope, the 9 environment variables) is stable under [docs/API_STABILITY.md](docs/API_STABILITY.md): removals, renames and narrowings are semver-major.
- The **57 `PKI_*` error codes**, **43 `PKI_REASON_*` reasons** and **97 `PKI_DIAG_*` diagnostics** are passed through verbatim from the engine, where they are frozen; removing or renaming one is a pkinative major and therefore a pkinative-mcp major. Registries: [docs/data/errors.json](docs/data/errors.json), [docs/data/reasons.json](docs/data/reasons.json), [docs/data/diagnostics.json](docs/data/diagnostics.json).
- The **bytes** `create_certificate`, `create_csr`, `sign_cms`, `amend_cms`, `create_ocsp_request`, `create_timestamp_request`, `encode_asn1` and `encode_x509_structure` produce for pinned inputs and a deterministic key are byte-identical across patch and minor releases; a change to them is semver-major.
- **Security defaults are never weakened** in a non-major release: SHA-1 opt-in, the explicit RSA scheme, PBES2 / PBMAC1 only, the `PkiLimits` defaults, the operator ceiling defaults, the sandbox rules, the no-overwrite rule and the secret policy.

## Disclosure policy

Confirmed vulnerabilities are fixed in a patch release with a GitHub Security Advisory and a CHANGELOG entry crediting the reporter (unless anonymity is requested).

## Disclosure history

_None yet._
