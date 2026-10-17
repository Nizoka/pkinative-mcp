---
description: "Use when touching secrets, key views, the signer, the sandbox, file IO, the HTTP transport, the cache, resources, input bounds or the workflows."
applyTo: "src/secrets.ts,src/key-views.ts,src/signer.ts,src/sandbox.ts,src/http.ts,src/auth.ts,src/cache.ts,src/resources.ts,src/pki-input.ts,src/content-input.ts,src/output.ts,src/caps.ts,src/tools/sign-cms.ts,src/tools/convert-pem.ts,src/server.ts,.github/workflows/**"
---
# Security Standards

## Secrets
- A password reaches the server through the per-call `password` input or the operator-side `PKINATIVE_MCP_PASSWORD` (`src/secrets.ts`: one source per call, both at once is `VALIDATION_ERROR`; ≤ 4096 bytes). It is never logged, never echoed in an error text, never written to a cache file (`carriesSecret` → not cacheable), never served as a resource, never part of a result; `redact` scrubs every outgoing text. Only the PRESENCE of `PKINATIVE_MCP_PASSWORD` / `PKINATIVE_MCP_HTTP_TOKEN` is logged at boot.
- Key material never leaves pkinative's non-extractable Web Crypto keys. `PrivateKeyInfo.der`, keyBag and secretBag values and `authenticatedSafe` hold plaintext: reports over them are ALLOW-LIST views built field by field in `src/key-views.ts` (algorithm, key id, encryption parameters, bag types, MAC parameters), and `assertResultClean` (tests/_pki-assert.ts, needles from tests/_secrets.ts) proves no key byte, scalar, JWK member, encrypted-key body or password is printed by any key or password-bearing result, on stderr, in a cache file or in the stdio transcript.
- The signer (`src/signer.ts`) imports a PKCS#8 / PKCS#12 key into a `SigningKey` and returns `SIGNING_KEY_VIEW_SCHEMA` facts only; a signing call is never cached.

## Doctrine (never add)
- No key generation, no key export (no JWK `d`, no PEM of a private key, no `.key` / `.p8` / `.p12` / `.pfx` written or served).
- No PKCS#8 / PKCS#12 / CRL / OCSP-response / time-stamp-response writer.
- No network code path, EVER — not behind an env var, not for CRL / OCSP / TSA / AIA fetching, not for telemetry, not for GitHub. No `fetch`, `https`, `dns`, `tls` or socket code anywhere; `node:http` only in `src/http.ts` (which only LISTENS on loopback) and the dynamic import of `src/cli.ts` that starts it; `node:net` only for the pure `isIPv4` / `isIPv6` parsers of `src/names.ts` (`tests/no-network.test.ts` holds this). A tool argument never carries a URL that is fetched; revocation evidence and time-stamp tokens are inputs.
- SHA-1 is opt-in per call (`allowSha1`), the RSA scheme (PKCS#1 v1.5 / PSS) is explicit, PBES2 and PBMAC1 are the only password-based forms accepted; PBES1 / RC2 / 3DES / legacy SHA-1-MAC PKCS#12 are refused with the engine's remedy. Weakening any default is a human decision recorded in the PR (.github/AGENT_RULES.md rule 6).

## Filesystem confinement
- ONE boundary: `PKINATIVE_MCP_OUTPUT_DIR` (`src/sandbox.ts`). Every read (`path` of a PKI input, of a content input, of a signer) and write (`outputPath`, governance drafts) resolves through it; unset ⇒ file I/O is disabled and the tools work on inline PEM / base64 only.
- Reject: NUL bytes, absolute / Windows drive / UNC paths, `..` traversal, an output name outside `OUTPUT_EXTENSIONS` (`.md` / `.txt` / `.json` / `.pem` for text outputs); check the REALPATH of the parent after `mkdir -p` (a symlinked or junctioned directory must not redirect a write) AND the realpath of every file read (`resolveSandboxPath` — a planted symlink or junction must not redirect a read; the check is on the file itself, not only its parent); write exclusively (`wx`) — the server never overwrites (`OUTPUT_EXISTS`).
- Key-bearing extensions (`SECRET_EXTENSIONS`: `.key .p8 .p12 .pfx`) are read by the key tools only, NEVER written (`resolveOutputFile` refuses them) and NEVER listed or served by `resources/*`.
- Never leak an absolute path or an OS error message in an error text or on stderr: relative labels only. The one documented absolute path is `artefact.filePath` of a successful file-mode result (the host needs it to open the file).

## Bounds and ceilings
- Every inline input is capped by `src/caps.ts` (128 MiB decoded, 64 KiB hex, 256 bundle items, 1000 OIDs, 4096-byte password, 20 000 ASN.1 nodes …); every PKI object by `limits.maxInputBytes`; the 22 engine limits widen for one call only and never above the operator ceilings `PKINATIVE_MCP_MAX_INPUT_BYTES` / `PKINATIVE_MCP_MAX_KDF_ITERATIONS` / `PKINATIVE_MCP_MAX_PATHS_EXPLORED` (`LIMIT_CEILING_EXCEEDED`). A hostile PBES2 key or PKCS#12 is bounded by the KDF ceiling; a hostile chain by the path ceiling. Never add a ceiling a tool argument can raise.
- Specs (`src/x509-spec.ts`, `src/asn1-spec.ts`) are depth-bounded, built with `Object.create(null)`-safe parsing: no `__proto__` / `constructor` / `prototype` key reaches an object the server builds.

## Network and HTTP
- HTTP mode (`PKINATIVE_MCP_PORT`) binds 127.0.0.1 and checks Host / Origin (`src/http.ts`, 403); `PKINATIVE_MCP_HTTP_TOKEN` (`src/auth.ts`, ≥ 16 chars, no whitespace, constant-time compare, RFC 6750 challenge) is the only authentication — recommend it, and document that without it any local process can reach the endpoint.
- The cache (`PKINATIVE_MCP_CACHE_DIR`) stores results in plaintext: never cache path inputs, file outputs, a call carrying a password or a signer, a clock-dependent or random result, or anything environment-dependent.

## Dependency and CI security
- Exactly three runtime dependencies (pkinative, `@modelcontextprotocol/server`, zod); adding one is a governance blocker (`dependency-review.yml`, tests/tools/workflows.test.ts).
- npm publish via OIDC Trusted Publishing only (`publish.yml`, environment `npm-publish`, no NPM_TOKEN); the attest job attaches a CycloneDX SBOM and a Sigstore attestation.
- Every action is pinned by a 40-hex commit SHA with a `# vX.Y.Z` comment, one SHA per action across the tree; every checkout uses `persist-credentials: false`; every job starts with `step-security/harden-runner` (skipped on macOS only); `npm ci --ignore-scripts` everywhere; `permissions: contents: read` at the top of every workflow. OpenSSL, zlint and pkilint are runner tools, never dependencies; zlint is pinned by archive SHA-256, pkilint by `--require-hashes`.
- The OpenSSL fixtures (`tests/fixtures/pki/`, 42 files, `SHA256SUMS`) are foreign-provenance TEST-ONLY material and are never regenerated in place; a test never calls OpenSSL to make a fixture.
