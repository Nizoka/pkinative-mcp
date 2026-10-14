# Third-party notices

pkinative-mcp is published under the MIT License (see [LICENSE](LICENSE)). It
has exactly three runtime dependencies and nothing else ships in the published
package. This file lists them, the external tools the test suite relies on, the
vendored material and the specifications the code implements. Development
dependencies (never shipped) are listed in `package.json` and carry their own
licences; the publish workflow attaches a CycloneDX SBOM (`npm sbom`) naming the
exact resolved versions to every GitHub release. This file quotes the version
ranges of `package.json`, so it does not go stale with a lockfile update.

## Runtime dependencies

### pkinative — MIT

`pkinative` (`^1.0.0`), from [Nizoka/pkinative](https://github.com/Nizoka/pkinative)
(copyright 2026 Nizoka; MIT) — the zero-dependency PKI engine every tool delegates
to: ASN.1 / X.690, X.509, PKCS#10, CRL, OCSP, CMS, RFC 3161, PKCS#8 and PKCS#12
parsing and encoding, RFC 5280 path building and validation, revocation checking,
and every signature through the host's Web Crypto. The registries under
`src/data/pkinative/` (`errors.json`, `reasons.json`, `diagnostics.json`,
`limits.json`, `core-exports.json`) are copied from the engine's `docs/data/` at the
v1.0.0 tag (MIT, same author) and mirrored under `docs/data/`.

### @modelcontextprotocol/server — Apache-2.0

`@modelcontextprotocol/server` (`^2.0.0`) and its dependency
`@modelcontextprotocol/core`, from
[modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk)
(copyright Anthropic, PBC). The packages declare `"license": "Apache-2.0"`; their
`LICENSE` file records the project's transition from the MIT License to Apache-2.0 —
contributions whose authors have not granted relicensing consent remain under MIT, and
no rights beyond the applicable original licence are conveyed for them. The SDK provides
the Model Context Protocol transport and request handling — `server/discover` on
MCP 2026-07-28, the legacy `initialize` fallback, stdio framing and the Streamable HTTP
handler. pkinative-mcp registers its tools, prompts and resources on the SDK's low-level
`Server` and adds its own loopback guard and bearer-token check around the HTTP
transport (`src/http.ts`, `src/auth.ts`).

### zod — MIT

`zod` (`^4.2.0`), from [colinhacks/zod](https://github.com/colinhacks/zod) (copyright
2025 Colin McDonnell; MIT). Every `tools/call` argument is validated at the boundary
with a `.strict()` zod schema kept in lock-step with the JSON Schema advertised in
`tools/list`. zod is also a dependency of the MCP SDK; npm deduplicates it to one copy.

The full licence text of each dependency is shipped in its own package
(`node_modules/<name>/LICENSE`).

## External tools (test time and CI only, never dependencies)

- **OpenSSL 3.x** (Apache-2.0) — the interoperability judge of this server: `npm run
  validate:pki`, `tests/interop/openssl.test.ts` and the `interop` workflow run it on
  every artefact the built server writes. It is found on `PATH` (`OPENSSL_BIN`
  overrides); LibreSSL and OpenSSL < 3.0 are refused with the reason. The fixtures under
  `tests/fixtures/pki/` were produced by OpenSSL 3.5.5 running
  `tests/fixtures/make-test-pki.sh`; the files are the output of that script, released
  under this project's MIT licence, and described in
  [tests/fixtures/PROVENANCE.md](tests/fixtures/PROVENANCE.md). Every private key there is
  public TEST-ONLY material. Nothing of OpenSSL is bundled or redistributed.
- **zlint** (Apache-2.0, by the Zmap project) and **pkilint** (MIT, by DigiCert, with its
  Python dependencies under permissive licences) — the optional certificate linters of
  `tests/interop/lint.test.ts` (`npm run test:lint-certs`, the gate's publish profile).
  Installed on the release runner only, when the pinned requirements file
  `scripts/data/lint-python-requirements.txt` is present — zlint by the SHA-256 of its
  release archive, pkilint by `--require-hashes`; absent, the step is skipped with the
  reason. `scripts/validators/pkilint-driver.py` is adapted from pkinative (MIT, same
  author); the reviewed waivers live in `scripts/data/lint-waivers.json` (none today).

## Vendored material (repository only, not in the npm package)

| File | Upstream | Licence |
| --- | --- | --- |
| `src/data/pkinative/*.json`, `docs/data/{errors,reasons,diagnostics,limits,core-exports}.json` | pkinative `docs/data/` at the v1.0.0 tag | MIT (Nizoka) |
| `src/pki-input.ts`, `src/names.ts`, `src/spki.ts`, `src/time.ts`, `src/wire.ts` (adapted) | pkinative-cli `src/utils/{pki-input,names,spki,time,wire}.ts` | MIT (Nizoka) |
| `tests/fixtures/pki/`, `tests/fixtures/SHA256SUMS`, `tests/fixtures/PROVENANCE.md`, `tests/fixtures/make-test-pki.sh` | pkinative-cli `tests/fixtures/` (byte-identical copy, 2026-10-13) | MIT (Nizoka) |
| `tests/_fixtures/server.schema.2025-12-11.json` | the MCP registry `server.json` schema, published by [modelcontextprotocol/registry](https://github.com/modelcontextprotocol/registry); vendored so the gate's `server-json` step validates `server.json` offline | the registry project's own licence |
| `scripts/gate.ts`, `scripts/verify-docs.ts`, `scripts/release-prepare.ts`, `scripts/lib/{sample-fingerprint,tool-shape,mcp-surface,markdown-anchors,agent-config,prose-language}.ts` (ported) | pdfnative-mcp 1.7.0 / zipnative-mcp 1.0.0 `scripts/` | MIT (Nizoka) |

pkinative, pkinative-cli, pdfnative-mcp and zipnative-mcp: copyright (c) 2026 Nizoka, MIT License.

## Not included

No private key, certificate, CRL, OCSP response or time-stamp other than the TEST-ONLY
fixtures above is committed to this repository, and none of them ships in the package
(`files` holds `dist/`, the licence files, the README, the changelog, `server.json` and
`llms.txt`). The OpenSSL interoperability corpus and the sample set are generated at test
time under `test-output/` (git-ignored) from those fixtures.

## Specifications (references, not code)

- ITU-T X.680 / X.690 — ASN.1 and its BER / DER encoding rules
- RFC 5280 — X.509 certificates and CRLs, path validation; RFC 6818, RFC 9549 updates
- RFC 2986 — PKCS#10 certification requests; RFC 5958 — PKCS#8 asymmetric key packages; RFC 8018 — PBES2 / PBKDF2
- RFC 7292 — PKCS#12; RFC 9579 — PBMAC1 in PKCS#12
- RFC 5652 — Cryptographic Message Syntax; RFC 5035 — ESS SigningCertificateV2; RFC 6211 — CMSAlgorithmProtection
- RFC 6960 — OCSP; RFC 8954 — the OCSP nonce extension
- RFC 3161 — Time-Stamp Protocol
- RFC 6125 — server identity verification; RFC 7468 — PEM textual encodings
- RFC 6750 §3.1 — the bearer-token challenge of the HTTP transport
- Model Context Protocol specification 2026-07-28 (https://modelcontextprotocol.io)
