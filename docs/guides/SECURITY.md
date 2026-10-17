# Security model — pkinative-mcp

> pkinative-mcp treats every PKI object as untrusted input, the LLM driving it as an
> untrusted caller, and a private key as something that must never cross the wire in any
> direction. The engine's default code path is the safe one; the server adds a single
> filesystem boundary, byte caps on every exchange, operator ceilings that no tool argument
> can exceed, two password channels that never meet a log, and allow-list views that cannot
> leak a key byte whatever the engine returns. Refusals carry a frozen code and name the
> remedy.

This guide is the threat-and-defence view. The reporting policy, supported versions and
release-integrity statement are in [`SECURITY.md`](../../SECURITY.md) at the repository
root; the engine's own model is
[pkinative `SECURITY.md`](https://github.com/Nizoka/pkinative/blob/main/SECURITY.md).

---

## 1. Why PKI needs this

A certificate is attacker-controlled input by definition: it arrives from the other end of
the connection, it is parsed before anything about it is known, and the parser's job is to
decide whether to trust it. Most historical PKI CVEs are parser differentials (two readers
disagreeing about what a Name or an extension says), resource exhaustion (a path-building
search that explodes, a PKCS#12 declaring 2^31 PBKDF2 iterations), downgrade (SHA-1,
RC2, a missing MAC) and confusion of a key check for a trust decision. All four are
addressed structurally by the engine, and the server never re-implements a byte of ASN.1,
X.509, CMS or PKCS#12 parsing that could reintroduce them. The server adds the one risk
the engine does not have — it holds keys, passwords and a filesystem — and bounds it.

## 2. Trust boundaries

| Party | Trust | Consequence |
|---|---|---|
| The **host process** (Claude Desktop, Cursor, an HTTP client on loopback) | trusted | It spawned the server, chose the environment, and owns the pipe — and its transcript holds every `password` input. |
| The **operator** who sets the environment variables | trusted | The sandbox directory, the ceilings, the pinned instant, the operator password and the HTTP token are their decisions. |
| The **LLM** controlling the host | **untrusted** | Every tool argument may be malicious: paths, limits, base64, specs, a `nodePath`, a `fields` list. |
| **PKI inputs** (certificates, CRLs, responses, CMS, tokens, keys, PKCS#12 files) | **untrusted** | Every tag, length, name, extension, iteration count and signature may lie. |
| **Trust anchors** | what the caller says they are | A verdict is relative to the anchors named in the call; no system store is consulted. |
| The **filesystem outside `PKINATIVE_MCP_OUTPUT_DIR`** | must remain inaccessible | The server neither reads nor writes anywhere else, except the opt-in response cache under `PKINATIVE_MCP_CACHE_DIR` (§6). |
| The **network** | does not exist | There is no network code path: no CRL, OCSP, AIA or TSA fetch, no telemetry, no URL from any argument, no operator-configurable endpoint. |

## 3. Threats and defences (engine guards, on by default)

| Threat | Defence | CWE | Where an agent sees it |
|---|---|---|---|
| Hostile DER: truncated, overflowing or non-minimal lengths, indefinite forms, constructed strings, deep nesting, giant INTEGERs | strict X.690 DER by default (BER only under `encodingRules: 'ber'`, reported as `PKI_DIAG_BER_CONSTRUCT_ACCEPTED`); the decoder is iterative and bounded by `maxDepth` 64, `maxNodes` 200 000, `maxIntegerBytes` 8 192, `maxOidBytes` 256, `maxBerSegments` 10 000 | CWE-125 / CWE-130 / CWE-674 / CWE-770 | `PKI_ASN1_*` (19 codes), `PKI_LIMIT_EXCEEDED` with `data.limit` |
| Parser differentials in names, extensions, GeneralNames | one reader, RFC 5280 field by field; duplicate extensions refused (`PKI_X509_EXTENSION_DUPLICATE`), unknown critical extensions reported and refused at validation (`PKI_REASON_UNKNOWN_CRITICAL_EXTENSION`), malformed values refused (`PKI_X509_EXTENSION_MALFORMED`) rather than guessed | CWE-436 / CWE-1286 | `PKI_X509_*`, the diagnostics |
| Path-building explosion (RFC 5280 §6 is exponential in the candidate set) | `maxPathsExplored` 1 000 (the §6 work bound), `maxChainLength` 10, `maxPolicyNodes` 4 096 — raised per call only under the operator ceiling | CWE-400 | `PKI_REASON_LIMIT_EXCEEDED` in a verdict; `LIMIT_CEILING_EXCEEDED` on a raise above `PKINATIVE_MCP_MAX_PATHS_EXPLORED` |
| KDF denial of service (a PKCS#12 or PBES2 key declaring billions of PBKDF2 iterations the host would run inside Web Crypto) | `maxKdfIterations` 10 000 000 per derivation and `maxPkcs12KdfIterations` 10 000 000 per file, under `PKINATIVE_MCP_MAX_KDF_ITERATIONS` | CWE-400 | `PKI_LIMIT_EXCEEDED`; `PKI_DIAG_KEY_KDF_ITERATIONS_LOW` the other way |
| Giant CRLs, OCSP responses, SignedData bags | `maxRevokedCertificates` 1 000 000 walked by a lazy cursor, `maxOcspSingleResponses` 256, `maxSignerInfos` 64, `maxCmsCertificatesAndCrls` 1 024, `maxAttributes` 256, `maxPkcs12Bags` 4 096 | CWE-400 | `PKI_LIMIT_EXCEEDED` |
| A verified signature mistaken for trust | the read tools report ONE signature against ONE key as a fact (`signature.valid`, `signerSignature`); only `verify_certificate_chain` / `verify_cms` / `verify_timestamp` judge a path to the anchors **you** name, at an instant, with name, purpose, policy and revocation | — | `PKI_REASON_NO_TRUST_ANCHOR`, `PKI_REASON_ISSUER_NOT_FOUND`, `PKI_REASON_NOT_A_CA` |
| Downgrade: SHA-1 signatures, MD2 / MD5 | SHA-1 refused by default (`PKI_CRYPTO_ALGORITHM_REFUSED`; `allowSha1: true` is an explicit, per-call archival decision, never a default), MD2 / MD5 never verified | CWE-327 | `PKI_CRYPTO_ALGORITHM_REFUSED`, `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` |
| Legacy PKCS#12 / PBES1 (RC2, 3DES, the RFC 7292 Appendix B KDF, a missing MAC) | only PBES2 (PBKDF2 + AES-CBC) decrypted and PBMAC1 (RFC 9579) verified; the rest refused with the OpenSSL 3.4 conversion remedy; an unverified MAC is a negative verdict unless `allowUnverifiedIntegrity: true` | CWE-327 / CWE-354 | `PKI_KEY_ENCRYPTION_UNSUPPORTED`, `PKI_KEY_MAC_UNSUPPORTED`, `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED` |
| Algorithm substitution in CMS (RFC 6211) | digestAlgorithm, signatureAlgorithm and CMSAlgorithmProtection must agree; ESS signing-certificate must name the verifying certificate; `requireAlgorithmProtection` / `requireSigningCertificate` enforce the profile | CWE-757 | `PKI_REASON_CMS_ALGORITHM_MISMATCH`, `PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH` |
| Replayed or substituted OCSP / TSA answers | the nonce must be echoed (`check_ocsp_status nonce` / `requireNonce`, `verify_timestamp request`), the CertID / imprint must match, freshness is judged at `at` | CWE-294 | `PKI_REASON_REVOCATION_MISMATCH`, `PKI_REASON_TSP_REQUEST_MISMATCH`, `PKI_REASON_TSP_IMPRINT_MISMATCH`, `PKI_REASON_REVOCATION_STALE` |
| Unauthorised OCSP responders | RFC 6960 §4.2.2.2: the CA, a delegate the CA issued with id-kp-OCSPSigning, or an explicit `responderTrusted: true` | — | `responderAuthorized: false` in the verdict |
| RSA key used under the wrong scheme | no default scheme (`rsaScheme: 'pkcs1' \| 'pss'` required; an id-RSASSA-PSS key signs PSS only) | CWE-757 | `RSA_SCHEME_REQUIRED`, `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED` |
| Keys of a kind Web Crypto cannot sign with (DSA, X25519, non-NIST curves, ML-DSA) | parsed and described, never signed with or verified: a refusal, not a silent false | — | `UNSUPPORTED_KEY`, `PKI_CRYPTO_KEY_UNSUPPORTED`, `PKI_REASON_SIGNATURE_NOT_CHECKED` |

Every relaxation is an explicit, named input (`encodingRules`, `pemMode`, `allowSha1`,
`allowTrailingData`, `allowUnverifiedIntegrity`, `allowCommonNameFallback`,
`allowNonCriticalTimeStampingEku`, `responderTrusted`, `restrictIssuers`, `limits`) — never a
silent default — and every refusal carries the frozen `PKI_*` code in `_meta.error.code`
with the engine message that names the remedy. The machine-readable registries are
[`../data/errors.json`](../data/errors.json), [`../data/reasons.json`](../data/reasons.json)
and [`../data/diagnostics.json`](../data/diagnostics.json).

## 4. What the server adds on top

| Threat | Defence | CWE |
|---|---|---|
| A private key leaving in a result, a message, a log, a cache file or a resource | the engine imports every key **non-extractable** (Web Crypto); `src/key-views.ts` builds every key / PKCS#12 report field by field from an allow-list (`PrivateKeyView`, `EncryptedKeyView`, `MacView`, `BagView`, `CryptoKeyView` — the interfaces ARE the allow-list), never by serialising the engine object; `src/views.ts` strips every raw DER echo (`der`, `tbsDer`, `valueDer`, `raw`); `convert_pem extractIndex`, `decode_asn1`, `encode_asn1` and `resources/read` refuse private-key material by PEM label **and** by parsing the DER as PKCS#8 / PKCS#12 (`refuseSecretDer`); nothing writes a key-bearing file (`resolveOutputFile` refuses `.key .p8 .p12 .pfx`, the engine has no writer); `tests/secret-leak.test.ts` sweeps every result, stderr, the cache and the stdio transcript with needles computed from the fixtures, and `dist-probe` sweeps the emitted JavaScript | CWE-200 / CWE-312 / CWE-522 |
| A password in the transcript, a log or an error | two channels, never both: the `password` input (the documented trade-off — it lands in the host's transcript) or `PKINATIVE_MCP_PASSWORD` (it does not); both at once is `VALIDATION_ERROR`; `redact()` strips the value from every error message that leaves a handler which held it; `parseInput` never echoes a rejected password value; only the **presence** of the variable is logged; a call carrying a password or a signer is never cached, nor any password-accepting tool while the variable is set | CWE-532 / CWE-256 |
| The LLM naming a file outside the sandbox (`path`, `content.path`, `outputPath`) | `src/sandbox.ts` is the single boundary: relative paths only; NUL, absolute, Windows-absolute and UNC rejected (also on POSIX); `path.relative` containment; extension allow-lists (PKI inputs, outputs minus the key-bearing ones, text); `INPUT_NOT_FOUND` messages carry the relative path only; nothing reads without `PKINATIVE_MCP_OUTPUT_DIR` set | CWE-22 / CWE-73 |
| A symlink or junction pre-planted inside the sandbox redirecting a write **or a read** outside it | writes: after every `mkdir -p`, the **real** path of the parent must still lie inside the real sandbox; reads (`path`, `content.path`, `resources/read`): the **real** path of the file itself must lie inside it — the check is on the file, not only its parent, so a file symlink cannot slip past (`assertRealpathInside`) — `SECURITY_VIOLATION` otherwise, `INPUT_NOT_FOUND` for a dangling link, and no absolute path ever leaves in the message | CWE-59 |
| Arbitrary file overwrite | every write opens with `wx` (`OUTPUT_EXISTS` when the target exists); a partial file is removed on failure; an input file is never touched | CWE-73 |
| Resource exhaustion through the JSON-RPC exchange | the `src/caps.ts` envelope: 256 MiB stdio frame / HTTP body (413), 128 MiB decoded inline PKI input per call (the sum, through the parse context's running budget), 128 MiB inline content / 1 GiB by path, 64 MiB decoded size of one PKI object (the effective `maxInputBytes`, under its ceiling), 50 MiB inline output, 1 GiB file output, 64 KiB inline hex, 256 bundle items, 256 inline attributes, 1000 OIDs, 2000 list rows, 1 MiB SHAKE, 4096-character passwords, 200 diagnostics, 16 `fields`, 20 000 ASN.1 nodes; `resources/list` ≤ 1000 files at depth ≤ 8, `resources/read` ≤ 50 MiB | CWE-400 |
| The LLM raising engine limits to disable the bounds | per-call `limits` are capped by the **operator ceilings** `PKINATIVE_MCP_MAX_INPUT_BYTES`, `PKINATIVE_MCP_MAX_KDF_ITERATIONS`, `PKINATIVE_MCP_MAX_PATHS_EXPLORED` (`LIMIT_CEILING_EXCEEDED` names the variable in `data.env`); a ceiling below an engine default tightens it silently; an invalid ceiling refuses to start; there is no "unbounded" (every value is an integer ≥ 1) | CWE-400 / CWE-409 |
| Prototype pollution / unexpected keys | `additionalProperties: false` on every JSON Schema object; Zod `z.strictObject` at every nesting level (unknown keys → `VALIDATION_ERROR`, never stripped); the loose spec objects (`spec`, the ASN.1 node spec) are walked by name and refuse or ignore `__proto__` / `constructor` without touching `Object.prototype` (`tests/prototype-pollution.test.ts`) | CWE-1321 |
| Malformed base64 reaching the parser | `src/base64.ts` diagnoses `data:` URIs, PEM text, nested URIs, double encoding and empty payloads before the engine sees a byte, with the remedy in the message | — |
| Code injection through the engine's extension points | `ExternalSigner.produceSignature` and `PkiParseOptions.onDiagnostic` are **unexposed** — no tool argument can name a function, a module or a worker; `describe_engine.unexposed` says so with the rationale | CWE-94 |
| A signed artefact that does not match its key or certificate (a confused-deputy issuance) | every artefact tool verifies its own output against the signer's public key before the bytes return — `create_certificate` against the issuer or itself, `create_csr` the proof of possession, `sign_cms` the signer certificate — `KEY_MISMATCH` otherwise; `amend_cms` checks a token's imprint against the signature value before it writes | CWE-345 |
| Non-reproducible or guessable randomness | the engine generates nothing random; the wrapper draws `'random'` serials (127 bits) and nonces (16 bytes / 63 bits) from `node:crypto` only when asked, reports it (`randomSerial`, `randomNonce`), and never caches such a call | CWE-330 |
| DNS rebinding against the HTTP transport | bound to `127.0.0.1`; foreign `Host` / `Origin` answered 403; `GET` / `DELETE` 405; a fresh connection-less `Server` per request | CWE-350 |
| Unauthenticated local access to the HTTP transport | *only when the operator opts in:* `PKINATIVE_MCP_HTTP_TOKEN` (≥ 16 chars, no whitespace; a weaker value aborts startup) makes every `/mcp` request require `Authorization: Bearer <token>`, else 401 + `WWW-Authenticate` (RFC 6750 §3.1); constant-time comparison; never logged | CWE-306 |
| Listener exhaustion on keep-alive HTTP connections | disconnect detection is attached per response, not per socket | CWE-400 |
| Diagnostics corrupting the stdio wire | the engine's `console.warn` fallback is never reached: a diagnostic sink is installed on every engine call (the three 1.0.0 entry points without an `onDiagnostic` option are pre-parsed through one) and the rows travel in the result | — |
| Information leakage in errors | absolute sandbox paths, the HTTP token, passwords, key bytes and errno details beyond the code never appear in `_meta.error` or on stderr | CWE-209 |
| A clock-dependent verdict served from the cache | the cache gate refuses an unpinned `at` / `notBefore` / `signingTime`, a `'now'`, a `'random'`, a `path`, a secret, file output, `describe_engine` and `draft_governance_issue`; the key namespace carries the tool API, package and engine versions | — |

## 5. Limits and ceilings — the fragment every engine tool accepts

```jsonc
"limits": {
  "maxInputBytes": 67108864,         // ≤ PKINATIVE_MCP_MAX_INPUT_BYTES (also the decoded cap of one PKI object)
  "maxDepth": 64,
  "maxNodes": 200000,
  "maxIntegerBytes": 8192,
  "maxOidBytes": 256,
  "maxBerSegments": 10000,
  "maxPemBlocks": 10000,
  "maxExtensions": 256,
  "maxGeneralNames": 10000,
  "maxNameAttributes": 1024,
  "maxPolicies": 1024,
  "maxChainLength": 10,
  "maxPolicyNodes": 4096,
  "maxRevokedCertificates": 1000000,
  "maxOcspSingleResponses": 256,
  "maxPathsExplored": 1000,          // ≤ PKINATIVE_MCP_MAX_PATHS_EXPLORED
  "maxSignerInfos": 64,
  "maxAttributes": 256,
  "maxCmsCertificatesAndCrls": 1024,
  "maxKdfIterations": 10000000,      // ≤ PKINATIVE_MCP_MAX_KDF_ITERATIONS
  "maxPkcs12Bags": 4096,
  "maxPkcs12KdfIterations": 10000000 // ≤ PKINATIVE_MCP_MAX_KDF_ITERATIONS
}
```

The values above are the engine defaults (`DEFAULT_PKI_LIMITS`, reported by
`describe_engine.defaultLimits`, CWE-tagged in [`../data/limits.json`](../data/limits.json)).
Absent keys keep them; `Infinity` is not JSON and there is no "unbounded": "disable" is
spelled as the ceiling. Raising a bound is always an explicit decision for **trusted input
only**; the operator decides how far an agent may go by setting the three ceilings in the
server environment, and `describe_engine.ceilings` reports them.

## 6. The sandbox — reads and writes

`PKINATIVE_MCP_OUTPUT_DIR` is the **only** directory the server touches, for reading
(`path` inputs, `content.path`, `resources/read`) as much as for writing (`outputMode: 'file'`,
governance drafts, PEM bundles). Unset, the server performs no file I/O except the opt-in
response cache under `PKINATIVE_MCP_CACHE_DIR` and works on inline PEM / base64 only — the
recommended posture when the host does not need files.

When set: give it a directory the host owns, keep it empty or trusted (a pre-existing
symlink or junction inside it is detected by the realpath check on reads and writes alike,
but "use an empty destination" is the documented posture), and remember that everything
in it is enumerable through `resources/list` and readable through `resources/read`
(≤ 50 MiB per read) by the same host — **except key material**, which is never listed
and never served: refused by extension (`.key .p8 .p12 .pfx`) and by **content** anywhere in
the file (a PEM key after a prefix, hidden among many blocks, a raw DER key behind junk,
base64 key material in a text file), whatever the name. The same content test guards
`convert_pem encode` (exactly one DER value) and the content inputs (`content.path` of
`sign_cms`, `data.path` of `create_timestamp_request`): content is never a key.
Drop a `.key` or `.p12` in it only for the key and signer tools to read;
prefer `PKINATIVE_MCP_PASSWORD` to a `password` input for its password.

The cache (`PKINATIVE_MCP_CACHE_DIR`) stores tool output in plaintext at rest; the gate
keeps every password-bearing, signer-bearing, path-referencing, file-writing and
clock-dependent call out of it, and refusals are never persisted.

## 7. Symlink handling, in one place

- Reading: `path` / `content.path` / `resources/read` go through the same resolver **and**
  the same realpath check, applied to the file itself: a file or directory link whose real
  location leaves the sandbox is refused (`SECURITY_VIOLATION`), a dangling link is
  `INPUT_NOT_FOUND`, and a regular file still reads.
- Writing: a symlink **on disk** inside the sandbox is followed by `realpath` before any
  write, and a parent whose real location leaves the sandbox is refused
  (`SECURITY_VIOLATION`); an existing target — link or file — is `OUTPUT_EXISTS`.
- Nothing the server writes is ever a link, and nothing it reads is ever executed.

## 8. The two password channels, in one place

| Channel | Where the secret lives | When to use it |
|---|---|---|
| the `password` input (top level, or `signer.password`) | in the tool call — the host's transcript, the model's context | a throwaway or TEST-ONLY password; interactive use |
| `PKINATIVE_MCP_PASSWORD` | the server's environment only | production keys and PKCS#12 files; anything the model should never see |

Both at once is `VALIDATION_ERROR` ("give the password once"); neither when one is needed is
`SECRET_REQUIRED`; a wrong one is `PKI_CRYPTO_DECRYPTION_FAILED` (or `integrity: 'mismatch'`
with `PKI_REASON_PKCS12_MAC_MISMATCH` on `open_pkcs12`) and the value is never echoed. A tool
that does not open a key does not accept a `password` (its presence is `VALIDATION_ERROR`).
The value never reaches stdout, stderr, a message, `_meta.error.data`, a cache key or a
log; the needle tests hold it.

## 9. Conformant does not mean safe

Every artefact the server writes is read and verified by OpenSSL 3 in CI
([`CONFORMANCE.md`](CONFORMANCE.md)). Four of the five refusal canaries of that corpus —
a SHA-1-signed CA, a certificate signed from a legacy PKCS#12, an RSA key without a stated
scheme, a validity window ending before it starts — are requests OpenSSL would fulfil:
conformance constrains the bytes, not the policy. That is precisely why the refusals above
exist on top of conformance, and why the gate records those canaries as part of the
verdict instead of pretending the format catches what it does not.

## 10. What the server never does

No network egress of any kind (no CRL / OCSP / AIA / TSA fetch, no telemetry, no GitHub, no
URL from any source — there is no network code path to configure), no key generation, no
key export, no writer for PKCS#8 / PKCS#12 / CRL / OCSP response / time-stamp response, no
`eval`, no dynamic import of caller-named modules, no filesystem access outside the sandbox
except the opt-in cache, no overwrite, no silent fallback on a bad configuration (a weak
token, an invalid ceiling or an invalid `PKINATIVE_MCP_AT` exits 1 with one `fatal:` line).
The supply chain is three runtime dependencies; CI runs CodeQL, OpenSSF Scorecard,
dependency review, `npm audit`, the OpenSSL gate on Linux, Windows and macOS, and the
package is published through OIDC Trusted Publishing with provenance, a CycloneDX SBOM and a
build attestation ([`SECURITY.md`](../../SECURITY.md) → *Release integrity*).

## 11. Reporting

Privately, via GitHub Security Advisories — see [`SECURITY.md`](../../SECURITY.md).
Engine-level findings (a parser, a verifier, a limit, a `PKI_*` code raised on a valid
object) belong to
[Nizoka/pkinative](https://github.com/Nizoka/pkinative/security/advisories/new);
report to both when unsure.
