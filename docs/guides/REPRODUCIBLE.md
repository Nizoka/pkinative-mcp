# Reproducible output guide (for AI agents and operators)

Applies to pkinative-mcp v1.0.0 · pkinative 1.0.0.

**The promise:** the same inputs and the same pinned instants give the **same bytes** — across
calls, on every host and in every time zone — for every artefact whose signature is
deterministic, and the **same verdict** for every verification. It is what a golden-file test
suite, a reproducible build or a regulated archive needs, and it is what lets the response
cache and `structuredContent.sha256` mean something.

Three facts make it work:

1. **Every instant is written in UTC.** The engine encodes `UTCTime` / `GeneralizedTime` from
   the instant you pin, never from a local rendering; the summaries render instants as ISO 8601
   with a `Z`. A server in Kiritimati and one in Anchorage write the same DER.
2. **Nothing is drawn at random unless you ask.** A certificate serial and an OCSP / TSP nonce
   are `'random'` only when you say so; the result then says `randomSerial: true` /
   `randomNonce: true`, and such a call is never cached.
3. **Every omitted instant has one declared fallback.** `at`, `spec.notBefore` and `signingTime`
   fall back to the operator's `PKINATIVE_MCP_AT`, else to the wall clock — and the result names
   its source (`evaluatedAtSource`, `notBeforeSource`, `signingTimeSource`: `input` | `pinned` |
   `clock`), so an unpinned result is visible, and never cached.

Nothing is pinned by default: a call that pins nothing uses the wall clock, and two such calls
differ.

## TL;DR — pin everything on the call

```json
{ "tool": "create_certificate", "arguments": {
  "spec": { "serialNumber": 1, "subject": { "C": "FR", "O": "Acme", "CN": "Acme Test CA" },
            "notBefore": "2027-01-01T00:00:00Z", "validityDays": 3650,
            "extensions": { "basicConstraints": { "ca": true, "pathLen": 0 }, "keyUsage": ["keyCertSign", "cRLSign"] } },
  "signer": { "key": { "path": "fixtures/ed25519.key.pem" } },
  "encoding": "der" } }
```

Call it twice, on two machines if you like, and compare `structuredContent.sha256`: identical.
Worked example: [`create-certificate-self-signed-ca.json`](../../examples/create-certificate-self-signed-ca.json).

## What to pin, per tool

| Input | Tools | Pin with | Omitted |
| --- | --- | --- | --- |
| `at` — the instant of evaluation | every verdict tool (`verify_certificate_chain`, `verify_cms`, `verify_timestamp`, `check_crl_revocation`, `check_ocsp_status`, `validate_certificate_path`, `build_certificate_path`, …) | ISO 8601 (`2027-01-01T00:00:00Z`; a date-time without a zone is UTC) or epoch milliseconds; `'now'` is the clock, explicitly | `PKINATIVE_MCP_AT`, else the wall clock |
| `spec.notBefore` (+ `validityDays` or `notAfter`) | `create_certificate` | ISO 8601 or epoch milliseconds | `PKINATIVE_MCP_AT`, else the wall clock (whole seconds) |
| `spec.serialNumber` | `create_certificate` | an integer, a decimal string or `0x` hex you manage | `'random'` — 127 bits from `node:crypto`, `summary.randomSerial: true` |
| `signingTime` | `sign_cms` | ISO 8601, or `'none'` to omit the attribute | `PKINATIVE_MCP_AT`, else the wall clock |
| `nonce` | `create_ocsp_request` (1–32 bytes hex), `create_timestamp_request` (decimal or `0x` hex) | a value you keep for the answer | `'random'` — `summary.randomNonce: true` |
| the signer | `create_certificate`, `create_csr`, `sign_cms` | Ed25519 or RSA PKCS#1 v1.5 for byte identity | ECDSA / RSA-PSS: the signature value differs on every call (see below) |

A request (`create_csr`) carries no instant and no serial: with a deterministic signer its
bytes repeat as soon as the spec does. An encoding (`encode_asn1`, `encode_x509_structure`,
`convert_pem`, `decode_asn1 reencode`) is a pure function of its input.

## The operator pin: `PKINATIVE_MCP_AT`

`PKINATIVE_MCP_AT` (ISO 8601 or epoch milliseconds — never `'now'`) is the instant every omitted
`at`, `spec.notBefore` and `signingTime` falls back to. It follows the rules of every operator
knob:

- **Read once at boot.** A tool argument cannot change it; changing the environment of a running
  server does nothing. `describe_engine.sandbox.pinnedInstant` reports it (`null` when unset).
- **An invalid value refuses to start** with a line naming the variable. Silently falling back to
  the wall clock would leave the operator believing the output is pinned.
- **A call's own instant still wins**, so an agent that pins per call is unaffected.
- **The response cache is namespaced by the pin** (`PKINATIVE_MCP_CACHE_DIR`): a verdict cached
  under one pinned instant is never served under another, or under none; an unpinned (`clock`)
  result is never cached at all.
- `SOURCE_DATE_EPOCH` is **not** honoured: no artefact of this server takes an implicit instant —
  every instant is an explicit input or `PKINATIVE_MCP_AT`, and the result says which.

```json
{
  "mcpServers": {
    "pkinative": {
      "command": "npx",
      "args": ["-y", "pkinative-mcp"],
      "env": { "PKINATIVE_MCP_AT": "2027-01-01T00:00:00Z" }
    }
  }
}
```

With this block every verdict is evaluated and every certificate dated at the same instant, with
no per-call argument — useful for a fixture set or a replayed audit, and dangerous for a
production verdict (an expired certificate stays "valid" at the pinned instant: the
`evaluatedAtSource: 'pinned'` tell is there for that).

## What is NOT reproducible, and why

| Not covered | Why | Can it be pinned? |
| --- | --- | --- |
| An ECDSA or RSA-PSS signature value | Web Crypto draws a fresh random per signature (no RFC 6979); the signed part — the TBSCertificate, the CertificationRequestInfo, the signed attributes — is identical | No — use Ed25519 or RSA PKCS#1 v1.5 when the bytes must repeat; the baseline compares such artefacts in `tbs` mode |
| A `'random'` serial or nonce | 127 / 63 random bits from `node:crypto`, reported as `randomSerial` / `randomNonce`; never cached | **Yes** — pass a value |
| A time-stamp token, an OCSP response, a CRL | Produced by the TSA, the responder or the CA — this server has no writer for them; they carry the issuer's own clock and nonce | No — they are inputs you fetched |
| A PKCS#12 file or an encrypted PKCS#8 key | Never written here (no writer, by doctrine); a fresh salt and IV per export would defeat it anyway | No |
| A verdict under the wall clock | `at` omitted without `PKINATIVE_MCP_AT`; `evaluatedAtSource: 'clock'` says so; never cached | **Yes** — pass `at` |

## Proving it from an agent

Call the tool twice with identical arguments and compare `structuredContent.sha256` (or the
embedded resource bytes). With `PKINATIVE_MCP_CACHE_DIR` set, a repeated call may be served from
the cache (`_meta.cached: true`) — the bytes are then the earlier result, which proves nothing;
compare against a server without the cache, or across two hosts. Feed the bytes back to the
matching `inspect_*` tool (`compute_fingerprint` for the exact DER digest) to prove the two
artefacts are the same object and not merely the same size.

## How the repository proves it

- **A two-time-zone test on the built server.**
  [`tests/reproducible-build.test.ts`](../../tests/reproducible-build.test.ts) spawns
  `dist/cli.js` under `Pacific/Kiritimati` (UTC+14) and `America/Anchorage` (UTC−9), on opposite
  sides of the date line for the pinned instant, drives the same `create_certificate` (Ed25519,
  pinned `notBefore`, explicit serial) and `create_timestamp_request` (fixed nonce) through each,
  and compares the bytes with each other and with the in-process UTC call. Unit tests cannot
  show this: the test runner pins `TZ=UTC`.
- **A 98-sample byte baseline.** `npm run test:generate` drives the **built** server under
  `TZ=UTC`, with every operator variable scrubbed, `PKINATIVE_MCP_AT=2027-01-01T00:00:00Z` and a
  sandbox holding the fixtures, over every hermetic example; `npm run verify:samples` holds the
  98 samples to [`tests/_fixtures/samples.sha256.json`](../../tests/_fixtures/samples.sha256.json)
  in three modes recorded per sample (`scripts/lib/sample-fingerprint.ts`):

  | Mode | What is hashed | Samples | Why |
  | --- | --- | --- | --- |
  | `bytes` | the artefact, byte for byte | 10 | deterministic signers (Ed25519, RSA PKCS#1 v1.5), requests, encodings |
  | `tbs` | the signed part only (the first element of the outer SEQUENCE) | 3 | ECDSA / RSA-PSS: the signature value is randomised, the structure is not |
  | `semantic` | a canonical projection of the result, volatile members dropped | 85 | reports and verdicts, and artefacts drawn with `'random'` |

  ```bash
  npm run build && npm run test:generate && npm run verify:samples
  ```

  The baseline is a chain: an unchanged entry keeps the release it was anchored at (`since`), so
  a byte change is always attributable; `tests/samples-regression.test.ts` holds the chain and
  the justification of every `tbs` row, read back from the example that produced it. A sample
  moved from `bytes` to `tbs` or `semantic` is a byte change in disguise.
- **The OpenSSL corpus, produced twice.** Every `deterministic: true` entry of the conformance
  corpus (14 of the 23) is generated twice and must hash the same (`sha256Again` in the
  manifest) before OpenSSL reads it ([CONFORMANCE.md](CONFORMANCE.md)).

An intended output change is rebaselined on purpose (`npx tsx scripts/verify-samples.ts --update`)
and declared in the release note; a default artefact's bytes changing for the same deterministic
inputs is semver-major ([API_STABILITY.md](../API_STABILITY.md)). The baseline is never refreshed
to silence a surprise.

## See also

- [SIGNING.md](SIGNING.md#reproducibility) — the deterministic signers and the `tbs` baseline mode.
- [VERIFICATION.md](VERIFICATION.md) — `at` and `evaluatedAtSource` on every verdict.
- [../AGENT_CONTRACT.md](../AGENT_CONTRACT.md) §4 — the operator variables and the cache gate.
- [../../SECURITY.md](../../SECURITY.md#reproducibility) — the same promise in the threat model.
