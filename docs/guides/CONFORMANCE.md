# Conformance and validation — the OpenSSL gate

> PKI has no veraPDF either — but it has something better placed: the implementation every
> other one is measured against. This server ships a corpus of every artefact kind the tools
> write, a level-0 round trip through the engine, and a level-1 pass in which **OpenSSL 3**
> reads, dumps and verifies each one. This page is the authority story: what "conformant"
> means for a certificate, a request, a CMS signature or a time-stamp request, who checks it,
> what a pass proves — and what it does not.

The corpus table is [`scripts/lib/pki-corpus.ts`](../../scripts/lib/pki-corpus.ts); the
declared counts and the OpenSSL command families are
[`docs/data/interop.json`](../data/interop.json); the sibling story for the CLI is in
pkinative-cli's own interop suite. This document describes the gate as it runs in **this**
repository.

---

## 1. Why OpenSSL, and why it is not a dependency

An engine that validates its own output attests the engine with the engine. The engine's
readers are strict (X.690 DER, RFC 5280 field by field), which catches a malformed
structure; they cannot catch a structure that is well-formed and wrong — a subjectAltName
encoded under the right OID with the wrong tag, a CMS whose signed attributes OpenSSL
sorts differently, an OCSP request whose CertID hashes the wrong octets. For that you need
a foreign reader, and the foreign reader that matters is OpenSSL: it is what every CA,
TSA, responder and relying party on the other side of the wire runs.

OpenSSL is therefore an **external CI tool installed on the runner image**, never bundled:
the package keeps its three runtime dependencies. The judge is located on `PATH` (or
through `OPENSSL_BIN`), qualified by `openssl version` — **LibreSSL** (what macOS answers)
and **OpenSSL < 3.0** are refused with the reason, because `-pbmac1_pbkdf2`, `-attime` on
`cms` and the PBES2 defaults the fixtures were made with are 3.x behaviour — and its version
is recorded before any judgement.

The other direction holds too: the 42 fixtures of `tests/fixtures/pki/` were written by
OpenSSL 3.5.5 (foreign provenance, [`tests/fixtures/PROVENANCE.md`](../../tests/fixtures/PROVENANCE.md)),
so every read tool is exercised on bytes neither the server nor the engine produced.

## 2. Level 0 — the engine round trip

`npm run validate:pki` first feeds every conformant artefact back into the **built** server
in-process (`dist/server.js`, `callToolDirect()` — the same function `tools/call` delegates
to), and judges the structured result:

| Artefact kind | Round trip |
|---|---|
| certificate (`create_certificate`) | `inspect_certificate` with `checkSelfSignature: true` (a CA) or `issuer` (a leaf) → `signature.valid`; then `verify_certificate_chain` to the corpus CA at the pinned instant, with `serverName` and `purposes: ['serverAuth']` for the leaves → `valid: true` |
| request (`create_csr`) | `inspect_csr` with the proof of possession → `signature.valid` |
| CMS attached / detached (`sign_cms`) | `verify_cms` with the trust anchors (and the detached content) → `valid: true` |
| time-stamp request (`create_timestamp_request`) | `decode_asn1` of the bytes, plus an independent `node:crypto` reckoning of the message imprint and the nonce |
| OCSP request (`create_ocsp_request`) | `decode_asn1` of the bytes, plus an independent `node:crypto` reckoning of the CertID hashes and the serial |
| PEM re-encoding (`convert_pem`) | the DER fixture decoded back through the matching read tool |

Two more rules at this level: a **deterministic** entry (`deterministic: true` — 14 of the
23: the Ed25519 and RSA PKCS#1 artefacts including the pathLen-0 intermediate signed by the
Ed25519 CA, every request, every PEM re-encoding) is produced
twice by the generator and the two digests must be equal; and a **negative canary**
(`expectRefused`) must be refused with its declared code — a canary that writes bytes is an
**XPASS** and fails the run, the one way to know the refusals are real and not a validator
that accepts everything.

### Conformant does not mean safe

The five canaries are not malformed inputs — they are requests OpenSSL would happily
fulfil: a SHA-1-signed CA, a certificate signed from a legacy RC2 / 3DES PKCS#12, an RSA key
with no stated scheme, a validity window ending before it starts, a spec with a stray
`url` member. OpenSSL conformance constrains the bytes, not the policy; that is precisely
why the server refuses them before a byte is written (`VALIDATION_ERROR`,
`PKI_KEY_ENCRYPTION_UNSUPPORTED`, `RSA_SCHEME_REQUIRED`), and why the gate records those
refusals as part of conformance instead of pretending the profile catches what it does not.

## 3. The corpus

`npm run corpus:pki` (`scripts/generate-pki-corpus.ts`) drives the built tool handlers
through `callToolDirect` under the hermetic environment (`TZ=UTC`, every `PKINATIVE_MCP_*`
scrubbed, `PKINATIVE_MCP_AT=2027-01-01T00:00:00Z`, a temporary sandbox holding the
fixtures) and writes the artefacts to `test-output/pki/` with a `manifest.json`:

```jsonc
{
  "entries": [{
    "id": "leaf-ed25519", "tool": "create_certificate", "kind": "cert",
    "status": "written" | "refused" | "xpass" | "skipped",   // skipped: the tool is not registered, or a <corpus:ID> input was not produced
    "file": "leaf-ed25519.der", "sha256": "…",
    "sha256Again": "…"                                       // a deterministic entry, produced twice
  }]
}
```

Every entry names the tool that produces it and the arguments as a host would send them,
with placeholders: `<fixture:NAME>` (the PKI input fragment of a fixture), `<content:NAME>`
(a content fragment), `<corpus:ID>` (the bytes of an **earlier** entry — the order matters
and execution is sequential), `<password:test-only>`. The table:

| Entry | Tool | What it covers | Deterministic |
|---|---|---|---|
| `ca-ed25519`, `ca-rsa-pkcs1`, `ca-rsa-pss`, `ca-ec` | `create_certificate` | a self-signed CA per signature family (critical basicConstraints + keyUsage) | Ed25519, RSA PKCS#1: yes; RSA-PSS, EC: no |
| `leaf-ed25519`, `leaf-rsa-pkcs1`, `leaf-rsa-pss`, `leaf-ec` | `create_certificate` | a serverAuth leaf under each CA — the subject key from a CSR, a certificate or a PUBLIC KEY; SAN with DNS, IPv4 and IPv6 | as above |
| `inter-pathlen0`, `leaf-under-inter` | `create_certificate` | a pathLen-0 intermediate and a leaf issued under it (`-untrusted` on the OpenSSL side) | intermediate: yes (signed by the Ed25519 CA); leaf: no (EC) |
| `csr-ec-san`, `csr-rsa-pss`, `csr-ed25519` | `create_csr` | requests with a SAN extensionRequest, per family | Ed25519: yes |
| `cms-attached`, `cms-detached`, `cms-ed25519-attached` | `sign_cms` | attached and detached SignedData over `content.txt` with the chain embedded; an Ed25519 signer against its own root (its `cms -verify` is under the judge gap `cms-eddsa`, §4) | Ed25519: yes |
| `tsq-sha256`, `tsq-sha384` | `create_timestamp_request` | TimeStampReq over data and over a digest, nonce and policy pinned | yes |
| `ocsp-req-leaf`, `ocsp-req-revoked` | `create_ocsp_request` | OCSPRequest with a SHA-256 / SHA-1 CertID and a pinned nonce | yes |
| `pem-root-cert`, `pem-inter-crl`, `pem-leaf-csr` | `convert_pem` | PEM re-encodings of DER fixtures (a certificate, a CRL, a request) | yes |
| `refuse-sha1`, `refuse-legacy-p12`, `refuse-rsa-no-scheme`, `refuse-notafter-before-notbefore`, `refuse-url-member` | `create_certificate` | the five negative canaries and their codes | — |

A coverage canary fails the run when the number of written and refused entries differs
from `declared.conformant` (23) / `declared.refused` (5) of `docs/data/interop.json`, so a
generator that silently dropped an entry cannot shrink the gate; `tests/tools/pki-corpus.test.ts`
holds the JSON to the table.

## 4. Level 1 — OpenSSL

The same run hands every conformant artefact to OpenSSL through the command builders and
outcome classifiers of `scripts/lib/interop-tools.ts` (pure functions over strings, unit
tested with inline transcripts), with the raw transcripts under `test-output/pki/reports/`.
The 12 command families of `docs/data/interop.json`:

| Family | Command | Expects |
|---|---|---|
| `x509-text` | `openssl x509 -inform DER -noout -text` | a dump of every certificate |
| `x509-text-pem` | `openssl x509 -inform PEM -noout -text` | a dump of every PEM re-encoding |
| `verify` | `openssl verify -CAfile <ca> [-untrusted <inter>] [-attime <t>] <leaf>` | `<file>: OK` from each CA to itself and from each leaf to its CA, at `-attime 2027-01-01` |
| `verify-sslserver` | `openssl verify -CAfile <ca> [-untrusted <inter>] -purpose sslserver [-attime <t>] <leaf>` | `OK` for every leaf (the pathLen-0 intermediate passed `-untrusted`) |
| `req-verify` | `openssl req -inform DER -noout -verify` | `Certificate request self-signature verify OK` |
| `req-verify-pem` | `openssl req -inform PEM -noout -verify` | the same on the PEM re-encoding |
| `crl-text-pem` | `openssl crl -inform PEM -noout -text` | a dump of the re-encoded intermediate CRL |
| `cms-verify-attached` | `openssl cms -verify -binary -inform DER -CAfile <root> -purpose any [-attime <t>] -out <devnull>` | `CMS Verification successful` (the fixture root; the Ed25519 signer against its own root — gap `cms-eddsa` below) |
| `cms-verify-detached` | `… -content <file> …` | the same with the detached content |
| `asn1parse` | `openssl asn1parse -inform DER` | a dump of the EC request |
| `ocsp-req-text` | `openssl ocsp -reqin <file> -req_text` | the `Serial Number` of each OCSP request |
| `ts-query-text` | `openssl ts -query -in <file> -text` | the `Nonce` of each time-stamp request |

Outcomes are read from each command's own contract: `verify` prints `<file>: OK` on
stdout and every failure on stderr; `req -verify` and `cms -verify` report success on
stderr on 3.x. Absent or unusable OpenSSL is reported as a **skip with the reason** — never
simulated — unless `PKINATIVE_INTEROP_REQUIRED=1` (CI, and the gate's `interop` step), where
it is exit 3.

### Known gaps of the judge

What OpenSSL cannot verify before a given release is declared once, in
`scripts/lib/pki-corpus.ts` (`KNOWN_OPENSSL_GAPS`: the checks covered, the OpenSSL floor, the
reason and the proof), the way the engine declares its own in pkinative's
`scripts/lib/interop.ts`. `docs/data/interop.json` carries the same table (`knownGaps`) and
this section names every gap; `tests/tools/pki-corpus.test.ts` and `verify:docs` hold the
three together. A judge below the floor **skips** the covered check with the reason on the
entry's PASS line and the summary counts it (`N OpenSSL check(s) skipped below a floor`);
level 0 still judges the bytes. On the CI legs whose judge is OpenSSL 3.5+ (windows-latest
and macos-latest: Git for Windows and Homebrew), `PKINATIVE_INTEROP_FLOORS_REQUIRED=1` turns
such a skip into exit 3, so every check runs on at least one required leg and a runner image
falling behind a floor is visible, never a quiet skip.

| Gap | Checks | Floor | Reason | Proof |
|---|---|---|---|---|
| `cms-eddsa` | `cms-ed25519-attached` → `cms-verify-attached` | OpenSSL 3.5 | Ed25519 signs the data, not a digest (RFC 8419). OpenSSL before 3.5.0 refuses every digest for EdDSA in CMS (`eddsa_digest_signverify_init: invalid digest`) and can neither sign nor verify an Ed25519 SignedData; 3.5.0 added the signature schemes without a signing digest to CMS. | Verifies with `openssl cms -verify` on OpenSSL 3.5.5 (Windows, macOS); fails with that error on 3.0.13 (Ubuntu 24.04) and 3.0.2 (Ubuntu 22.04); the engine round trip accepts it on every host. |

The read direction lives in `tests/interop/openssl.test.ts` (`npm run test:interop`): a CA
and a leaf per signature family produced by the tools and verified by OpenSSL with
`-purpose sslserver`, and the 42 OpenSSL-written fixtures parsed and verified by the read
tools. The certificate **linters** — zlint v3 and pkilint over a CA per family and two
leaves — are the publish-profile extra (`tests/interop/lint.test.ts`; `REQUIRE_LINT=1`):
an ERROR or FATAL fails, a WARNING or NOTICE must be reviewed into
`scripts/data/lint-waivers.json` (none today).

## 5. Outcomes and exit codes

Per entry the validator reports:

| Outcome | Meaning |
|---|---|
| `PASS` | conformant, as expected: every round trip and every OpenSSL check held (and a deterministic entry hashed the same twice) |
| `FAIL` | a conformant entry was refused, a round trip came back negative, OpenSSL rejected it, or a canary was refused with the **wrong** code |
| `XFAIL` | a negative canary refused with its declared code |
| `XPASS` | a negative canary that wrote bytes — the refusals are not real; always fatal |
| `INFRA` | OpenSSL spawned but produced no usable transcript, or the corpus is incomplete — not a verdict |
| `SKIP` | level 1 skipped (OpenSSL absent or unusable, not required), or an entry whose tool is not registered |

| Exit | Meaning |
|------|---------|
| 0 | Every expectation met — **or** OpenSSL is absent and `PKINATIVE_INTEROP_REQUIRED` is unset: level 1 is **skipped** (a skip of level 1, not a pass of it; level 0 verdicts still hold) |
| 1 | A conformance expectation was not met (`FAIL` / `XPASS`), or the coverage canary tripped (the written / refused counts differ from `docs/data/interop.json`) |
| 2 | Corpus directory / manifest or `dist/` absent — run `npm run build && npm run corpus:pki` first; OpenSSL installed but unusable |
| 3 | OpenSSL required (`PKINATIVE_INTEROP_REQUIRED=1`) but not found; or the judge is below a floor of the known gaps (§4) while `PKINATIVE_INTEROP_FLOORS_REQUIRED=1` |

## 6. Running it locally

```bash
npm run build && npm run corpus:pki && npm run validate:pki
# level 0 needs nothing but Node; level 1 uses the OpenSSL 3 on PATH (or OPENSSL_BIN) and skips visibly without it
npx tsx scripts/validate-pki.ts --verbose      # the per-entry table; --json for the machine form
```

Which binary to install per OS — Git for Windows' `usr/bin` on Windows, Homebrew's
`openssl@3` on macOS — is in [`LOCAL_TESTING.md`](LOCAL_TESTING.md) §5. Only
`test-output/pki/` is scanned. To judge one artefact you produced by hand, use the same
commands directly: `openssl x509 -inform DER -in out.der -noout -text`,
`openssl verify -CAfile ca.pem -attime 1798761600 leaf.pem`,
`openssl cms -verify -binary -inform DER -in sig.p7s -content data.txt -CAfile root.pem -purpose any -out /dev/null`.

## 7. Where it blocks

- `.github/workflows/interop.yml` — the corpus, the validator and the interop suite with
  `PKINATIVE_INTEROP_REQUIRED=1` on **ubuntu-22.04, ubuntu-24.04, windows-latest and
  macos-latest**, on every push and pull request and weekly. `interop (ubuntu-24.04)` and
  `interop (windows-latest)` are **required status checks** (`.github/rulesets/main.json`);
  ubuntu-22.04 (OpenSSL 3.0, no PBMAC1) and macOS (Homebrew OpenSSL 3 next to the system
  LibreSSL) report but do not block, because their OpenSSL builds differ in ways that are
  theirs. windows-latest and macos-latest also carry `PKINATIVE_INTEROP_FLOORS_REQUIRED=1`:
  their OpenSSL 3.5+ must run every check under a known gap (§4), the ubuntu legs skip those
  with the reason. The workflow carries no `paths:` filter, so a required check can never be
  left "Expected — waiting for status"; tool versions land in the job summary and the raw
  transcripts are uploaded as artifacts.
- `.github/workflows/ci.yml` — the gate's CI profile with `--require-all` on ubuntu × Node
  22 / 24, windows-latest and macos-latest: the corpus and `validate:pki` run there too,
  with OpenSSL 3 exposed the same way.
- `.github/workflows/publish.yml` — the `--publish --require-all` profile (the linters
  included) re-runs between the tag and `npm publish`: a release can never publish a server
  whose artefacts OpenSSL rejects.

No dependency is added — the validator is a script, and the judge is external.
