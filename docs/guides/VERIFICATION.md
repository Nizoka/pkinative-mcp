# Verification guide — verify before you trust (for AI agents and operators)

Applies to pkinative-mcp v1.0.0 · pkinative 1.0.0.

This guide explains, in two pages, the difference between a **fact** and a **verdict** in
this server, which of the four path tools answers which question, what `at`, the anchors and
the evidence mean, and how to read `reasons[]`. The server-side recipe is the
`verify_before_trust` prompt; revocation continues in [REVOCATION.md](REVOCATION.md), CMS and
time-stamps in [TIMESTAMPS.md](TIMESTAMPS.md).

## TL;DR — facts, then the verdict

| Question | Tool | What it checks | What it is not |
| --- | --- | --- | --- |
| What is this certificate? | `inspect_certificate` | subject, issuer, validity, key, the 19 extension kinds, fingerprints, diagnostics; `issuer` / `checkSelfSignature: true` add ONE signature check | trust |
| **Is it trustworthy?** | `verify_certificate_chain` | path building to YOUR anchors, every signature, RFC 5280 §6 at `at`, `serverName`, `purposes`, policies, offline revocation | — |
| Which intermediates does the chain need, why does no path reach an anchor? | `build_certificate_path` | path **discovery** under the structural rules; signatures NOT checked | a verdict (`valid` is always false) |
| Is this ordered path valid? | `validate_certificate_path` | RFC 5280 §6.1 on a path you ordered, every link signature first | revocation |
| Is it valid for this host? | `check_certificate_name` | RFC 6125 host / IP identity against the SAN | validity, trust, revocation |
| May it serve this purpose? | `check_certificate_purpose` | extended key usage along the path | validity, trust, revocation |

A signature that verifies is not a certificate that is trusted; a verdict is relative to
the anchors **you** name, at the instant **you** pin, with the evidence **you** bring.

```jsonc
// The one-call verdict — examples/verify-certificate-chain-server.json
{ "tool": "verify_certificate_chain", "arguments": {
  "leaf": { "path": "fixtures/leaf.crt.pem" },
  "candidates": [{ "path": "fixtures/inter.crt.pem" }],       // untrusted intermediates (a CMS message's embedded certificates count too)
  "trustAnchors": [{ "path": "fixtures/root.crt.pem" }],      // required: YOUR roots
  "at": "2027-01-01T00:00:00Z",                                // pin it: reproducible and cacheable
  "serverName": { "host": "a.wild.example.test" },             // RFC 6125 (or { "ip": "192.0.2.1" })
  "purposes": ["serverAuth"],                                  // extended key usage along the path
  "verbosity": "summary" } }
// → { valid: true, reasonCodes: [], pathLength, evaluatedAt, revocationEvidence, diagnosticCount }
```

The same chain at `"at": "2050-01-01T00:00:00Z"` returns `valid: false` with
`PKI_REASON_EXPIRED` — a verdict, never `isError`
([`verify-certificate-chain-expired.json`](../../examples/verify-certificate-chain-expired.json)).

## The inputs of a verdict

| Input | Meaning |
| --- | --- |
| `leaf` | The certificate judged. |
| `trustAnchors` | Required, ≤ 256, every PEM block of every item. The verdict is relative to them; no system store is consulted. A leaf that chains to a CA you did not anchor is `PKI_REASON_NO_TRUST_ANCHOR`. |
| `candidates` | Untrusted intermediates the path may use. A server that sends only its leaf, judged against a root anchor, is the usual `PKI_REASON_SIGNATURE_NOT_CHECKED` + `PKI_REASON_NO_TRUST_ANCHOR` pair — no link could be built; `build_certificate_path` names the issuer that is missing. |
| `at` | The instant of evaluation (ISO 8601; a date-time without a zone is UTC; an impossible date is refused). Omitted: `PKINATIVE_MCP_AT`, else the wall clock — then never cached. `evaluatedAt` / `evaluatedAtSource` (`input` \| `pinned` \| `clock`) echo it. |
| `serverName` | `{ host }` or `{ ip }`: the RFC 6125 identity check (SAN dNSName / iPAddress, wildcards). Also available alone as `check_certificate_name`. |
| `purposes` | `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `ocspSigning`, `any`, or a dotted OID — judged along the path (a CA's own extKeyUsage restricts what it issued, the Web PKI reading). Also alone as `check_certificate_purpose`. |
| `policy` | RFC 5280 §6.1.1 inputs: `initialPolicySet`, `requireExplicitPolicy`, `inhibitPolicyMapping`, `inhibitAnyPolicy`. |
| `crls`, `ocspResponses`, `requireRevocation` | The revocation evidence you fetched ([REVOCATION.md](REVOCATION.md)); `requireRevocation: true` demands authenticated evidence for the end-entity certificate (`PKI_REASON_REVOCATION_UNKNOWN` otherwise — the engine's rule; an intermediate is judged from the evidence you pass, and `revocationEvidence` counts what covered the path). |
| `allowSha1`, `encodingRules`, `pemMode`, `strict`, `limits` | The shared parse options; `limits.maxPathsExplored` (default 1 000) and `limits.maxChainLength` (10) bound the §6 search under the operator ceiling. |

## Reading the result

`valid` is the verdict; `reasons[]` the rows that made it (`{ code, message, remedy, path?, … }`,
`PKI_REASON_*`); `path[]` the chain found, leaf first up to the anchor, `pathLength` its
length, `explored` how many candidates were walked, `signatureVerifications[]` the per-link
checks, `revocationEvidence` what evidence covered which certificate. Branch on
`reasons[].code` — `reasonCodes[]` under `verbosity: 'summary'` — never on the prose.

The reasons a chain verdict returns, by family:

| Family | Codes |
| --- | --- |
| Validity | `PKI_REASON_NOT_YET_VALID`, `PKI_REASON_EXPIRED` |
| Path | `PKI_REASON_ISSUER_NOT_FOUND`, `PKI_REASON_NO_TRUST_ANCHOR`, `PKI_REASON_NOT_A_CA`, `PKI_REASON_PATH_TOO_LONG`, `PKI_REASON_PATH_LOOPS`, `PKI_REASON_LIMIT_EXCEEDED` |
| Signatures | `PKI_REASON_SIGNATURE_INVALID`, `PKI_REASON_SIGNATURE_NOT_CHECKED` (SHA-1 without `allowSha1`, an algorithm this runtime refuses — never a rejection) |
| Names and purposes | `PKI_REASON_NAME_MISMATCH`, `PKI_REASON_NAME_NOT_PERMITTED`, `PKI_REASON_NAME_EXCLUDED`, `PKI_REASON_PURPOSE_NOT_PERMITTED`, `PKI_REASON_UNKNOWN_CRITICAL_EXTENSION` |
| Policies | `PKI_REASON_NO_VALID_POLICY`, `PKI_REASON_POLICY_MAPPING_INVALID` |
| Revocation | `PKI_REASON_REVOKED`, `PKI_REASON_REVOCATION_UNKNOWN`, `PKI_REASON_REVOCATION_STALE`, `PKI_REASON_REVOCATION_WRONG_ISSUER`, `PKI_REASON_REVOCATION_OUT_OF_SCOPE`, `PKI_REASON_REVOCATION_PARTIAL`, `PKI_REASON_REVOCATION_MISMATCH` |
| Input | `PKI_REASON_INPUT_MALFORMED` (the `errorCode` member carries the `PKI_*` the parser would have thrown) |

The meaning and remedy of every one is in [AGENT_CONTRACT.md](../AGENT_CONTRACT.md) §6.3;
`explain_code { code }` returns the same with the standard it cites.

## Explaining a failing path

`build_certificate_path` is **discovery**: it walks from the leaf through the candidates to
an anchor under the structural rules at `at` (validity, basic constraints, key usage, name
constraints, the policy inputs) and reports the path it found, without verifying a single
signature — every link carries `PKI_REASON_SIGNATURE_NOT_CHECKED`, so `valid` is always
false and the verdict is `found` + `structuralReasons`
([`build-certificate-path.json`](../../examples/build-certificate-path.json)); the leaf alone
with `PKI_REASON_NO_TRUST_ANCHOR` when no path reached an anchor
([`build-certificate-path-no-anchor.json`](../../examples/build-certificate-path-no-anchor.json)).
Use it to learn which intermediates a chain needs.

`validate_certificate_path` judges a path **you ordered** (`path`, leaf first, then each
issuer) against the anchors at `at` — RFC 5280 §6.1 — with every link signature verified
first (certificate i against i+1, the last against the anchor whose subject matches its
issuer) and reported per link in `signatures[]`
([`validate-certificate-path.json`](../../examples/validate-certificate-path.json));
`checkSignatures: false` gives the structural verdict: `valid` stays false, `failingReasons`
carries what actually fails, `signaturesChecked` says which one you got
([`validate-certificate-path-structure-only.json`](../../examples/validate-certificate-path-structure-only.json)).
No revocation here.

```jsonc
{ "tool": "validate_certificate_path", "arguments": {
  "path": [{ "path": "fixtures/leaf.crt.pem" }, { "path": "fixtures/inter.crt.pem" }],
  "trustAnchors": [{ "path": "fixtures/root.crt.pem" }], "at": "2027-01-01T00:00:00Z",
  "checkSignatures": false, "fields": ["valid", "failingReasons.code", "signaturesChecked", "signatures.verdict"] } }
```

## Names and purposes alone

`check_certificate_name` has two forms: the certificate form — `certificate` + exactly one of
`host` / `ip` — judges the SAN (`allowWildcards` default true; `allowCommonNameFallback`
default false reads a CN-only certificate's commonName and then needs `chain`, the issuing
CAs, so the CN is held to their name constraints as a SAN would be); the match form —
`presented` + `reference` — is one RFC 6125 §6.4 comparison with no certificate
([`check-certificate-name-wildcard.json`](../../examples/check-certificate-name-wildcard.json),
[`check-certificate-name-mismatch.json`](../../examples/check-certificate-name-mismatch.json),
[`check-certificate-name-match.json`](../../examples/check-certificate-name-match.json)).

`check_certificate_purpose` judges `[certificate, ...chain]` for one `purpose`
(`restrictIssuers` default true — a CA's own extKeyUsage restricts what it issued, which no
sentence of RFC 5280 requires and every Web PKI validator does; `requireExplicitPurpose`
default false — a certificate without extKeyUsage is unrestricted)
([`check-certificate-purpose-server-auth.json`](../../examples/check-certificate-purpose-server-auth.json),
[`check-certificate-purpose-refused.json`](../../examples/check-certificate-purpose-refused.json)).
Both are `valid: false` + `reasons[]` for a negative verdict, never `isError`; an unknown
purpose name is `VALIDATION_ERROR`.

## Requests, CRLs, responses and tokens have a signature check too

`inspect_csr` verifies the **proof of possession** by default (`verify`, one Web Crypto
verification): `signature.valid` tells whether the request was signed by the key it
carries — not that any CA vouches for it. `inspect_crl { issuer }`,
`inspect_ocsp_response { responder }` and `inspect_cms { signerCertificate }` each add ONE
signature check against ONE key and report it as a fact; `check_crl_revocation`,
`check_ocsp_status`, `verify_cms` and `verify_timestamp` are the verdicts.

## Pitfalls

- **`inspect_certificate.signature.valid` is not trust.** It says this certificate was
  signed by that key. Whether that key belongs to a CA you trust, whether the CA was valid
  at the time, whether a name constraint forbids the name — only `verify_certificate_chain`
  says.
- **Pin `at`.** A verdict depends on the instant; an unpinned one follows the wall clock,
  cannot be cached, and will flip the day a certificate expires. `evaluatedAtSource: 'clock'`
  in the result is the tell.
- **No evidence, no revocation.** Without `crls` / `ocspResponses` the verdict is silent on
  revocation (`revocationEvidence` says so); `requireRevocation: true` makes the silence a
  reason. The server never fetches.
- **SHA-1 is not evidence.** A SHA-1-signed link is `PKI_REASON_SIGNATURE_NOT_CHECKED`
  unless `allowSha1: true`, and then an archival fact rather than an authentication decision.
- **DSA, ML-DSA and unknown key kinds** are parsed, never verified
  (`PKI_REASON_SIGNATURE_NOT_CHECKED`): ask on a runtime that implements the algorithm,
  never treat it as a rejection.
- **Diagnostics are not reasons.** A serial longer than 20 octets or a missing SKI is in
  `diagnostics[]`, not in `reasons[]`; `strict: true` escalates the first warning to
  `PKI_STRICT_DIAGNOSTIC` (an `isError`) if your policy wants that.

## Caching and reproducibility

A verdict with a pinned `at` and inline inputs is served from the opt-in cache on a repeat
(`_meta.cached: true`); a `path` input, an unpinned instant or `strict` escalation never is.
The semantic fingerprint of every verdict example (`evaluatedAt` excluded) is held by the
sample baseline, so a changed verdict for the same inputs is a regression
([LOCAL_TESTING.md](LOCAL_TESTING.md) §3.4). On the OpenSSL side the same verdicts read
`openssl verify -CAfile root.pem -untrusted inter.pem -purpose sslserver -attime 1798761600 leaf.pem`
— the corpus gate holds the two implementations to the same answer
([CONFORMANCE.md](CONFORMANCE.md)).
