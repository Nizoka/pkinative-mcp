# Revocation guide — CRL and OCSP without a network (for AI agents and operators)

Applies to pkinative-mcp v1.0.0 · pkinative 1.0.0.

This guide explains how revocation is judged when the server **never fetches anything**:
where the evidence comes from, how `create_ocsp_request` builds the request you send, how
`check_crl_revocation` / `check_ocsp_status` judge one certificate, and how
`verify_certificate_chain` / `verify_cms` judge a whole chain from the same bytes. The
server-side recipe is the `offline_revocation` prompt.

## TL;DR — the evidence is yours to carry

| Step | Tool | Network |
| --- | --- | --- |
| Where to fetch | `inspect_certificate` → `extensions` `crlDistributionPoints` (the CRL URL) and `authorityInfoAccess` (the OCSP responder URL) | — |
| Build the OCSP request | `create_ocsp_request { certificate, issuer, hashAlgorithm, nonce }` → the DER you POST | **you** (`Content-Type: application/ocsp-request`) |
| Fetch the CRL | — | **you** (`curl`, `openssl crl`, …) |
| Judge one certificate against a CRL | `check_crl_revocation { certificate, crl, delta?, issuer, at }` | — |
| Judge one certificate against an OCSP response | `check_ocsp_status { response, certificate, issuer, responder?, nonce, requireNonce, at }` | — |
| The whole chain in one call | `verify_certificate_chain { …, crls: […], ocspResponses: […], requireRevocation: true }` (and `verify_cms`, `verify_timestamp`) | — |
| The facts only | `inspect_crl { crl, find, issuer }`, `inspect_ocsp_response { response, responder }` | — |

Doctrine: no network, ever (`describe_engine.refusals`; `network: 'none'`). The engine
judges bytes; the transport is the caller's — a browser, `curl`, your own service.
Saying "valid" without evidence is a choice you make: the verdict says so
(`revocationEvidence` empty, or `PKI_REASON_REVOCATION_UNKNOWN` under `requireRevocation`).

## CRLs

```jsonc
// examples/check-crl-revocation.json — two verdicts at a pinned instant
{ "tool": "check_crl_revocation", "arguments": {
  "certificate": { "path": "fixtures/leaf.crt.pem" },
  "crl": { "path": "fixtures/inter.crl.pem" },
  "issuer": { "path": "fixtures/inter.crt.pem" },     // the CRL issuer certificate: the signature is verified against it
  "at": "2027-01-01T00:00:00Z", "verbosity": "summary" } }
// → { valid: true, reasonCodes: [], signatureVerified: true, evaluatedAt, crlNumber, diagnosticCount }
{ "tool": "check_crl_revocation", "arguments": {
  "certificate": { "path": "fixtures/revoked.crt.pem" }, "crl": { "path": "fixtures/inter.crl.der" },
  "issuer": { "path": "fixtures/inter.crt.pem" }, "at": "2027-01-01T00:00:00Z",
  "fields": ["valid", "reasons.code", "signatureVerified", "crlNumber"] } }
// → { valid: false, reasons: [{ code: "PKI_REASON_REVOKED" }], … }   — a verdict, never isError
```

The RFC 5280 §6.3 verdict of ONE certificate against ONE base CRL: the list must be **in
scope** for the certificate (issuer, issuing distribution point, reasons), **fresh**
(`nextUpdate`, or `staleTolerance` milliseconds past it; the engine policy by default),
**signature-verified** against `issuer` — without it the list is not accepted as evidence
(a verdict: `valid: false`, `PKI_REASON_REVOCATION_UNKNOWN`, `signatureVerified: null`;
never `isError`), so pass it for a real verdict — and the serial must not be listed
(`PKI_REASON_REVOKED` carries the revocation date and reason). `delta` applies a delta CRL
over the base: it must carry a `deltaCRLIndicator` (a base passed as the delta is
`VALIDATION_ERROR` — [`check-crl-revocation-not-delta.json`](../../examples/check-crl-revocation-not-delta.json))
and name the base's number; both signatures are reported (`signatureVerified`,
`deltaSignatureVerified`; [`check-crl-revocation-delta.json`](../../examples/check-crl-revocation-delta.json)),
and a delta whose signature does not verify against `issuer` is **not applied**: the verdict
is `valid: false` with `PKI_REASON_REVOCATION_UNKNOWN` on `delta`.

`inspect_crl` shows the list's facts — issuer, `thisUpdate` / `nextUpdate`, `crlNumber`,
`isDelta` / `baseCrlNumber`, the issuing distribution point, `entryCount` (walked with a lazy
cursor, bounded by `limits.maxRevokedCertificates` = 1 000 000, never all decoded),
extensions — and `find` looks ONE serial up (`serialHex`, or a `certificate` whose serial and
issuer are used) → `entry { revoked, revocationDate, reason, invalidityDate, extensions }`
([`inspect-crl.json`](../../examples/inspect-crl.json)).

Fetching, on your side: the URL is `crlDistributionPoints` of `inspect_certificate`;
`curl -sS -o ca.crl "$URL"` then pass `{ "path": "ca.crl" }` (DER) or convert
(`openssl crl -in ca.crl -inform DER -outform PEM -out ca.crl.pem`; both forms are read).

## OCSP

```jsonc
// 1. examples/create-ocsp-request.json — the request you POST
{ "tool": "create_ocsp_request", "arguments": {
  "certificate": { "path": "fixtures/leaf.crt.pem" },
  "issuer": { "path": "fixtures/inter.crt.pem" },      // the CA that issued it: its name and key hashes make the CertID
  "hashAlgorithm": "SHA-256",                          // default 'SHA-1' (RFC 6960, what every responder answers)
  "nonce": "random",                                   // RFC 8954; 16 bytes from node:crypto (summary.randomNonce) — or your own hex (1–32 bytes)
  "encoding": "hex" } }
// → summary { certIdHex, hashAlgorithm, nonceHex, randomNonce: true, serialNumber, subject, issuer }
// 2. POST the bytes yourself to the responder named by authorityInfoAccess:
//    curl -sS -H 'Content-Type: application/ocsp-request' --data-binary @leaf.orq "$OCSP_URL" -o leaf.ocsp
// 3. examples/check-ocsp-status.json — judge the answer, nonce demanded
{ "tool": "check_ocsp_status", "arguments": {
  "response": { "path": "fixtures/leaf.ocsp.der" },
  "certificate": { "path": "fixtures/leaf.crt.pem" }, "issuer": { "path": "fixtures/inter.crt.pem" },
  "nonce": "1538349c433373ed058c291909df5b3e", "requireNonce": true,
  "at": "2027-01-01T00:00:00Z", "verbosity": "summary" } }
// → { valid: true, reasonCodes: [], status: "good", signatureVerified: true, responderAuthorized: true, responder, evaluatedAt, diagnosticCount }
```

`check_ocsp_status` is the RFC 6960 verdict of ONE response for ONE certificate: the
**CertID** is recomputed from `issuer` with the hash the response used (or `hashAlgorithm`)
and must be answered; the **signature** is verified with `responder`, else the certificates
embedded in the response, else the issuer itself; the signer must be **authorised**
(RFC 6960 §4.2.2.2: the CA, a delegate the CA issued carrying id-kp-OCSPSigning, or
`responderTrusted: true` for a trust you hold out of band); then the engine judges the
**status** (`good`; `PKI_REASON_REVOKED` with the reason / `unknown`), **freshness** at `at`
(`thisUpdate` / `nextUpdate` / `producedAt`, `staleTolerance` and `futureTolerance` in
milliseconds, the engine policy by default), and the **nonce** (`nonce` must be echoed as
sent; `requireNonce: true` refuses a response without one). A non-successful response
status is a negative verdict with `status: null`. The second example of the shipped file
judges the revoked leaf against the known responder certificate (`responder`).

`inspect_ocsp_response` shows the facts — the response status, the responder id (by name or
key hash), `producedAt`, every SingleResponse (CertID, status, times, extensions), the
embedded certificates, `noncePresent` — and `responder` adds ONE signature check; omitted,
the embedded certificates are tried and the one that verifies is named
([`inspect-ocsp-response.json`](../../examples/inspect-ocsp-response.json)).

### The CertID hash defaults to SHA-1

RFC 6960 identifies the certificate by hashes of the issuer name and key, and SHA-1 is what
every deployed responder answers — so `hashAlgorithm` defaults to `'SHA-1'` on
`create_ocsp_request`. This is an identifier, not a signature: nothing is verified under
it, so the SHA-1 policy (`allowSha1`) does not apply. Ask for `'SHA-256'` explicitly where
the responder supports it; `check_ocsp_status` recomputes the CertID with whatever the
response answered, unless `hashAlgorithm` says otherwise, and reports it in `hashAlgorithm`
/ `certIdHex`.

## The whole chain in one call

`verify_certificate_chain { leaf, candidates, trustAnchors, crls: […], ocspResponses: […], requireRevocation: true, at }`
judges the path from the evidence given — `requireRevocation: true` demands authenticated
evidence for the **end-entity** certificate (the engine's rule); an intermediate is judged
from the evidence you pass and `revocationEvidence` counts what covered the path — plus, for `verify_cms`,
the CRLs the message carries ([`verify-certificate-chain-revoked.json`](../../examples/verify-certificate-chain-revoked.json),
[`verify-cms-attached-offline-revocation.json`](../../examples/verify-cms-attached-offline-revocation.json)).
`PKI_REASON_REVOKED` is reported only from **authenticated** evidence (a CRL whose
signature a key entitled to sign it verified; an OCSP response signed by an authorised
responder); a listing on an unverified list is a claim in the message, and the verdict is
`PKI_REASON_REVOCATION_UNKNOWN`. Partial lists are accumulated (RFC 5280 §6.3.3
`reasons_mask`) and `PKI_REASON_REVOCATION_PARTIAL` dropped once the union is complete.
`revocationEvidence` in the result names which evidence covered which certificate.

## The reasons

| Code | Meaning | What to do |
| --- | --- | --- |
| `PKI_REASON_REVOKED` | A covering, authenticated list or response says revoked; the message carries the date | A signature made before that instant may still be good — decide with the date. |
| `PKI_REASON_REVOCATION_UNKNOWN` | No authenticated evidence covers the certificate | Not "not revoked": bring the evidence and the `issuer`, or make the soft-fail decision deliberately. |
| `PKI_REASON_REVOCATION_STALE` | No `nextUpdate`, or it passed beyond `staleTolerance`, or `thisUpdate` lies beyond `futureTolerance` | Fetch a current list / response; widen the tolerance only for a policy you own. |
| `PKI_REASON_REVOCATION_WRONG_ISSUER` | The list names another issuer | Use the list the certificate's issuer publishes. |
| `PKI_REASON_REVOCATION_OUT_OF_SCOPE` | The issuing distribution point excludes this certificate | Fetch the list published at the distribution point the certificate names. |
| `PKI_REASON_REVOCATION_PARTIAL` | The list covers only some reasons | Supply the other lists the CA publishes. |
| `PKI_REASON_REVOCATION_MISMATCH` | The answer is about another certificate, or does not echo the nonce | Do not retry the same response; suspect a cache or a substitution. |

## Pitfalls

- **A CRL without its issuer is not evidence.** `check_crl_revocation` without `issuer`
  cannot verify the signature, so the list is not accepted as evidence — a verdict
  (`valid: false`, `PKI_REASON_REVOCATION_UNKNOWN`), not an error; pass the CRL
  issuer certificate (usually the CA that issued the certificate).
- **A delegated responder must be authorised.** A response signed by a certificate the CA
  did not issue with id-kp-OCSPSigning is `responderAuthorized: false` — unless you state
  `responderTrusted: true`, which is your decision, recorded in the result.
- **The nonce is the only replay protection.** Keep `summary.nonceHex` from the request and
  pass it as `nonce` (+ `requireNonce: true`); a response without it may be a replay.
- **Pin `at`.** Freshness is judged at the instant you name; the wall clock makes the verdict
  flip the day `nextUpdate` passes, and keeps it out of the cache.
- **The evidence is never fetched, never cached by the server, never embedded unread:**
  `sign_cms` parses every CRL before embedding it; `verify_cms` judges the message's own
  CRLs like yours.

## OpenSSL on your side

```bash
# fetch a CRL (the URL from crlDistributionPoints) and read it
curl -sS -o ca.crl "$CRL_URL" && openssl crl -inform DER -in ca.crl -noout -text
# build the OCSP request with the server (create_ocsp_request, outputMode 'file' → ocsp/leaf.orq), then
openssl ocsp -reqin ocsp/leaf.orq -req_text                       # what the corpus gate checks (Serial Number)
curl -sS -H 'Content-Type: application/ocsp-request' --data-binary @ocsp/leaf.orq "$OCSP_URL" -o leaf.ocsp
openssl ocsp -respin leaf.ocsp -resp_text                          # the facts; the verdict is check_ocsp_status
```

The corpus gate ([CONFORMANCE.md](CONFORMANCE.md)) holds every OCSP request the server
writes to `openssl ocsp -reqin … -req_text` and to an independent `node:crypto` reckoning
of the CertID hashes; the fixture responses (`leaf.ocsp.der`, `revoked.ocsp.der`) and CRLs
(`inter.crl.*`, the Ed25519 base + delta pair) were written by OpenSSL 3.5.5
([`tests/fixtures/PROVENANCE.md`](../../tests/fixtures/PROVENANCE.md)).
