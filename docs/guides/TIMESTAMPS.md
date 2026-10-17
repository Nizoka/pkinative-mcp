# Time-stamp guide — RFC 3161 requests, tokens and counter time-stamps (for AI agents and operators)

Applies to pkinative-mcp v1.0.0 · pkinative 1.0.0.

This guide explains how the four time-stamp tools — `create_timestamp_request`,
`inspect_timestamp`, `verify_timestamp` and `amend_cms add-timestamp` — fit together with
`sign_cms` and `verify_cms`, what the **counter time-stamp** of a CMS signature actually
stamps, and what a verified token proves. The server-side recipe is the `sign_and_timestamp`
prompt; the signing side is in [SIGNING.md](SIGNING.md).

## TL;DR — the ladder as five tool calls

| Step | What it does | Tool | Network |
| --- | --- | --- | --- |
| **Sign** | A CMS SignedData with ESS signing-certificate-v2 and CMSAlgorithmProtection (CAdES-B) | `sign_cms` | no |
| **Imprint** | The signer's **signature value** — what a counter time-stamp stamps | `inspect_cms { fields: ['signerInfos.signature'] }` | no |
| **Request** | The RFC 3161 TimeStampReq over its hash (`digestHex`) with a nonce | `create_timestamp_request` | no — **you** POST the `.tsq` (`Content-Type: application/timestamp-query`) |
| **Attach** | The TSA's token as `id-aa-signatureTimeStampToken` (CAdES-T / PAdES B-T), imprint checked first | `amend_cms { operation: 'add-timestamp', token }` | no |
| **Verdict** | Every signer, every chain, every time-stamp, offline revocation in one call | `verify_cms { atTimeStamp: true }` | no |
| a token alone | The RFC 3161 verdict against the request, the data or the digest it stamps | `verify_timestamp` | no |

The server never talks to a TSA: `create_timestamp_request` produces bytes the caller
transports, and the response comes back as an input. Worked examples:
[`sign-cms-detached-then-verify.json`](../../examples/sign-cms-detached-then-verify.json),
[`inspect-cms-signature-value.json`](../../examples/inspect-cms-signature-value.json),
[`create-timestamp-request-digest-hex.json`](../../examples/create-timestamp-request-digest-hex.json),
[`create-timestamp-request-random-nonce.json`](../../examples/create-timestamp-request-random-nonce.json),
[`amend-cms-add-timestamp-refused.json`](../../examples/amend-cms-add-timestamp-refused.json),
[`verify-timestamp-response-request.json`](../../examples/verify-timestamp-response-request.json),
[`verify-timestamp-token-digest.json`](../../examples/verify-timestamp-token-digest.json),
[`inspect-timestamp-response.json`](../../examples/inspect-timestamp-response.json).

```jsonc
// 1. Sign (chain embedded, signingTime pinned)
{ "tool": "sign_cms", "arguments": {
  "content": { "path": "fixtures/content.txt" }, "detached": true,
  "certificate": { "path": "fixtures/leaf.crt.pem" }, "chain": [{ "path": "fixtures/inter.crt.pem" }],
  "signingTime": "2027-01-01T00:00:00Z", "signer": { "key": { "path": "fixtures/leaf.key.pem" } } } }
// 2. The signature value to stamp (+ a one-key check against the signer certificate)
{ "tool": "inspect_cms", "arguments": {
  "signedData": { "path": "fixtures/detached.p7s" }, "signerCertificate": { "path": "fixtures/leaf.crt.pem" },
  "content": { "path": "fixtures/content.txt" }, "fields": ["signerInfos.signature", "signerInfos.sid", "signerSignature"] } }
// 3. The request over its hash (SHA-256 of the signature value octets), nonce pinned → reproducible .tsq
{ "tool": "create_timestamp_request", "arguments": {
  "digestHex": "<sha256 of signerInfos[0].signature>", "hashAlgorithm": "SHA-256", "nonce": "random", "certReq": true } }
//    curl -sS -H 'Content-Type: application/timestamp-query' --data-binary @req.tsq "$TSA_URL" -o resp.tsr
// 4. Attach — the token's imprint is checked against the signature value BEFORE anything is written
{ "tool": "amend_cms", "arguments": {
  "signedData": { "derBase64": "<from 1>" }, "operation": "add-timestamp", "token": { "path": "resp.tsr" } } }
// 5. The one verdict, each signer judged at the time its verified token proves
{ "tool": "verify_cms", "arguments": {
  "signedData": { "derBase64": "<from 4>" }, "content": { "path": "fixtures/content.txt" },
  "trustAnchors": [{ "path": "fixtures/root.crt.pem" }], "at": "2027-01-01T00:00:00Z", "atTimeStamp": true } }
```

## What a counter time-stamp stamps

**The signer's SIGNATURE VALUE, not the document.** RFC 3161 and CAdES define the
signature time-stamp as a token whose message imprint is the hash of the `SignerInfo`
`signature` octets (without tag or length). `inspect_cms` returns those octets as hex
(`signerInfos[i].signature`); hash them with the TSA's algorithm and pass the digest as
`digestHex` — or pass the octets as `data: { base64 }` and let the tool hash them.
`amend_cms` checks the token's imprint against that value **before** writing a byte: a token
over anything else — the fixture `content.tsr` stamps `content.txt`, not the signature — is
refused with `VALIDATION_ERROR` and `data.detail` `PKI_REASON_TSP_IMPRINT_MISMATCH`, the
remedy spelled out ([`amend-cms-add-timestamp-refused.json`](../../examples/amend-cms-add-timestamp-refused.json)).
Trust is not judged there (`verify_cms` is); `amend_cms` is deterministic and every signed
octet of the message stays unchanged (the token lands in the **unsigned** attributes).

## Building the request (`create_timestamp_request`)

| Input | Meaning |
| --- | --- |
| `data` or `digestHex` | What is stamped: a content input (`text` / `base64` / `path`) hashed with `hashAlgorithm`, or a digest already computed with it (a wrong length is `VALIDATION_ERROR`). Exactly one. |
| `hashAlgorithm` | `SHA-256` (default), `SHA-384`, `SHA-512`. |
| `nonce` | `'random'` draws 63 bits from `node:crypto` (`summary.randomNonce: true`; never cached) — without a nonce nothing ties the response to **this** request; a decimal or `0x`-hex value pins it (reproducible bytes). |
| `policy` | The TSA policy OID to request under. |
| `certReq` | Default true: ask for the TSA certificate in the token (RFC 3161 §2.4.1). A token that then carries none is `PKI_DIAG_TSP_CERTREQ_UNMET`. |

The summary carries `hashAlgorithm`, `imprintHex`, `nonce` (decimal), `randomNonce`,
`policy`, `certReq`, `dataBytes`. **Keep the request bytes** (or `imprintHex` and the nonce):
`verify_timestamp { request }` is the only way to check that the response answers this
request — imprint, nonce and policy together. Output DER (default, `.tsq`), PEM or hex;
`openssl ts -query -in req.tsq -text` prints it (the corpus gate's check).

## Reading a response (`inspect_timestamp`)

A `.tsr` (TimeStampResp: `status`, `statusStrings`, `failInfo`, and the token when granted),
a `.tst` (TimeStampToken) or a bare TSTInfo — auto-detected in that order, or named with
`as`. The TSTInfo view: `policy`, the message imprint (algorithm + hex), `serialNumber`,
`genTime` (epoch ms + ISO), `accuracy` (null = undeclared), `ordering`, `nonce` (decimal),
the TSA name **as stated** (a hint, not an identity), extensions; the token view adds its CMS
envelope (signer count, embedded certificates). Parsing proves nothing: `verify_timestamp`
is the verdict. OpenSSL-made tokens carry `PKI_DIAG_CMS_SET_NOT_SORTED` (`strict: true`
would escalate it).

## The verdict (`verify_timestamp`)

Exactly one of `token` (a TimeStampToken) or `response` (the whole TimeStampResp — a
declined response is `PKI_REASON_TSP_NOT_GRANTED` with the failure codes), judged against
what **you** say was stamped — `request` (the `.tsq`: imprint, nonce and policy are all
checked, the only way to catch a replay), `data` (hashed with the token's own algorithm) or
`digestHex`; at least one is required, because a token verified without what it stamps
proves nothing (`VALIDATION_ERROR` otherwise). Then the TSA's signature, its certificate's
chain to one of **your** `trustAnchors` (through `candidates` and the certificates the token
carries) at `at` with a **critical** timeStamping EKU (`allowNonCriticalTimeStampingEku: true`
for deployed TSAs that are not — RFC 3161 §2.3 requires it critical), and revocation from
the `crls` / `ocspResponses` you supply (`requireRevocation: true` demands evidence for the
TSA's end-entity certificate; its intermediates are judged from what you pass).
`genTime` / `earliest` / `latest` (accuracy applied) are established only when `valid`.

```jsonc
// examples/verify-timestamp-response-request.json
{ "tool": "verify_timestamp", "arguments": {
  "response": { "path": "fixtures/content.tsr" }, "request": { "path": "fixtures/content.tsq" },
  "data": { "path": "fixtures/content.txt" },
  "trustAnchors": [{ "path": "fixtures/root.crt.pem" }], "candidates": [{ "path": "fixtures/inter.crt.pem" }],
  "at": "2027-01-01T00:00:00Z" } }
// examples/verify-timestamp-other-data.json — a good token of something else: valid false, PKI_REASON_TSP_IMPRINT_MISMATCH (never isError)
```

| Code | Returned when |
| --- | --- |
| `PKI_REASON_TSP_NOT_GRANTED` | The response status is neither granted nor grantedWithMods (the message carries the TSA's failure codes: badAlg, unacceptedPolicy, …) |
| `PKI_REASON_TSP_TOKEN_INVALID` | The token breaks an RFC 3161 token rule: several signers, a tsa name its certificate does not hold, an imprint digest pkinative does not compute |
| `PKI_REASON_TSP_IMPRINT_MISMATCH` | The token's `messageImprint` differs from the hash of the request, the data or the signature value expected |
| `PKI_REASON_TSP_REQUEST_MISMATCH` | The token does not echo the request's nonce as the same integer, or was not issued under the policy requested |
| `PKI_REASON_CMS_*`, `PKI_REASON_NO_TRUST_ANCHOR`, `PKI_REASON_PURPOSE_NOT_PERMITTED`, revocation reasons | The token is a CMS SignedData and the TSA certificate a chain: every CMS and path reason applies |

## Long-term validation (`verify_cms atTimeStamp: true`)

`verify_cms` verifies every counter time-stamp of every signer like `verify_timestamp` would
(its imprint over that signer's signature value, the TSA signature, the TSA chain to your
anchors — always judged at `at`). With `atTimeStamp: true` a signer's **own** chain is judged
at the instant its verified token proves instead of `at` — a signature whose certificate has
since expired stays valid when a trusted TSA stamped it in time; a signer without a valid
token is still judged at `at`. `signingTime` is a **claim** the signer wrote and is never
proof of time; only a verified time-stamp is. The per-signer summary shows
`timeStampTokens` counts (`inspect_cms`) and `signers[i].valid` / `intact` (`verify_cms`).

## Pitfalls

- **Hash the signature value, not the content.** The commonest mistake; `amend_cms` catches
  it before writing, `verify_cms` would report `PKI_REASON_TSP_IMPRINT_MISMATCH` on a token
  smuggled in otherwise.
- **A token without its request is unverifiable against replay.** `data` / `digestHex` prove
  what was stamped; only `request` proves this response answers this request (nonce, policy).
- **The TSA must chain to your anchors** with a critical timeStamping EKU; the TSA name in
  the TSTInfo is a statement, not an identity.
- **`genTime` is established only when `valid`.** Read it from the verdict, not from
  `inspect_timestamp`.
- **Reproducibility:** a request with a pinned `nonce` is byte-identical (the corpus entries
  `tsq-sha256` / `tsq-sha384` are deterministic); `nonce: 'random'` is never cached. Tokens
  are minted by the TSA and never reproducible.

## OpenSSL on your side

```bash
openssl ts -query -in req.tsq -text                                     # read the request the server built
curl -sS -H 'Content-Type: application/timestamp-query' --data-binary @req.tsq "$TSA_URL" -o resp.tsr
openssl ts -reply -in resp.tsr -text                                    # the facts; the verdict is verify_timestamp
openssl ts -verify -in resp.tsr -queryfile req.tsq -CAfile root.pem     # OpenSSL's own verdict against the request
```

The fixture request / response / token (`content.tsq`, `content.tsr`, `content.tst`) were
made by OpenSSL 3.5.5 with the fixture TSA (`tsa.crt.pem`, a critical timeStamping EKU),
and every time-stamp request the server writes is held to `openssl ts -query -text` by the
corpus gate ([CONFORMANCE.md](CONFORMANCE.md)).
