# Fixture provenance

Every file under `pki/` was produced by **OpenSSL 3.5.5** running
[`make-test-pki.sh`](make-test-pki.sh)
on 2026-10-04. It has foreign provenance: neither the CLI nor pkinative wrote
any of it, so a defect cannot be baked into both a fixture and its reading.
The files are never regenerated in place; re-running the script makes new keys,
which are new fixtures with new checksums.

[`SHA256SUMS`](SHA256SUMS) pins every file; `tests/fixtures.test.ts` fails
on a changed checksum, a missing file or an unlisted one.

**Every private key here is public TEST-ONLY material** (`*.key.pem`,
`*.key.der`, `*.key.enc.pem`, `*.p12`; password `test-only-password`). The
CA, OCSP-responder and TSA keys were deleted after signing.

| File | What it is |
|---|---|
| `root.crt.{pem,der}` | Test Root CA, ECDSA P-256, self-signed, serial 0x01 |
| `inter.crt.{pem,der}` | Test Intermediate CA, ECDSA P-256, pathLen 0, serial 0x02 |
| `leaf.crt.{pem,der}` | `example.test`, ECDSA P-256, serial 0x1001; SAN `example.test`, `*.wild.example.test`, `192.0.2.1`, `leaf@example.test`; EKU serverAuth, clientAuth, emailProtection; CRL DP and OCSP AIA |
| `leaf.key.{pem,der}`, `leaf.pub.pem` | The leaf's PKCS#8 private key and SPKI public key |
| `leaf.key.enc.pem` | The leaf key as PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC) EncryptedPrivateKeyInfo |
| `leaf.csr.{pem,der}` | PKCS#10 request for `csr.example.test` with a SAN extension request |
| `leaf.p12` | PKCS#12 with the leaf key and certificate plus the intermediate; PBES2 AES-256-CBC, PBMAC1 integrity (RFC 9579) |
| `rsa.p12` | PKCS#12 with the RSA key and certificate; PBES2, PBMAC1 |
| `ed25519.p12` | PKCS#12 with the Ed25519 key and certificate; PBES2, PBMAC1 (added 2026-10-05, OpenSSL 3.5.5, for the `--p12` signer rules) |
| `legacy.p12` | The leaf key and certificate in the legacy form (RC2 / 3DES, RFC 7292 SHA-1 HMAC) pkinative refuses |
| `plain-keybag.p12` | The leaf key in an UNENCRYPTED keyBag and its certificate, PBMAC1: proves no report prints key bytes |
| `nomac.p12` | The intermediate certificate in a PKCS#12 with no MAC and no encryption |
| `certs-only.p12` | PKCS#12 holding the intermediate certificate only (no key bag); PBES2, PBMAC1 |
| `revoked.crt.pem` | `revoked.example.test`, serial 0x1002, revoked (keyCompromise, 2026-06-01) |
| `rsa.crt.{pem,der}`, `rsa.key.pem`, `rsa.key.enc.pem` | `rsa.example.test`, RSA 2048, serial 0x1003, and its key (plain and PBES2) |
| `ed25519.crt.{pem,der}`, `ed25519.key.pem` | Test Ed25519 Root, self-signed CA, serial 0x03, and its key |
| `ocsp.crt.pem` | Delegated OCSP responder (EKU OCSPSigning), serial 0x1004 |
| `tsa.crt.pem` | Time-stamping authority (critical EKU timeStamping), serial 0x1005 |
| `inter.crl.{pem,der}` | CRL of the intermediate, revoking 0x1002 |
| `ed25519.crl.der`, `ed25519-delta.crl.der` | Base CRL of the Ed25519 CA (number 1, revokes 0x77) and its delta (deltaCRLIndicator 1, number 2, adds 0x99) |
| `leaf.ocsp-req.der` | OCSP request for the leaf (SHA-256 CertID, with a nonce) |
| `leaf.ocsp.der`, `revoked.ocsp.der` | Delegated-responder answers: good for 0x1001, revoked for 0x1002 |
| `content.txt` | The content every signature and time-stamp covers |
| `attached.p7s`, `detached.p7s` | CMS SignedData by the leaf over `content.txt`, encapsulated and detached |
| `content.tsq`, `content.tsr`, `content.tst` | RFC 3161 request (SHA-256, certReq), response and bare token from the TSA |

All certificates are valid from 2026-01-01 to 2046-01-01 (UTC); the tests pin
`--at` inside that window.

## Copy in pkinative-mcp

This directory is a byte-identical copy of `tests/fixtures/` of pkinative-cli
1.0.0, taken on 2026-10-13: the files, `SHA256SUMS` and this document. Nothing
was regenerated; `tests/fixtures.test.ts` pins the checksum of `SHA256SUMS`
itself, so the two repositories cannot drift silently. The generator
`make-test-pki.sh` is kept next to it for provenance only and is never run in
CI (a run would produce new keys, hence new fixtures with new checksums).

The MCP examples reference these files as `fixtures/<name>` inside the
sandbox: `tests/examples.test.ts` and `scripts/generate-samples.ts` copy the
set under `<PKINATIVE_MCP_OUTPUT_DIR>/fixtures/` before every run.
