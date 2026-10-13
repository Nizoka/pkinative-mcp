---
name: Interop report
about: An artefact a pkinative-mcp tool wrote that OpenSSL (or another PKI stack) rejects, or a real-world object the tools mishandle
title: '[interop] '
labels: interop
assignees: ''
---

<!-- The server contains no PKI logic of its own: bytes are written and read
     by the pkinative engine. This template collects the evidence; if the root
     cause is in the engine (it usually is), the maintainers move the report
     to https://github.com/Nizoka/pkinative/issues/new/choose and the server
     ships the fixed engine in a patch release.

     TEST MATERIAL ONLY. Never attach or paste a real private key, a real
     PKCS#12 file or a real password — not even an "expired" one. Re-create the
     case with a key generated for the report (`openssl genpkey`, or the
     fixtures under tests/fixtures/pki/, which are public TEST-ONLY material). -->

## Direction

- [ ] `create_certificate` / `create_csr` / `sign_cms` / `amend_cms` / `create_ocsp_request` / `create_timestamp_request` / `encode_asn1` / `encode_x509_structure` / `convert_pem` **wrote** an artefact that another tool rejects or reads differently
- [ ] Another tool **wrote** an object that `inspect_*` / `verify_*` / `check_*` / `validate_certificate_path` / `build_certificate_path` / `open_pkcs12` / `decode_*` mishandles

## The other tool

Name and **exact version** (e.g. `OpenSSL 3.4.1`, `LibreSSL 3.3.6`, `GnuTLS 3.8.9`, `BouncyCastle 1.80`,
`Java 21 keytool`, `Python cryptography 44.0`, `Windows 11 certutil`, `macOS 15 Keychain`), and the exact
command or API call, so anyone can repeat it:

## The tool call

<!-- The exact tools/call, short enough to run as-is. The `signer` input, if
     any, names a fixture key, never a real one. -->

```json
{
  "method": "tools/call",
  "params": {
    "name": "create_certificate",
    "arguments": {}
  }
}
```

## Evidence

- The other tool's output, verbatim (`openssl verify …`, `openssl cms -verify …`, `openssl asn1parse …`):
- pkinative-mcp result: `<tool> failed [CODE]: …`, the verdict's `valid` and `reasons[]`, or the `inspect_*` diagnostics:
- Artefact attached as DER (base64) or PEM, or the generator call — public material only:
- Does pkinative-mcp read back what it wrote? `inspect_*` with **no diagnostic** / with codes: … / **refuses its own output** (always a bug, say so plainly):

## What the standard says

The clause that decides it (`RFC 5280 §4.2.1.6`, `RFC 5652 §5.4`, `RFC 3161 §2.4.2`, `ITU-T X.690 §11.6`, …) and the
sentence itself. A disagreement between two implementations is not settled by either of them:

## Producer

If the object came from a real-world producer (a public CA, a HSM, a TSA, a signing service, a device),
name it and the version — the engine's interop corpus grows from these reports.
