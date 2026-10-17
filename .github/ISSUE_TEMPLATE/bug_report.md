---
name: Bug Report
about: Report a bug in pkinative-mcp
title: ''
labels: bug
assignees: ''
---

<!-- Security problems (a key byte or a password in a result, a log, a cache
     file or an error message; a sandbox escape; a crash or resource
     exhaustion on hostile input) are NOT reported here: follow SECURITY.md
     and use private vulnerability reporting.

     If the pkinative engine, called directly, behaves the same way, the bug
     belongs to the engine: https://github.com/Nizoka/pkinative/issues/new/choose
     The server contains no PKI logic of its own. -->

## Description

<!-- A clear description of the bug. -->

## Steps to Reproduce

1.
2.
3.

## Expected Behavior

<!-- What should happen? -->

## Actual Behavior

<!-- What happens instead? Include the `isError` text (`<tool> failed [CODE]: …`),
     the `_meta.error` object, or the verdict's `reasons[]`. -->

## Environment

- **pkinative-mcp version:** <!-- `describe_engine` → server.version, or `npx pkinative-mcp --version` -->
- **pkinative version:** <!-- `describe_engine` → engine.version -->
- **Runtime:** <!-- Node.js 22 / 24, Claude Desktop, Cursor, ChatGPT, an HTTP client, … -->
- **Transport:** <!-- stdio or Streamable HTTP (PKINATIVE_MCP_PORT) -->
- **OS:**
- **Operator variables set:** <!-- names only (PKINATIVE_MCP_OUTPUT_DIR, _AT, …), never the value of _PASSWORD or _HTTP_TOKEN -->

## Minimal Reproduction

<!-- The exact tools/call. Use a certificate, request or CRL from a key generated
     for the report — never a production object, never a private key, never a
     PKCS#12 file, never a password. -->

```json
{
  "method": "tools/call",
  "params": {
    "name": "inspect_certificate",
    "arguments": { "pem": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----" }
  }
}
```

## Additional Context

<!-- `openssl x509 -noout -text` output, the producer of the object, stderr
     lines of the server, diagnostics[] of the result, etc. -->
