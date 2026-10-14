# Support

Need help with `pkinative-mcp`? Here's where to go:

- 🐛 **Bug?** [Open an issue](https://github.com/Nizoka/pkinative-mcp/issues/new?labels=bug) — include the `tools/call` payload (with TEST material only — never a real key, a real PKCS#12 or a password), the `_meta.error` block verbatim, and the `describe_engine` result.
- ✨ **Feature request?** [Open an issue](https://github.com/Nizoka/pkinative-mcp/issues/new?labels=enhancement) or a PR. The `draft_governance_issue` tool produces a compliant draft for a human to submit.
- ❓ **Question?** [Start a discussion](https://github.com/Nizoka/pkinative-mcp/discussions) or check existing threads first. The [AI agent guide](docs/AI_GUIDE.md), the [agent contract](docs/AGENT_CONTRACT.md) and the [knowledge base](docs/KNOWLEDGE_BASE.md) answer most "which tool / why was this refused" questions; `explain_code` explains any code the server emits.
- 🔐 **Security issue?** Read [SECURITY.md](SECURITY.md) — please **do not** open a public issue.
- 📦 **PKI engine bugs** (ASN.1 / X.509 / CMS / PKCS#12 parsing, path validation, signatures, revocation, the 22 limits, a `PKI_*` code raised on a valid object): file upstream at [Nizoka/pkinative](https://github.com/Nizoka/pkinative/issues). A refusal whose message names a doctrine line (SHA-1, a missing `rsaScheme`, a legacy PKCS#12, a ceiling) is the security posture working, not a bug.
- 🧪 **OpenSSL disagreement?** Use the [interoperability report](https://github.com/Nizoka/pkinative-mcp/issues/new?template=interop_report.md) template with the `openssl version` line and the command that disagrees.
- 🖥️ **CLI questions**: the companion [pkinative-cli](https://github.com/Nizoka/pkinative-cli) exposes the same engine on the command line.
- 🤖 **MCP protocol questions**: see [modelcontextprotocol.io](https://modelcontextprotocol.io) or the [TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk).

We aim to triage issues within 5 business days. This is an open-source project maintained by volunteers — please be patient and constructive.
