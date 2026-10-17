# Release Notes Template

This directory contains release notes for each published version of pkinative-mcp.

## File naming

- One file per version: release-notes/vMAJOR.MINOR.PATCH.md
- Examples: v1.0.0.md, v1.0.1.md, v1.1.0.md
- Released notes are read-only history: a correction goes in the next release note, never in a shipped one.

## Template

`npx tsx scripts/release-prepare.ts --version X.Y.Z` scaffolds release-notes/vX.Y.Z.md from the block below
(it resolves `vX.Y.Z`, `X.Y.Z`, the previous tag `vX.Y.Z-1` and `YYYY-MM-DD`, and unescapes the inner code fences);
copying the block by hand works too. Omit sections that do not apply (do not leave empty headings).
The release PR body has its own template: [PR_TEMPLATE.md](PR_TEMPLATE.md).

```markdown
# pkinative-mcp vX.Y.Z

<!-- GitHub Release title: vX.Y.Z - short description -->

_Released YYYY-MM-DD_

<!-- One or two paragraphs: what the release is about (engine alignment / feature / hardening / security), the engine version it aligns with, and what did NOT change (tool count, defaults, the bytes of the deterministic artefacts). -->

<!-- Compatibility statement, e.g.: "No breaking changes to the tool API: every vX.Y.Z-1 input is still accepted and the deterministic artefacts are byte-identical except where listed under Upgrade. All new behaviour is opt-in." -->

## Highlights

<!-- 3 to 6 bullets calling out the most user-visible changes; name the real inputs, enum values and tools. -->

- **...** — ...

## Security

<!-- Only when present; keep it first. CWE reference, affected versions, mitigation. A change to a security default (SHA-1, the RSA scheme, PBES2 / PBMAC1, the key-bearing extensions, a cap or a ceiling) is called out here even when it tightens. -->

- **fix(security):** ...

## Breaking Changes

<!-- Only for MAJOR bumps. Each entry: what changed, why, migration path. A default artefact's bytes changing for the same deterministic inputs is a breaking change (.github/AGENT_RULES.md rule 5). -->

- **BREAKING:** ...

## Added

<!-- New tools, inputs, enum values, wrapper codes, PKI_* mappings, prompts, operator variables, examples, tooling. Group with ### sub-headings when long (engine surface / conformance / repository). State what an agent cannot guess: preconditions, engine limits, what a verdict does NOT establish. -->

- **feat(scope):** ...

## Changed

<!-- Non-breaking behaviour changes, the engine pin (`pkinative` `^A.B.C` → `^D.E.F`), TOOL_API_VERSION, server.json, tooling, the size of tools/list. -->

- **deps:** ...
- **api:** `TOOL_API_VERSION` ... (or "unchanged")

## Fixed

<!-- Bug fixes. Say whose bytes change and why. Reference GitHub issues (#NN) where applicable. -->

- **fix(scope):** ... ([#NN])

## Deprecated

- **deprecate(scope):** ... Will be removed in vX+1.0.0.

## Removed

<!-- Only for MAJOR bumps. Cross-reference the deprecation notice. -->

- **remove(scope):** ...

## Inherited from pkinative D.E.F

<!-- Engine issues closed upstream and therefore closed here (#NN), with the test, example or corpus entry that proves it through the server. -->

- **#NN** — ...

## Deferred by design

<!-- What is NOT in this release and why: ROADMAP items, limits blocked upstream (each pinned by an `it.fails` test and drafted under .github/drafts/), the doctrine (no network, no key generation, no key export, no PKCS#8 / PKCS#12 / CRL / OCSP-response / time-stamp-response writer), items unchanged since the previous release. -->

- ...

## Install

\`\`\`bash
npm install pkinative-mcp@X.Y.Z
\`\`\`

## Upgrade

<!-- Declare EVERY output change and EVERY rebaselined sample here, before publication. For a PATCH release with none, the sentence below suffices and the sub-section is omitted. -->

No breaking changes. Drop-in replacement for vX.Y.Z-1.

### Migrating from vX.Y.Z-1

1. **Rebaseline once if you compare bytes.** <!-- which artefacts change bytes, and why the previous output was wrong or incomplete; which stay byte-identical -->
2. **...** <!-- new wrapper codes a client may now receive, stricter validation, operator variables newly honoured, changed defaults of the repository tooling -->

## Verification

<!-- The gate steps and the figures they printed on the release branch — never typed from memory. Mark a figure the integrator must re-measure at the release commit with a re-measure comment. -->

| Gate | Command | Result |
|---|---|---|
| ... | `...` | ... |

## Links

- CHANGELOG: ../CHANGELOG.md
- Full diff: https://github.com/Nizoka/pkinative-mcp/compare/vX.Y.Z-1...vX.Y.Z
- pkinative D.E.F release notes: https://github.com/Nizoka/pkinative/blob/main/release-notes/vD.E.F.md
- Agent contract: ../docs/AGENT_CONTRACT.md
```

## Conventions

- GitHub Release title format: vX.Y.Z - short description. The GitHub Release body is this file.
- Decide SemVer level first (major/minor/patch); decide `TOOL_API_VERSION` separately, under docs/API_STABILITY.md.
- Keep the sections in the order above and omit the empty ones.
- Mirror bullets in CHANGELOG.md, and add the compare link for the new `## [X.Y.Z]` heading (`verify:docs` rule `changelog-ladder`).
- Use conventional prefixes: feat(scope), fix(scope), chore(scope), docs(scope), ci(scope).
- Every figure quoted (tests, coverage, tools, samples, corpus verdicts, the size of tools/list) comes from a command run on the release branch — never typed from memory. `docs/assets/ecosystem.json` is the single source of counts; `npm run verify:docs` holds the note to it.
- Never name an input, enum value, tool, wrapper code, `PKI_*` code or operator variable that does not exist: check `src/` first.
- Never quote a private key, a scalar, a PKCS#12 body or a password other than the public fixture password `test-only-password`; `verify:docs` rule `no-secret-material` sweeps every note with the needle table of the fixtures.
- Include a compatibility statement for patch and minor releases. The Upgrade section declares every output change and every rebaselined sample before publication.
- Be honest about limits: say what a feature does not do, what a verdict does not establish and what is blocked upstream.
- English everywhere. No emojis. No `Co-Authored-By` trailer and no mention of an AI assistant in commits, PR bodies or release notes.

## Publication workflow

Full procedure: [CONTRIBUTING.md](../CONTRIBUTING.md#release).

1. `npx tsx scripts/release-prepare.ts --version X.Y.Z` — the mechanical bump and the two scaffolds.
2. Write release-notes/vX.Y.Z.md, mirror bullets into CHANGELOG.md, update ROADMAP.md.
3. `npx tsx scripts/gate.ts --publish --require-all` with OpenSSL 3 on PATH and zlint / pkilint installed (every step, no SKIP).
4. Fill .github/drafts/pr-vX.Y.Z.md. Stop: everything after this line is done by the maintainer.
5. Merge to main, tag vX.Y.Z and publish the GitHub Release.
6. The publish workflow releases to npm via OIDC Trusted Publishing; the MCP registry publication follows.
