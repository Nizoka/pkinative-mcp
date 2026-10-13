---
paths:
  - "package.json"
  - "server.json"
  - "src/version.ts"
  - "CITATION.cff"
  - "CHANGELOG.md"
  - "release-notes/**"
  - ".github/workflows/publish.yml"
---
<!-- GENERATED from .github/instructions/release.instructions.md by scripts/build-claude-rules.ts — do not edit -->

# Release Standards

## Structure
- One file per release: release-notes/vX.Y.Z.md — mandatory, written before the version bump. No emojis. English.
- Keep sections ordered and omit empty sections; the Upgrade section is present whenever an artefact's bytes, a default, an error code or a wrapper code changed, and declares every rebaseline.
- Use conventional prefixes in bullets: feat(scope), fix(scope), chore(scope), docs(scope), ci(scope).
- Name the engine version shipped (`pkinative x.y.z`), the tool API version and the OpenSSL versions the corpus was validated with.

## Version lock-step
- package.json, server.json (`version` twice: the server and its npm package), CITATION.cff and `src/version.ts` (`PKINATIVE_MCP_VERSION`) carry the same version (asserted by tests/metadata.test.ts, `verify:docs`); the nine `PKINATIVE_MCP_*` variables of server.json match what `src/` reads.
- `TOOL_API_VERSION` (`src/version.ts`) is independent of the package version: bump it ONLY when a tool's input or output schema, a wrapper code or a `PKI_*` mapping changes in a way that would make a cached response unsafe to serve — then say so under docs/API_STABILITY.md. A schema change that ships without the bump leaves hosts and the response cache on a stale contract; diff `tests/_fixtures/tool-shape.json` against the previous tag.
- `tests/_fixtures/tool-shape.v1.0.0.json` is FROZEN: the live catalogue stays a superset (no tool, property or enum value removed; no new `required`; no tighter bound) for the whole 1.x line. A violation is a major.
- CHANGELOG.md mirrors the release-note bullets; the GitHub Release body comes from release-notes/vX.Y.Z.md; title `vX.Y.Z - short description`.
- A compatibility statement for patch / minor releases: tool names, schemas (additive only), byte identity of default artefacts for the same deterministic inputs (a change is semver-major, .github/AGENT_RULES.md rule 5), the refusals (nothing refused by doctrine becomes accepted silently).

## Publication flow
1. Write release-notes/vX.Y.Z.md; mirror into CHANGELOG.md.
2. `npx tsx scripts/release-prepare.ts` (mechanical bump of the four files + scaffolds `.github/drafts/pr-vX.Y.Z.md`; it never commits, tags or publishes).
3. `npx tsx scripts/gate.ts --publish --require-all` with OpenSSL 3 on PATH and `PKINATIVE_INTEROP_REQUIRED=1`; the release audit (`.claude/skills/release-audit/`) ends on GO.
4. The maintainer pushes, opens the PR from the draft, merges, creates the tag `vX.Y.Z` and publishes the GitHub Release — never an agent (`.github/AGENT_RULES.md` rule 8; `.claude/hooks/guard.mjs` refuses `git push`, `git tag <name>`, `gh release`, `npm publish`).
5. `publish.yml` re-runs the publish gate (OpenSSL, and zlint + pkilint when `scripts/data/lint-python-requirements.txt` is present), pins npm 11.19.1, publishes to npm through Trusted Publishing (OIDC, provenance, environment `npm-publish`, no NPM_TOKEN), then the attest job attaches the tarball, the CycloneDX SBOM and the Sigstore attestation to the release.

## Pre-publish dry run and rollback
- **Dry run the registry payload** before tagging: tests/metadata.test.ts (registry name regex, description ≤ 100 chars, the vendored `server.schema.2025-12-11.json`) and `npm pack --dry-run`.
- **npm:** Trusted Publishing runs from the tag — do **not** publish manually. If a bad version ships, do **not** unpublish; cut a superseding patch (vX.Y.Z+1) and, if within npm's 72 h window and truly broken, the maintainer runs `npm deprecate pkinative-mcp@X.Y.Z "use X.Y.Z+1"`.
- **Tags are immutable once released** (`.github/rulesets/tags.json`: no deletion, no force-update, no update). A mistake = new patch tag, never a force-moved tag.
- **Engine bump:** a pkinative upgrade is a patch of this server only when the OpenSSL corpus, the interop suite and the full suite stay green and no `PKI_*` code, reason code or diagnostic code was added (the registries in `src/pki-errors.ts` fail `tsc` otherwise — then it is a minor with docs updates and a `TOOL_API_VERSION` review).
- **Sample baseline:** a rebaseline (`npx tsx scripts/verify-samples.ts --update`) is declared in the release note with its reason; the chain keeps every `since` release.
