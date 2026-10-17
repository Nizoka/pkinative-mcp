---
description: "Investigate and fix a GitHub issue or CI failure with minimal, test-backed changes."
agent: "agent"
---
# GitHub Fix Workflow

Given an issue or CI failure, execute this workflow:

1. Reproduce the issue locally — a `tools/call` against the built server (`npm run build`, then `node dist/cli.js` over stdio) or a vitest case; with a key generated for the reproduction, never a real one.
2. Isolate root cause with file-level evidence. Decide where it lives: a wrong byte, a wrong verdict or a `PKI_*` code on a valid object is the engine's (`Nizoka/pkinative`, draft the upstream issue with `draft_governance_issue`); a schema, sandbox, secrets, cache, projection or transport defect is this server's.
3. Apply the smallest safe fix. Never weaken a refusal, a cap, a ceiling or a sandbox check to make a test pass.
4. Add or update tests proving the fix; name the test after the finding id when there is one (`it('A-003: …')`); call `assertResultClean` on any key or password result the fix touches.
5. Run quality gate:
   - npm run typecheck:all
   - npm run lint
   - npm run test
   - npm run build
   - npm run gate (the CI profile; `PKINATIVE_INTEROP_REQUIRED=1` when OpenSSL 3 is on PATH)
6. Update CHANGELOG and release-notes if user-visible; review `TOOL_API_VERSION` if a schema or a code changed.
7. Provide a concise summary:
   - root cause
   - fix
   - tests added
   - risk assessment

Hand the fix to the maintainer: never push, tag, publish or open the PR yourself (`.github/AGENT_RULES.md` rule 8).
