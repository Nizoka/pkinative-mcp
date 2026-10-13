# Ledger and verdict formats

Everything lives under `.audit/<version>/` (git-ignored). Plain Markdown, one table per file, so `git diff`-style review and grep both work. No report ever holds a key body, a private scalar or a password: a leak finding quotes the needle's NAME (`leaf.key.pem body`, `PASSWORD`) and the file:line where it was found.

## Finding format (auditors)

One row per claim or surface, including the ones that hold:

| id | severity | claim / surface | evidence command | observed | expected | status |
|---|---|---|---|---|---|---|
| A-003 | blocker | "no key byte leaves `inspect_pkcs12`" | `npx vitest run tests/inspect-pkcs12.test.ts -t "assertResultClean"` | needle `leaf.key.pem body` in diagnostics[0].message | no needle | finding |
| B-007 | major | the code table documents `LIMIT_CEILING_EXCEEDED` with a remedy | `npx vitest run tests/explain-code.test.ts` | row present, remedy empty | remedy names the env var | finding |
| A-011 | note | `verify_cms` with an expired signer is `valid: false`, not `isError` | `node dist/cli.js < .audit/1.0.0/a-011.jsonl` | `valid: false`, reason `PKI_CERT_EXPIRED` | same | holds |

- `id` — `A-` (security / protocol), `B-` (coverage / docs), `D-` (autonomy pass) or `V-` (raised by a verifier), zero-padded to three digits. A test written to close a finding carries the id in its name (`it('A-003: …')`).
- `severity` — `blocker` (a secret leaks, a refusal is bypassed, a shipped claim is false, a public surface is wrong, a gate would fail), `major` (a user or an agent is misled, no gate catches it), `minor` (wording, ordering, a stale example that still behaves), `note` (observation, no action).
- `evidence command` — the exact command; the verifier re-runs it verbatim. A row without one is `unverified`. A request file under `.audit/<version>/` is part of the evidence and holds fixture material only.
- `status` — `holds`, `finding`, `unverified`.

## Verifier format

The auditor table plus two columns:

| … | stamp | justification |
|---|---|---|
| … | CONFIRMED | re-ran the needle suite; `redact()` is not applied to `diagnostics[]` in src/diagnostics.ts:84 |
| … | DOWNGRADED → minor | real, but `verify:docs` rule `code-parity` fails the gate on it — cannot ship silently |
| … | REJECTED | the prerequisite is stated in the tool description and in `serverInfo.instructions` |
| … | DUPLICATE of B-002 | same missing sentence, different document |

## Ledger (`ledger.md`)

Only `CONFIRMED` and `DOWNGRADED` findings, sorted by severity then id, with two more columns:

| id | severity | claim / surface | evidence command | fix | waiver |
|---|---|---|---|---|---|

- `fix` — the commit hash that resolved it, or `open`.
- `waiver` — empty, or the maintainer's one-line reason for shipping with it (only `major` and below may be waived; a secret leak is never waivable).

Above the table: the tally per severity and per stamp, the previous tag, the HEAD hash audited, the OpenSSL version the corpus was judged with, and the date.

## Verdict (`verdict.md`)

```
Verdict: GO | NO-GO
Release: v<version>   HEAD: <hash>   Previous: <tag>   Date: <YYYY-MM-DD>   OpenSSL: <version>
Blockers open: <n>   Majors open: <n>   Waived: <n>
Findings: <confirmed> confirmed, <downgraded> downgraded, <rejected> rejected, <duplicate> duplicate
Next: <the one command the maintainer runs next — the fix loop, or scripts/release-prepare.ts>
```

Then the open blockers, one per line, each with its evidence command.
