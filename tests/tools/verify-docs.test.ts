import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import {
    ENGINE_DATA_FILES,
    EXPECTED_DOCUMENTS,
    KNOWN_NON_TOOLS,
    MANIFEST_REL,
    OFFLINE_RULES,
    isExpectedDocument,
    isSuppressed,
    lineOf,
    semverLess,
    verifyDocs,
    workflowJobs,
    type Problem,
    type Skip,
} from '../../scripts/verify-docs.js';
import { buildSecretNeedles, findSecretMaterial, pemBody, PRIVATE_KEY_BLOCK } from '../../scripts/lib/secret-needles.js';
import { SECRET_NEEDLES } from '../_secrets.js';
import { fixtureText } from '../_pki-fixtures.js';

// The documentation verifier. The helpers are unit-tested; the verifier
// itself runs twice: once against the real tree (the same run the gate's
// `verify:docs` step performs — zero errors is the release condition, which
// applies once every expected document is present; until then a document
// not present yet is a skip, never an error) and once against a sandbox
// copy that was corrupted on purpose, to prove the rules fire.

const ROOT = resolve(import.meta.dirname, '..', '..');
const SKIP = new Set(['node_modules', '.git', 'dist', 'coverage', 'test-output', '.audit']);
const FIXTURES = join(ROOT, 'tests', 'fixtures', 'pki');
const docsComplete = EXPECTED_DOCUMENTS.every((d) => existsSync(join(ROOT, d)));

describe('verify-docs — helpers', () => {
    it('computes 1-based line numbers from offsets', () => {
        expect(lineOf('a\nb\nc', 0)).toBe(1);
        expect(lineOf('a\nb\nc', 2)).toBe(2);
        expect(lineOf('a\nb\nc', 4)).toBe(3);
    });

    it('honours an allow marker on the line or the line above, for that rule only', () => {
        const lines = ['<!-- verify-docs:allow stale-token -->', '11 tools', 'x', 'y <!-- verify-docs:allow count-tokens -->'];
        expect(isSuppressed(lines, 2, 'stale-token')).toBe(true);
        expect(isSuppressed(lines, 2, 'count-tokens')).toBe(false);
        expect(isSuppressed(lines, 4, 'count-tokens')).toBe(true);
        expect(isSuppressed(lines, 3, 'stale-token')).toBe(false);
    });

    it('orders plain semver triples', () => {
        expect(semverLess('1.0.0', '1.0.1')).toBe(true);
        expect(semverLess('1.1.0', '1.0.9')).toBe(false);
        expect(semverLess('1.0.0', '1.0.0')).toBe(false);
        expect(semverLess('1.10.0', '1.9.0')).toBe(false);
    });

    it('reads job ids, display names and matrix values from workflows', () => {
        const ci = 'name: CI\non: push\njobs:\n  ci:\n    name: ci\n    strategy:\n      matrix:\n        node-version: [22, 24]\n    steps: []\n  windows:\n    runs-on: windows-latest\n';
        const { jobs, matrixValues } = workflowJobs([ci, 'jobs:\n  sample-regression:\n    steps: []\n']);
        expect([...jobs].sort()).toEqual(['ci', 'sample-regression', 'windows']);
        expect([...matrixValues.get('ci')!]).toEqual(['22', '24']);
    });

    it('knows the documents the release is written against, and the doctrine names that are not tools', () => {
        expect(isExpectedDocument('docs/AGENT_CONTRACT.md')).toBe(true);
        expect(isExpectedDocument('docs\\guides\\KEYS.md')).toBe(true);
        expect(isExpectedDocument('docs/NOT_THERE.md')).toBe(false);
        expect(EXPECTED_DOCUMENTS).toContain('CHANGELOG.md');
        expect(KNOWN_NON_TOOLS).toContain('create_crl');
        expect(ENGINE_DATA_FILES).toEqual(['errors.json', 'reasons.json', 'diagnostics.json', 'limits.json', 'core-exports.json']);
    });
});

describe('verify-docs — the secret-needle table', () => {
    it('recomputes the needles of tests/_secrets.ts from the fixtures, minus the public password', () => {
        const needles = buildSecretNeedles(FIXTURES);
        expect(needles.length).toBeGreaterThan(20);
        for (const n of needles) expect(SECRET_NEEDLES, n.slice(0, 16)).toContain(n);
        expect(needles).not.toContain('test-only-password');
        // Everything tests/_secrets.ts knows, except the password, is here.
        const missing = SECRET_NEEDLES.filter((n) => n !== 'test-only-password' && !needles.includes(n));
        expect(missing.map((n) => n.slice(0, 16))).toEqual([]);
        expect(buildSecretNeedles(join(ROOT, 'no-such-dir'))).toEqual([]);
    });

    it('finds a needle in any case for hex, a PRIVATE KEY block with a body, and a development-host path', () => {
        const needles = buildSecretNeedles(FIXTURES);
        const body = pemBody(fixtureText('leaf.key.pem'));
        expect(findSecretMaterial(`prose ${body.slice(0, 48)} more`, needles).map((f) => f.reason)).toEqual([expect.stringContaining('fixture private-key needle')]);
        const hexNeedle = needles.find((n) => /^[0-9a-f]{64}$/.test(n))!;
        expect(findSecretMaterial(hexNeedle.toUpperCase(), needles)).toHaveLength(1);
        expect(findSecretMaterial('-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAoGCCqGSM49\n-----END EC PRIVATE KEY-----', [])).toEqual([expect.objectContaining({ reason: expect.stringContaining('PRIVATE KEY PEM block') })]);
        expect(findSecretMaterial('-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----', [])).toEqual([]);
        expect(findSecretMaterial('set PKINATIVE_MCP_OUTPUT_DIR to D:\\Github\\sandbox', [])).toEqual([expect.objectContaining({ reason: expect.stringContaining('development-host absolute path') })]);
        expect(findSecretMaterial('"C:\\\\path\\\\to\\\\sandbox" is fine as an illustration', [])).toEqual([]);
        PRIVATE_KEY_BLOCK.lastIndex = 0;
    });
});

describe('verify-docs — the real tree', () => {
    it('declares the rule list the report prints: the 24 ported rules and the three PKI rules', () => {
        for (const rule of ['tool-parity', 'error-parity', 'env-var-parity', 'changelog-ladder', 'agent-config-parity', 'prose-language', 'no-secret-material', 'engine-data-parity', 'interop-counts']) {
            expect(OFFLINE_RULES).toContain(rule);
        }
        expect(OFFLINE_RULES).toHaveLength(27);
        expect(new Set(OFFLINE_RULES).size).toBe(OFFLINE_RULES.length);
        expect(MANIFEST_REL).toBe('docs/assets/ecosystem.json');
    });

    it('never errors on a document that is not present yet — it skips it, and the tooling-owned rules pass now', async () => {
        const { problems, skips, files } = await verifyDocs(ROOT);
        expect(files).toBeGreaterThan(5);
        const errors = problems.filter((p) => p.severity === 'error');
        const missing = EXPECTED_DOCUMENTS.filter((d) => !existsSync(join(ROOT, d)));
        for (const d of missing) {
            expect(errors.filter((p) => p.file === d).map((p) => `${p.file}:${p.line} [${p.rule}] ${p.message}`), `${d} is not present yet: a skip, never an error`).toEqual([]);
            expect(skips.some((s: Skip) => s.file === d), `${d} is reported as a skip`).toBe(true);
        }
        for (const rule of ['engine-data-parity', 'interop-counts', 'no-secret-material', 'manifest-shape', 'claude-rules-sync', 'ruleset-parity', 'node-pin-parity', 'skills-shape', 'eol-lf']) {
            expect(errors.filter((p) => p.rule === rule).map((p) => `${p.file}:${p.line} ${p.message}`), rule).toEqual([]);
        }
    }, 60_000);

    it.skipIf(!docsComplete)('passes every offline rule once every expected document is present (the gate condition)', async () => {
        const { problems, skips } = await verifyDocs(ROOT, { requireAll: true });
        const errors = problems.filter((p) => p.severity === 'error').map((p) => `${p.file}:${p.line} [${p.rule}] ${p.message}`);
        expect(skips).toEqual([]);
        expect(errors).toEqual([]);
    }, 60_000);

    it('--require-all turns a skip into an error', async () => {
        const lenient = await verifyDocs(ROOT);
        const strict = await verifyDocs(ROOT, { requireAll: true });
        expect(strict.skips).toEqual([]);
        expect(strict.problems.filter((p) => p.severity === 'error').length).toBe(lenient.problems.filter((p) => p.severity === 'error').length + lenient.skips.length);
    }, 60_000);
});

describe('verify-docs — a corrupted sandbox', () => {
    let sandbox = '';
    let problems: Problem[] = [];
    const contractPresent = existsSync(join(ROOT, 'docs', 'AGENT_CONTRACT.md'));
    const changelogPresent = existsSync(join(ROOT, 'CHANGELOG.md'));

    beforeAll(async () => {
        sandbox = mkdtempSync(join(tmpdir(), 'pkinative-mcp-verify-docs-'));
        cpSync(ROOT, sandbox, {
            recursive: true,
            filter: (src) => !SKIP.has(basename(src)),
        });
        const edit = (rel: string, fn: (text: string) => string): void => {
            const p = join(sandbox, rel);
            writeFileSync(p, fn(readFileSync(p, 'utf8')));
        };
        edit(MANIFEST_REL, (text) => {
            const manifest = JSON.parse(text) as {
                derived: Record<string, unknown>;
                declared: Record<string, unknown>;
                packages: Record<string, { version: string }>;
            };
            manifest.derived['prompts'] = 99;
            manifest.derived['typoKey'] = 1;
            manifest.declared['wrapperCodes'] = 1;
            manifest.declared['engineErrorCodes'] = 2;
            (manifest.derived['toolGroups'] as Record<string, string[]>)['Encodings']!.push('render_cert');
            manifest.packages['pkinative-mcp']!.version = '9.9.9';
            return JSON.stringify(manifest, null, 2);
        });
        const keyNeedle = SECRET_NEEDLES.find((n) => /^[0-9a-f]{64}$/.test(n))!;
        edit('README.md', (text) => `${text}\n\nStale: pkinative-mcp v0.0.1 has 11 tools; call \`convert_pdf\` and set PKINATIVE_MCP_NOPE. A 3-sample baseline over 4 corpus entries and 5 limits.\n\nBroken anchors: [same](#no-such-heading), [cross](docs/AGENT_CONTRACT.md#nope-either).\n\n[allowed](#also-missing) <!-- verify-docs:allow anchor-parity -->\n\nPlanned: \`generate_certificate\` <!-- verify-docs:allow tool-parity -->\n\nDoctrine: no \`create_crl\` here.\n\n[gone](docs/NOT_THERE.md)\n\nLeak: ${keyNeedle.toUpperCase()} and the sandbox at D:\\Github\\sandbox.\n\n-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----\n`);
        // A documented code the source never emits, and a code the source emits with its row removed.
        if (contractPresent) {
            edit('docs/AGENT_CONTRACT.md', (text) => text
                .replace(/^\| `GOVERNANCE_VIOLATION` \|.*\n/m, '')
                .replace(/^(\| `VALIDATION_ERROR` \|.*\n)/m, '$1| `INVENTED_CODE` | never | nothing |\n'));
        }
        // The CHANGELOG loses the link definition of the current release.
        if (changelogPresent) edit('CHANGELOG.md', (text) => text.replace(/^\[1\.0\.0\]:.*\r?\n/m, ''));
        // The source reads a variable server.json does not declare.
        edit('src/version.ts', (text) => `${text}\nexport const SECRET_KNOB = process.env['PKINATIVE_MCP_UNDECLARED'];\n`);
        // A fourth runtime dependency.
        edit('package.json', (text) => text.replace('"zod":', '"left-pad": "^1.3.0",\n        "zod":'));
        // A governance source that does not exist (and is not an expected document).
        edit('.github/ai-governance.json', (text) => text.replace('".github/AGENT_RULES.md"', '".github/AGENT_RULES_GONE.md"'));
        // The guard loses its PowerShell matcher.
        edit('.claude/settings.json', (text) => text.replace('"matcher": "PowerShell"', '"matcher": "Pwsh"'));
        // A rule edited by hand.
        edit('.claude/rules/testing.md', (text) => `${text}\n- Edited by hand.\n`);
        // The engine-data mirror drifts, and the interop declaration lies.
        edit('docs/data/errors.json', (text) => text.replace('"schemaVersion": 1', '"schemaVersion": 2'));
        edit('docs/data/interop.json', (text) => text.replace('"conformant": 23', '"conformant": 1'));
        problems = (await verifyDocs(sandbox)).problems;
    }, 120_000);

    afterAll(() => {
        if (sandbox) rmSync(sandbox, { recursive: true, force: true });
    });

    const messages = (rule: string): string[] => problems.filter((p) => p.rule === rule && p.severity === 'error').map((p) => `${p.file}:${p.line} ${p.message}`);

    it('fails derived-counts and manifest-shape on the corrupted manifest and the fourth dependency', () => {
        expect(messages('derived-counts')).toEqual(expect.arrayContaining([
            expect.stringContaining('derived.prompts says 99'),
            expect.stringContaining('declared.wrapperCodes says 1'),
            expect.stringContaining('declared.engineErrorCodes says 2'),
        ]));
        expect(messages('manifest-shape')).toEqual(expect.arrayContaining([
            expect.stringContaining('derived.typoKey'),
            expect.stringContaining('package.json says'),
            expect.stringContaining('left-pad'),
            expect.stringMatching(/src\/version\.ts:1 says \d+\.\d+\.\d+ but the manifest says 9\.9\.9/),
            expect.stringMatching(/server\.json:1 carries version/),
        ]));
    });

    it('fails stale-token, version-token and count-tokens on the appended README line', () => {
        expect(messages('stale-token')).toEqual(expect.arrayContaining([expect.stringMatching(/README\.md:\d+ "11 tools"/)]));
        expect(messages('version-token')).toEqual(expect.arrayContaining([expect.stringContaining('pkinative-mcp v0.0.1')]));
        expect(messages('count-tokens')).toEqual(expect.arrayContaining([
            expect.stringContaining('"3-sample baseline"'),
            expect.stringContaining('"4 corpus entries"'),
            expect.stringContaining('"5 limits"'),
        ]));
    });

    it('fails tool-parity on an invented tool in the docs and in the manifest groups, and honours the allow marker and the doctrine names', () => {
        const found = messages('tool-parity');
        expect(found).toEqual(expect.arrayContaining([
            expect.stringMatching(/README\.md:\d+ `convert_pdf` reads like a tool name/),
            expect.stringContaining('derived.toolGroups differs from the TOOLS registry — unknown: render_cert'),
        ]));
        expect(found.some((m) => m.includes('generate_certificate'))).toBe(false);
        expect(found.some((m) => m.includes('create_crl'))).toBe(false);
    });

    it.skipIf(!contractPresent)('fails error-parity in both directions', () => {
        expect(messages('error-parity')).toEqual(expect.arrayContaining([
            expect.stringContaining('§6 has no row for GOVERNANCE_VIOLATION'),
            expect.stringMatching(/AGENT_CONTRACT\.md:\d+ §6 documents `INVENTED_CODE`/),
        ]));
        expect(messages('error-parity').some((m) => m.includes('PKI_LIMIT_EXCEEDED'))).toBe(false);
    });

    it('fails env-var-parity on an undeclared variable in the docs and in the source', () => {
        expect(messages('env-var-parity')).toEqual(expect.arrayContaining([
            expect.stringMatching(/README\.md:\d+ PKINATIVE_MCP_NOPE is not an operator variable/),
            expect.stringMatching(/src\/version\.ts:\d+ PKINATIVE_MCP_UNDECLARED is read by the source/),
        ]));
    });

    it.skipIf(!changelogPresent)('fails changelog-ladder on the missing rung', () => {
        expect(messages('changelog-ladder')).toEqual(expect.arrayContaining([expect.stringContaining('heading [1.0.0] has no link definition')]));
    });

    it('fails internal-links and anchor-parity, and honours the allow marker', () => {
        expect(messages('internal-links')).toEqual(expect.arrayContaining([expect.stringMatching(/README\.md:\d+ "docs\/NOT_THERE\.md" does not resolve/)]));
        const found = messages('anchor-parity');
        expect(found).toEqual(expect.arrayContaining([expect.stringMatching(/README\.md:\d+ "#no-such-heading" is not a heading anchor of README\.md/)]));
        if (contractPresent) expect(found).toEqual(expect.arrayContaining([expect.stringMatching(/README\.md:\d+ "#nope-either" is not a heading anchor of docs\/AGENT_CONTRACT\.md/)]));
        expect(found.some((m) => m.includes('#also-missing'))).toBe(false);
    });

    it('fails governance-sources, agent-config-parity and claude-rules-sync on the agent layer', () => {
        expect(messages('governance-sources')).toEqual(expect.arrayContaining([expect.stringContaining('".github/AGENT_RULES_GONE.md", which does not exist')]));
        expect(messages('agent-config-parity')).toEqual(expect.arrayContaining([expect.stringContaining('no PowerShell matcher')]));
        expect(messages('claude-rules-sync')).toEqual(expect.arrayContaining([expect.stringMatching(/\.claude\/rules\/testing\.md:1 differs from its instruction file/)]));
    });

    it('fails no-secret-material on a key needle, a PRIVATE KEY body and a development-host path', () => {
        const found = messages('no-secret-material');
        expect(found).toEqual(expect.arrayContaining([
            expect.stringMatching(/README\.md:\d+ carries a fixture private-key needle/),
            expect.stringMatching(/README\.md:\d+ carries a PRIVATE KEY PEM block/),
            expect.stringMatching(/README\.md:\d+ carries a development-host absolute path/),
        ]));
        // The fixtures themselves are never scanned (they are the needles), and the password is not a needle.
        expect(found.some((m) => m.includes('tests/fixtures'))).toBe(false);
        expect(found.some((m) => m.includes('PROVENANCE'))).toBe(false);
    });

    it('fails engine-data-parity on a drifted mirror and interop-counts on a wrong declaration', () => {
        expect(messages('engine-data-parity')).toEqual([expect.stringContaining('docs/data/errors.json:1 differs from src/data/pkinative/errors.json')]);
        expect(messages('interop-counts')).toEqual(expect.arrayContaining([
            expect.stringContaining('declared.conformant is 1 but the corpus table has 23'),
            expect.stringContaining('derived.corpusConformant says 23 but docs/data/interop.json declares 1'),
        ]));
    });

    it('never runs eol-lf outside a git checkout', () => {
        expect(problems.filter((p) => p.rule === 'eol-lf')).toEqual([]);
    });
});
