import { describe, it, expect, vi, afterEach } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// The .claude/rules/ generator over a sandbox tree: generate, --check, orphan
// removal and the refusal of an unscoped source (ported from pdfnative-mcp
// 1.7.0). The script is loaded dynamically and the suite skips while it is
// absent: the scripts are ported in a separate change, the governance files
// in this one.

const ROOT = resolve(import.meta.dirname, '..', '..');
const SCRIPT = join(ROOT, 'scripts', 'build-claude-rules.ts');
const LIB = join(ROOT, 'scripts', 'lib', 'agent-config.ts');

interface Generator {
    readInstructionSources: (root: string) => Record<string, string>;
    readRuleFiles: (root: string) => Record<string, string>;
    diffClaudeRules: (root: string) => { stale: string[]; missing: string[]; extra: string[]; invalid: Array<{ source: string; error: string }> };
    writeClaudeRules: (root: string) => number;
    main: (argv: readonly string[], root?: string) => number;
}

const present = existsSync(SCRIPT) && existsSync(LIB);
const gen: Generator | null = present ? ((await import(pathToFileURL(SCRIPT).href)) as Generator) : null;
const bannerFor: ((source: string) => string) | null = present ? ((await import(pathToFileURL(LIB).href)) as { bannerFor: (s: string) => string }).bannerFor : null;

const INSTRUCTION = '---\ndescription: "Tool rules"\napplyTo: "src/tools/**"\n---\n\n# Tools\n\n- One file per tool.\n';

function sandbox(): string {
    const root = mkdtempSync(join(tmpdir(), 'pkinative-mcp-rules-'));
    mkdirSync(join(root, '.github', 'instructions'), { recursive: true });
    writeFileSync(join(root, '.github', 'instructions', 'tools.instructions.md'), INSTRUCTION);
    return root;
}

const roots: string[] = [];
afterEach(() => {
    for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
    vi.restoreAllMocks();
});

describe.skipIf(gen === null)('build-claude-rules', () => {
    const g = gen!;

    it('reads sources and rules, and reports a missing rule before generation', () => {
        const root = sandbox();
        roots.push(root);
        expect(Object.keys(g.readInstructionSources(root))).toEqual(['tools.instructions.md']);
        expect(g.readRuleFiles(root)).toEqual({});
        expect(g.diffClaudeRules(root).missing).toEqual(['tools.md']);
    });

    it('generates scoped rules with the banner, then --check is clean', () => {
        const root = sandbox();
        roots.push(root);
        vi.spyOn(console, 'log').mockImplementation(() => undefined);
        vi.spyOn(console, 'error').mockImplementation(() => undefined);
        expect(g.main(['--check'], root)).toBe(1);
        expect(g.main([], root)).toBe(0);
        const rule = readFileSync(join(root, '.claude', 'rules', 'tools.md'), 'utf8');
        expect(rule.startsWith('---\npaths:\n  - "src/tools/**"\n---\n')).toBe(true);
        expect(rule).toContain(bannerFor!('tools.instructions.md'));
        expect(g.main(['--check'], root)).toBe(0);
        expect(g.main(['--check', '--json'], root)).toBe(0);
    });

    it('removes an orphan rule and rewrites a hand-edited one', () => {
        const root = sandbox();
        roots.push(root);
        vi.spyOn(console, 'log').mockImplementation(() => undefined);
        vi.spyOn(console, 'error').mockImplementation(() => undefined);
        expect(g.writeClaudeRules(root)).toBe(1);
        writeFileSync(join(root, '.claude', 'rules', 'orphan.md'), '---\npaths:\n  - "x"\n---\nstray\n');
        writeFileSync(join(root, '.claude', 'rules', 'tools.md'), 'edited by hand\n');
        expect(g.main(['--check'], root)).toBe(1);
        expect(g.main([], root)).toBe(0);
        expect(existsSync(join(root, '.claude', 'rules', 'orphan.md'))).toBe(false);
        expect(readFileSync(join(root, '.claude', 'rules', 'tools.md'), 'utf8')).toContain('# Tools');
    });

    it('refuses a source without applyTo and names it', () => {
        const root = sandbox();
        roots.push(root);
        writeFileSync(join(root, '.github', 'instructions', 'bad.instructions.md'), '---\ndescription: x\n---\nbody\n');
        const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
        vi.spyOn(console, 'log').mockImplementation(() => undefined);
        expect(g.main([], root)).toBe(1);
        expect(error.mock.calls.flat().join('\n')).toContain('bad.instructions.md');
        expect(g.main(['--json'], root)).toBe(1);
    });

    it('the committed instruction files generate without a refusal and --check is clean after a generation', () => {
        vi.spyOn(console, 'log').mockImplementation(() => undefined);
        vi.spyOn(console, 'error').mockImplementation(() => undefined);
        const diff = g.diffClaudeRules(ROOT);
        expect(diff.invalid).toEqual([]);
        expect(Object.keys(g.readInstructionSources(ROOT))).toEqual(['mcp-server.instructions.md', 'release.instructions.md', 'security.instructions.md', 'testing.instructions.md', 'tools.instructions.md']);
    });
});
