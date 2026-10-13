import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

/**
 * The Claude Code agent configuration: `.claude/settings.json` (the deny and
 * allow families on BOTH shell tools, the guard hook wired to both matchers,
 * no commit attribution) and the pure functions of
 * `scripts/lib/agent-config.ts` behind the verify-docs rules
 * `agent-config-parity`, `claude-rules-sync`, `claude-rules-budget`,
 * `pr-template-parity`, `eol-lf`, `skills-shape` and the `.node-version` /
 * `tags.json` extensions (ported from pdfnative-mcp 1.7.0).
 *
 * The first suite reads the committed settings directly, so it holds even
 * before the script lands; the second loads the script dynamically and skips
 * while it is absent (the scripts are ported in a separate change).
 */

const ROOT = resolve(import.meta.dirname, '..', '..');
const SETTINGS_PATH = join(ROOT, '.claude', 'settings.json');
const HOOK_PATH = join(ROOT, '.claude', 'hooks', 'guard.mjs');
const LIB_PATH = join(ROOT, 'scripts', 'lib', 'agent-config.ts');

const SHELLS = ['Bash', 'PowerShell'] as const;
const DENY_FAMILIES = ['npm publish', 'git push', 'gh pr create', 'gh issue create', 'gh release'] as const;
const ALLOW_FAMILIES = ['npm run ', 'npx vitest ', 'npx tsx scripts/', 'npx tsc ', 'npx eslint ', 'node -e ', 'node scripts/', 'git status', 'git diff', 'git log', 'git show'] as const;
const NEVER_READ = ['dist/**', 'coverage/**', 'test-output/**', 'package-lock.json', 'node_modules/**', 'tests/_fixtures/tool-shape*.json', 'tests/_fixtures/samples.sha256.json'] as const;

interface Settings {
    attribution?: { commit?: unknown };
    permissions?: { allow?: string[]; deny?: string[] };
    hooks?: { PreToolUse?: Array<{ matcher?: string; hooks?: Array<{ type?: string; command?: string; timeout?: number }> }> };
}

describe('.claude/settings.json — the committed agent configuration', () => {
    const settings = JSON.parse(readFileSync(SETTINGS_PATH, 'utf8')) as Settings;
    const deny = settings.permissions?.deny ?? [];
    const allow = settings.permissions?.allow ?? [];

    it('adds no commit attribution (no Co-Authored-By trailer)', () => {
        expect(settings.attribution?.commit).toBe('');
    });

    it('denies every HITL command family on both shell tools', () => {
        for (const shell of SHELLS) {
            for (const family of DENY_FAMILIES) {
                expect(deny.some((d) => d.startsWith(`${shell}(${family}`)), `${shell}(${family}…)`).toBe(true);
            }
            expect(deny).toContain(`${shell}(git push)`);
            expect(deny).toContain(`${shell}(git push *)`);
            expect(deny.some((d) => d.startsWith(`${shell}(gh api `) && d.includes('POST')), `${shell}(gh api … POST)`).toBe(true);
        }
    });

    it('denies the same families on both shells (no shell is weaker than the other)', () => {
        const strip = (shell: string): string[] => deny.filter((d) => d.startsWith(`${shell}(`)).map((d) => d.slice(shell.length)).sort();
        expect(strip('PowerShell')).toEqual(strip('Bash'));
        const allowed = (shell: string): string[] => allow.filter((d) => d.startsWith(`${shell}(`)).map((d) => d.slice(shell.length)).sort();
        expect(allowed('PowerShell')).toEqual(allowed('Bash'));
    });

    it('denies Read on the generated, bulky and secret-shaped files', () => {
        for (const glob of NEVER_READ) expect(deny, glob).toContain(`Read(${glob})`);
    });

    it('allows the gate, the test runner, the scripts and read-only git on both shells', () => {
        for (const shell of SHELLS) {
            for (const family of ALLOW_FAMILIES) {
                expect(allow.some((a) => a.startsWith(`${shell}(${family}`)), `${shell}(${family}…)`).toBe(true);
            }
        }
        // Never a blanket shell allowance, never a push or publish allowance.
        expect(allow.some((a) => /^(Bash|PowerShell)\(\*?\)$/.test(a))).toBe(false);
        expect(allow.some((a) => /git push|npm publish|gh (pr|issue|release)/.test(a))).toBe(false);
    });

    it('wires the guard hook as a PreToolUse command on both matchers', () => {
        const pre = settings.hooks?.PreToolUse ?? [];
        for (const shell of SHELLS) {
            const entry = pre.find((h) => h.matcher === shell);
            expect(entry, `${shell} matcher`).toBeDefined();
            const hook = entry?.hooks?.find((x) => x.type === 'command' && x.command?.includes('.claude/hooks/guard.mjs'));
            expect(hook, `${shell} runs guard.mjs`).toBeDefined();
            expect(hook?.timeout).toBeGreaterThan(0);
        }
    });

    it('the hook exists, parses, and its type declarations sit next to it', () => {
        expect(existsSync(HOOK_PATH)).toBe(true);
        expect(existsSync(join(ROOT, '.claude', 'hooks', 'guard.d.mts'))).toBe(true);
        const check = spawnSync(process.execPath, ['--check', HOOK_PATH], { encoding: 'utf8', windowsHide: true });
        expect(check.status, check.stderr).toBe(0);
    });

    it('the generated rules directory is not hand-written: every rule is scoped and carries the banner', () => {
        const dir = join(ROOT, '.claude', 'rules');
        if (!existsSync(dir)) return; // generated by `npm run agents:rules` once the script lands
        for (const name of readdirSync(dir).filter((f) => f.endsWith('.md'))) {
            const text = readFileSync(join(dir, name), 'utf8').replace(/\r\n/g, '\n');
            expect(text, name).toMatch(/^---\npaths:\n(?:  - "[^"]+"\n)+---\n<!-- GENERATED from \.github\/instructions\//);
            expect(existsSync(join(ROOT, '.github', 'instructions', name.replace(/\.md$/, '.instructions.md'))), `${name} has a source`).toBe(true);
        }
    });

    it('every instruction file declares applyTo (the generator refuses an unscoped source)', () => {
        const dir = join(ROOT, '.github', 'instructions');
        const files = readdirSync(dir).filter((f) => f.endsWith('.instructions.md')).sort();
        expect(files).toEqual(['mcp-server.instructions.md', 'release.instructions.md', 'security.instructions.md', 'testing.instructions.md', 'tools.instructions.md']);
        for (const name of files) {
            const text = readFileSync(join(dir, name), 'utf8').replace(/\r\n/g, '\n');
            expect(text, name).toMatch(/^---\n(?:[\s\S]*?\n)?applyTo:\s*"[^"\n]+"\n(?:[\s\S]*?\n)?---\n/);
        }
    });
});

// ── The pure functions of scripts/lib/agent-config.ts ────────────────

// The module's shape, declared here so the suite type-checks while the script
// is still being ported; a drift between the two fails at runtime, which is
// the point.
interface Finding { severity: 'error' | 'warn'; file: string; line: number; message: string }
interface Parsed { applyTo: readonly string[]; description: string | null; body: string }
interface AgentConfig {
    CLAUDE_CONTEXT_BUDGET: number;
    EOL_LF_MODE: 'warn' | 'fail';
    GUARDED_SHELL_TOOLS: readonly string[];
    HITL_BASH_DENY_FAMILIES: readonly string[];
    bannerFor: (source: string) => string;
    checkAgentConfigParity: (input: { settingsText: string | null; claudeMd: string; hook: { exists: boolean; checkStatus: number | null; checkStderr: string } }) => Finding[];
    checkClaudeRulesBudget: (input: { claudeMd: string; resolveImport: (name: string) => string | null; rules: Record<string, string> }) => Finding[];
    checkEol: (lsFiles: string, mode?: 'warn' | 'fail') => Finding[];
    checkNodeVersionPin: (input: { nodeVersion: string | null; enginesNode: string | null; ciMatrix: readonly number[] }) => Finding[];
    checkPrTemplateParity: (template: string | null, contributing: string) => Finding[];
    checkSkillShape: (input: { dir: string; text: string | null; existsInSkill: (n: string) => boolean; existsInRepo: (p: string) => boolean }) => Finding[];
    checkTagRuleset: (text: string | null) => Finding[];
    checklistItems: (text: string) => string[];
    claudeImports: (claudeMd: string) => string[];
    crlfTextFiles: (entries: Array<{ index: string; worktree: string; attrs: string; path: string }>) => Array<{ path: string }>;
    denyEntryFor: (glob: string) => string;
    diffRules: (sources: Record<string, string>, rules: Record<string, string>) => { stale: string[]; missing: string[]; extra: string[]; invalid: Array<{ source: string; error: string }> };
    markdownSection: (text: string, heading: string) => string | null;
    neverReadGlobs: (claudeMd: string) => string[];
    parseInstruction: (text: string) => Parsed | { error: string };
    parseLsFilesEol: (output: string) => Array<{ index: string; worktree: string; attrs: string; path: string }>;
    renderRule: (source: string, text: string) => string | { error: string };
    ruleHasPaths: (text: string) => boolean;
    ruleNameFor: (source: string) => string;
    skillFileReferences: (body: string) => { siblings: string[]; repo: string[] };
}

const lib: AgentConfig | null = existsSync(LIB_PATH) ? ((await import(pathToFileURL(LIB_PATH).href)) as AgentConfig) : null;

const INSTRUCTION = `---\r\ndescription: "Tool rules"\r\napplyTo: "src/tools/**,src/server.ts"\r\n---\r\n# Tools\r\n\r\n- One file per tool.\r\n`;

const SETTINGS = JSON.stringify({
    attribution: { commit: '' },
    permissions: {
        deny: [
            'Read(test-output/**)',
            'Read(coverage/**)',
            'Read(package-lock.json)',
            'Bash(npm publish*)',
            'Bash(git push *)',
            'Bash(gh pr create*)',
            'Bash(gh issue create*)',
            'Bash(gh release *)',
            'PowerShell(npm publish*)',
            'PowerShell(git push *)',
            'PowerShell(gh pr create*)',
            'PowerShell(gh issue create*)',
            'PowerShell(gh release *)',
        ],
    },
    hooks: {
        PreToolUse: [
            { matcher: 'Bash', hooks: [{ type: 'command', command: 'node .claude/hooks/guard.mjs' }] },
            { matcher: 'PowerShell', hooks: [{ type: 'command', command: 'node .claude/hooks/guard.mjs' }] },
        ],
    },
});

const CLAUDE_MD = `@AGENTS.md\n\n## Token discipline\n\n- Never Read \`test-output/\`, \`coverage/\`, \`package-lock.json\`.\n  The deny list in \`.claude/settings.json\` applies to Read.\n- Other bullet \`server.json\`.\n`;

const HOOK_OK = { exists: true, checkStatus: 0, checkStderr: '' };

describe.skipIf(lib === null)('agent-config — generated Claude rules', () => {
    const m = lib!;
    it('parses applyTo (comma-separated, quoted, CRLF) and strips the frontmatter from the body', () => {
        const parsed = m.parseInstruction(INSTRUCTION);
        expect(parsed).toMatchObject({ applyTo: ['src/tools/**', 'src/server.ts'], description: 'Tool rules' });
        if ('error' in parsed) throw new Error(parsed.error);
        expect(parsed.body.startsWith('# Tools')).toBe(true);
        expect(parsed.body).not.toContain('\r');
    });

    it('refuses a source without applyTo or without frontmatter', () => {
        expect(m.parseInstruction('---\ndescription: x\n---\nbody')).toHaveProperty('error', expect.stringContaining('applyTo'));
        expect(m.parseInstruction('# no frontmatter')).toHaveProperty('error', expect.stringContaining('frontmatter'));
    });

    it('renders a scoped rule with the banner, LF endings and one trailing newline', () => {
        const rendered = m.renderRule('tools.instructions.md', INSTRUCTION);
        expect(typeof rendered).toBe('string');
        expect(rendered).toBe(`---\npaths:\n  - "src/tools/**"\n  - "src/server.ts"\n---\n${m.bannerFor('tools.instructions.md')}\n\n# Tools\n\n- One file per tool.\n`);
        expect(m.ruleHasPaths(rendered as string)).toBe(true);
        expect(m.ruleNameFor('tools.instructions.md')).toBe('tools.md');
    });

    it('diffRules reports stale, missing, extra and invalid, and is clean on a fresh render', () => {
        const fresh = m.renderRule('tools.instructions.md', INSTRUCTION) as string;
        const clean = m.diffRules({ 'tools.instructions.md': INSTRUCTION }, { 'tools.md': fresh });
        expect(clean).toMatchObject({ stale: [], missing: [], extra: [], invalid: [] });
        // CRLF in the working copy is not drift (eol-lf owns line endings).
        expect(m.diffRules({ 'tools.instructions.md': INSTRUCTION }, { 'tools.md': fresh.replace(/\n/g, '\r\n') }).stale).toEqual([]);
        const drift = m.diffRules(
            { 'tools.instructions.md': INSTRUCTION, 'testing.instructions.md': INSTRUCTION, 'bad.instructions.md': '# nope' },
            { 'tools.md': `${fresh}\nedited by hand\n`, 'orphan.md': '---\npaths:\n  - "x"\n---\n' },
        );
        expect(drift.stale).toEqual(['tools.md']);
        expect(drift.missing).toEqual(['testing.md']);
        expect(drift.extra).toEqual(['orphan.md']);
        expect(drift.invalid).toEqual([{ source: 'bad.instructions.md', error: expect.stringContaining('frontmatter') }]);
    });

    it('ruleHasPaths is false for an unscoped rule', () => {
        expect(m.ruleHasPaths('---\ndescription: x\n---\nbody')).toBe(false);
        expect(m.ruleHasPaths('no frontmatter')).toBe(false);
    });

    it('renders every committed instruction file (none is refused)', () => {
        const dir = join(ROOT, '.github', 'instructions');
        for (const name of readdirSync(dir).filter((f) => f.endsWith('.instructions.md'))) {
            const rendered = m.renderRule(name, readFileSync(join(dir, name), 'utf8'));
            expect(typeof rendered, name).toBe('string');
            expect(m.ruleHasPaths(rendered as string), name).toBe(true);
        }
    });
});

describe.skipIf(lib === null)('agent-config — agent-config-parity', () => {
    const m = lib!;
    it('derives the Never Read globs from the CLAUDE.md bullet and maps them to deny entries', () => {
        expect(m.neverReadGlobs(CLAUDE_MD)).toEqual(['test-output/', 'coverage/', 'package-lock.json']);
        expect(m.denyEntryFor('coverage/')).toBe('Read(coverage/**)');
        expect(m.denyEntryFor('tests/_fixtures/tool-shape*.json')).toBe('Read(tests/_fixtures/tool-shape*.json)');
        expect(m.neverReadGlobs('# nothing')).toEqual([]);
    });

    it('passes a consistent settings / CLAUDE.md / hook triple', () => {
        expect(m.checkAgentConfigParity({ settingsText: SETTINGS, claudeMd: CLAUDE_MD, hook: HOOK_OK })).toEqual([]);
    });

    it('passes the committed settings.json against the committed hook', () => {
        const check = spawnSync(process.execPath, ['--check', HOOK_PATH], { encoding: 'utf8', windowsHide: true });
        const findings = m.checkAgentConfigParity({
            settingsText: readFileSync(SETTINGS_PATH, 'utf8'),
            claudeMd: existsSync(join(ROOT, 'CLAUDE.md')) ? readFileSync(join(ROOT, 'CLAUDE.md'), 'utf8') : '',
            hook: { exists: true, checkStatus: check.status, checkStderr: check.stderr },
        });
        expect(findings).toEqual([]);
    });

    it('fails when a Never Read glob has no deny entry', () => {
        const settings = SETTINGS.replace('"Read(coverage/**)",', '');
        const findings = m.checkAgentConfigParity({ settingsText: settings, claudeMd: CLAUDE_MD, hook: HOOK_OK });
        expect(findings.map((f) => f.message)).toEqual([expect.stringContaining('Read(coverage/**)')]);
    });

    it('holds the HITL gate on both shell tools: a PowerShell deny family or matcher cannot go missing', () => {
        expect(m.GUARDED_SHELL_TOOLS).toEqual(['Bash', 'PowerShell']);
        const noPush = SETTINGS.replace('"PowerShell(git push *)"', '"PowerShell(git fetch *)"');
        expect(m.checkAgentConfigParity({ settingsText: noPush, claudeMd: CLAUDE_MD, hook: HOOK_OK }).map((f) => f.message)).toEqual([expect.stringContaining('PowerShell(git push')]);
        const bashOnly = SETTINGS.replace('"matcher":"PowerShell"', '"matcher":"Pwsh"');
        expect(m.checkAgentConfigParity({ settingsText: bashOnly, claudeMd: CLAUDE_MD, hook: HOOK_OK }).map((f) => f.message)).toEqual([expect.stringContaining('no PowerShell matcher')]);
    });

    it('fails on a missing HITL family, a non-empty attribution, an unwired hook, a broken hook and invalid JSON', () => {
        expect(m.HITL_BASH_DENY_FAMILIES).toHaveLength(5);
        const noRelease = SETTINGS.replace('"Bash(gh release *)"', '"Bash(gh run *)"');
        expect(m.checkAgentConfigParity({ settingsText: noRelease, claudeMd: CLAUDE_MD, hook: HOOK_OK }).map((f) => f.message)).toEqual([expect.stringContaining('Bash(gh release')]);
        const trailer = SETTINGS.replace('"commit":""', '"commit":"Co-Authored-By: x"');
        expect(m.checkAgentConfigParity({ settingsText: trailer, claudeMd: CLAUDE_MD, hook: HOOK_OK }).map((f) => f.message)).toEqual([expect.stringContaining('attribution.commit')]);
        const unwired = SETTINGS.replace('guard.mjs', 'other.mjs');
        expect(m.checkAgentConfigParity({ settingsText: unwired, claudeMd: CLAUDE_MD, hook: HOOK_OK }).map((f) => f.message)).toEqual([expect.stringContaining('no Bash matcher')]);
        const broken = m.checkAgentConfigParity({ settingsText: SETTINGS, claudeMd: CLAUDE_MD, hook: { exists: true, checkStatus: 1, checkStderr: 'SyntaxError: x\n' } });
        expect(broken).toEqual([expect.objectContaining({ file: '.claude/hooks/guard.mjs', message: expect.stringContaining('SyntaxError') })]);
        expect(m.checkAgentConfigParity({ settingsText: SETTINGS, claudeMd: CLAUDE_MD, hook: { exists: false, checkStatus: null, checkStderr: '' } })[0].message).toContain('missing');
        expect(m.checkAgentConfigParity({ settingsText: '{', claudeMd: CLAUDE_MD, hook: HOOK_OK })[0].message).toContain('not valid JSON');
        expect(m.checkAgentConfigParity({ settingsText: null, claudeMd: CLAUDE_MD, hook: HOOK_OK })[0].message).toContain('missing');
    });
});

describe.skipIf(lib === null)('agent-config — claude-rules-budget', () => {
    const m = lib!;
    const scoped = '---\npaths:\n  - "src/**"\n---\nbody\n';
    it('sums CLAUDE.md, its @imports and unscoped rules against the 16 KiB budget', () => {
        expect(m.claudeImports(CLAUDE_MD)).toEqual(['AGENTS.md']);
        expect(m.checkClaudeRulesBudget({ claudeMd: CLAUDE_MD, resolveImport: () => 'x'.repeat(1000), rules: { 'a.md': scoped } })).toEqual([]);
        const over = m.checkClaudeRulesBudget({ claudeMd: CLAUDE_MD, resolveImport: () => 'x'.repeat(m.CLAUDE_CONTEXT_BUDGET), rules: {} });
        expect(over).toEqual([expect.objectContaining({ severity: 'error', message: expect.stringContaining('always loaded') })]);
    });

    it('fails an unscoped rule and a missing import; warns on a scoped rule over 32 KiB', () => {
        const unscoped = m.checkClaudeRulesBudget({ claudeMd: CLAUDE_MD, resolveImport: () => '', rules: { 'free.md': '---\ndescription: x\n---\nbody' } });
        expect(unscoped).toEqual([expect.objectContaining({ file: '.claude/rules/free.md', severity: 'error', message: expect.stringContaining('paths') })]);
        expect(m.checkClaudeRulesBudget({ claudeMd: CLAUDE_MD, resolveImport: () => null, rules: {} })[0].message).toContain('@AGENTS.md');
        const big = m.checkClaudeRulesBudget({ claudeMd: CLAUDE_MD, resolveImport: () => '', rules: { 'big.md': `${scoped}${'y'.repeat(33 * 1024)}` } });
        expect(big).toEqual([expect.objectContaining({ severity: 'warn', file: '.claude/rules/big.md' })]);
    });
});

describe.skipIf(lib === null)('agent-config — pr-template-parity', () => {
    const m = lib!;
    const CONTRIBUTING = '# C\n\n## Pull Request Checklist\n\n- [ ] `npm run gate` passes\n- [ ] New code has tests\n\n## Commit Messages\n\n- [ ] not a checklist item of the section\n';
    it('extracts checklist items and sections', () => {
        expect(m.checklistItems('- [ ] a\n- [x] b\n- c\n')).toEqual(['a', 'b']);
        expect(m.markdownSection(CONTRIBUTING, 'Pull Request Checklist')).toContain('New code has tests');
        expect(m.markdownSection(CONTRIBUTING, 'Pull Request Checklist')).not.toContain('not a checklist item');
        expect(m.markdownSection(CONTRIBUTING, 'Nope')).toBeNull();
    });

    it('passes a template whose items are verbatim and mention the gate', () => {
        expect(m.checkPrTemplateParity('## Checklist\n\n- [ ] `npm run gate` passes\n- [ ] New code has tests\n', CONTRIBUTING)).toEqual([]);
    });

    it('tolerates re-pointed link targets (the template lives in .github/) but not reworded link text', () => {
        const contributing = '## Pull Request Checklist\n\n- [ ] `npm run gate` passes — see [Release](#release)\n';
        expect(m.checklistItems(contributing)).toEqual(['`npm run gate` passes — see [Release]']);
        expect(m.checkPrTemplateParity('- [ ] `npm run gate` passes — see [Release](../CONTRIBUTING.md#release)\n', contributing)).toEqual([]);
        expect(m.checkPrTemplateParity('- [ ] `npm run gate` passes — see [Releasing](../CONTRIBUTING.md#release)\n', contributing)).toHaveLength(1);
    });

    it('fails a reworded item, a template without the gate, a missing template and a missing section', () => {
        const reworded = m.checkPrTemplateParity('- [ ] `npm run gate` passes\n- [ ] New code has unit tests\n', CONTRIBUTING);
        expect(reworded).toEqual([expect.objectContaining({ line: 2, message: expect.stringContaining('New code has unit tests') })]);
        expect(m.checkPrTemplateParity('- [ ] New code has tests\n', CONTRIBUTING).map((f) => f.message)).toEqual([expect.stringContaining('npm run gate')]);
        expect(m.checkPrTemplateParity(null, CONTRIBUTING)[0].message).toContain('missing');
        expect(m.checkPrTemplateParity('- [ ] x', '# no section')[0].file).toBe('CONTRIBUTING.md');
    });
});

describe.skipIf(lib === null)('agent-config — eol-lf', () => {
    const m = lib!;
    const LS = [
        'i/lf    w/lf    attr/text=auto eol=lf     \tsrc/index.ts',
        'i/crlf  w/crlf  attr/text=auto eol=lf     \tCHANGELOG.md',
        'i/mixed w/mixed attr/text=auto eol=lf     \tdocs/x.md',
        'i/crlf  w/crlf  attr/-text linguist-vendored=true\tscripts/data/Blocks.txt',
        'i/-text w/-text attr/-text -diff -merge   \ttests/fixtures/pki/leaf.crt.der',
        'i/crlf  w/crlf  attr/binary                \tweird.bin',
        'i/none  w/none  attr/text=auto eol=lf     \tempty.txt',
    ].join('\n');

    it('parses the ls-files table and keeps only CRLF/mixed text blobs', () => {
        expect(m.parseLsFilesEol(LS)).toHaveLength(7);
        expect(m.crlfTextFiles(m.parseLsFilesEol(LS)).map((e) => e.path)).toEqual(['CHANGELOG.md', 'docs/x.md']);
    });

    it('fails on a CRLF blob; the warn mode stays available', () => {
        expect(m.EOL_LF_MODE).toBe('fail');
        expect(m.checkEol(LS).map((f) => f.severity)).toEqual(['error', 'error']);
        expect(m.checkEol(LS, 'warn').map((f) => f.severity)).toEqual(['warn', 'warn']);
        expect(m.checkEol(LS, 'fail').map((f) => f.severity)).toEqual(['error', 'error']);
        expect(m.checkEol(LS)[0]).toMatchObject({ file: 'CHANGELOG.md', message: expect.stringContaining('CRLF') });
        expect(m.checkEol('')).toEqual([]);
    });
});

describe.skipIf(lib === null)('agent-config — node-pin-parity (.node-version)', () => {
    const m = lib!;
    it('passes when the pin equals the engines major and the CI floor', () => {
        expect(m.checkNodeVersionPin({ nodeVersion: '22\n', enginesNode: '>=22', ciMatrix: [22, 24] })).toEqual([]);
    });

    it('fails a missing file, a disagreeing major, a higher CI floor and a non-version', () => {
        expect(m.checkNodeVersionPin({ nodeVersion: null, enginesNode: '>=22', ciMatrix: [22] })[0].message).toContain('missing');
        expect(m.checkNodeVersionPin({ nodeVersion: '20\n', enginesNode: '>=22', ciMatrix: [22] }).map((f) => f.message)).toEqual([
            expect.stringContaining('engines.node'),
            expect.stringContaining('lowest CI matrix'),
        ]);
        expect(m.checkNodeVersionPin({ nodeVersion: 'lts/iron\n', enginesNode: '>=22', ciMatrix: [] })[0].message).toContain('not a Node version');
        expect(m.checkNodeVersionPin({ nodeVersion: '22', enginesNode: '>=22', ciMatrix: [] })).toEqual([expect.objectContaining({ severity: 'warn', message: expect.stringContaining('trailing newline') })]);
    });
});

describe.skipIf(lib === null)('agent-config — ruleset-parity (tags.json)', () => {
    const m = lib!;
    const TAGS = { name: 'tags', target: 'tag', conditions: { ref_name: { include: ['refs/tags/v*'], exclude: [] } }, rules: [{ type: 'deletion' }, { type: 'non_fast_forward' }, { type: 'update' }] };
    it('passes a tag ruleset that protects refs/tags/v* against deletion, force and update — the committed one included', () => {
        expect(m.checkTagRuleset(JSON.stringify(TAGS))).toEqual([]);
        expect(m.checkTagRuleset(readFileSync(join(ROOT, '.github', 'rulesets', 'tags.json'), 'utf8'))).toEqual([]);
    });

    it('fails a missing file, invalid JSON, a branch target, a missing include, a missing rule and a creation rule', () => {
        expect(m.checkTagRuleset(null)[0].message).toContain('missing');
        expect(m.checkTagRuleset('{')[0].message).toContain('not valid JSON');
        expect(m.checkTagRuleset(JSON.stringify({ ...TAGS, target: 'branch' })).map((f) => f.message)).toEqual([expect.stringContaining('"tag"')]);
        expect(m.checkTagRuleset(JSON.stringify({ ...TAGS, conditions: { ref_name: { include: ['~ALL'] } } })).map((f) => f.message)).toEqual([expect.stringContaining('refs/tags/v*')]);
        expect(m.checkTagRuleset(JSON.stringify({ ...TAGS, rules: [{ type: 'deletion' }] })).map((f) => f.message)).toEqual([
            expect.stringContaining('non_fast_forward'),
            expect.stringContaining('"update"'),
        ]);
        expect(m.checkTagRuleset(JSON.stringify({ ...TAGS, rules: [...TAGS.rules, { type: 'creation' }] })).map((f) => f.message)).toEqual([expect.stringContaining('creation')]);
    });
});

describe.skipIf(lib === null)('agent-config — skills-shape', () => {
    const m = lib!;
    const SKILL = '---\nname: release-audit\ndescription: Audit a release.\ndisable-model-invocation: true\n---\n# Audit\n\nRead `ledger.md` and `docs/data/core-exports.json`; drive `tests/fixtures/pki/leaf.crt.pem`; write under `.audit/<version>/`; the note is `release-notes/vX.Y.Z.md`.\n';
    const files = new Set(['ledger.md']);
    const repo = new Set(['docs/data/core-exports.json', 'tests/fixtures/pki/leaf.crt.pem']);
    const input = (overrides: Partial<Parameters<AgentConfig['checkSkillShape']>[0]> = {}) => ({
        dir: 'release-audit',
        text: SKILL,
        existsInSkill: (n: string) => files.has(n),
        existsInRepo: (p: string) => repo.has(p),
        ...overrides,
    });

    it('collects sibling and repository references and skips placeholders', () => {
        expect(m.skillFileReferences(SKILL)).toEqual({ siblings: ['ledger.md'], repo: ['docs/data/core-exports.json', 'tests/fixtures/pki/leaf.crt.pem'] });
    });

    it('passes a well-formed skill', () => {
        expect(m.checkSkillShape(input())).toEqual([]);
    });

    it('the committed release-audit skill names its four sibling templates and a directory that matches its name', () => {
        const dir = join(ROOT, '.claude', 'skills', 'release-audit');
        const text = readFileSync(join(dir, 'SKILL.md'), 'utf8');
        const refs = m.skillFileReferences(text);
        expect(refs.siblings.sort()).toEqual(['auditor-a.md', 'auditor-b.md', 'ledger.md', 'verifier.md']);
        for (const sibling of refs.siblings) expect(existsSync(join(dir, sibling)), sibling).toBe(true);
        expect(text).toMatch(/^name: release-audit$/m);
        expect(text).toMatch(/^disable-model-invocation: true$/m);
    });

    it('fails a name that differs from the directory, a missing description, a missing template and a missing SKILL.md', () => {
        expect(m.checkSkillShape(input({ dir: 'audit' })).map((f) => f.message)).toEqual([expect.stringContaining('"audit"')]);
        expect(m.checkSkillShape(input({ text: SKILL.replace('description: Audit a release.', 'description:') })).map((f) => f.message)).toEqual([expect.stringContaining('description')]);
        expect(m.checkSkillShape(input({ existsInSkill: () => false })).map((f) => f.message)).toEqual([expect.stringContaining('ledger.md')]);
        expect(m.checkSkillShape(input({ existsInRepo: () => false })).map((f) => f.message)).toEqual([expect.stringContaining('core-exports.json'), expect.stringContaining('leaf.crt.pem')]);
        expect(m.checkSkillShape(input({ text: null }))[0].message).toContain('missing');
        expect(m.checkSkillShape(input({ text: '# no frontmatter' }))[0].message).toContain('frontmatter');
    });
});
