// Contract of scripts/gate.ts: the STEPS table is the one place the quality
// gate is defined, so these tests hold it to the shape CI, CONTRIBUTING and
// the agent files rely on. No step is executed here; the pure judges
// (`probeDist`, `judgeSmoke`, `secretNeedles`) are fed hostile input directly.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { DIST_FILES, STEPS, judgeSmoke, parseArgs, probeDist, secretNeedles, selectSteps } from '../../scripts/gate.js';
import { SECRET_NEEDLES } from '../_secrets.js';

const ROOT = resolve(import.meta.dirname, '..', '..');
const pkg = JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf8')) as { scripts: Record<string, string>; bin?: Record<string, string>; main?: string; types?: string };

const ids = (profile: 'fast' | 'ci' | 'publish'): string[] => STEPS.filter((s) => s.profiles.includes(profile)).map((s) => s.id);

describe('gate: step table', () => {
    it('has unique ids', () => {
        const all = STEPS.map((s) => s.id);
        expect(new Set(all).size).toBe(all.length);
    });

    it('every npm-script step names a script that exists in package.json', () => {
        for (const s of STEPS) {
            if (s.npmScript !== undefined) expect(pkg.scripts, s.id).toHaveProperty(s.npmScript);
        }
    });

    it('every step is either an npm script or an inline check, never both', () => {
        for (const s of STEPS) {
            expect(Boolean(s.npmScript) !== Boolean(s.inline), s.id).toBe(true);
        }
    });

    it('the fast profile is exactly typecheck:all, lint, test, code-tables, server-json and verify:docs', () => {
        expect(ids('fast')).toEqual(['typecheck:all', 'lint', 'test', 'code-tables', 'server-json', 'verify:docs']);
    });

    it('fast ⊂ ci ⊂ publish — the coverage run standing in for the plain test run', () => {
        const fast = ids('fast');
        const ci = ids('ci');
        const publish = ids('publish');
        for (const id of fast.filter((x) => x !== 'test')) expect(ci, id).toContain(id);
        expect(ci).toContain('test:coverage');
        expect(ci).not.toContain('test');
        for (const id of ci) expect(publish, id).toContain(id);
        expect(ci).not.toContain('lint:certs');
        expect(publish).toEqual(STEPS.filter((s) => s.id !== 'test').map((s) => s.id));
    });

    it('the skippable steps are the OpenSSL steps and lint:certs (a missing judge skips with a reason; --require-all fails it)', () => {
        const skippable = STEPS.filter((s) => s.skipWhen !== undefined).map((s) => s.id);
        expect(skippable).toEqual(['validate:pki', 'interop', 'lint:certs']);
    });

    it('interop and lint:certs carry their skip condition and the env that makes an absent tool fatal', () => {
        const interop = STEPS.find((s) => s.id === 'interop');
        expect(interop?.skipWhen).toBeTypeOf('function');
        expect(interop?.env).toEqual({ PKINATIVE_INTEROP_REQUIRED: '1' });
        expect(interop?.npmScript).toBe('test:interop');
        const lint = STEPS.find((s) => s.id === 'lint:certs');
        expect(lint?.skipWhen).toBeTypeOf('function');
        expect(lint?.env).toEqual({ REQUIRE_LINT: '1' });
        expect(lint?.profiles).toEqual(['publish']);
        expect(STEPS.find((s) => s.id === 'validate:pki')?.env).toEqual({ PKINATIVE_INTEROP_REQUIRED: '1' });
    });

    it('builds before every step that drives dist/ — the coverage run included', () => {
        const order = STEPS.map((s) => s.id);
        const build = order.indexOf('build');
        for (const id of ['dist-check', 'dist-probe', 'smoke', 'verify:tool-shape', 'test:generate', 'test:coverage', 'corpus:pki', 'validate:pki', 'interop']) {
            expect(order.indexOf(id), id).toBeGreaterThan(build);
        }
        expect(order.indexOf('corpus:pki')).toBeLessThan(order.indexOf('validate:pki'));
        expect(order.indexOf('test:generate')).toBeLessThan(order.indexOf('verify:samples'));
        expect(order.indexOf('smoke')).toBe(order.indexOf('dist-probe') + 1);
    });

    it('generates the samples before the coverage run, so the regression suite runs on CI', () => {
        const order = STEPS.map((s) => s.id);
        expect(order.indexOf('test:generate')).toBeLessThan(order.indexOf('test:coverage'));
    });

    it('the fast profile runs the tests without a build; the coverage run requires the artifacts', () => {
        expect(STEPS.find((s) => s.id === 'test')?.env).toEqual({ GATE: '1' });
        expect(STEPS.find((s) => s.id === 'test:coverage')?.env).toEqual({ GATE: '1', GATE_REQUIRE_ARTIFACTS: '1' });
    });

    it('the code tables, the stdio smoke, the dist probe and the registry-schema check are inline steps', () => {
        for (const id of ['code-tables', 'dist-check', 'dist-probe', 'smoke', 'server-json']) {
            expect(STEPS.find((s) => s.id === id)?.inline, id).toBeTypeOf('function');
        }
        expect(STEPS.find((s) => s.id === 'smoke')?.profiles).toEqual(['ci', 'publish']);
    });

    it('dist-check covers every entry point package.json publishes, and the generated code tables', () => {
        const published = [...Object.values(pkg.bin ?? {}), pkg.main ?? '', pkg.types ?? ''].filter((p) => p !== '').map((p) => p.replace(/^\.\//, ''));
        expect(published.length).toBeGreaterThan(0);
        for (const p of published) expect(DIST_FILES as readonly string[], p).toContain(p);
        expect(DIST_FILES).toContain('dist/data/pkinative/code-tables.js');
    });
});

describe('gate: dist probe', () => {
    it('passes an emitted tree that holds only src/ and logs to stderr', () => {
        expect(probeDist([
            { path: 'dist/cli.js', text: "process.stderr.write('ready\\n');" },
            { path: 'dist/tools/create-csr.js', text: 'console.error("x");' },
            { path: 'dist/index.d.ts', text: '' },
        ])).toEqual([]);
    });

    it('fails on console.log in emitted JavaScript — stdout is the JSON-RPC channel', () => {
        const failures = probeDist([{ path: 'dist\\server.js', text: 'console.log ("debug")' }]);
        expect(failures).toHaveLength(1);
        expect(failures[0]).toMatch(/dist\/server\.js: console\.log\(\) would corrupt the stdio JSON-RPC channel/);
    });

    it('ignores console.log in a declaration file, and fails on tests/ or scripts/ under dist/', () => {
        expect(probeDist([{ path: 'dist/index.d.ts', text: '/** console.log(x) */' }])).toEqual([]);
        expect(probeDist([{ path: 'dist/tests/a.test.js', text: '' }, { path: 'dist/scripts/gate.js', text: '' }])).toHaveLength(2);
    });

    it('fails on a secret needle anywhere under dist/, hex case-insensitively', () => {
        const needles = secretNeedles();
        expect(needles.length).toBeGreaterThan(8);
        expect(needles).toContain('test-only-password');
        for (const n of needles) expect(SECRET_NEEDLES, `${n.slice(0, 12)}… is in tests/_secrets.ts`).toContain(n);
        const hex = needles.find((n) => /^[0-9a-f]{64}$/.test(n)) as string;
        expect(probeDist([{ path: 'dist/signer.js', text: `const k = '${hex.toUpperCase()}';` }], needles)).toEqual([expect.stringMatching(/dist\/signer\.js: carries a secret needle/)]);
        expect(probeDist([{ path: 'dist/data/x.json', text: `{"p":"test-only-password"}` }], needles)).toHaveLength(1);
        expect(probeDist([{ path: 'dist/signer.js', text: 'nothing here' }], needles)).toEqual([]);
    });

    it('computes an empty needle table (but the password) when the fixtures are absent', () => {
        expect(secretNeedles(resolve(ROOT, 'nowhere'))).toEqual(['test-only-password']);
    });
});

describe('gate: stdio smoke judge', () => {
    const frame = (o: object): string => JSON.stringify({ jsonrpc: '2.0', ...o });
    const INIT = frame({ id: 1, result: { serverInfo: { name: 'pkinative-mcp', version: '1.0.0' } } });
    const LIST = frame({ id: 2, result: { tools: [{}, {}, {}] } });
    const CALL = frame({ id: 3, result: { content: [{ type: 'text', text: 'x' }], structuredContent: { server: {} } } });
    const EXPECT = { version: '1.0.0', tools: 3 };
    const CLEAN = `${INIT}\n${LIST}\n${CALL}\n`;

    it('passes a clean session', () => {
        expect(judgeSmoke({ status: 0, stdout: CLEAN, stderr: '[pkinative-mcp] ready\n' }, EXPECT)).toEqual([]);
    });

    it('fails on any stdout line that is not a JSON-RPC 2.0 frame', () => {
        const banner = judgeSmoke({ status: 0, stdout: `pkinative-mcp ready\n${CLEAN}`, stderr: '' }, EXPECT);
        expect(banner).toEqual([expect.stringMatching(/stdout purity.*pkinative-mcp ready/)]);
        const bareJson = judgeSmoke({ status: 0, stdout: `{"level":"info"}\n${CLEAN}`, stderr: '' }, EXPECT);
        expect(bareJson).toEqual([expect.stringMatching(/stdout purity/)]);
    });

    it('fails on a version or tool-count mismatch, an unanswered request, a failed call and a non-zero exit', () => {
        expect(judgeSmoke({ status: 0, stdout: CLEAN, stderr: '' }, { version: '1.0.1', tools: 3 })).toEqual([expect.stringMatching(/serverInfo\.version is "1\.0\.0"/)]);
        expect(judgeSmoke({ status: 0, stdout: CLEAN, stderr: '' }, { version: '1.0.0', tools: 34 })).toEqual([expect.stringMatching(/returned 3 tools, dist\/server\.js registers 34/)]);
        expect(judgeSmoke({ status: 0, stdout: `${INIT}\n${LIST}\n`, stderr: '' }, EXPECT)).toEqual([expect.stringMatching(/describe_engine was not answered/)]);
        expect(judgeSmoke({ status: 0, stdout: `${INIT}\n${CALL}\n`, stderr: '' }, EXPECT)).toEqual([expect.stringMatching(/tools\/list was not answered/)]);
        const errored = judgeSmoke({ status: 0, stdout: `${frame({ id: 1, error: { message: 'boom' } })}\n${LIST}\n${CALL}\n`, stderr: '' }, EXPECT);
        expect(errored).toEqual([expect.stringMatching(/initialize was not answered: boom/)]);
        const failedCall = judgeSmoke({ status: 0, stdout: `${INIT}\n${LIST}\n${frame({ id: 3, result: { isError: true, content: [] } })}\n`, stderr: '' }, EXPECT);
        expect(failedCall).toEqual([expect.stringMatching(/describe_engine returned an error/)]);
        expect(judgeSmoke({ status: 1, stdout: CLEAN, stderr: 'Error: x' }, EXPECT)).toEqual([expect.stringMatching(/server exited 1/)]);
    });
});

describe('gate: argument parsing and step selection', () => {
    it('defaults to the ci profile', () => {
        const opts = parseArgs([]);
        expect('error' in opts).toBe(false);
        if (!('error' in opts)) expect(opts.profile).toBe('ci');
    });

    it('rejects two profiles, unknown steps and unknown flags', () => {
        expect(parseArgs(['--fast', '--ci'])).toHaveProperty('error');
        expect(parseArgs(['--only', 'nope'])).toHaveProperty('error');
        expect(parseArgs(['--only'])).toHaveProperty('error');
        expect(parseArgs(['--bogus'])).toHaveProperty('error');
    });

    it('--only selects one step regardless of profile', () => {
        const opts = parseArgs(['--fast', '--only', 'lint:certs']);
        if ('error' in opts) throw new Error(opts.error);
        expect(selectSteps(opts).map((s) => s.id)).toEqual(['lint:certs']);
    });

    it('--from resumes the profile at the given step', () => {
        const opts = parseArgs(['--ci', '--from', 'build']);
        if ('error' in opts) throw new Error(opts.error);
        const stepIds = selectSteps(opts).map((s) => s.id);
        expect(stepIds[0]).toBe('build');
        expect(stepIds).not.toContain('lint');
    });

    it('--from a step outside the profile resumes at its table position', () => {
        const opts = parseArgs(['--fast', '--from', 'build']);
        if ('error' in opts) throw new Error(opts.error);
        expect(selectSteps(opts).map((s) => s.id)).toEqual(['server-json', 'verify:docs']);
        const fromTest = parseArgs(['--fast', '--from', 'test']);
        if ('error' in fromTest) throw new Error(fromTest.error);
        expect(selectSteps(fromTest).map((s) => s.id)).toEqual(['test', 'code-tables', 'server-json', 'verify:docs']);
    });

    it('--require-all and --json are recognised', () => {
        const opts = parseArgs(['--publish', '--require-all', '--json']);
        if ('error' in opts) throw new Error(opts.error);
        expect(opts.requireAll).toBe(true);
        expect(opts.json).toBe(true);
        expect(opts.profile).toBe('publish');
    });
});

describe('gate: wiring', () => {
    it('package.json routes gate and gate:fast to the script, and publishing through the build only', () => {
        expect(pkg.scripts['gate']).toMatch(/scripts\/gate\.ts/);
        expect(pkg.scripts['gate:fast']).toMatch(/scripts\/gate\.ts --fast/);
        expect(pkg.scripts['prepublishOnly']).toBe('npm run build');
        expect(pkg.scripts).not.toHaveProperty('prepare');
    });
});
