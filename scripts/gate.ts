#!/usr/bin/env tsx
/**
 * pkinative-mcp — Quality gate
 * =============================
 * The single definition of what "green" means. CI, the contributor docs and
 * the agent instructions all point here instead of each carrying its own
 * list of commands, so the list cannot drift between them. Ported from
 * pdfnative-mcp's scripts/gate.ts (1.7.0) with this server's own step table:
 * OpenSSL is the external judge here (the role veraPDF plays there), and the
 * certificate linters (zlint, pkilint) the publish-only extra.
 *
 * Every step is an existing npm script, plus the inline checks: the code
 * tables are in sync with the vendored registries (`code-tables`), `dist/`
 * is complete (`dist-check`), it carries nothing it should not — no
 * `console.log`, no byte of a test key (`dist-probe`) —, the BUILT server
 * answers over stdio and writes nothing but JSON-RPC frames to stdout
 * (`smoke`), and `server.json` conforms to the vendored MCP registry schema
 * (`server-json`). The gate runs them in order, captures each one's full
 * output to `test-output/.gate/<id>.log`, and prints ONE line per step — a
 * passing run is under twenty lines, which is what makes it usable from an
 * agent loop where every line of output costs tokens. On the first failure
 * it prints the tail of that step's log and stops.
 *
 * The gate is hermetic: no step needs the network, and operator knobs
 * inherited from the shell are scrubbed (helpers/hermetic.ts), so its verdict
 * is the same on a laptop and on a runner. `npm audit` and the MCP publisher's
 * online `validate server.json` run OUTSIDE the gate on purpose.
 *
 * Usage:
 *   npm run gate                     # --ci: everything except lint:certs
 *   npm run gate:fast                # typecheck:all, lint, test, code-tables, server-json, verify:docs
 *   npx tsx scripts/gate.ts --publish   # everything, lint:certs included
 *   npx tsx scripts/gate.ts --only lint
 *   npx tsx scripts/gate.ts --from build
 *   npx tsx scripts/gate.ts --ci --json
 *   npx tsx scripts/gate.ts --publish --require-all   # what publish.yml runs
 *
 * (PowerShell swallows a bare `--`, so call the script directly when passing
 * flags rather than `npm run gate -- --fast`; `npm run gate:fast` exists for
 * the common case.)
 *
 * Profiles:
 *   --fast     typecheck:all, lint, test, code-tables, server-json, verify:docs
 *   --ci       every step except lint:certs (default); `interop` SKIPs with a
 *              reason when OpenSSL 3.x is absent
 *   --publish  every step; lint:certs SKIPs with a reason when zlint / pkilint
 *              are absent, like the suite it wraps
 *
 * Flags:
 *   --require-all  a step that would SKIP fails instead, with
 *                  `required by --require-all: <reason>`. CI and the release
 *                  workflow pass it: a runner without OpenSSL must go red,
 *                  never quietly skip a check.
 *
 * Exit codes:
 *   0 — every selected step passed or was skipped with a reason
 *   1 — a step failed (its log tail is printed; the full log is on disk),
 *       or a step would have skipped under --require-all
 *   2 — bad usage
 */

// Must be first: pins TZ and scrubs operator knobs before dist/ is loaded.
import './helpers/hermetic.js';

import { spawnSync, type SpawnSyncOptions } from 'node:child_process';
import { closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, rmSync, statSync, writeSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { FIXTURE_PASSWORD, FIXTURES_DIR, REPO_ROOT } from './helpers/io.js';
import { opensslMissing } from './lib/interop-tools.js';
import { validate, type Json } from './lib/json-schema-lite.js';

const LOG_DIR = join(REPO_ROOT, 'test-output', '.gate');
const VITEST_JSON = join(LOG_DIR, 'vitest.json');
const COVERAGE_SUMMARY = join(REPO_ROOT, 'coverage', 'coverage-summary.json');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
const SERVER_MODULE = join(REPO_ROOT, 'dist', 'server.js');
const SERVER_JSON = join(REPO_ROOT, 'server.json');
const FIXTURES = join(REPO_ROOT, 'tests', '_fixtures');

export type Profile = 'fast' | 'ci' | 'publish';

export interface Step {
    readonly id: string;
    /** The npm script this step runs. Absent for the inline checks. */
    readonly npmScript?: string;
    readonly profiles: readonly Profile[];
    /** Returns a reason to skip the step, or null to run it. */
    readonly skipWhen?: () => string | null;
    /** Extra environment for the child process. */
    readonly env?: Readonly<Record<string, string>>;
    /** In-process check; returns the failure lines, empty when it passes. */
    readonly inline?: () => readonly string[] | Promise<readonly string[]>;
    /** A short figure to show next to PASS, read after the step succeeds. */
    readonly note?: () => string | null;
}

// ── Skip conditions ─────────────────────────────────────────────────

/** zlint and a Python that imports pkilint, found the way tests/interop/lint.test.ts finds them. */
export function lintersMissing(): string | null {
    const ok = (cmd: string, args: string[]): boolean => spawnSync(cmd, args, { encoding: 'utf8', windowsHide: true }).status === 0;
    const zlint = ok(process.env['ZLINT'] ?? 'zlint', ['-list-lints-source']);
    const pkilint = [process.env['PKILINT_PYTHON'], 'python3', 'python', 'py'].some((p) => p !== undefined && ok(p, ['-c', 'import pkilint.bin.lint_pkix_cert']));
    const missing = [zlint ? null : 'zlint', pkilint ? null : 'pkilint'].filter((m): m is string => m !== null);
    return missing.length === 0 ? null : `${missing.join(' and ')} not found (ZLINT, PKILINT_PYTHON)`;
}

// ── Notes (figures shown next to PASS) ──────────────────────────────

function testCount(): string | null {
    if (!existsSync(VITEST_JSON)) return null;
    // The whole suite, skipped tests included — the figure `declared.tests`
    // in docs/assets/ecosystem.json is held to it.
    const report = JSON.parse(readFileSync(VITEST_JSON, 'utf8')) as { numTotalTests?: number; numPassedTests?: number; numPendingTests?: number };
    const total = report.numTotalTests ?? report.numPassedTests;
    if (typeof total !== 'number') return null;
    // A skipped suite is visible in the summary line, never silent.
    const pending = report.numPendingTests ?? 0;
    return pending > 0 ? `${total} tests, ${pending} skipped` : `${total} tests`;
}

function coverageFigure(): string | null {
    if (!existsSync(COVERAGE_SUMMARY)) return null;
    const summary = JSON.parse(readFileSync(COVERAGE_SUMMARY, 'utf8')) as {
        total?: { statements?: { pct?: number } };
    };
    const pct = summary.total?.statements?.pct;
    return typeof pct === 'number' ? `${pct.toFixed(1)}% stmts` : null;
}

function joinNotes(...parts: Array<string | null>): string | null {
    const kept = parts.filter((p): p is string => p !== null);
    return kept.length > 0 ? kept.join(', ') : null;
}

function walkFiles(dir: string, visit: (path: string) => void): void {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir)) {
        const p = join(dir, entry);
        if (statSync(p).isDirectory()) walkFiles(p, visit);
        else visit(p);
    }
}

function sampleCount(): string | null {
    const dir = join(REPO_ROOT, 'test-output', 'samples');
    if (!existsSync(dir)) return null;
    let n = 0;
    walkFiles(dir, (p) => { if (!p.endsWith('manifest.json')) n++; });
    return `${n} samples`;
}

function corpusCount(): string | null {
    const manifest = join(REPO_ROOT, 'test-output', 'pki', 'manifest.json');
    if (!existsSync(manifest)) return null;
    const entries = (JSON.parse(readFileSync(manifest, 'utf8')) as { entries?: Array<{ status?: string }> }).entries ?? [];
    const n = (s: string): number => entries.filter((e) => e.status === s).length;
    const skipped = n('skipped');
    return `${n('written')} written, ${n('refused')} refused${skipped > 0 ? `, ${skipped} skipped` : ''}`;
}

/** The tool count of the built server, read by the smoke step and shown next to it. */
let distToolCount: number | null = null;

// ── Inline checks ───────────────────────────────────────────────────

function codeTables(): readonly string[] {
    const r = spawnSync(process.execPath, [join(REPO_ROOT, 'scripts', 'build-code-tables.mjs'), '--check'], { cwd: REPO_ROOT, encoding: 'utf8', windowsHide: true });
    if (r.error) return [`could not run scripts/build-code-tables.mjs: ${r.error.message}`];
    return r.status === 0 ? [] : [(r.stderr || r.stdout || `exit ${String(r.status)}`).trim()];
}

/** Files `npm run build` must leave behind for the package to be complete. */
export const DIST_FILES = ['dist/cli.js', 'dist/index.js', 'dist/index.d.ts', 'dist/server.js', 'dist/data/pkinative/code-tables.js'] as const;

function distCheck(): readonly string[] {
    const failures = DIST_FILES.filter((f) => !existsSync(join(REPO_ROOT, f))).map((f) => `missing: ${f}`);
    if (existsSync(CLI)) {
        const firstLine = readFileSync(CLI, 'utf8').split('\n', 1)[0] ?? '';
        if (!firstLine.startsWith('#!/usr/bin/env node')) failures.push('dist/cli.js does not start with the node shebang');
    }
    return failures;
}

function pemBody(text: string): string {
    return text.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

/**
 * The needle table of the secret-leak probe, recomputed from the fixtures
 * the way tests/_secrets.ts does, never written as a literal: the PEM body
 * of each private key (whole and its first 48 characters), its DER as hex
 * (whole and its first 64 characters), the DER key as hex and base64, the
 * body of the encrypted keys, and the password. A needle anywhere under
 * dist/ means a build that would ship test key material.
 */
export function secretNeedles(fixturesDir: string = FIXTURES_DIR): readonly string[] {
    const read = (name: string): Buffer | null => {
        const p = join(fixturesDir, name);
        return existsSync(p) ? readFileSync(p) : null;
    };
    const needles = new Set<string>([FIXTURE_PASSWORD]);
    for (const name of ['leaf.key.pem', 'rsa.key.pem', 'ed25519.key.pem']) {
        const pem = read(name)?.toString('utf8');
        if (pem === undefined) continue;
        const body = pemBody(pem);
        needles.add(body);
        needles.add(body.slice(0, 48));
        const der = Buffer.from(body, 'base64');
        needles.add(der.toString('hex'));
        needles.add(der.toString('hex').slice(0, 64));
    }
    const derKey = read('leaf.key.der');
    if (derKey !== null) {
        needles.add(derKey.toString('hex'));
        needles.add(derKey.toString('base64'));
    }
    const enc = read('leaf.key.enc.pem')?.toString('utf8');
    if (enc !== undefined) {
        needles.add(pemBody(enc));
        needles.add(pemBody(enc).slice(0, 48));
    }
    const rsaEnc = read('rsa.key.enc.pem')?.toString('utf8');
    if (rsaEnc !== undefined) needles.add(pemBody(rsaEnc).slice(0, 48));
    return [...needles].filter((n) => n.length >= 8);
}

/**
 * `tsc` does not bundle, so there is no bundle to probe; what can go wrong is
 * cheaper to state. Emitted JavaScript must never call `console.log` — on the
 * stdio transport stdout IS the JSON-RPC channel, and one stray line corrupts
 * the framing for every host —, the emitted tree must hold only `src/` (a
 * `tests/` or `scripts/` directory under dist/ means a tsconfig regression
 * that would ship fixtures and tooling to npm), and no file may carry a
 * secret needle (a test key pasted into a source, a fixture copied by a
 * build step).
 */
export function probeDist(files: ReadonlyArray<{ readonly path: string; readonly text: string }>, needles: readonly string[] = []): string[] {
    const failures: string[] = [];
    for (const { path, text } of files) {
        const rel = path.replace(/\\/g, '/');
        if (/(^|\/)dist\/(tests|scripts)\//.test(rel)) failures.push(`${rel}: only src/ may be emitted into dist/`);
        if (rel.endsWith('.js') && /\bconsole\.log\s*\(/.test(text)) failures.push(`${rel}: console.log() would corrupt the stdio JSON-RPC channel — write diagnostics to stderr`);
        const lower = text.toLowerCase();
        for (const n of needles) {
            if (text.includes(n) || (/^[0-9a-f]+$/.test(n) && lower.includes(n))) {
                failures.push(`${rel}: carries a secret needle (${n.length} characters, ${n.slice(0, 8)}…) — a test key or password reached the emitted tree`);
                break;
            }
        }
    }
    return failures;
}

function distProbe(): readonly string[] {
    const dist = join(REPO_ROOT, 'dist');
    if (!existsSync(dist)) return ['dist/ is missing (run build first)'];
    const files: Array<{ path: string; text: string }> = [];
    walkFiles(dist, (p) => files.push({ path: relative(REPO_ROOT, p), text: readFileSync(p, 'utf8') }));
    // The catalogue's `_meta.examples` name the PUBLIC fixture password on purpose
    // (`signer: { p12: { path: 'fixtures/leaf.p12' }, password: 'test-only-password' }`),
    // so the password is not a needle for the emitted tree; every key needle is.
    return probeDist(files, secretNeedles().filter((n) => n !== FIXTURE_PASSWORD));
}

/** One newline-delimited JSON-RPC request per line, exactly as an MCP host frames stdio. */
const SMOKE_INPUT = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'gate-smoke', version: '0' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'describe_engine', arguments: {} } },
].map((m) => JSON.stringify(m)).join('\n') + '\n';

interface SmokeFrame {
    readonly jsonrpc?: string;
    readonly id?: number;
    readonly result?: { readonly serverInfo?: { readonly version?: string }; readonly tools?: readonly unknown[]; readonly isError?: boolean; readonly structuredContent?: unknown };
    readonly error?: { readonly message?: string };
}

/**
 * Judge a finished stdio session. Pure, so tests/tools/gate.test.ts can feed
 * it a polluted stdout without spawning anything.
 */
export function judgeSmoke(run: { readonly status: number | null; readonly stdout: string; readonly stderr: string }, expect: { readonly version: string; readonly tools: number }): string[] {
    const failures: string[] = [];
    const frames: SmokeFrame[] = [];
    for (const line of run.stdout.split('\n').map((l) => l.trim()).filter((l) => l.length > 0)) {
        try {
            const frame = JSON.parse(line) as SmokeFrame;
            if (frame === null || typeof frame !== 'object' || frame.jsonrpc !== '2.0') throw new Error('not a JSON-RPC 2.0 frame');
            frames.push(frame);
        } catch {
            failures.push(`stdout purity: a non-JSON-RPC line reached stdout: ${line.slice(0, 120)}`);
        }
    }
    const init = frames.find((f) => f.id === 1);
    const list = frames.find((f) => f.id === 2);
    const call = frames.find((f) => f.id === 3);
    if (init?.result === undefined) failures.push(`initialize was not answered${init?.error ? `: ${init.error.message}` : ''}`);
    else if (init.result.serverInfo?.version !== expect.version) {
        failures.push(`serverInfo.version is "${String(init.result.serverInfo?.version)}" but package.json says ${expect.version}`);
    }
    if (list?.result === undefined) failures.push(`tools/list was not answered${list?.error ? `: ${list.error.message}` : ''}`);
    else if ((list.result.tools ?? []).length !== expect.tools) {
        failures.push(`tools/list returned ${(list.result.tools ?? []).length} tools, dist/server.js registers ${expect.tools}`);
    }
    if (call?.result === undefined) failures.push(`tools/call describe_engine was not answered${call?.error ? `: ${call.error.message}` : ''}`);
    else if (call.result.isError === true || call.result.structuredContent === undefined) failures.push('tools/call describe_engine returned an error or no structuredContent');
    if (run.status !== 0) failures.push(`server exited ${String(run.status)} after stdin closed (expected a clean 0)\n${run.stderr.slice(-400)}`);
    return failures;
}

/**
 * Drive the BUILT server the way a host would. Source tests import the
 * handlers directly, so this is the only place the emitted tree itself is
 * exercised before publish: the shebang entry point, the stdio transport,
 * and the rule that stdout carries nothing but JSON-RPC frames. The expected
 * tool count is read from dist/server.js, never from a hard-coded list.
 */
async function smoke(): Promise<readonly string[]> {
    if (!existsSync(CLI) || !existsSync(SERVER_MODULE)) return ['dist/cli.js or dist/server.js is missing (run build first)'];
    const server = (await import(pathToFileURL(SERVER_MODULE).href)) as { listToolsPayload: () => { tools: readonly unknown[] } };
    distToolCount = server.listToolsPayload().tools.length;
    const r = spawnSync(process.execPath, [CLI], {
        cwd: REPO_ROOT, encoding: 'utf8', windowsHide: true, input: SMOKE_INPUT, timeout: 60_000,
        maxBuffer: 64 * 1024 * 1024,
        env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' },
    });
    if (r.error) return [`could not run dist/cli.js: ${r.error.message}`];
    const version = (JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as { version: string }).version;
    return judgeSmoke({ status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' }, { version, tools: distToolCount });
}

/**
 * `server.json` against the MCP registry schema it names, offline. The schema
 * is vendored under tests/_fixtures/ (its `$id` is the URL `server.json`
 * points at); the online `npx @modelcontextprotocol/publisher validate` stays
 * a maintainer step before tagging.
 */
function serverJson(): readonly string[] {
    const doc = JSON.parse(readFileSync(SERVER_JSON, 'utf8')) as { readonly [key: string]: Json };
    const url = doc['$schema'];
    if (typeof url !== 'string') return ['server.json has no $schema'];
    const revision = /\/schemas\/([^/]+)\/server\.schema\.json$/.exec(url)?.[1];
    const vendored = join(FIXTURES, `server.schema.${revision ?? 'unknown'}.json`);
    if (revision === undefined || !existsSync(vendored)) {
        return [`server.json names ${url} but ${relative(REPO_ROOT, vendored).replace(/\\/g, '/')} is not vendored — add that revision (maintainer download) in the same change`];
    }
    const schema = JSON.parse(readFileSync(vendored, 'utf8')) as { readonly [key: string]: Json };
    if (schema['$id'] !== url) return [`vendored schema $id is ${String(schema['$id'])}, server.json names ${url}`];
    return validate(doc, schema);
}

// ── The gate ────────────────────────────────────────────────────────

// Order matters in the ci / publish profiles: `build` and `test:generate`
// run BEFORE `test:coverage`, because the suites that spawn dist/cli.js
// (tests/cli-stdio) and read test-output/samples/ need what they produce.
// With the tests first those suites would skip silently on every CI runner;
// `GATE_REQUIRE_ARTIFACTS=1` makes them fail loudly when their input is
// missing. The fast profile keeps `test` first (no build). `corpus:pki`
// precedes `validate:pki` and `interop` (the vitest form of level 1).
export const STEPS: readonly Step[] = [
    { id: 'typecheck:all', npmScript: 'typecheck:all', profiles: ['fast', 'ci', 'publish'] },
    { id: 'lint', npmScript: 'lint', profiles: ['fast', 'ci', 'publish'] },
    {
        id: 'test', npmScript: 'test', profiles: ['fast'],
        env: { GATE: '1' }, note: testCount,
    },
    { id: 'code-tables', profiles: ['fast', 'ci', 'publish'], inline: codeTables },
    { id: 'build', npmScript: 'build', profiles: ['ci', 'publish'] },
    { id: 'dist-check', profiles: ['ci', 'publish'], inline: distCheck },
    { id: 'dist-probe', profiles: ['ci', 'publish'], inline: distProbe },
    { id: 'smoke', profiles: ['ci', 'publish'], inline: smoke, note: () => (distToolCount !== null ? `${distToolCount} tools` : null) },
    { id: 'verify:tool-shape', npmScript: 'verify:tool-shape', profiles: ['ci', 'publish'] },
    { id: 'server-json', profiles: ['fast', 'ci', 'publish'], inline: serverJson },
    { id: 'test:generate', npmScript: 'test:generate', profiles: ['ci', 'publish'], note: sampleCount },
    {
        id: 'test:coverage', npmScript: 'test:coverage', profiles: ['ci', 'publish'],
        env: { GATE: '1', GATE_REQUIRE_ARTIFACTS: '1' }, note: () => joinNotes(testCount(), coverageFigure()),
    },
    { id: 'verify:docs', npmScript: 'verify:docs', profiles: ['fast', 'ci', 'publish'] },
    { id: 'verify:samples', npmScript: 'verify:samples', profiles: ['ci', 'publish'] },
    { id: 'corpus:pki', npmScript: 'corpus:pki', profiles: ['ci', 'publish'], note: corpusCount },
    { id: 'validate:pki', npmScript: 'validate:pki', profiles: ['ci', 'publish'], env: { PKINATIVE_INTEROP_REQUIRED: '1' }, skipWhen: opensslMissing },
    { id: 'interop', npmScript: 'test:interop', profiles: ['ci', 'publish'], skipWhen: opensslMissing, env: { PKINATIVE_INTEROP_REQUIRED: '1' } },
    { id: 'lint:certs', npmScript: 'test:lint-certs', profiles: ['publish'], skipWhen: lintersMissing, env: { REQUIRE_LINT: '1' } },
];

// ── Running a step ──────────────────────────────────────────────────

/**
 * Run an npm script with its stdout and stderr interleaved into one log
 * file. `npm_execpath` is set whenever this script itself was started by
 * npm, and running that CLI under the current node keeps the whole gate on
 * one toolchain; outside npm (a bare `tsx scripts/gate.ts`) fall back to
 * whatever `npm` is on PATH — through a shell, since on Windows that is an
 * `npm.cmd` shim which Node refuses to spawn directly.
 */
function runNpmScript(script: string, logPath: string, extraEnv: Readonly<Record<string, string>>): number {
    const env: NodeJS.ProcessEnv = { ...process.env, ...extraEnv, NO_COLOR: '1', FORCE_COLOR: '0' };
    const fd = openSync(logPath, 'w');
    try {
        const npmCli = process.env['npm_execpath'];
        const common: SpawnSyncOptions = { cwd: REPO_ROOT, env, stdio: ['ignore', fd, fd], windowsHide: true };
        const result = npmCli !== undefined && existsSync(npmCli)
            ? spawnSync(process.execPath, [npmCli, 'run', script], common)
            : spawnSync('npm', ['run', script], { ...common, shell: true });
        if (result.error) throw result.error;
        return result.status ?? 1;
    } finally {
        closeSync(fd);
    }
}

async function runInline(check: () => readonly string[] | Promise<readonly string[]>, logPath: string): Promise<number> {
    let failures: readonly string[];
    try {
        failures = await check();
    } catch (err) {
        failures = [`inline check threw: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`];
    }
    const fd = openSync(logPath, 'w');
    try {
        writeSync(fd, failures.length === 0 ? 'ok\n' : `${failures.join('\n')}\n`);
    } finally {
        closeSync(fd);
    }
    return failures.length === 0 ? 0 : 1;
}

function tail(file: string, lines: number): string[] {
    if (!existsSync(file)) return [];
    const all = readFileSync(file, 'utf8').replace(/\r\n/g, '\n').trimEnd().split('\n');
    return all.slice(-lines);
}

// ── CLI ─────────────────────────────────────────────────────────────

export interface Options {
    readonly profile: Profile;
    readonly only: string | null;
    readonly from: string | null;
    readonly json: boolean;
    /** Turn every SKIP into a FAIL (CI and the release workflow). */
    readonly requireAll: boolean;
}

function usage(): string {
    return [
        'Usage: npx tsx scripts/gate.ts [--fast | --ci | --publish] [--only <id>] [--from <id>] [--require-all] [--json]',
        '',
        `Steps: ${STEPS.map((s) => s.id).join(', ')}`,
    ].join('\n');
}

export function parseArgs(argv: readonly string[]): Options | { error: string } {
    let profile: Profile | null = null;
    let only: string | null = null;
    let from: string | null = null;
    let json = false;
    let requireAll = false;
    const ids = new Set(STEPS.map((s) => s.id));

    for (let i = 0; i < argv.length; i++) {
        const a = argv[i] as string;
        if (a === '--fast' || a === '--ci' || a === '--publish') {
            const p = a.slice(2) as Profile;
            if (profile !== null && profile !== p) return { error: `--${profile} and ${a} are mutually exclusive` };
            profile = p;
        } else if (a === '--only' || a === '--from') {
            const id = argv[i + 1];
            if (id === undefined || id.startsWith('--')) return { error: `${a} needs a step id` };
            if (!ids.has(id)) return { error: `unknown step "${id}"` };
            if (a === '--only') only = id; else from = id;
            i++;
        } else if (a === '--json') {
            json = true;
        } else if (a === '--require-all') {
            requireAll = true;
        } else {
            return { error: `unknown argument "${a}"` };
        }
    }
    return { profile: profile ?? 'ci', only, from, json, requireAll };
}

interface StepOutcome {
    readonly id: string;
    readonly status: 'pass' | 'fail' | 'skip';
    readonly seconds: number;
    readonly note: string | null;
}

export function selectSteps(opts: Options): readonly Step[] {
    if (opts.only !== null) return STEPS.filter((s) => s.id === opts.only);
    let selected = STEPS.filter((s) => s.profiles.includes(opts.profile));
    if (opts.from !== null) {
        const at = selected.findIndex((s) => s.id === opts.from);
        if (at < 0) {
            // The step exists but is not in this profile: run the profile
            // from the position it would occupy in the full table.
            const full = STEPS.findIndex((s) => s.id === opts.from);
            selected = selected.filter((s) => STEPS.indexOf(s) >= full);
        } else {
            selected = selected.slice(at);
        }
    }
    return selected;
}

async function main(): Promise<number> {
    const parsed = parseArgs(process.argv.slice(2));
    if ('error' in parsed) {
        process.stderr.write(`gate: ${parsed.error}\n${usage()}\n`);
        return 2;
    }
    const opts = parsed;
    const steps = selectSteps(opts);
    const width = Math.max(...STEPS.map((s) => s.id.length));
    const say = (line: string): void => { if (!opts.json) process.stdout.write(`${line}\n`); };

    mkdirSync(LOG_DIR, { recursive: true });
    const outcomes: StepOutcome[] = [];
    const startedAt = Date.now();
    say(`gate --${opts.profile}${opts.requireAll ? ' --require-all' : ''}: ${steps.length} step(s)`);

    let failedAt: string | null = null;
    for (const step of steps) {
        const reason = step.skipWhen?.() ?? null;
        if (reason !== null) {
            if (opts.requireAll) {
                const note = `required by --require-all: ${reason}`;
                outcomes.push({ id: step.id, status: 'fail', seconds: 0, note });
                say(`FAIL  ${step.id.padEnd(width)}          ${note}`);
                failedAt = step.id;
                break;
            }
            outcomes.push({ id: step.id, status: 'skip', seconds: 0, note: reason });
            say(`SKIP  ${step.id.padEnd(width)}          (${reason})`);
            continue;
        }

        const logPath = join(LOG_DIR, `${step.id.replace(/[^a-z0-9-]/gi, '-')}.log`);
        // A stale report from an earlier run must never be reported as this run's.
        if (step.env?.['GATE'] === '1') rmSync(VITEST_JSON, { force: true });
        if (step.id === 'test:coverage') rmSync(COVERAGE_SUMMARY, { force: true });

        const t0 = Date.now();
        const status = step.inline
            ? await runInline(step.inline, logPath)
            : runNpmScript(step.npmScript ?? step.id, logPath, step.env ?? {});
        const seconds = (Date.now() - t0) / 1000;
        const clock = `${seconds.toFixed(1)}s`.padStart(7);

        if (status === 0) {
            const note = step.note?.() ?? null;
            outcomes.push({ id: step.id, status: 'pass', seconds, note });
            say(`PASS  ${step.id.padEnd(width)}  ${clock}${note ? `  ${note}` : ''}`);
            continue;
        }

        const rel = relative(REPO_ROOT, logPath).replace(/\\/g, '/');
        outcomes.push({ id: step.id, status: 'fail', seconds, note: `exit ${status}; log: ${rel}` });
        say(`FAIL  ${step.id.padEnd(width)}  ${clock}  exit ${status}`);
        for (const line of tail(logPath, 12)) say(`      ${line}`);
        say(`      (full log: ${rel})`);
        failedAt = step.id;
        break;
    }

    const total = ((Date.now() - startedAt) / 1000).toFixed(1);
    if (opts.json) {
        process.stdout.write(`${JSON.stringify({ ok: failedAt === null, profile: opts.profile, requireAll: opts.requireAll, steps: outcomes }, null, 2)}\n`);
    } else if (failedAt !== null) {
        process.stdout.write(`gate: failed at ${failedAt}\n`);
    } else {
        const passed = outcomes.filter((o) => o.status === 'pass').length;
        const skipped = outcomes.filter((o) => o.status === 'skip').length;
        process.stdout.write(`gate: ${passed} passed, ${skipped} skipped in ${total} s\n`);
    }
    return failedAt === null ? 0 : 1;
}

// Only run when executed directly, so tests can import STEPS/parseArgs/selectSteps.
if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    process.exit(await main());
}
