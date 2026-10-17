/**
 * pkinative-mcp — OpenSSL plumbing (pure parts + the one spawn)
 * ==============================================================
 * OpenSSL is the external judge of this server (the role veraPDF plays for
 * pdfnative-mcp): what the tools write, a foreign implementation must read
 * and verify. Shared by scripts/validate-pki.ts (level 1), scripts/gate.ts
 * (the `interop` skip condition) and tests/interop/openssl.test.ts.
 *
 * Everything except `runOpenssl` / `opensslVersion` is a pure function over
 * strings — the version parser, the command builders and the outcome
 * classifiers — so tests/tools/interop-tools.test.ts covers them with inline
 * fixtures. LibreSSL (macOS' `openssl`) and OpenSSL 1.x are rejected on
 * purpose: `-pbmac1_pbkdf2`, `-attime` on `cms`, and the PBES2 defaults the
 * fixtures were made with are 3.x behaviour.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

// ── Locate and qualify the binary ───────────────────────────────────

/** `OPENSSL_BIN` names the binary; otherwise `openssl` on PATH. */
export const OPENSSL_BIN_ENV = 'OPENSSL_BIN';

export interface LocateDeps {
    readonly env: NodeJS.ProcessEnv;
    /** True when `p` is an existing regular file (a directory or a dangling path is not an executable). */
    readonly exists: (p: string) => boolean;
    /** `which` / `where openssl` — the first path or null. */
    readonly probePath: () => string | null;
}

const DEFAULT_LOCATE: LocateDeps = {
    env: process.env,
    exists: (p) => {
        try {
            return statSync(p).isFile();
        } catch {
            return false;
        }
    },
    probePath: () => {
        const probe = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['openssl'], { encoding: 'utf8', windowsHide: true });
        if (probe.status === 0 && probe.stdout.trim().length > 0) return probe.stdout.trim().split(/\r?\n/)[0] ?? null;
        return null;
    },
};

/**
 * Where the binary came from and, when it was not found, why — the reason
 * the gate prints after SKIP. An `OPENSSL_BIN` that does not resolve to an
 * executable is reported as such, with its value: PATH is never consulted
 * behind an explicit override, so "openssl not on PATH" would be wrong
 * (A2-060: the override was dangling while OpenSSL 3 sat on PATH).
 */
export type Located =
    | { readonly bin: string; readonly source: 'override' | 'path'; readonly reason: null }
    | { readonly bin: null; readonly source: 'override' | 'path'; readonly reason: string };

/** `OPENSSL_BIN` first (it must name an executable file), then whatever `openssl` is on PATH. */
export function locateOpensslOrReason(deps: LocateDeps = DEFAULT_LOCATE): Located {
    const override = deps.env[OPENSSL_BIN_ENV];
    if (override !== undefined && override.trim() !== '') {
        if (deps.exists(override)) return { bin: override, source: 'override', reason: null };
        return { bin: null, source: 'override', reason: `${OPENSSL_BIN_ENV}=${override} is not an executable` };
    }
    const bin = deps.probePath();
    if (bin === null) return { bin: null, source: 'path', reason: 'openssl not on PATH' };
    return { bin, source: 'path', reason: null };
}

/** The located binary, or null when nothing is found (see {@link locateOpensslOrReason} for the reason). */
export function locateOpenssl(deps: LocateDeps = DEFAULT_LOCATE): string | null {
    return locateOpensslOrReason(deps).bin;
}

export interface OpensslVersion {
    /** `OpenSSL` or `LibreSSL` (or whatever the first word was). */
    readonly product: string;
    readonly major: number;
    readonly minor: number;
    readonly patch: number;
    /** The first line of `openssl version`, trimmed. */
    readonly raw: string;
}

/** Parse the first line of `openssl version` (`OpenSSL 3.5.5 27 Jan 2026 (Library: …)`, `LibreSSL 3.9.2`). */
export function parseOpensslVersion(output: string): OpensslVersion | null {
    const line = output.trim().split(/\r?\n/)[0] ?? '';
    const m = /^(\S+)\s+(\d+)\.(\d+)(?:\.(\d+))?/.exec(line);
    if (m === null) return null;
    return { product: m[1] as string, major: Number(m[2]), minor: Number(m[3]), patch: Number(m[4] ?? '0'), raw: line };
}

/** The reason a version is unusable, or null: what the gate prints after SKIP. */
export function judgeOpensslVersion(version: OpensslVersion | null): string | null {
    if (version === null) return 'openssl not on PATH';
    if (/libressl/i.test(version.product)) return 'LibreSSL is not OpenSSL';
    if (!/^openssl$/i.test(version.product)) return `${version.product} is not OpenSSL`;
    if (version.major < 3) return 'OpenSSL < 3.0';
    return null;
}

/** The version of the located binary, or null when it is absent or does not answer. */
export function opensslVersion(bin: string | null = locateOpenssl()): OpensslVersion | null {
    if (bin === null) return null;
    const r = spawnSync(bin, ['version'], { encoding: 'utf8', windowsHide: true });
    if (r.error !== undefined || r.status !== 0) return null;
    return parseOpensslVersion(r.stdout);
}

/** The gate's skip condition: a reason to skip the OpenSSL steps, or null when a usable OpenSSL 3.x is present. */
export function opensslMissing(deps: LocateDeps = DEFAULT_LOCATE): string | null {
    const located = locateOpensslOrReason(deps);
    if (located.bin === null) return located.reason;
    const version = opensslVersion(located.bin);
    // An override that exists but does not answer is named too; a PATH hit that does not answer reads as absent.
    if (version === null && located.source === 'override') return `${OPENSSL_BIN_ENV}=${located.bin} does not answer \`openssl version\``;
    return judgeOpensslVersion(version);
}

// ── Running ─────────────────────────────────────────────────────────

export interface OpensslRun {
    /** Exit status; null when the process could not be spawned or was killed. */
    readonly status: number | null;
    readonly stdout: string;
    readonly stderr: string;
}

export interface RunOptions {
    readonly input?: string | Buffer;
    readonly cwd?: string;
    readonly bin?: string;
    readonly timeoutMs?: number;
}

/** Run `openssl <args>`; stdout and stderr captured as UTF-8. Never throws: a spawn failure is `status: null` with the message on stderr. */
export function runOpenssl(args: readonly string[], options: RunOptions = {}): OpensslRun {
    const located: Located = options.bin !== undefined ? { bin: options.bin, source: 'override', reason: null } : locateOpensslOrReason();
    if (located.bin === null) return { status: null, stdout: '', stderr: located.reason };
    const bin = located.bin;
    const r = spawnSync(bin, [...args], {
        encoding: 'utf8', windowsHide: true, maxBuffer: 64 * 1024 * 1024, timeout: options.timeoutMs ?? 60_000,
        ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
        ...(options.input !== undefined ? { input: options.input } : {}),
        env: { ...process.env, LC_ALL: 'C', LANG: 'C' },
    });
    if (r.error !== undefined) return { status: null, stdout: r.stdout ?? '', stderr: `${r.stderr ?? ''}${r.error.message}` };
    return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

// ── Commands and classifiers ────────────────────────────────────────

/** The corpus commands, by id (the ids `docs/data/interop.json` and the corpus table name). */
export type CommandId =
    | 'x509-text'
    | 'x509-text-pem'
    | 'verify'
    | 'verify-sslserver'
    | 'req-verify'
    | 'req-verify-pem'
    | 'crl-text-pem'
    | 'cms-verify-attached'
    | 'cms-verify-detached'
    | 'asn1parse'
    | 'ocsp-req-text'
    | 'ts-query-text';

export interface CommandContext {
    /** The artefact under test. */
    readonly file: string;
    /** `-CAfile` for verify / cms. */
    readonly caFile?: string;
    /** `-untrusted` intermediates for verify. */
    readonly untrusted?: readonly string[];
    /** The detached content for cms -verify. */
    readonly content?: string;
    /** Where cms -verify writes the content it accepted (never stdout: the verdict is on stderr). */
    readonly outFile?: string;
    /** `-attime` epoch seconds for verify / cms (a pinned instant inside every validity window). */
    readonly attime?: number;
}

export interface Outcome {
    readonly ok: boolean;
    readonly detail: string;
}

export interface Command {
    readonly id: CommandId;
    /** The command line as `docs/data/interop.json` prints it. */
    readonly describe: string;
    readonly build: (ctx: CommandContext) => string[];
    readonly classify: (run: OpensslRun) => Outcome;
}

function need<K extends keyof CommandContext>(ctx: CommandContext, key: K): NonNullable<CommandContext[K]> {
    const v = ctx[key];
    if (v === undefined) throw new Error(`openssl command needs ${key}`);
    return v as NonNullable<CommandContext[K]>;
}

const lastLines = (text: string, n = 3): string => text.trim().split(/\r?\n/).filter((l) => l.length > 0).slice(-n).join(' | ');

/** `openssl verify … <file>` prints `<file>: OK` on stdout; every failure is on stderr with `error <n> at <depth> depth lookup: …`. */
export function classifyVerify(run: OpensslRun): Outcome {
    if (run.status === 0 && /: OK\s*$/m.test(run.stdout)) return { ok: true, detail: 'OK' };
    const error = /error \d+ at \d+ depth lookup: [^\r\n]+/.exec(run.stderr)?.[0] ?? lastLines(run.stderr || run.stdout) ?? `exit ${String(run.status)}`;
    return { ok: false, detail: error || `exit ${String(run.status)}` };
}

/** `openssl req -verify` says `Certificate request self-signature verify OK` (stderr on 3.x; stdout on older builds). */
export function classifyReqVerify(run: OpensslRun): Outcome {
    const both = `${run.stdout}\n${run.stderr}`;
    if (run.status === 0 && /Certificate request self-signature verify OK|verify OK/i.test(both)) return { ok: true, detail: 'Certificate request self-signature verify OK' };
    return { ok: false, detail: lastLines(both) || `exit ${String(run.status)}` };
}

/** `openssl cms -verify` reports `CMS Verification successful` on stderr. */
export function classifyCmsVerify(run: OpensslRun): Outcome {
    if (run.status === 0 && /CMS Verification successful|Verification successful/.test(run.stderr)) return { ok: true, detail: 'CMS Verification successful' };
    return { ok: false, detail: lastLines(run.stderr || run.stdout) || `exit ${String(run.status)}` };
}

/** A text dump (`x509 -text`, `crl -text`, `asn1parse`) succeeds when it exits 0 and printed something. */
export function classifyDump(marker: RegExp): (run: OpensslRun) => Outcome {
    return (run) => {
        if (run.status === 0 && marker.test(run.stdout)) return { ok: true, detail: `${marker.source} present` };
        return { ok: false, detail: run.status === 0 ? `${marker.source} not found in the dump` : (lastLines(run.stderr) || `exit ${String(run.status)}`) };
    };
}

const attime = (ctx: CommandContext): string[] => (ctx.attime !== undefined ? ['-attime', String(ctx.attime)] : []);
const untrusted = (ctx: CommandContext): string[] => (ctx.untrusted ?? []).flatMap((u) => ['-untrusted', u]);

export const COMMANDS: Readonly<Record<CommandId, Command>> = {
    'x509-text': {
        id: 'x509-text',
        describe: 'x509 -inform DER -noout -text',
        build: (ctx) => ['x509', '-inform', 'DER', '-in', ctx.file, '-noout', '-text'],
        classify: classifyDump(/^\s*Signature Algorithm:/m),
    },
    'x509-text-pem': {
        id: 'x509-text-pem',
        describe: 'x509 -inform PEM -noout -text',
        build: (ctx) => ['x509', '-inform', 'PEM', '-in', ctx.file, '-noout', '-text'],
        classify: classifyDump(/^\s*Signature Algorithm:/m),
    },
    verify: {
        id: 'verify',
        describe: 'verify -CAfile <ca> [-untrusted <inter>] [-attime <t>] <leaf>',
        build: (ctx) => ['verify', '-CAfile', need(ctx, 'caFile'), ...untrusted(ctx), ...attime(ctx), ctx.file],
        classify: classifyVerify,
    },
    'verify-sslserver': {
        id: 'verify-sslserver',
        describe: 'verify -CAfile <ca> [-untrusted <inter>] -purpose sslserver [-attime <t>] <leaf>',
        build: (ctx) => ['verify', '-CAfile', need(ctx, 'caFile'), ...untrusted(ctx), '-purpose', 'sslserver', ...attime(ctx), ctx.file],
        classify: classifyVerify,
    },
    'req-verify': {
        id: 'req-verify',
        describe: 'req -inform DER -noout -verify',
        build: (ctx) => ['req', '-inform', 'DER', '-in', ctx.file, '-noout', '-verify'],
        classify: classifyReqVerify,
    },
    'req-verify-pem': {
        id: 'req-verify-pem',
        describe: 'req -inform PEM -noout -verify',
        build: (ctx) => ['req', '-inform', 'PEM', '-in', ctx.file, '-noout', '-verify'],
        classify: classifyReqVerify,
    },
    'crl-text-pem': {
        id: 'crl-text-pem',
        describe: 'crl -inform PEM -noout -text',
        build: (ctx) => ['crl', '-inform', 'PEM', '-in', ctx.file, '-noout', '-text'],
        classify: classifyDump(/Certificate Revocation List/),
    },
    'cms-verify-attached': {
        id: 'cms-verify-attached',
        describe: 'cms -verify -binary -inform DER -CAfile <root> -purpose any [-attime <t>] -out <devnull>',
        build: (ctx) => ['cms', '-verify', '-binary', '-inform', 'DER', '-in', ctx.file, '-CAfile', need(ctx, 'caFile'), '-purpose', 'any', ...attime(ctx), '-out', need(ctx, 'outFile')],
        classify: classifyCmsVerify,
    },
    'cms-verify-detached': {
        id: 'cms-verify-detached',
        describe: 'cms -verify -binary -inform DER -CAfile <root> -purpose any -content <file> [-attime <t>] -out <devnull>',
        build: (ctx) => ['cms', '-verify', '-binary', '-inform', 'DER', '-in', ctx.file, '-CAfile', need(ctx, 'caFile'), '-purpose', 'any', '-content', need(ctx, 'content'), ...attime(ctx), '-out', need(ctx, 'outFile')],
        classify: classifyCmsVerify,
    },
    asn1parse: {
        id: 'asn1parse',
        describe: 'asn1parse -inform DER',
        build: (ctx) => ['asn1parse', '-inform', 'DER', '-in', ctx.file],
        classify: classifyDump(/SEQUENCE/),
    },
    'ocsp-req-text': {
        id: 'ocsp-req-text',
        describe: 'ocsp -reqin <file> -req_text',
        build: (ctx) => ['ocsp', '-reqin', ctx.file, '-req_text'],
        classify: classifyDump(/Serial Number:/),
    },
    'ts-query-text': {
        id: 'ts-query-text',
        describe: 'ts -query -in <file> -text',
        build: (ctx) => ['ts', '-query', '-in', ctx.file, '-text'],
        classify: classifyDump(/Nonce:/),
    },
};

export const COMMAND_IDS = Object.keys(COMMANDS) as readonly CommandId[];

// ── Trust files are PEM ──────────────────────────────────────────────
// `-CAfile` and `-untrusted` are documented as PEM; OpenSSL 3.0 reads them
// through `X509_LOOKUP_load_file(…, X509_FILETYPE_PEM)` and answers a DER
// file with "no certificate or crl found" (ubuntu's 3.0.x), while 3.2+ happens
// to autodetect DER (a developer's 3.5 passes). The artefact under test stays
// DER: the positional certificate, `-in` and `-inform DER` are decoded by
// OSSL_STORE on every 3.x.

/**
 * The path OpenSSL receives for a trust file: the file itself when it is
 * PEM (or not DER at all — OpenSSL then reports it), else its PEM re-encoding
 * written as `<name>.pem` under `scratchDir`.
 */
export function pemTrustFile(file: string, scratchDir: string): string {
    const bytes = readFileSync(file);
    if (bytes.subarray(0, 10).toString('latin1').startsWith('-----BEGIN') || bytes[0] !== 0x30) return file;
    const body = bytes.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
    const out = join(scratchDir, `${basename(file)}.pem`);
    mkdirSync(scratchDir, { recursive: true });
    writeFileSync(out, `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`);
    return out;
}

/** The context with every trust file (`caFile`, `untrusted`) handed over as PEM; the scratch directory is the command's output directory, else the artefact's. */
export function withPemTrust(ctx: CommandContext): CommandContext {
    if (ctx.caFile === undefined && ctx.untrusted === undefined) return ctx;
    const scratch = dirname(ctx.outFile ?? ctx.file);
    return {
        ...ctx,
        ...(ctx.caFile !== undefined ? { caFile: pemTrustFile(ctx.caFile, scratch) } : {}),
        ...(ctx.untrusted !== undefined ? { untrusted: ctx.untrusted.map((u) => pemTrustFile(u, scratch)) } : {}),
    };
}

/** Build, run and classify one corpus command (its trust files handed over as PEM). */
export function judgeWithOpenssl(id: CommandId, ctx: CommandContext, options: RunOptions = {}): Outcome & { readonly run: OpensslRun; readonly args: readonly string[] } {
    const command = COMMANDS[id];
    const args = command.build(withPemTrust(ctx));
    const run = runOpenssl(args, options);
    return { ...command.classify(run), run, args };
}
