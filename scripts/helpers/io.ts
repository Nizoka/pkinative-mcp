/**
 * I/O helpers shared by the sample generator, the corpus generator and the
 * verifiers. Ported from pdfnative-mcp's scripts/helpers/io.ts; the
 * generators here drive the BUILT server (`dist/server.js`) through the same
 * `callToolDirect()` the `tools/call` handler reaches, so files are written
 * by the script from the returned bytes.
 */

import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(here, '..', '..');
/** Every generated artefact lives under here; git-ignored. */
export const TEST_OUTPUT_DIR = resolve(REPO_ROOT, 'test-output');
/** The reproducible sample set (`npm run test:generate`). */
export const OUTPUT_DIR = resolve(TEST_OUTPUT_DIR, 'samples');
/** The OpenSSL-made TEST-ONLY PKI (tests/fixtures/PROVENANCE.md). */
export const FIXTURES_DIR = resolve(REPO_ROOT, 'tests', 'fixtures', 'pki');
/** The published MCP call payloads. */
export const EXAMPLES_DIR = resolve(REPO_ROOT, 'examples');

/**
 * The instant every sample and corpus entry is pinned to: inside the
 * fixtures' validity window (2026-01-01 .. 2046-01-01), the value
 * tests/_pki-fixtures.ts pins `at` to. Exported to the server as
 * `PKINATIVE_MCP_AT`, so every omitted `at` / `notBefore` / `signingTime`
 * falls back to it and a generator that forgets a pin still produces the
 * baseline bytes. Changing it invalidates every baseline hash.
 */
export const SAMPLE_AT = '2027-01-01T00:00:00Z';
export const AT_ENV = 'PKINATIVE_MCP_AT';
export const SANDBOX_ENV = 'PKINATIVE_MCP_OUTPUT_DIR';

/** The password of every encrypted fixture (PKCS#8 PBES2 and PKCS#12) — public test material. */
export const FIXTURE_PASSWORD = 'test-only-password';

export function fixturePath(name: string): string {
    return join(FIXTURES_DIR, name);
}

export function fixtureExists(name: string): boolean {
    return /^[A-Za-z0-9._-]+$/.test(name) && existsSync(fixturePath(name));
}

export function fixtureBytes(name: string): Buffer {
    if (!fixtureExists(name)) throw new Error(`unknown fixture "${name}" (tests/fixtures/pki)`);
    return readFileSync(fixturePath(name));
}

/** The DER of a fixture: the bytes of a binary file, the first block of a PEM one. */
export function fixtureDer(name: string): Uint8Array {
    const bytes = fixtureBytes(name);
    if (!name.endsWith('.pem')) return new Uint8Array(bytes);
    const m = /-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/.exec(bytes.toString('utf8'));
    if (m === null) throw new Error(`fixture "${name}" has no PEM block`);
    return new Uint8Array(Buffer.from((m[1] as string).replace(/\s+/g, ''), 'base64'));
}

/** `{ pem }` for a `.pem` fixture (its text), `{ derBase64 }` for a binary one — the PKI input fragment of a tool call. */
export function fixtureInput(name: string): { readonly pem: string } | { readonly derBase64: string } {
    const bytes = fixtureBytes(name);
    return name.endsWith('.pem') ? { pem: bytes.toString('utf8') } : { derBase64: bytes.toString('base64') };
}

/** `{ base64 }` — the CONTENT input fragment (bytes to sign or stamp) of a fixture. */
export function contentInput(name: string): { readonly base64: string } {
    return { base64: fixtureBytes(name).toString('base64') };
}

/**
 * A fresh sandbox with the fixture set copied under `fixtures/`, exported to
 * the server as `PKINATIVE_MCP_OUTPUT_DIR` (so the `path: 'fixtures/…'` inputs
 * of the examples resolve), with the instant pinned. Call after
 * ./hermetic.js has scrubbed the inherited values. Returns the directory;
 * `removeSandbox` deletes it and forgets the variables.
 */
export function prepareSandbox(prefix = 'pkinative-mcp-samples-'): string {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    mkdirSync(join(dir, 'fixtures'), { recursive: true });
    cpSync(FIXTURES_DIR, join(dir, 'fixtures'), { recursive: true });
    process.env[SANDBOX_ENV] = dir;
    process.env[AT_ENV] = SAMPLE_AT;
    return dir;
}

export function removeSandbox(dir: string | null): void {
    Reflect.deleteProperty(process.env, SANDBOX_ENV);
    Reflect.deleteProperty(process.env, AT_ENV);
    if (dir !== null) rmSync(dir, { recursive: true, force: true });
}

export interface OutputMode {
    /** Summary lines only. Implied when stdout is not a terminal, unless --verbose. */
    readonly quiet: boolean;
    /** Machine-readable output on stdout. Implies quiet for everything else. */
    readonly json: boolean;
}

/**
 * Parse the `--quiet` / `--verbose` / `--json` trio shared by the sample
 * scripts. A pipe (CI log, an agent's captured output, `scripts/gate.ts`)
 * gets the quiet form by default so a human at a terminal sees the full
 * table and everyone else sees a few lines; `--verbose` forces the table
 * through a pipe, `--quiet` forces the summary at a terminal.
 *
 * Returns an error message for anything else, so callers can exit 2.
 */
export function parseOutputMode(argv: readonly string[], isTTY: boolean = process.stdout.isTTY === true): OutputMode | { readonly error: string } {
    let quiet = false;
    let verbose = false;
    let json = false;
    for (const a of argv) {
        if (a === '--quiet') quiet = true;
        else if (a === '--verbose') verbose = true;
        else if (a === '--json') json = true;
        else return { error: `Unknown argument "${a}". Expected --quiet, --verbose and/or --json.` };
    }
    if (quiet && verbose) return { error: '--quiet and --verbose are mutually exclusive.' };
    return { quiet: json || quiet || (!isTTY && !verbose), json };
}

export function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
