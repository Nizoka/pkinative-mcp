#!/usr/bin/env tsx
/**
 * pkinative-mcp — OpenSSL interoperability validator
 * ===================================================
 * Judges the corpus `scripts/generate-pki-corpus.ts` wrote under
 * `test-output/pki/` on two levels:
 *
 *   level 0  engine round trip, in-process through the BUILT server: every
 *            artefact is fed back to its read / verify tool (inspect +
 *            verify_certificate_chain to the corpus CA at the pinned instant,
 *            inspect_csr with the proof of possession, verify_cms with the
 *            content and the trust anchors, decode_asn1 + an independent
 *            node:crypto reckoning of the OCSP CertID and the TSP imprint);
 *            a `deterministic` entry must have produced the same digest
 *            twice.
 *   level 1  OpenSSL 3.x (the external judge): `x509 -text`, `verify`,
 *            `req -verify`, `cms -verify`, `asn1parse`, `ocsp -req_text`,
 *            `ts -query -text` — the command ids of scripts/lib/interop-tools.ts.
 *            SKIPPED with the reason when a usable OpenSSL is absent
 *            (exit 0 is a skip, not a pass; the gate's --require-all and
 *            PKINATIVE_INTEROP_REQUIRED=1 turn it into a failure).
 *
 * Outcomes per entry (one line each on stdout):
 *   PASS     every check met
 *   FAIL     a check failed (its detail is printed)
 *   REFUSED  a negative canary was refused with the expected code
 *   XPASS    a negative canary PRODUCED bytes — always fatal
 *   SKIP     the tool is not registered yet (the generator said so)
 *
 * Coverage canary: the table's conformant / refused counts must equal
 * `declared` in docs/data/interop.json, and every artefact the manifest
 * lists must be on disk.
 *
 * Usage:
 *   npm run build && npm run corpus:pki && npm run validate:pki
 *   npx tsx scripts/validate-pki.ts [--quiet | --verbose] [--json]
 *   PKINATIVE_INTEROP_REQUIRED=1 npx tsx scripts/validate-pki.ts   # OpenSSL must be present
 *
 * Exit codes:
 *   0 — every expectation met (level 1 skipped with a reason when OpenSSL is absent)
 *   1 — a FAIL or an XPASS, or a coverage canary tripped
 *   2 — infrastructure: the corpus or dist/ is missing, bad usage
 *   3 — PKINATIVE_INTEROP_REQUIRED=1 and OpenSSL is absent or unusable
 */

// Must be first: pins TZ and scrubs operator knobs before dist/ is loaded.
import './helpers/hermetic.js';

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT, fixturePath, parseOutputMode, prepareSandbox, removeSandbox } from './helpers/io.js';
import { errorText, loadBuiltServer, type BuiltServer } from './helpers/server.js';
import { COMMANDS, judgeWithOpenssl, locateOpenssl, opensslMissing, opensslVersion, type CommandContext } from './lib/interop-tools.js';
import { CORPUS, CORPUS_ATTIME, CONFORMANT, REFUSED, resolvePlaceholders, type CorpusEntry, type FileRef, type ProducedBytes } from './lib/pki-corpus.js';
import { CORPUS_DIR, MANIFEST_PATH, loadManifest, type ManifestEntry } from './lib/pki-corpus-manifest.js';

export const EXIT_OK = 0;
export const EXIT_CONFORMANCE = 1;
export const EXIT_INFRA = 2;
export const EXIT_TOOL_MISSING = 3;

const INTEROP_JSON = join(REPO_ROOT, 'docs', 'data', 'interop.json');
const REQUIRED_ENV = 'PKINATIVE_INTEROP_REQUIRED';

interface Declared {
    readonly conformant: number;
    readonly refused: number;
}

function declaredCounts(): Declared | null {
    if (!existsSync(INTEROP_JSON)) return null;
    const doc = JSON.parse(readFileSync(INTEROP_JSON, 'utf8')) as { declared?: { conformant?: unknown; refused?: unknown } };
    const c = doc.declared?.conformant;
    const r = doc.declared?.refused;
    return typeof c === 'number' && typeof r === 'number' ? { conformant: c, refused: r } : null;
}

type Outcome = 'PASS' | 'FAIL' | 'REFUSED' | 'XPASS' | 'SKIP';

interface Verdict {
    readonly id: string;
    readonly outcome: Outcome;
    readonly details: readonly string[];
    readonly level0: number;
    readonly level1: number;
}

/** Resolve a `corpus:ID` / `fixture:NAME` reference to a path on disk. */
function pathOf(ref: FileRef, files: ReadonlyMap<string, string>): string {
    if (ref.startsWith('corpus:')) {
        const p = files.get(ref.slice('corpus:'.length));
        if (p === undefined) throw new Error(`${ref} was not produced`);
        return p;
    }
    return fixturePath(ref.slice('fixture:'.length));
}

async function levelZero(server: BuiltServer, entry: CorpusEntry, record: ManifestEntry, produced: ReadonlyMap<string, ProducedBytes>, bytes: Uint8Array): Promise<{ failures: string[]; checks: number }> {
    const failures: string[] = [];
    let checks = 0;
    const expect = entry.expect;
    if (expect === undefined) return { failures, checks };
    if (expect.deterministic) {
        checks++;
        if (record.sha256Again !== record.sha256) failures.push(`deterministic: the second production hashed to ${record.sha256Again ?? 'nothing'} (first ${record.sha256 ?? '?'})`);
    }
    if (record.sha256 !== undefined && createHash('sha256').update(bytes).digest('hex') !== record.sha256) {
        failures.push('the file on disk does not match the manifest sha256');
    }
    if (expect.engineCheck !== undefined) {
        checks++;
        try {
            const problem = expect.engineCheck(bytes);
            if (problem !== null) failures.push(`engine check: ${problem}`);
        } catch (err) {
            failures.push(`engine check threw: ${err instanceof Error ? err.message : String(err)}`);
        }
    }
    for (const rt of expect.roundTrip) {
        checks++;
        if (!server.toolNames().includes(rt.tool)) {
            failures.push(`round trip ${rt.tool}: tool not registered`);
            continue;
        }
        const args = resolvePlaceholders(rt.arguments, produced);
        const result = await server.callToolDirect(rt.tool, args);
        if (result.isError === true) {
            failures.push(`round trip ${rt.tool}: ${errorText(rt.tool, result)}`);
            continue;
        }
        const structured = result.structuredContent ?? {};
        const problem = rt.assert !== undefined
            ? rt.assert(structured)
            : 'valid' in structured && structured['valid'] !== true ? `valid is ${JSON.stringify(structured['valid'])}: ${JSON.stringify((structured['reasons'] as unknown[] | undefined)?.map((r) => (r as { code?: string }).code) ?? structured['reasonCodes'] ?? [])}` : null;
        if (problem !== null) failures.push(`round trip ${rt.tool}: ${problem}`);
    }
    return { failures, checks };
}

function levelOne(entry: CorpusEntry, file: string, files: ReadonlyMap<string, string>, reportDir: string): { failures: string[]; checks: number } {
    const failures: string[] = [];
    let checks = 0;
    for (const check of entry.expect?.openssl ?? []) {
        checks++;
        let ctx: CommandContext;
        try {
            ctx = {
                file,
                ...(check.caFile !== undefined ? { caFile: pathOf(check.caFile, files) } : {}),
                ...(check.untrusted !== undefined ? { untrusted: check.untrusted.map((u) => pathOf(u, files)) } : {}),
                ...(check.content !== undefined ? { content: pathOf(check.content, files) } : {}),
                outFile: join(reportDir, `${entry.id}.${check.command}.out`),
                attime: CORPUS_ATTIME,
            };
        } catch (err) {
            failures.push(`${check.command}: ${err instanceof Error ? err.message : String(err)}`);
            continue;
        }
        const r = judgeWithOpenssl(check.command, ctx);
        writeFileSync(join(reportDir, `${entry.id}.${check.command}.txt`), `$ openssl ${r.args.join(' ')}\n--- exit ${String(r.run.status)}\n--- stdout\n${r.run.stdout}\n--- stderr\n${r.run.stderr}\n`);
        if (!r.ok) failures.push(`openssl ${COMMANDS[check.command].describe}: ${r.detail}`);
    }
    return { failures, checks };
}

async function main(): Promise<number> {
    const mode = parseOutputMode(process.argv.slice(2));
    if ('error' in mode) {
        process.stderr.write(`${mode.error}\n`);
        return EXIT_INFRA;
    }
    const { quiet, json } = mode;
    const out = (s: string): void => { if (!json) process.stdout.write(`${s}\n`); };
    const note = (s: string): void => { if (!json && !quiet) process.stderr.write(`${s}\n`); };
    const log = (s: string): void => { process.stderr.write(`${s}\n`); };

    const manifest = loadManifest();
    if (manifest === null) {
        log('No PKI corpus found in test-output/pki/. Run `npm run build && npm run corpus:pki` first.');
        return EXIT_INFRA;
    }
    const server = await loadBuiltServer();
    if (server === null) {
        log('dist/server.js not found — run `npm run build` first.');
        return EXIT_INFRA;
    }

    // Coverage canaries: the table against the declaration, the manifest against the disk.
    let canaryFailures = 0;
    const declared = declaredCounts();
    if (declared === null) {
        log('Coverage canary: docs/data/interop.json has no declared.conformant / declared.refused.');
        canaryFailures++;
    } else if (declared.conformant !== CONFORMANT.length || declared.refused !== REFUSED.length) {
        log(`Coverage canary: the corpus table has ${CONFORMANT.length} conformant and ${REFUSED.length} refused entries but docs/data/interop.json declares ${declared.conformant} / ${declared.refused}. Update the declaration in the same change as the table.`);
        canaryFailures++;
    }
    if (REFUSED.length === 0) {
        log('Negative canary missing: the corpus table has no expectRefused entry.');
        canaryFailures++;
    }
    const byId = new Map(manifest.entries.map((e) => [e.id, e] as const));
    for (const entry of CORPUS) {
        if (!byId.has(entry.id)) {
            log(`Coverage canary: ${entry.id} is in the table but not in manifest.json — regenerate the corpus.`);
            canaryFailures++;
        }
    }
    const listed = new Set(manifest.entries.map((e) => e.file).filter((f): f is string => f !== undefined));
    const unlisted = readdirSync(CORPUS_DIR).filter((f) => f !== 'manifest.json' && f !== 'reports' && !listed.has(f));
    if (unlisted.length > 0) note(`Note: ${unlisted.length} file(s) in test-output/pki/ are not in manifest.json and are ignored: ${unlisted.join(', ')}`);
    if (canaryFailures > 0) {
        log(`\nCoverage canary failed (${canaryFailures}).`);
        return EXIT_CONFORMANCE;
    }

    // OpenSSL: present and usable, or a documented skip.
    const required = process.env[REQUIRED_ENV] === '1';
    const missing = opensslMissing();
    if (missing !== null && required) {
        log(`${REQUIRED_ENV}=1 but OpenSSL is unusable: ${missing}`);
        return EXIT_TOOL_MISSING;
    }
    const version = missing === null ? opensslVersion() : null;
    if (missing === null) note(`Using ${version?.raw ?? 'openssl'} (${locateOpenssl() ?? 'openssl'})`);
    else note(`OpenSSL level skipped: ${missing}`);

    const reportDir = join(CORPUS_DIR, 'reports');
    mkdirSync(reportDir, { recursive: true });
    const sandbox = prepareSandbox('pkinative-mcp-validate-');
    try {
        const produced = new Map<string, ProducedBytes>();
        const files = new Map<string, string>();
        const verdicts: Verdict[] = [];
        for (const entry of CORPUS) {
            const record = byId.get(entry.id) as ManifestEntry;
            const rel = record.file !== undefined ? relative(REPO_ROOT, join(CORPUS_DIR, record.file)).split('\\').join('/') : entry.id;
            if (record.status === 'skipped') {
                verdicts.push({ id: entry.id, outcome: 'SKIP', details: [record.reason ?? 'skipped'], level0: 0, level1: 0 });
                if (!quiet) out(`  SKIP     ${rel}  (${record.reason ?? 'skipped'})`);
                continue;
            }
            if (entry.expectRefused !== undefined) {
                if (record.status === 'refused') {
                    verdicts.push({ id: entry.id, outcome: 'REFUSED', details: [record.code ?? ''], level0: 1, level1: 0 });
                    if (!quiet) out(`  REFUSED  ${entry.id}  (${entry.expectRefused}, as expected)`);
                } else if (record.status === 'xpass') {
                    verdicts.push({ id: entry.id, outcome: 'XPASS', details: [`produced ${record.bytes ?? '?'} bytes although ${entry.expectRefused} was expected`], level0: 1, level1: 0 });
                    out(`  XPASS    ${entry.id}  (negative canary ACCEPTED — the refusal is not real)`);
                } else {
                    verdicts.push({ id: entry.id, outcome: 'FAIL', details: [`refused with ${record.code ?? 'no code'}, expected ${entry.expectRefused}: ${record.reason ?? ''}`], level0: 1, level1: 0 });
                    out(`  FAIL     ${entry.id}  refused with ${record.code ?? 'no code'}, expected ${entry.expectRefused}`);
                }
                continue;
            }
            if (record.status !== 'written' || record.file === undefined || !existsSync(join(CORPUS_DIR, record.file))) {
                verdicts.push({ id: entry.id, outcome: 'FAIL', details: [record.reason ?? `status ${record.status}, file ${record.file ?? 'none'}`], level0: 0, level1: 0 });
                out(`  FAIL     ${entry.id}  (${record.reason ?? `status ${record.status}`})`);
                continue;
            }
            const file = join(CORPUS_DIR, record.file);
            const bytes = new Uint8Array(readFileSync(file));
            produced.set(entry.id, { bytes, kind: entry.kind });
            files.set(entry.id, file);

            const l0 = await levelZero(server, entry, record, produced, bytes);
            const l1 = missing === null ? levelOne(entry, file, files, reportDir) : { failures: [], checks: 0 };
            const details = [...l0.failures, ...l1.failures];
            const outcome: Outcome = details.length === 0 ? 'PASS' : 'FAIL';
            verdicts.push({ id: entry.id, outcome, details, level0: l0.checks, level1: l1.checks });
            if (outcome === 'PASS') {
                if (!quiet) out(`  PASS     ${rel}  (${l0.checks} engine, ${l1.checks} openssl)`);
            } else {
                out(`  FAIL     ${rel}`);
                for (const d of details) out(`           - ${d}`);
            }
        }

        const count = (o: Outcome): number => verdicts.filter((v) => v.outcome === o).length;
        const counts = { PASS: count('PASS'), FAIL: count('FAIL'), REFUSED: count('REFUSED'), XPASS: count('XPASS'), SKIP: count('SKIP') };
        const level0 = verdicts.reduce((n, v) => n + v.level0, 0);
        const level1 = verdicts.reduce((n, v) => n + v.level1, 0);
        const code = counts.FAIL > 0 || counts.XPASS > 0 ? EXIT_CONFORMANCE : EXIT_OK;
        if (json) {
            process.stdout.write(`${JSON.stringify({ ok: code === EXIT_OK, counts, level0Checks: level0, level1Checks: level1, openssl: version?.raw ?? null, opensslSkipped: missing, verdicts, manifest: MANIFEST_PATH }, null, 2)}\n`);
            return code;
        }
        out('');
        out(`Summary: ${counts.PASS} PASS, ${counts.REFUSED} REFUSED, ${counts.FAIL} FAIL, ${counts.XPASS} XPASS, ${counts.SKIP} SKIP (of ${verdicts.length} entries; ${level0} engine checks, ${level1} OpenSSL checks${missing !== null ? ` — OpenSSL level SKIPPED: ${missing}` : version !== null ? ` with ${version.raw}` : ''}).`);
        if (counts.XPASS > 0) out('XPASS: a canary the server must refuse produced bytes — the refusal is not real; do not trust the PASS lines.');
        if (code === EXIT_OK) out(missing === null ? 'All expectations met.' : 'All engine expectations met; the OpenSSL level was skipped (exit 0 is a skip, not a pass).');
        return code;
    } finally {
        removeSandbox(sandbox);
    }
}

process.exit(await main());
