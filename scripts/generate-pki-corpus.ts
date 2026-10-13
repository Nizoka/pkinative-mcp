#!/usr/bin/env tsx
/**
 * pkinative-mcp — OpenSSL interoperability corpus generator
 * ==========================================================
 * Drives the BUILT server (`dist/server.js`, through the same
 * `callToolDirect()` the `tools/call` handler reaches) to produce the corpus
 * table of scripts/lib/pki-corpus.ts under `test-output/pki/`, with a
 * `manifest.json` that records what happened to every entry. The validator
 * (scripts/validate-pki.ts) then re-reads every artefact through the engine
 * (level 0) and hands it to OpenSSL (level 1).
 *
 * Usage:  npm run build && npm run corpus:pki
 *         npx tsx scripts/generate-pki-corpus.ts [--quiet | --verbose] [--json]
 * Exit:   0 when every entry was written, refused as expected, or skipped
 *           because its tool is not registered yet (the manifest says which);
 *         1 when a conformant entry was refused (its message is reproduced)
 *           — a canary that produced bytes is recorded as `xpass` and left to
 *           the validator, which fails on it;
 *         2 when dist/ is missing or on bad usage.
 *
 * Reproducible: hermetic environment (helpers/hermetic.ts), the instant
 * pinned (`PKINATIVE_MCP_AT`), serials and nonces fixed in the table; a
 * `deterministic` entry is produced twice and both digests are recorded.
 */

// Must be first: pins TZ and scrubs operator knobs before dist/ is loaded.
import './helpers/hermetic.js';

import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { SAMPLE_AT, parseOutputMode, prepareSandbox, removeSandbox } from './helpers/io.js';
import { artefactOf, errorCode, errorText, loadBuiltServer, packageVersion, type BuiltServer } from './helpers/server.js';
import { CORPUS, corpusDependencies, resolvePlaceholders, type CorpusEntry, type ProducedBytes } from './lib/pki-corpus.js';
import { CORPUS_DIR, MANIFEST_PATH, countStatuses, fileNameFor, type CorpusManifest, type ManifestEntry } from './lib/pki-corpus-manifest.js';

const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

async function produceOnce(server: BuiltServer, entry: CorpusEntry, produced: ReadonlyMap<string, ProducedBytes>): Promise<{ bytes: Uint8Array } | { code: string | null; message: string }> {
    const args = resolvePlaceholders(entry.arguments, produced);
    const result = await server.callToolDirect(entry.tool, args);
    if (result.isError === true) return { code: errorCode(result), message: errorText(entry.tool, result) };
    const artefact = artefactOf(result);
    if (artefact === null) return { code: null, message: `${entry.tool}: no artefact in the tool result` };
    return { bytes: artefact.bytes };
}

async function main(): Promise<number> {
    const mode = parseOutputMode(process.argv.slice(2));
    if ('error' in mode) {
        process.stderr.write(`${mode.error}\n`);
        return 2;
    }
    const { quiet, json } = mode;
    const say = (s: string): void => { if (!json && !quiet) process.stdout.write(`${s}\n`); };

    const server = await loadBuiltServer();
    if (server === null) {
        process.stderr.write('dist/server.js not found — run `npm run build` first.\n');
        return 2;
    }
    const tools = new Set(server.toolNames());
    const sandbox = prepareSandbox('pkinative-mcp-corpus-');
    try {
        mkdirSync(CORPUS_DIR, { recursive: true });
        // Prune artefacts of an older table so the validator's "unlisted file" note only ever points at something unexpected.
        const current = new Set(CORPUS.map((e) => fileNameFor(e.id, e.kind)));
        for (const stale of readdirSync(CORPUS_DIR).filter((f) => f !== 'manifest.json' && f !== 'reports' && !current.has(f))) {
            rmSync(join(CORPUS_DIR, stale), { recursive: true, force: true });
            say(`  pruned ${stale}`);
        }

        const produced = new Map<string, ProducedBytes>();
        const entries: ManifestEntry[] = [];
        let failures = 0;
        let totalBytes = 0;
        const started = Date.now();

        for (const entry of CORPUS) {
            const base = { id: entry.id, tool: entry.tool, kind: entry.kind };
            if (!tools.has(entry.tool)) {
                entries.push({ ...base, status: 'skipped', reason: `tool ${entry.tool} is not registered yet` });
                say(`  skip   ${entry.id.padEnd(34)} (${entry.tool} is not registered yet)`);
                continue;
            }
            const missing = corpusDependencies(entry.arguments).filter((id) => !produced.has(id));
            if (missing.length > 0) {
                entries.push({ ...base, status: 'skipped', reason: `depends on ${missing.join(', ')}, not produced` });
                say(`  skip   ${entry.id.padEnd(34)} (depends on ${missing.join(', ')}, not produced)`);
                continue;
            }

            const first = await produceOnce(server, entry, produced);
            if (entry.expectRefused !== undefined) {
                if ('bytes' in first) {
                    const file = fileNameFor(entry.id, entry.kind);
                    writeFileSync(join(CORPUS_DIR, file), first.bytes);
                    entries.push({ ...base, status: 'xpass', file, bytes: first.bytes.byteLength, sha256: sha256(first.bytes), expectRefused: entry.expectRefused });
                    say(`  XPASS  ${entry.id.padEnd(34)} produced ${first.bytes.byteLength} bytes although ${entry.expectRefused} was expected`);
                } else if (first.code === entry.expectRefused) {
                    entries.push({ ...base, status: 'refused', expectRefused: entry.expectRefused, code: first.code });
                    say(`  refuse ${entry.id.padEnd(34)} ${entry.expectRefused} (as expected)`);
                } else {
                    entries.push({ ...base, status: 'refused-other', expectRefused: entry.expectRefused, code: first.code ?? undefined, reason: first.message });
                    say(`  FAIL   ${entry.id.padEnd(34)} refused with ${first.code ?? 'no code'}, expected ${entry.expectRefused}`);
                }
                continue;
            }

            if (!('bytes' in first)) {
                failures++;
                entries.push({ ...base, status: 'failed', code: first.code ?? undefined, reason: first.message });
                process.stderr.write(`FAIL  ${entry.id}\n      ${first.message}\n`);
                continue;
            }
            const deterministic = entry.expect?.deterministic === true;
            let sha256Again: string | undefined;
            if (deterministic) {
                const second = await produceOnce(server, entry, produced);
                sha256Again = 'bytes' in second ? sha256(second.bytes) : 'second production failed';
            }
            const file = fileNameFor(entry.id, entry.kind);
            writeFileSync(join(CORPUS_DIR, file), first.bytes);
            produced.set(entry.id, { bytes: first.bytes, kind: entry.kind });
            totalBytes += first.bytes.byteLength;
            entries.push({ ...base, status: 'written', file, bytes: first.bytes.byteLength, sha256: sha256(first.bytes), deterministic, ...(sha256Again !== undefined ? { sha256Again } : {}) });
            say(`  wrote  ${file.padEnd(34)} ${String(first.bytes.byteLength).padStart(7)} B  (${entry.tool}${deterministic ? ', deterministic' : ''})`);
        }

        const manifest: CorpusManifest = { generatedBy: 'scripts/generate-pki-corpus.ts', at: SAMPLE_AT, serverVersion: packageVersion(), tools: [...tools], entries };
        writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);

        const counts = countStatuses(entries);
        const seconds = (Date.now() - started) / 1000;
        if (json) {
            process.stdout.write(`${JSON.stringify({ generated: counts.written, bytes: totalBytes, seconds, counts, outputDir: CORPUS_DIR, entries }, null, 2)}\n`);
        } else {
            process.stdout.write(
                `PKI corpus: ${counts.written} written (${totalBytes} bytes), ${counts.refused} refused as expected, ${counts.skipped} skipped`
                + `${counts.xpass > 0 ? `, ${counts.xpass} XPASS` : ''}${counts.refusedOther > 0 ? `, ${counts.refusedOther} refused with another code` : ''}`
                + `${counts.failed > 0 ? `, ${counts.failed} FAILED` : ''}, ${seconds.toFixed(1)} s → test-output/pki/\n`,
            );
        }
        return failures > 0 ? 1 : 0;
    } finally {
        removeSandbox(sandbox);
    }
}

process.exit(await main());
