#!/usr/bin/env tsx
/**
 * pkinative-mcp — structural fingerprint of `tools/list`
 * ========================================================
 *   npx tsx scripts/tool-shape.ts            # print the fingerprint
 *   npx tsx scripts/tool-shape.ts --write    # refresh tests/_fixtures/tool-shape.json
 *   npx tsx scripts/tool-shape.ts --check    # exit 1 when dist/ differs from the fixture,
 *                                            # or the catalogue exceeds its size budget
 *
 * `tests/catalogue-parity.test.ts` asserts the live catalogue matches the
 * committed fixture, so wording can be tuned freely (descriptions, examples,
 * instructions) while any schema change must be a deliberate, reviewed
 * fixture update (docs/API_STABILITY.md §5). Run `--write` ONLY after such a
 * change, and after `npm run build`: the fingerprint is taken from `dist/`.
 *
 * Exit codes: 0 ok · 1 --check found a difference · 2 dist/ is missing or bad usage.
 */

import './helpers/hermetic.js';

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './helpers/io.js';
import { loadBuiltServer } from './helpers/server.js';
import { judgeCatalogueBudget, serializeShape, type CatalogueSize, type ListedTool } from './lib/tool-shape.js';

const FIXTURE = join(REPO_ROOT, 'tests', '_fixtures', 'tool-shape.json');
const MANIFEST = join(REPO_ROOT, 'docs', 'assets', 'ecosystem.json');

/** What a host receives: the whole `tools/list` result and the instructions, in UTF-8 bytes. */
function measure(server: { listToolsPayload: () => unknown; __serverInstructions: string }): CatalogueSize {
    let declaredToolsBytes: number | null = null;
    if (existsSync(MANIFEST)) {
        const declared = (JSON.parse(readFileSync(MANIFEST, 'utf8')) as { declared?: { toolsListBytes?: unknown } }).declared?.toolsListBytes;
        declaredToolsBytes = typeof declared === 'number' ? declared : null;
    }
    return {
        toolsBytes: Buffer.byteLength(JSON.stringify(server.listToolsPayload()), 'utf8'),
        instructionsBytes: Buffer.byteLength(server.__serverInstructions, 'utf8'),
        declaredToolsBytes,
    };
}

async function main(): Promise<number> {
    const args = process.argv.slice(2);
    const unknown = args.find((a) => a !== '--write' && a !== '--check');
    if (unknown !== undefined || (args.includes('--write') && args.includes('--check'))) {
        process.stderr.write('Usage: npx tsx scripts/tool-shape.ts [--write | --check]\n');
        return 2;
    }
    const server = await loadBuiltServer();
    if (server === null) {
        process.stderr.write('dist/server.js not found — run `npm run build` first.\n');
        return 2;
    }
    const tools = server.listToolsPayload().tools as readonly ListedTool[];
    const json = serializeShape(tools);

    if (args.includes('--write')) {
        writeFileSync(FIXTURE, json);
        process.stdout.write(`wrote tests/_fixtures/tool-shape.json (${tools.length} tools)\n`);
        return 0;
    }
    if (args.includes('--check')) {
        const committed = existsSync(FIXTURE) ? readFileSync(FIXTURE, 'utf8').replace(/\r\n/g, '\n') : '';
        if (committed !== json) {
            process.stderr.write(`tools/list (dist/) differs from tests/_fixtures/tool-shape.json${committed === '' ? ' (the fixture is absent: run --write once the catalogue is final)' : ''} — see docs/API_STABILITY.md §5 before refreshing it.\n`);
            return 1;
        }
        const size = measure(server);
        const failures = judgeCatalogueBudget(size);
        if (failures.length > 0) {
            for (const f of failures) process.stderr.write(`${f}\n`);
            return 1;
        }
        process.stdout.write(`tools/list matches tests/_fixtures/tool-shape.json (${tools.length} tools, ${size.toolsBytes} bytes; instructions ${size.instructionsBytes} bytes)\n`);
        return 0;
    }
    process.stdout.write(json);
    return 0;
}

process.exit(await main());
