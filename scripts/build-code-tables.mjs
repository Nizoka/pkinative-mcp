#!/usr/bin/env node
// Regenerates src/data/pkinative/code-tables.ts from the vendored registries.
// Usage: node scripts/build-code-tables.mjs [--check]
import { readFileSync, writeFileSync } from 'node:fs';

const read = (name) => JSON.parse(readFileSync(new URL(`../src/data/pkinative/${name}.json`, import.meta.url), 'utf8'));
const errors = read('errors').errors;
const reasons = read('reasons').reasons;
const diagnostics = read('diagnostics').diagnostics;
const version = read('errors').package?.version ?? '1.0.0';

let out = `/**
 * Generated from src/data/pkinative/{errors,reasons,diagnostics}.json (pkinative v${version}).
 * The three vocabularies as literal tables typed \`satisfies Record<…>\`, so an engine
 * release that adds or removes a code fails \`tsc\` here instead of drifting silently.
 * Regenerate with: node scripts/build-code-tables.mjs (tests/engine-data.test.ts checks drift).
 */
import type { PkiDiagnosticCode, PkiErrorCode, PkiReasonCode } from 'pkinative';

`;
out += `/** The ${errors.length} frozen PKI_* error codes and the engine class that raises each. */\nexport const PKI_ERROR_CLASSES = {\n${errors.map((x) => `    ${x.code}: '${x.class}',`).join('\n')}\n} as const satisfies Record<PkiErrorCode, string>;\n\n`;
out += `/** The ${reasons.length} PKI_REASON_* codes (returned in reports, never thrown). */\nexport const PKI_REASON_TABLE = {\n${reasons.map((x) => `    ${x.code}: true,`).join('\n')}\n} as const satisfies Record<PkiReasonCode, true>;\n\n`;
out += `/** The ${diagnostics.length} PKI_DIAG_* codes and their severity. */\nexport const PKI_DIAGNOSTIC_SEVERITY = {\n${diagnostics.map((x) => `    ${x.code}: '${x.severity}',`).join('\n')}\n} as const satisfies Record<PkiDiagnosticCode, 'warning' | 'info'>;\n`;

const target = new URL('../src/data/pkinative/code-tables.ts', import.meta.url);
if (process.argv.includes('--check')) {
    const current = readFileSync(target, 'utf8');
    if (current !== out) {
        process.stderr.write('src/data/pkinative/code-tables.ts is out of date: run node scripts/build-code-tables.mjs\n');
        process.exit(1);
    }
    process.stdout.write('code-tables: in sync\n');
} else {
    writeFileSync(target, out);
    process.stdout.write(`code-tables: ${errors.length} errors, ${reasons.length} reasons, ${diagnostics.length} diagnostics\n`);
}
