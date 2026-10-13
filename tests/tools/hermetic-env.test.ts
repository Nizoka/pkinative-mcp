// scripts/helpers/hermetic.ts is imported first by every generator and by
// the gate: it pins TZ=UTC and removes every operator knob inherited from the
// developer's shell, so a local PKINATIVE_MCP_PASSWORD or _CACHE_DIR can
// neither change the bytes a script produces nor open a cache. These tests
// hold that promise, and hold it to the variables server.json actually
// declares.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { isOperatorKnob, scrubEnv } from '../../scripts/helpers/hermetic.js';
import { serverJsonEnvVars } from '../../scripts/lib/mcp-surface.js';

const ROOT = resolve(import.meta.dirname, '..', '..');

describe('hermetic environment', () => {
    it('pins the process time zone to UTC on import', () => {
        expect(process.env['TZ']).toBe('UTC');
        expect(new Date(Date.UTC(2027, 0, 1)).getTimezoneOffset()).toBe(0);
    });

    it('recognises every variable server.json declares as an operator knob', () => {
        const declared = serverJsonEnvVars(readFileSync(resolve(ROOT, 'server.json'), 'utf8'));
        expect(declared.length).toBeGreaterThanOrEqual(9);
        for (const name of declared) expect(isOperatorKnob(name), name).toBe(true);
    });

    it('recognises the prefix and nothing unrelated', () => {
        expect(isOperatorKnob('PKINATIVE_MCP_AT')).toBe(true);
        expect(isOperatorKnob('PKINATIVE_MCP_OUTPUT_DIR')).toBe(true);
        for (const name of ['PATH', 'TZ', 'NODE_OPTIONS', 'GATE', 'GATE_REQUIRE_ARTIFACTS', 'OPENSSL_BIN', 'ZLINT', 'PKILINT_PYTHON', 'PKINATIVE_INTEROP_REQUIRED', 'PKINATIVE', 'XPKINATIVE_MCP_X', 'PDFNATIVE_MCP_OUTPUT_DIR']) {
            expect(isOperatorKnob(name), name).toBe(false);
        }
    });

    it('scrubs the knobs in place, reports them, and leaves the rest of the environment alone', () => {
        const env: NodeJS.ProcessEnv = {
            PATH: '/usr/bin',
            TZ: 'UTC',
            PKINATIVE_MCP_PASSWORD: 'hunter2',
            PKINATIVE_MCP_CACHE_DIR: '/tmp/cache',
            PKINATIVE_MCP_OUTPUT_DIR: '/tmp/out',
            PKINATIVE_INTEROP_REQUIRED: '1',
            OPENSSL_BIN: '/usr/bin/openssl',
        };
        const removed = scrubEnv(env).sort();
        expect(removed).toEqual(['PKINATIVE_MCP_CACHE_DIR', 'PKINATIVE_MCP_OUTPUT_DIR', 'PKINATIVE_MCP_PASSWORD']);
        expect(env).toEqual({ PATH: '/usr/bin', TZ: 'UTC', PKINATIVE_INTEROP_REQUIRED: '1', OPENSSL_BIN: '/usr/bin/openssl' });
        expect(scrubEnv(env)).toEqual([]);
    });

    it('left no operator knob in this process after the import', () => {
        expect(Object.keys(process.env).filter(isOperatorKnob)).toEqual([]);
    });
});
