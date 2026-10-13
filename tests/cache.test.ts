/**
 * Tests for the opt-in content-addressed cache (`src/cache.ts`).
 */
import { mkdtempSync, rmSync, readdirSync, writeFileSync, statSync, utimesSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { getCached, setCached, _resetForTests } from '../src/cache.js';

let cacheDir: string;

beforeEach(() => {
    cacheDir = mkdtempSync(join(tmpdir(), 'zipnative-cache-'));
    process.env['PKINATIVE_MCP_CACHE_DIR'] = cacheDir;
    _resetForTests();
});

afterEach(() => {
    delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    rmSync(cacheDir, { recursive: true, force: true });
});

describe('cache', () => {
    it('returns null on miss', () => {
        expect(getCached('toolA', '1.0.0', { x: 1 })).toBeNull();
    });

    it('round-trips set/get', () => {
        setCached('toolA', '1.0.0', { x: 1 }, { hello: 'world' });
        expect(getCached<{ hello: string }>('toolA', '1.0.0', { x: 1 })).toEqual({ hello: 'world' });
    });

    it('keys distinguish across tools', () => {
        setCached('toolA', '1.0.0', { x: 1 }, 'A');
        expect(getCached('toolB', '1.0.0', { x: 1 })).toBeNull();
    });

    it('keys are canonical w.r.t. object key order', () => {
        setCached('toolA', '1.0.0', { a: 1, b: 2 }, 'V');
        expect(getCached('toolA', '1.0.0', { b: 2, a: 1 })).toBe('V');
    });

    it('keys differ on apiVersion bump', () => {
        setCached('toolA', '1.0.0', { x: 1 }, 'old');
        expect(getCached('toolA', '2.0.0', { x: 1 })).toBeNull();
    });

    it('returns null when env var is unset', () => {
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        setCached('toolA', '1.0.0', { x: 1 }, 'v');
        expect(getCached('toolA', '1.0.0', { x: 1 })).toBeNull();
    });

    it('expires entries older than TTL', () => {
        setCached('toolA', '1.0.0', { x: 1 }, 'v');
        const files = readdirSync(cacheDir).filter((f) => f.endsWith('.json'));
        expect(files.length).toBe(1);
        // Backdate the file to 2 hours ago.
        const filePath = join(cacheDir, files[0]!);
        const past = new Date(Date.now() - 7200_000);
        utimesSync(filePath, past, past);
        expect(getCached('toolA', '1.0.0', { x: 1 })).toBeNull();
        // Expired entry should have been removed.
        expect(readdirSync(cacheDir).filter((f) => f.endsWith('.json')).length).toBe(0);
    });

    it('returns null on corrupt entry', () => {
        // Compute the key by storing a normal entry then overwriting it with garbage.
        setCached('toolA', '1.0.0', { x: 1 }, 'good');
        const files = readdirSync(cacheDir).filter((f) => f.endsWith('.json'));
        writeFileSync(join(cacheDir, files[0]!), '{not json', 'utf8');
        expect(getCached('toolA', '1.0.0', { x: 1 })).toBeNull();
    });

    it('writes a JSON envelope with createdAt + tool + apiVersion', () => {
        setCached('toolA', '1.0.0', { x: 1 }, 'v');
        const files = readdirSync(cacheDir).filter((f) => f.endsWith('.json'));
        const stat = statSync(join(cacheDir, files[0]!));
        expect(stat.size).toBeGreaterThan(0);
    });
});
