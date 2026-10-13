/**
 * Tests for `src/engine.ts` — the engine version, the Node security floor
 * and the runtime capability probe.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { ensureEngineReady, PKINATIVE_NODE_FLOOR, PKINATIVE_VERSION, probeRuntime, satisfiesNodeFloor } from '../src/engine.js';

const ROOT = path.resolve(import.meta.dirname, '..');

function readJson(file: string): Record<string, unknown> {
    return JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
}

/** `^x.y.z` caret satisfaction for the one range this package declares. */
function satisfiesCaret(range: string, version: string): boolean {
    const m = /^\^(\d+)\.(\d+)\.(\d+)$/.exec(range);
    const v = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
    if (m === null || v === null) return false;
    const [rMajor, rMinor, rPatch] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const [major, minor, patch] = [Number(v[1]), Number(v[2]), Number(v[3])];
    if (major !== rMajor) return false;
    return minor > rMinor || (minor === rMinor && patch >= rPatch);
}

describe('engine identity', () => {
    it('PKINATIVE_VERSION is the installed package version and satisfies the declared dependency range', () => {
        const installed = readJson(path.join(ROOT, 'node_modules', 'pkinative', 'package.json'))['version'] as string;
        expect(PKINATIVE_VERSION).toBe(installed);
        expect(PKINATIVE_VERSION).toMatch(/^\d+\.\d+\.\d+/);
        const range = (readJson(path.join(ROOT, 'package.json'))['dependencies'] as Record<string, string>)['pkinative'] as string;
        expect(range).toMatch(/^\^\d+\.\d+\.\d+$/);
        expect(satisfiesCaret(range, PKINATIVE_VERSION)).toBe(true);
        expect(satisfiesCaret('^1.0.0', '2.0.0')).toBe(false);
        expect(satisfiesCaret('^1.2.0', '1.1.9')).toBe(false);
    });

    it('PKINATIVE_NODE_FLOOR names the three lines', () => {
        expect(PKINATIVE_NODE_FLOOR).toBe('^22.22.2 || ^24.14.1 || >=25.8.2');
    });
});

describe('satisfiesNodeFloor', () => {
    it('follows the floor table', () => {
        const rows: Array<[string, boolean]> = [
            ['22.22.1', false], ['22.22.2', true], ['22.23.0', true], ['22.99.99', true], ['22.21.9', false],
            ['23.0.0', false], ['23.11.1', false],
            ['24.0.0', false], ['24.14.0', false], ['24.14.1', true], ['24.15.0', true],
            ['25.0.0', false], ['25.8.1', false], ['25.8.2', true], ['25.9.0', true],
            ['26.0.0', true], ['30.1.2', true],
            ['21.7.3', false], ['20.19.0', false], ['18.20.0', false],
        ];
        for (const [version, expected] of rows) {
            expect(satisfiesNodeFloor(version), version).toBe(expected);
            expect(satisfiesNodeFloor(`v${version}`), `v${version}`).toBe(expected);
        }
    });

    it('tolerates a pre-release suffix and refuses garbage', () => {
        expect(satisfiesNodeFloor('v22.23.2-nightly')).toBe(true);
        expect(satisfiesNodeFloor('22.23')).toBe(false);
        expect(satisfiesNodeFloor('')).toBe(false);
        expect(satisfiesNodeFloor('latest')).toBe(false);
        expect(satisfiesNodeFloor('vv22.23.2')).toBe(false);
        expect(satisfiesNodeFloor(' 22.23.2')).toBe(false);
    });
});

describe('probeRuntime', () => {
    it('reports Web Crypto verify / sign / decrypt (all true on this host), the Node version, the floor and the platform', () => {
        const caps = probeRuntime();
        expect(caps).toEqual({
            canVerify: true,
            canSign: true,
            canDecrypt: true,
            node: process.version,
            nodeFloorSatisfied: satisfiesNodeFloor(process.version),
            platform: process.platform,
        });
        expect(Object.keys(caps)).toEqual(['canVerify', 'canSign', 'canDecrypt', 'node', 'nodeFloorSatisfied', 'platform']);
        expect(probeRuntime()).toEqual(caps);
        expect(probeRuntime()).not.toBe(caps);
    });
});

describe('ensureEngineReady', () => {
    it('is memoised and resolves to undefined', async () => {
        const first = ensureEngineReady();
        expect(first).toBeInstanceOf(Promise);
        expect(ensureEngineReady()).toBe(first);
        await expect(first).resolves.toBeUndefined();
        expect(ensureEngineReady()).toBe(first);
    });
});
