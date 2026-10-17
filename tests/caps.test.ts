/**
 * Tests for `src/caps.ts` — the operator ceilings and the input-size guard.
 */
import { describe, it, expect, afterEach } from 'vitest';

import * as caps from '../src/caps.js';
import {
    __resetCeilingsForTests, assertInputWithin, CAPS, DEFAULT_MAX_INPUT_BYTES_CEILING, DEFAULT_MAX_KDF_ITERATIONS_CEILING, DEFAULT_MAX_PATHS_EXPLORED_CEILING,
    getCeilings, MAX_INLINE_INPUT_BYTES_PER_CALL, MAX_INPUT_BYTES_ENV, MAX_KDF_ITERATIONS_ENV, MAX_PATHS_EXPLORED_ENV, readCeilings,
} from '../src/caps.js';
import { ToolError } from '../src/errors.js';

const ENV = [MAX_INPUT_BYTES_ENV, MAX_KDF_ITERATIONS_ENV, MAX_PATHS_EXPLORED_ENV];

describe('caps', () => {
    afterEach(() => {
        for (const name of ENV) delete process.env[name];
        __resetCeilingsForTests();
    });

    it('readCeilings returns the engine defaults for an empty environment', () => {
        expect(readCeilings({})).toEqual({ maxInputBytes: DEFAULT_MAX_INPUT_BYTES_CEILING, maxKdfIterations: DEFAULT_MAX_KDF_ITERATIONS_CEILING, maxPathsExplored: DEFAULT_MAX_PATHS_EXPLORED_CEILING });
        expect(readCeilings({ [MAX_INPUT_BYTES_ENV]: '' })).toEqual(readCeilings({}));
        expect(DEFAULT_MAX_INPUT_BYTES_CEILING).toBe(64 * 1024 * 1024);
        expect(DEFAULT_MAX_KDF_ITERATIONS_CEILING).toBe(10_000_000);
        expect(DEFAULT_MAX_PATHS_EXPLORED_CEILING).toBe(1000);
    });

    it('readCeilings parses valid values (whitespace tolerated)', () => {
        expect(readCeilings({ [MAX_INPUT_BYTES_ENV]: '1024', [MAX_KDF_ITERATIONS_ENV]: ' 1 ', [MAX_PATHS_EXPLORED_ENV]: '5' })).toEqual({ maxInputBytes: 1024, maxKdfIterations: 1, maxPathsExplored: 5 });
    });

    it('readCeilings refuses invalid and below-minimum values by name', () => {
        expect(() => readCeilings({ [MAX_PATHS_EXPLORED_ENV]: 'ten' })).toThrow(new RegExp(`${MAX_PATHS_EXPLORED_ENV} must be a non-negative integer`));
        expect(() => readCeilings({ [MAX_PATHS_EXPLORED_ENV]: '-1' })).toThrow(/non-negative integer/);
        expect(() => readCeilings({ [MAX_PATHS_EXPLORED_ENV]: '1.5' })).toThrow(/non-negative integer/);
        expect(() => readCeilings({ [MAX_PATHS_EXPLORED_ENV]: '0' })).toThrow(new RegExp(`${MAX_PATHS_EXPLORED_ENV} must be an integer >= 1`));
        expect(() => readCeilings({ [MAX_KDF_ITERATIONS_ENV]: '0' })).toThrow(/integer >= 1/);
        expect(() => readCeilings({ [MAX_INPUT_BYTES_ENV]: '1023' })).toThrow(/>= 1024/);
        expect(() => readCeilings({ [MAX_INPUT_BYTES_ENV]: '99999999999999999999' })).toThrow(/integer >= 1024/);
    });

    it('getCeilings memoises until reset', () => {
        process.env[MAX_PATHS_EXPLORED_ENV] = '42';
        __resetCeilingsForTests();
        expect(getCeilings().maxPathsExplored).toBe(42);
        process.env[MAX_PATHS_EXPLORED_ENV] = '43';
        expect(getCeilings().maxPathsExplored).toBe(42);
        __resetCeilingsForTests();
        expect(getCeilings().maxPathsExplored).toBe(43);
        expect(getCeilings()).toBe(getCeilings());
    });

    it('assertInputWithin throws INPUT_TOO_LARGE with the observed / cap detail and the sandbox remedy for inline input', () => {
        expect(() => assertInputWithin(10, 10, 'x')).not.toThrow();
        expect(() => assertInputWithin(0, 0, 'x')).not.toThrow();
        try {
            assertInputWithin(11, 10, 'certificate (derBase64, decoded)');
            expect.unreachable();
        } catch (e) {
            expect(e).toBeInstanceOf(ToolError);
            expect((e as ToolError).code).toBe('INPUT_TOO_LARGE');
            expect((e as ToolError).message).toMatch(/^certificate \(derBase64, decoded\) is 11 bytes, above the 10-byte cap — pass the bytes through a sandbox file instead \(a relative path under PKINATIVE_MCP_OUTPUT_DIR\)/);
            expect((e as ToolError).data).toEqual({ what: 'certificate (derBase64, decoded)', observed: 11, cap: 10, remedy: 'path' });
        }
    });

    it('a file input over its cap gets the split / ceiling remedy in the message and no data.remedy (the sandbox route is already in use)', () => {
        try {
            assertInputWithin(11, 10, "certificate.path 'big.crt'");
            expect.unreachable();
        } catch (e) {
            expect((e as ToolError).code).toBe('INPUT_TOO_LARGE');
            expect((e as ToolError).message).toBe(`certificate.path 'big.crt' is 11 bytes, above the 10-byte cap — split the input, or raise ${MAX_INPUT_BYTES_ENV} for trusted input only.`);
            expect((e as ToolError).data).toEqual({ what: "certificate.path 'big.crt'", observed: 11, cap: 10 });
        }
    });

    it('the serialisable CAPS view mirrors the constants', () => {
        expect(CAPS.maxInlineInputBytesPerCall).toBe(MAX_INLINE_INPUT_BYTES_PER_CALL);
        // The headline values are pinned (they are quoted in the docs) …
        expect(CAPS).toMatchObject({
            stdioMaxFrameBytes: 256 * 1024 * 1024,
            maxInlineInputBytesPerCall: 128 * 1024 * 1024,
            maxContentInlineBytes: 128 * 1024 * 1024,
            maxContentPathBytes: 1024 * 1024 * 1024,
            maxBundleItems: 256,
            maxBase64OutputBytes: 50 * 1024 * 1024,
            maxFileOutputBytes: 1024 * 1024 * 1024,
            maxHexInlineBytes: 64 * 1024,
            maxAttributesInline: 256,
            maxOidsPerCall: 1000,
            maxListLimit: 2000,
            defaultListLimit: 200,
            maxShakeOutputBytes: 1024 * 1024,
            maxPasswordBytes: 4096,
            maxDiagnostics: 200,
            maxFieldsPaths: 16,
            maxPreviewBytes: 32,
            maxTreeNodes: 20_000,
            maxListedResources: 1000,
            maxResourceWalkDepth: 8,
            maxResourceReadBytes: 50 * 1024 * 1024,
            cacheTtlSeconds: 3600,
            cacheMaxBytes: 256 * 1024 * 1024,
        });
        expect(Object.values(CAPS).every((v) => Number.isInteger(v) && v > 0)).toBe(true);
    });

    it('every numeric constant exported by src/caps.ts (except the ceiling defaults) is advertised in CAPS', () => {
        // Ceiling defaults are reported by describe_engine under `ceilings`, not `caps`.
        const ceilingNames = new Set(['DEFAULT_MAX_INPUT_BYTES_CEILING', 'DEFAULT_MAX_KDF_ITERATIONS_CEILING', 'DEFAULT_MAX_PATHS_EXPLORED_CEILING']);
        const advertised = new Set(Object.values(CAPS));
        const numericExports = Object.entries(caps).filter(([name, value]) => typeof value === 'number' && !ceilingNames.has(name));
        expect(numericExports.length).toBe(Object.keys(CAPS).length);
        const missing = numericExports.filter(([, value]) => !advertised.has(value as number)).map(([name]) => name);
        expect(missing, `caps.ts constants missing from CAPS: ${missing.join(', ')}`).toEqual([]);
        for (const [key, value] of Object.entries(CAPS)) {
            expect(numericExports.some(([, v]) => v === value), `CAPS.${key} = ${value} has no source constant`).toBe(true);
        }
    });
});
