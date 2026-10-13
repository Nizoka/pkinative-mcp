/**
 * Tests for `src/limits.ts` — the 22 named `PkiLimits` bounds exposed by
 * name, merged over the engine defaults under the operator ceilings.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { DEFAULT_PKI_LIMITS } from 'pkinative';

import { __resetCeilingsForTests, MAX_INPUT_BYTES_ENV, MAX_KDF_ITERATIONS_ENV, MAX_PATHS_EXPLORED_ENV, readCeilings } from '../src/caps.js';
import { ToolError } from '../src/errors.js';
import { effectiveLimits, effectiveMaxInputBytes, LIMIT_KEYS, LIMITS_INPUT_SCHEMA, LimitsSchema, resolveCallLimits } from '../src/limits.js';

const DEFAULT_CEILINGS = readCeilings({});
const ENV = [MAX_INPUT_BYTES_ENV, MAX_KDF_ITERATIONS_ENV, MAX_PATHS_EXPLORED_ENV];

function thrown(fn: () => unknown): ToolError {
    try {
        fn();
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to throw');
}

describe('limits', () => {
    afterEach(() => {
        for (const name of ENV) delete process.env[name];
        __resetCeilingsForTests();
    });

    it('LIMIT_KEYS are the 22 engine keys in engine order', () => {
        expect(LIMIT_KEYS).toHaveLength(22);
        expect([...LIMIT_KEYS]).toEqual(Object.keys(DEFAULT_PKI_LIMITS));
        expect(new Set(LIMIT_KEYS).size).toBe(22);
    });

    it('LIMITS_INPUT_SCHEMA: a closed object whose every key is an integer ≥ 1 described with the engine default', () => {
        expect(LIMITS_INPUT_SCHEMA.type).toBe('object');
        expect(LIMITS_INPUT_SCHEMA.additionalProperties).toBe(false);
        expect(Object.keys(LIMITS_INPUT_SCHEMA.properties)).toEqual([...LIMIT_KEYS]);
        for (const key of LIMIT_KEYS) {
            const property = LIMITS_INPUT_SCHEMA.properties[key];
            expect(property.type, key).toBe('integer');
            expect(property.minimum, key).toBe(1);
            expect(property.description, key).toMatch(new RegExp(`\\. Default ${DEFAULT_PKI_LIMITS[key]}\\.$`));
        }
        for (const env of ENV) expect(LIMITS_INPUT_SCHEMA.description).toContain(env);
        expect(LIMITS_INPUT_SCHEMA.description).toContain('LIMIT_CEILING_EXCEEDED');
    });

    it('LimitsSchema is in lock-step with the JSON schema keys and refuses 0, fractions and unknown keys', () => {
        expect(Object.keys(LimitsSchema.shape)).toEqual([...LIMIT_KEYS]);
        expect(LimitsSchema.safeParse({}).success).toBe(true);
        expect(LimitsSchema.safeParse({ maxDepth: 1 }).success).toBe(true);
        expect(LimitsSchema.safeParse({ maxDepth: 0 }).success).toBe(false);
        expect(LimitsSchema.safeParse({ maxDepth: 1.5 }).success).toBe(false);
        expect(LimitsSchema.safeParse({ maxDepth: '8' }).success).toBe(false);
        expect(LimitsSchema.safeParse({ other: 1 }).success).toBe(false);
        expect(LimitsSchema.safeParse({ maxInputBytes: -1 }).success).toBe(false);
    });

    it('returns undefined when nothing is requested and no ceiling tightens a default', () => {
        expect(resolveCallLimits(undefined, DEFAULT_CEILINGS)).toBeUndefined();
        expect(resolveCallLimits({}, DEFAULT_CEILINGS)).toBeUndefined();
        expect(resolveCallLimits({ maxDepth: undefined }, DEFAULT_CEILINGS)).toBeUndefined();
        expect(resolveCallLimits(undefined)).toBeUndefined();
    });

    it('merges the requested keys only; effectiveLimits lays them over the engine defaults', () => {
        expect(resolveCallLimits({ maxDepth: 8, maxPemBlocks: 2 }, DEFAULT_CEILINGS)).toEqual({ maxDepth: 8, maxPemBlocks: 2 });
        expect(effectiveLimits({ maxDepth: 8 }, DEFAULT_CEILINGS)).toEqual({ ...DEFAULT_PKI_LIMITS, maxDepth: 8 });
        expect(effectiveLimits(undefined, DEFAULT_CEILINGS)).toEqual(DEFAULT_PKI_LIMITS);
        expect(effectiveLimits(undefined, DEFAULT_CEILINGS)).not.toBe(DEFAULT_PKI_LIMITS);
        expect(effectiveMaxInputBytes(undefined, DEFAULT_CEILINGS)).toBe(DEFAULT_PKI_LIMITS.maxInputBytes);
        expect(effectiveMaxInputBytes({ maxInputBytes: 1024 }, DEFAULT_CEILINGS)).toBe(1024);
        expect(effectiveMaxInputBytes({ maxDepth: 2 }, DEFAULT_CEILINGS)).toBe(DEFAULT_PKI_LIMITS.maxInputBytes);
    });

    it('a value above the ceiling is LIMIT_CEILING_EXCEEDED with { limit, requested, ceiling, env }; the ceiling itself passes', () => {
        const rows = [
            ['maxInputBytes', DEFAULT_CEILINGS.maxInputBytes, MAX_INPUT_BYTES_ENV],
            ['maxKdfIterations', DEFAULT_CEILINGS.maxKdfIterations, MAX_KDF_ITERATIONS_ENV],
            ['maxPkcs12KdfIterations', DEFAULT_CEILINGS.maxKdfIterations, MAX_KDF_ITERATIONS_ENV],
            ['maxPathsExplored', DEFAULT_CEILINGS.maxPathsExplored, MAX_PATHS_EXPLORED_ENV],
        ] as const;
        for (const [key, ceiling, env] of rows) {
            const err = thrown(() => resolveCallLimits({ [key]: ceiling + 1 }, DEFAULT_CEILINGS));
            expect(err.code, key).toBe('LIMIT_CEILING_EXCEEDED');
            expect(err.data, key).toEqual({ limit: key, requested: ceiling + 1, ceiling, env });
            expect(err.message, key).toContain(env);
            expect(err.message, key).toContain(`limits.${key} = ${ceiling + 1}`);
            expect(resolveCallLimits({ [key]: ceiling }, DEFAULT_CEILINGS), key).toEqual({ [key]: ceiling });
        }
    });

    it('a ceiling below the engine default tightens the default silently (every ceiling-backed key)', () => {
        const tight = readCeilings({ [MAX_INPUT_BYTES_ENV]: '1048576', [MAX_KDF_ITERATIONS_ENV]: '1000', [MAX_PATHS_EXPLORED_ENV]: '5' });
        expect(resolveCallLimits(undefined, tight)).toEqual({ maxInputBytes: 1048576, maxKdfIterations: 1000, maxPkcs12KdfIterations: 1000, maxPathsExplored: 5 });
        expect(resolveCallLimits({ maxPathsExplored: 3, maxDepth: 4 }, tight)).toEqual({ maxInputBytes: 1048576, maxKdfIterations: 1000, maxPkcs12KdfIterations: 1000, maxPathsExplored: 3, maxDepth: 4 });
        expect(effectiveMaxInputBytes(undefined, tight)).toBe(1048576);
        expect(thrown(() => resolveCallLimits({ maxPathsExplored: 6 }, tight)).data).toEqual({ limit: 'maxPathsExplored', requested: 6, ceiling: 5, env: MAX_PATHS_EXPLORED_ENV });
        // The process ceilings are the default second argument.
        process.env[MAX_PATHS_EXPLORED_ENV] = '7';
        __resetCeilingsForTests();
        expect(resolveCallLimits(undefined)).toEqual({ maxPathsExplored: 7 });
        expect(effectiveLimits(undefined).maxPathsExplored).toBe(7);
    });

    it('a ceiling above the engine default changes nothing unless a value is requested', () => {
        const loose = readCeilings({ [MAX_PATHS_EXPLORED_ENV]: '5000' });
        expect(resolveCallLimits(undefined, loose)).toBeUndefined();
        expect(resolveCallLimits({ maxPathsExplored: 4000 }, loose)).toEqual({ maxPathsExplored: 4000 });
    });

    it('keys without a ceiling are never refused', () => {
        expect(resolveCallLimits({ maxDepth: 2 ** 20, maxRevokedCertificates: 2 ** 40, maxNodes: 1 }, DEFAULT_CEILINGS)).toEqual({ maxDepth: 2 ** 20, maxRevokedCertificates: 2 ** 40, maxNodes: 1 });
    });
});
