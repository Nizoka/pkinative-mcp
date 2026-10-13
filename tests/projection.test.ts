/**
 * Tests for `src/projection.ts` — the token-frugal projection layer: field
 * list parsing, dot-path selection with array mapping and deep merge, and
 * the two opt-in inputs every read tool spreads.
 */
import { describe, expect, it } from 'vitest';

import { MAX_FIELDS_PATHS } from '../src/caps.js';
import { parseFieldList, PROJECTION_INPUT_PROPERTIES, readFields, readVerbosity, selectFields } from '../src/projection.js';

describe('parseFieldList', () => {
    it('splits a comma-separated string into trimmed paths', () => {
        expect(parseFieldList('a, b.c ,, d')).toEqual(['a', 'b.c', 'd']);
    });

    it('accepts an array of paths and splits embedded commas', () => {
        expect(parseFieldList(['a', 'b.c,d'])).toEqual(['a', 'b.c', 'd']);
    });

    it('ignores non-string array entries and empty input', () => {
        expect(parseFieldList(['a', 42, null, ''])).toEqual(['a']);
        expect(parseFieldList(undefined)).toEqual([]);
        expect(parseFieldList(123)).toEqual([]);
        expect(parseFieldList({ fields: 'a' })).toEqual([]);
    });
});

describe('selectFields', () => {
    const value = {
        serialNumber: { hex: '1001', decimal: '4097' },
        subjectString: 'CN=example.test',
        extensions: [{ kind: 'basicConstraints', critical: true }, { kind: 'keyUsage', critical: false }],
        diagnostics: [],
    };

    it('projects a single top-level field', () => {
        expect(selectFields(value, ['subjectString'])).toEqual({ subjectString: 'CN=example.test' });
    });

    it('projects a nested dot-path preserving structure', () => {
        expect(selectFields(value, ['serialNumber.hex'])).toEqual({ serialNumber: { hex: '1001' } });
    });

    it('maps an array segment over every element', () => {
        expect(selectFields(value, ['extensions.kind'])).toEqual({ extensions: [{ kind: 'basicConstraints' }, { kind: 'keyUsage' }] });
        expect(selectFields(value, ['diagnostics'])).toEqual({ diagnostics: [] });
    });

    it('deep-merges multiple paths into one object', () => {
        expect(selectFields(value, ['subjectString', 'serialNumber.decimal'])).toEqual({ subjectString: 'CN=example.test', serialNumber: { decimal: '4097' } });
        expect(selectFields(value, ['serialNumber.hex', 'serialNumber.decimal'])).toEqual({ serialNumber: { hex: '1001', decimal: '4097' } });
    });

    it('deep-merges two array-mapped paths element-wise', () => {
        expect(selectFields(value, ['extensions.kind', 'extensions.critical'])).toEqual({ extensions: [{ kind: 'basicConstraints', critical: true }, { kind: 'keyUsage', critical: false }] });
    });

    it('omits unknown / non-existent paths leniently', () => {
        expect(selectFields(value, ['nope', 'serialNumber.zzz'])).toEqual({});
        expect(selectFields(value, ['subjectString', 'nope'])).toEqual({ subjectString: 'CN=example.test' });
    });

    it('returns an empty object when no paths resolve or none are given', () => {
        expect(selectFields(value, [])).toEqual({});
        expect(selectFields(value, [' ', '.', '..'])).toEqual({});
        expect(selectFields(42, ['x'])).toEqual({});
    });

    it('omits a path that walks into a primitive', () => {
        expect(selectFields(value, ['subjectString.x'])).toEqual({});
    });

    it('last path wins on a scalar conflict and a whole subtree merges with a part of it', () => {
        expect(selectFields(value, ['subjectString', 'subjectString'])).toEqual({ subjectString: 'CN=example.test' });
        expect(selectFields(value, ['serialNumber.hex', 'serialNumber'])).toEqual({ serialNumber: { hex: '1001', decimal: '4097' } });
    });

    it('trims blank segments inside a path', () => {
        expect(selectFields(value, [' serialNumber . hex '])).toEqual({ serialNumber: { hex: '1001' } });
    });
});

describe('readVerbosity / readFields', () => {
    it("defaults verbosity to 'full' and reads 'summary' when requested", () => {
        expect(readVerbosity(undefined)).toBe('full');
        expect(readVerbosity({})).toBe('full');
        expect(readVerbosity({ verbosity: 'full' })).toBe('full');
        expect(readVerbosity({ verbosity: 'summary' })).toBe('summary');
        expect(readVerbosity({ verbosity: 'bogus' })).toBe('full');
        expect(readVerbosity('summary')).toBe('full');
    });

    it('reads the fields list defensively', () => {
        expect(readFields(undefined)).toEqual([]);
        expect(readFields({})).toEqual([]);
        expect(readFields([])).toEqual([]);
        expect(readFields({ fields: ['a', 'b.c'] })).toEqual(['a', 'b.c']);
        expect(readFields({ fields: 'a,b' })).toEqual(['a', 'b']);
    });
});

describe('PROJECTION_INPUT_PROPERTIES', () => {
    it('advertises the two inputs with their enum, default and path cap', () => {
        expect(Object.keys(PROJECTION_INPUT_PROPERTIES)).toEqual(['verbosity', 'fields']);
        expect(PROJECTION_INPUT_PROPERTIES.verbosity).toMatchObject({ type: 'string', enum: ['full', 'summary'], default: 'full' });
        expect(PROJECTION_INPUT_PROPERTIES.fields).toMatchObject({ type: 'array', maxItems: MAX_FIELDS_PATHS, items: { type: 'string', minLength: 1 } });
        expect(PROJECTION_INPUT_PROPERTIES.fields.description).toContain('_meta.unmatchedFields');
    });
});
