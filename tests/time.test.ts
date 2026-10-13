/**
 * Tests for `src/time.ts` — instants parsed from the ISO 8601 fields (never
 * Date.parse), the operator pin PKINATIVE_MCP_AT, and the input > pinned >
 * clock resolution every verdict tool follows.
 */
import { afterEach, describe, expect, it } from 'vitest';

import { ToolError } from '../src/errors.js';
import { AT_ENV, formatInstant, instantSchema, isClockDependent, isIsoInstant, parseInstant, readPinnedInstant, resolveInstant } from '../src/time.js';
import { AT } from './_pki-fixtures.js';

const AT_MS = Date.UTC(2027, 0, 1);
const CLOCK_MS = Date.UTC(2030, 5, 15, 12, 30, 45, 123);
const clock = (): number => CLOCK_MS;

function thrown(fn: () => unknown): ToolError {
    try {
        fn();
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to throw');
}

describe('parseInstant', () => {
    it('reads an ISO date, a date-time (UTC unless zoned), zones, fractions, digits, numbers and "now"', () => {
        expect(parseInstant('2027-01-01', 'at')).toBe(AT_MS);
        expect(parseInstant('2027-01-01T00:00', 'at')).toBe(AT_MS);
        expect(parseInstant('2027-01-01T00:00:00', 'at')).toBe(AT_MS);
        expect(parseInstant(AT, 'at')).toBe(AT_MS);
        expect(parseInstant('2027-01-01t00:00:00z', 'at')).toBe(AT_MS);
        expect(parseInstant('  2027-01-01T00:00:00Z \n', 'at')).toBe(AT_MS);
        expect(parseInstant('2027-01-01T01:00:00+01:00', 'at')).toBe(AT_MS);
        expect(parseInstant('2027-01-01T01:00:00+0100', 'at')).toBe(AT_MS);
        expect(parseInstant('2026-12-31T19:30:00-04:30', 'at')).toBe(AT_MS);
        expect(parseInstant('2027-01-01T00:00:00.5Z', 'at')).toBe(AT_MS + 500);
        expect(parseInstant('2027-01-01T00:00:00.123456789Z', 'at')).toBe(AT_MS + 123);
        expect(parseInstant('2027-01-01T00:00:00.1', 'at')).toBe(AT_MS + 100);
        expect(parseInstant(String(AT_MS), 'at')).toBe(AT_MS);
        expect(parseInstant('0', 'at')).toBe(0);
        expect(parseInstant(AT_MS, 'at')).toBe(AT_MS);
        expect(parseInstant(-1, 'at')).toBe(-1);
        expect(parseInstant('now', 'at', clock)).toBe(CLOCK_MS);
        expect(parseInstant(' now ', 'at', clock)).toBe(CLOCK_MS);
    });

    it('handles leap years, month lengths and the century rule', () => {
        expect(parseInstant('2028-02-29', 'at')).toBe(Date.UTC(2028, 1, 29));
        expect(parseInstant('2000-02-29', 'at')).toBe(Date.UTC(2000, 1, 29));
        expect(thrown(() => parseInstant('2100-02-29', 'at')).code).toBe('VALIDATION_ERROR');
        expect(thrown(() => parseInstant('2027-02-29', 'at')).code).toBe('VALIDATION_ERROR');
        expect(parseInstant('2027-04-30', 'at')).toBe(Date.UTC(2027, 3, 30));
        expect(thrown(() => parseInstant('2027-04-31', 'at')).code).toBe('VALIDATION_ERROR');
    });

    it('refuses a date that does not exist or a field out of range (never rolled over) with VALIDATION_ERROR naming the field', () => {
        for (const bad of ['2027-02-31', '2027-13-01', '2027-00-10', '2027-01-00', '2027-01-01T24:00:00Z', '2027-01-01T00:60:00Z', '2027-01-01T00:00:60Z', '2027-01-01T00:00:00+25:00', '2027-01-01T00:00:00+00:60', 'yesterday', '', '2027-1-1', '2027-01-01T00', '2027-01-01 00:00:00', '1e3', '12.5', 'Mon, 01 Jan 2027 00:00:00 GMT']) {
            const err = thrown(() => parseInstant(bad, 'notBefore'));
            expect(err.code, bad).toBe('VALIDATION_ERROR');
            expect(err.message, bad).toContain('notBefore');
            expect(err.data, bad).toEqual({ field: 'notBefore' });
        }
    });

    it('refuses a non-safe integer (number or digits)', () => {
        for (const bad of [2 ** 53, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
            const err = thrown(() => parseInstant(bad, 'at'));
            expect(err.code, String(bad)).toBe('VALIDATION_ERROR');
            expect(err.data, String(bad)).toEqual({ field: 'at' });
        }
        expect(thrown(() => parseInstant('9007199254740993', 'at')).code).toBe('VALIDATION_ERROR');
        expect(parseInstant(Number.MAX_SAFE_INTEGER, 'at')).toBe(Number.MAX_SAFE_INTEGER);
    });
});

describe('isIsoInstant', () => {
    it('is true for an accepted ISO date or date-time only', () => {
        expect(isIsoInstant('2027-01-01')).toBe(true);
        expect(isIsoInstant(AT)).toBe(true);
        expect(isIsoInstant(' 2027-01-01T01:00:00+01:00 ')).toBe(true);
        expect(isIsoInstant('now')).toBe(false);
        expect(isIsoInstant(String(AT_MS))).toBe(false);
        expect(isIsoInstant('2027-02-31')).toBe(false);
        expect(isIsoInstant('')).toBe(false);
    });
});

describe('readPinnedInstant / resolveInstant / isClockDependent', () => {
    afterEach(() => {
        delete process.env[AT_ENV];
    });

    it('names the pin variable', () => {
        expect(AT_ENV).toBe('PKINATIVE_MCP_AT');
    });

    it('readPinnedInstant: null when unset or blank, the instant when valid, an Error naming the variable otherwise ("now" included)', () => {
        expect(readPinnedInstant({})).toBeNull();
        expect(readPinnedInstant({ [AT_ENV]: '' })).toBeNull();
        expect(readPinnedInstant({ [AT_ENV]: '  ' })).toBeNull();
        expect(readPinnedInstant({ [AT_ENV]: AT })).toBe(AT_MS);
        expect(readPinnedInstant({ [AT_ENV]: String(AT_MS) })).toBe(AT_MS);
        expect(() => readPinnedInstant({ [AT_ENV]: 'now' })).toThrow(new RegExp(`${AT_ENV} must be an ISO 8601 instant or epoch milliseconds, not "now"`));
        expect(() => readPinnedInstant({ [AT_ENV]: ' now ' })).toThrow(/not "now"/);
        expect(() => readPinnedInstant({ [AT_ENV]: '2027-02-31' })).toThrow(new RegExp(`${AT_ENV} expects an ISO 8601 date-time`));
        let caught: unknown;
        try {
            readPinnedInstant({ [AT_ENV]: 'bogus' });
        } catch (err) {
            caught = err;
        }
        expect(caught).toBeInstanceOf(Error);
        expect(caught).not.toBeInstanceOf(ToolError);
        process.env[AT_ENV] = AT;
        expect(readPinnedInstant()).toBe(AT_MS);
        delete process.env[AT_ENV];
        expect(readPinnedInstant()).toBeNull();
    });

    it('resolveInstant: an explicit input wins, then the pin, then the clock; "now" is the clock explicitly', () => {
        expect(resolveInstant(AT, 'at', clock)).toEqual({ ms: AT_MS, source: 'input', iso: '2027-01-01T00:00:00.000Z' });
        expect(resolveInstant(AT_MS, 'at', clock)).toEqual({ ms: AT_MS, source: 'input', iso: '2027-01-01T00:00:00.000Z' });
        expect(resolveInstant(undefined, 'at', clock)).toEqual({ ms: CLOCK_MS, source: 'clock', iso: '2030-06-15T12:30:45.123Z' });
        expect(resolveInstant('now', 'at', clock)).toEqual({ ms: CLOCK_MS, source: 'clock', iso: '2030-06-15T12:30:45.123Z' });
        process.env[AT_ENV] = '2028-06-01T00:00:00Z';
        expect(resolveInstant(undefined, 'at', clock)).toEqual({ ms: Date.UTC(2028, 5, 1), source: 'pinned', iso: '2028-06-01T00:00:00.000Z' });
        expect(resolveInstant(AT, 'at', clock).source).toBe('input');
        expect(resolveInstant('now', 'at', clock)).toEqual({ ms: CLOCK_MS, source: 'clock', iso: '2030-06-15T12:30:45.123Z' });
        // The default clock is the wall clock.
        const before = Date.now();
        const wall = resolveInstant(undefined, 'at');
        expect(wall.source).toBe('pinned');
        delete process.env[AT_ENV];
        const live = resolveInstant(undefined, 'at');
        expect(live.source).toBe('clock');
        expect(live.ms).toBeGreaterThanOrEqual(before);
        expect(live.iso).toBe(formatInstant(live.ms));
        expect(thrown(() => resolveInstant('2027-02-31', 'signingTime', clock)).data).toEqual({ field: 'signingTime' });
    });

    it('isClockDependent: "now" always, an explicit value never, omitted only without a pin', () => {
        expect(isClockDependent('now')).toBe(true);
        expect(isClockDependent(AT)).toBe(false);
        expect(isClockDependent(AT_MS)).toBe(false);
        expect(isClockDependent('garbage')).toBe(false);
        expect(isClockDependent(undefined)).toBe(true);
        process.env[AT_ENV] = AT;
        expect(isClockDependent(undefined)).toBe(false);
        expect(isClockDependent('now')).toBe(true);
    });
});

describe('formatInstant / instantSchema', () => {
    it('formatInstant renders UTC ISO 8601 with milliseconds', () => {
        expect(formatInstant(AT_MS)).toBe('2027-01-01T00:00:00.000Z');
        expect(formatInstant(0)).toBe('1970-01-01T00:00:00.000Z');
        expect(formatInstant(CLOCK_MS)).toBe('2030-06-15T12:30:45.123Z');
        expect(parseInstant(formatInstant(CLOCK_MS), 'x')).toBe(CLOCK_MS);
    });

    it('instantSchema is a non-empty string whose description names the forms and the pin', () => {
        const schema = instantSchema('The instant the verdict is evaluated at.');
        expect(schema.type).toBe('string');
        expect(schema.minLength).toBe(1);
        expect(schema.description.startsWith('The instant the verdict is evaluated at. ')).toBe(true);
        expect(schema.description).toContain('ISO 8601');
        expect(schema.description).toContain("'now'");
        expect(schema.description).toContain(AT_ENV);
        expect(schema.description).toContain('never cached');
    });
});
