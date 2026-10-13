/**
 * Tests for `src/wire.ts` — the ADR 0018 wire form: bigint → decimal,
 * Uint8Array → hex, absent optionals omitted, a CryptoKey described and
 * never exported, cycles refused.
 */
import { describe, expect, it } from 'vitest';
import { importPrivateKey } from 'pkinative';

import { fromHex, toHex, toWire, toWireRecord } from '../src/wire.js';
import { assertNoSecret } from './_pki-assert.js';
import { fixtureBytes } from './_pki-fixtures.js';

describe('toHex / fromHex', () => {
    it('toHex is lowercase, two digits per byte, empty for no bytes', () => {
        expect(toHex(new Uint8Array([0, 1, 0x0a, 0xff]))).toBe('00010aff');
        expect(toHex(new Uint8Array(0))).toBe('');
        expect(toHex(fixtureBytes('leaf.crt.der'))).toBe(Buffer.from(fixtureBytes('leaf.crt.der')).toString('hex'));
    });

    it('fromHex tolerates an 0x prefix, colons, spaces and surrounding whitespace, in either case', () => {
        expect(fromHex('00010aff')).toEqual(new Uint8Array([0, 1, 0x0a, 0xff]));
        expect(fromHex('0x00010AFF')).toEqual(new Uint8Array([0, 1, 0x0a, 0xff]));
        expect(fromHex('00:01:0a:ff')).toEqual(new Uint8Array([0, 1, 0x0a, 0xff]));
        expect(fromHex(' 00 01 0a ff\n')).toEqual(new Uint8Array([0, 1, 0x0a, 0xff]));
        expect(fromHex('0X10:01')).toEqual(new Uint8Array([0x10, 0x01]));
        expect(fromHex('')).toEqual(new Uint8Array(0));
        expect(fromHex('0x')).toEqual(new Uint8Array(0));
    });

    it('fromHex is undefined for an odd length or a non-hex character', () => {
        expect(fromHex('abc')).toBeUndefined();
        expect(fromHex('0xabc')).toBeUndefined();
        expect(fromHex('zz')).toBeUndefined();
        expect(fromHex('ab-cd')).toBeUndefined();
        expect(fromHex('0x0x')).toBeUndefined();
    });

    it('round-trips', () => {
        const der = fixtureBytes('leaf.crt.der');
        expect(fromHex(toHex(der))).toEqual(der);
    });
});

describe('toWire', () => {
    it('keeps strings, booleans, finite numbers and null; bigint → decimal string; Uint8Array → hex', () => {
        expect(toWire('x')).toBe('x');
        expect(toWire(true)).toBe(true);
        expect(toWire(42)).toBe(42);
        expect(toWire(-0)).toBe(-0);
        expect(toWire(null)).toBeNull();
        expect(toWire(4097n)).toBe('4097');
        expect(toWire(-5n)).toBe('-5');
        expect(toWire(2n ** 127n)).toBe((2n ** 127n).toString(10));
        expect(toWire(new Uint8Array([0x10, 0x01]))).toBe('1001');
        expect(toWire(Buffer.from([0xab]))).toBe('ab');
    });

    it('a non-finite number becomes its name as a string; undefined, functions and symbols have no top-level wire form', () => {
        expect(toWire(Number.NaN)).toBe('NaN');
        expect(toWire(Number.POSITIVE_INFINITY)).toBe('Infinity');
        expect(toWire(Number.NEGATIVE_INFINITY)).toBe('-Infinity');
        expect(toWire(undefined)).toBeNull();
        expect(toWire(() => 1)).toBeNull();
        expect(toWire(Symbol('s'))).toBeNull();
    });

    it('walks nested objects and arrays: undefined members are omitted in objects and null in arrays; functions and symbols are dropped', () => {
        const value = {
            serial: 4097n,
            bytes: new Uint8Array([1, 2]),
            absent: undefined,
            fn: () => 1,
            sym: Symbol('s'),
            list: [1n, undefined, new Uint8Array([3]), null, { deep: 7n }],
            nested: { epochMilliseconds: 1798761600000, name: 'x', more: { none: undefined } },
        };
        expect(toWire(value)).toEqual({
            serial: '4097',
            bytes: '0102',
            list: ['1', null, '03', null, { deep: '7' }],
            nested: { epochMilliseconds: 1798761600000, name: 'x', more: {} },
        });
        expect(toWire([])).toEqual([]);
        expect(toWire({})).toEqual({});
    });

    it('a Map becomes an object keyed by String(key); a Set becomes an array; an Error keeps name, message and a string code', () => {
        expect(toWire(new Map<unknown, unknown>([['a', 1n], [2, 'two'], [true, new Uint8Array([9])]]))).toEqual({ a: '1', '2': 'two', true: '09' });
        expect(toWire(new Set([1n, 'x', new Uint8Array([0xff])]))).toEqual(['1', 'x', 'ff']);
        const coded = Object.assign(new TypeError('boom'), { code: 'PKI_INTERNAL' });
        expect(toWire(coded)).toEqual({ name: 'TypeError', message: 'boom', code: 'PKI_INTERNAL' });
        expect(toWire(new Error('plain'))).toEqual({ name: 'Error', message: 'plain' });
        expect(toWire(Object.assign(new Error('n'), { code: 42 }))).toEqual({ name: 'Error', message: 'n' });
    });

    it('frozen engine-style values and shared (non-cyclic) references are fine; a cycle is a TypeError', () => {
        const shared = { v: 1n };
        expect(toWire(Object.freeze({ a: shared, b: shared, c: [shared, shared] }))).toEqual({ a: { v: '1' }, b: { v: '1' }, c: [{ v: '1' }, { v: '1' }] });
        const cyclic: Record<string, unknown> = { name: 'loop' };
        cyclic['self'] = cyclic;
        expect(() => toWire(cyclic)).toThrow(TypeError);
        expect(() => toWire(cyclic)).toThrow(/cyclic/);
        const list: unknown[] = [];
        list.push({ list });
        expect(() => toWire(list)).toThrow(TypeError);
    });

    it('a CryptoKey is described (type, algorithm, extractable, usages) and never exported', async () => {
        const signingKey = await importPrivateKey(fixtureBytes('leaf.key.der'), { algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
        const wire = toWire({ key: signingKey.key, algorithm: signingKey.algorithm });
        expect(wire).toEqual({
            key: { type: 'private', algorithm: 'ECDSA', extractable: false, usages: ['sign'] },
            algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },
        });
        const text = JSON.stringify(wire);
        assertNoSecret(text, 'toWire of a signing key');
        expect(text).not.toContain('"d"');
        expect(JSON.stringify(toWire(signingKey))).not.toMatch(/[0-9a-f]{64}/);
    });
});

describe('toWireRecord', () => {
    it('returns an object verbatim and wraps anything else under `value`', () => {
        expect(toWireRecord({ a: 1n })).toEqual({ a: '1' });
        expect(toWireRecord([1n])).toEqual({ value: ['1'] });
        expect(toWireRecord(7n)).toEqual({ value: '7' });
        expect(toWireRecord('s')).toEqual({ value: 's' });
        expect(toWireRecord(null)).toEqual({ value: null });
        expect(toWireRecord(undefined)).toEqual({ value: null });
        expect(toWireRecord(new Uint8Array([1]))).toEqual({ value: '01' });
    });
});
