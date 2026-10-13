/**
 * Tests for `src/random.ts` — the wrapper's randomness (the engine draws
 * nothing random): serial numbers, nonces and the describe_engine view.
 */
import { describe, expect, it } from 'vitest';

import { RANDOMNESS, randomNonceBytes, randomNonceInteger, randomSerialNumber } from '../src/random.js';

describe('randomSerialNumber', () => {
    it('is a positive 127-bit value: the high bit of the first octet clear, its low bit set, 16 octets', () => {
        for (let i = 0; i < 64; i++) {
            const serial = randomSerialNumber();
            expect(typeof serial).toBe('bigint');
            expect(serial).toBeGreaterThan(0n);
            expect(serial).toBeLessThan(2n ** 127n);
            // bytes[0] = (b & 0x7f) | 0x01: bit 127 is clear, bit 120 is set, so the serial always spans 16 octets.
            expect((serial >> 127n) & 1n).toBe(0n);
            expect((serial >> 120n) & 1n).toBe(1n);
            expect(serial).toBeGreaterThanOrEqual(2n ** 120n);
            expect([31, 32]).toContain(serial.toString(16).length);
        }
    });

    it('two draws differ', () => {
        expect(randomSerialNumber()).not.toBe(randomSerialNumber());
        expect(new Set(Array.from({ length: 16 }, () => randomSerialNumber())).size).toBe(16);
    });
});

describe('randomNonceBytes', () => {
    it('returns the requested length (16 by default) of fresh bytes', () => {
        expect(randomNonceBytes()).toHaveLength(16);
        expect(randomNonceBytes(1)).toHaveLength(1);
        expect(randomNonceBytes(32)).toHaveLength(32);
        expect(randomNonceBytes()).toBeInstanceOf(Uint8Array);
        expect(Buffer.from(randomNonceBytes()).equals(Buffer.from(randomNonceBytes()))).toBe(false);
        expect(randomNonceBytes(0)).toHaveLength(0);
    });
});

describe('randomNonceInteger', () => {
    it('is a positive 63-bit integer', () => {
        for (let i = 0; i < 64; i++) {
            const nonce = randomNonceInteger();
            expect(typeof nonce).toBe('bigint');
            expect(nonce).toBeGreaterThan(0n);
            expect(nonce).toBeLessThan(2n ** 63n);
        }
        expect(randomNonceInteger()).not.toBe(randomNonceInteger());
    });
});

describe('RANDOMNESS', () => {
    it('says the engine draws nothing and names the three tools that use node:crypto', () => {
        expect(RANDOMNESS.engine).toBe('none');
        expect(RANDOMNESS.wrapper).toBe('node:crypto');
        expect(RANDOMNESS.usedBy).toHaveLength(3);
        expect(RANDOMNESS.usedBy.map((u) => u.split(' ')[0])).toEqual(['create_certificate', 'create_ocsp_request', 'create_timestamp_request']);
        expect(RANDOMNESS.usedBy.every((u) => u.includes("'random'"))).toBe(true);
        expect(Object.keys(RANDOMNESS)).toEqual(['engine', 'wrapper', 'usedBy']);
    });
});
