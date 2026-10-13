/**
 * Tests for `src/base64.ts` — boundary diagnostics for base64 inputs: the
 * classic agent mistakes (a `data:` URI, PEM text where DER is expected,
 * base64 encoded twice) fail with a coded error and a remedy, never with an
 * opaque engine exception.
 */
import { describe, expect, it } from 'vitest';

import { decodeBase64Field, decodeDerBase64, encodeBase64 } from '../src/base64.js';
import { ToolError } from '../src/errors.js';
import { fixtureBase64, fixtureBytes, fixtureText } from './_pki-fixtures.js';

function thrown(fn: () => unknown): ToolError {
    try {
        fn();
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to throw');
}

describe('decodeBase64Field', () => {
    it('tolerates whitespace and a data: URI prefix', () => {
        const b64 = fixtureBase64('leaf.crt.der');
        const spaced = `data:application/pkix-cert;base64,${b64.slice(0, 40)}\n  ${b64.slice(40, 100)}\r\n\t${b64.slice(100)}`;
        expect(decodeBase64Field(spaced, 'certificate')).toEqual(fixtureBytes('leaf.crt.der'));
        expect(decodeBase64Field(b64, 'certificate')).toEqual(fixtureBytes('leaf.crt.der'));
    });

    it('rejects non-base64 characters and empty payloads with VALIDATION_ERROR naming the field', () => {
        const bad = thrown(() => decodeBase64Field('not base64!', 'derBase64'));
        expect(bad.code).toBe('VALIDATION_ERROR');
        expect(bad.message).toContain('derBase64');
        expect(bad.data).toEqual({ field: 'derBase64' });
        expect(thrown(() => decodeBase64Field('', 'content.base64')).data).toEqual({ field: 'content.base64' });
        expect(thrown(() => decodeBase64Field('   \n ', 'x')).code).toBe('VALIDATION_ERROR');
        expect(thrown(() => decodeBase64Field('AAAAé', 'x')).code).toBe('VALIDATION_ERROR');
    });

    it('accepts the base64url alphabet (no decode error at the boundary)', () => {
        expect(() => decodeBase64Field('AQ-_', 'x')).not.toThrow();
    });
});

describe('decodeDerBase64', () => {
    it('round-trips a real fixture DER and hands arbitrary bytes to the engine', () => {
        expect(decodeDerBase64(fixtureBase64('leaf.crt.der'))).toEqual(fixtureBytes('leaf.crt.der'));
        expect(decodeDerBase64(`data:application/pkix-cert;base64,${fixtureBase64('root.crt.der')}`)).toEqual(fixtureBytes('root.crt.der'));
        // Garbage that is not one of the unmistakable mistakes passes: the engine's parser is the authority.
        expect(() => decodeDerBase64(Buffer.from('this is not DER').toString('base64'))).not.toThrow();
    });

    it('reports an empty decoded buffer as VALIDATION_ERROR naming the field', () => {
        const err = thrown(() => decodeDerBase64('====', 'certificate.derBase64'));
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.message).toContain('certificate.derBase64');
        expect(err.message).toContain('empty');
        expect(err.data).toEqual({ field: 'certificate.derBase64' });
        expect(thrown(() => decodeDerBase64('data:application/pkix-cert;base64,')).code).toBe('VALIDATION_ERROR');
        expect(thrown(() => decodeDerBase64('   ')).code).toBe('VALIDATION_ERROR');
    });

    it("PEM text pasted as derBase64 is VALIDATION_ERROR with data.remedy 'pem'", () => {
        const err = thrown(() => decodeDerBase64(fixtureText('leaf.crt.pem')));
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.message).toContain('`pem`');
        expect(err.data).toEqual({ field: 'derBase64', remedy: 'pem' });
        // PEM text encoded ONCE as base64 is recognised by its decoded head.
        const encoded = thrown(() => decodeDerBase64(Buffer.from(fixtureText('leaf.crt.pem')).toString('base64')));
        expect(encoded.code).toBe('VALIDATION_ERROR');
        expect(encoded.message).toMatch(/PEM text/);
        expect(encoded.message).toContain('exactly once');
        expect(encoded.data?.['remedy']).toBe('pem');
    });

    it('names a nested data: URI and base64 encoded twice (VALIDATION_ERROR, no remedy)', () => {
        const nested = thrown(() => decodeDerBase64(Buffer.from(`data:application/pkix-cert;base64,${fixtureBase64('leaf.crt.der')}`).toString('base64')));
        expect(nested.code).toBe('VALIDATION_ERROR');
        expect(nested.message).toMatch(/nested data: URI/);
        expect(nested.data?.['field']).toBe('derBase64');
        expect(nested.data?.['remedy']).toBeUndefined();
        for (const name of ['leaf.crt.der', 'leaf.csr.der', 'inter.crl.der']) {
            const twice = thrown(() => decodeDerBase64(Buffer.from(fixtureBase64(name)).toString('base64')));
            expect(twice.code, name).toBe('VALIDATION_ERROR');
            expect(twice.message, name).toMatch(/encoded twice/);
            expect(twice.message, name).toContain('exactly once');
        }
    });

    it('the field name defaults to derBase64 and is carried verbatim otherwise', () => {
        expect(thrown(() => decodeDerBase64('!!!')).data).toEqual({ field: 'derBase64' });
        const custom = thrown(() => decodeDerBase64('!!!', 'trustAnchors[0].derBase64'));
        expect(custom.message).toContain('trustAnchors[0].derBase64');
        expect(custom.data).toEqual({ field: 'trustAnchors[0].derBase64' });
    });
});

describe('encodeBase64', () => {
    it('round-trips a subarray view without copying the whole backing buffer', () => {
        const backing = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
        const view = backing.subarray(2, 6);
        expect(encodeBase64(view)).toBe(Buffer.from([2, 3, 4, 5]).toString('base64'));
        expect(decodeBase64Field(encodeBase64(view), 'x')).toEqual(new Uint8Array([2, 3, 4, 5]));
        expect(encodeBase64(new Uint8Array(0))).toBe('');
        expect(encodeBase64(fixtureBytes('leaf.crt.der'))).toBe(fixtureBase64('leaf.crt.der'));
    });
});
