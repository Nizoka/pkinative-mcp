/**
 * Tests for `src/asn1-spec.ts` — the JSON node spec of encode_asn1: every
 * node type runs through the engine's own encoder (compared byte for byte
 * with a direct call), nesting is bounded by maxDepth, and a malformed node
 * is VALIDATION_ERROR naming its JSON path.
 */
import { describe, expect, it } from 'vitest';
import {
    DEFAULT_PKI_LIMITS,
    encodeBitString,
    encodeBoolean,
    encodeEnumerated,
    encodeExplicit,
    encodeImplicit,
    encodeInteger,
    encodeNamedBits,
    encodeNull,
    encodeObjectIdentifier,
    encodeOctetString,
    encodeRelativeOid,
    encodeSequence,
    encodeSet,
    encodeSetOf,
    encodeString,
    encodeTime,
    encodeTlv,
} from 'pkinative';

import { ASN1_NODE_SPEC_SCHEMA, ASN1_NODE_TYPES, encodeSpec } from '../src/asn1-spec.js';
import { ToolError } from '../src/errors.js';
import { createParseContext } from '../src/parse-context.js';
import { AT, fixtureBytes } from './_pki-fixtures.js';

const ctx = createParseContext({});
const AT_MS = Date.UTC(2027, 0, 1);

function thrown(fn: () => unknown): ToolError {
    try {
        fn();
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to throw');
}

describe('encodeSpec — every node type matches the engine encoder', () => {
    it('primitives', () => {
        expect(encodeSpec({ type: 'boolean', value: true }, ctx)).toEqual(encodeBoolean(true));
        expect(encodeSpec({ type: 'boolean', value: false }, ctx)).toEqual(encodeBoolean(false));
        expect(encodeSpec({ type: 'integer', value: 42 }, ctx)).toEqual(encodeInteger(42n));
        expect(encodeSpec({ type: 'integer', value: '12345678901234567890' }, ctx)).toEqual(encodeInteger(12345678901234567890n));
        expect(encodeSpec({ type: 'integer', value: '0x7f' }, ctx)).toEqual(encodeInteger(127n));
        expect(encodeSpec({ type: 'integer', value: '-5' }, ctx)).toEqual(encodeInteger(-5n));
        expect(encodeSpec({ type: 'integer', value: ' -0x10 ' }, ctx)).toEqual(encodeInteger(-16n));
        expect(encodeSpec({ type: 'enumerated', value: 3 }, ctx)).toEqual(encodeEnumerated(3n));
        expect(encodeSpec({ type: 'null' }, ctx)).toEqual(encodeNull());
        expect(encodeSpec({ type: 'bit-string', hex: '0a0b' }, ctx)).toEqual(encodeBitString(new Uint8Array([0x0a, 0x0b]), 0));
        expect(encodeSpec({ type: 'bit-string', hex: '0ab0', unusedBits: 4 }, ctx)).toEqual(encodeBitString(new Uint8Array([0x0a, 0xb0]), 4));
        // DER: the unused bits must be zero — the engine refuses otherwise, with its own code.
        expect(thrown(() => encodeSpec({ type: 'bit-string', hex: '0a0b', unusedBits: 4 }, ctx)).code).toBe('PKI_ASN1_VALUE_OUT_OF_RANGE');
        expect(encodeSpec({ type: 'named-bits', bits: [0, 5] }, ctx)).toEqual(encodeNamedBits([0, 5]));
        expect(encodeSpec({ type: 'named-bits', bits: [] }, ctx)).toEqual(encodeNamedBits([]));
        expect(encodeSpec({ type: 'octet-string', hex: '00:ff' }, ctx)).toEqual(encodeOctetString(new Uint8Array([0, 0xff])));
        expect(encodeSpec({ type: 'octet-string', hex: '' }, ctx)).toEqual(encodeOctetString(new Uint8Array(0)));
        expect(encodeSpec({ type: 'oid', value: '1.2.840.113549' }, ctx)).toEqual(encodeObjectIdentifier('1.2.840.113549'));
        expect(encodeSpec({ type: 'relative-oid', value: '840.113549' }, ctx)).toEqual(encodeRelativeOid('840.113549'));
        expect(encodeSpec({ type: 'string', stringType: 'utf8', value: 'héllo' }, ctx)).toEqual(encodeString('utf8', 'héllo'));
        expect(encodeSpec({ type: 'string', stringType: 'printable', value: 'FR' }, ctx)).toEqual(encodeString('printable', 'FR'));
        expect(encodeSpec({ type: 'string', stringType: 'ia5', value: 'a@b.test' }, ctx)).toEqual(encodeString('ia5', 'a@b.test'));
        expect(encodeSpec({ type: 'time', value: AT }, ctx)).toEqual(encodeTime(AT_MS, 'rfc5280'));
        expect(encodeSpec({ type: 'time', value: AT_MS }, ctx)).toEqual(encodeTime(AT_MS, 'rfc5280'));
        expect(encodeSpec({ type: 'time', value: AT, timeType: 'GeneralizedTime' }, ctx)).toEqual(encodeTime(AT_MS, 'GeneralizedTime'));
        expect(encodeSpec({ type: 'time', value: AT, timeType: 'UTCTime' }, ctx)).toEqual(encodeTime(AT_MS, 'UTCTime'));
    });

    it('constructed, tagged, tlv and der nodes', () => {
        const inner = encodeInteger(1n);
        expect(encodeSpec({ type: 'sequence', children: [{ type: 'integer', value: 1 }, { type: 'null' }] }, ctx)).toEqual(encodeSequence([inner, encodeNull()]));
        expect(encodeSpec({ type: 'sequence', children: [] }, ctx)).toEqual(encodeSequence([]));
        expect(encodeSpec({ type: 'set', children: [{ type: 'null' }, { type: 'integer', value: 1 }] }, ctx)).toEqual(encodeSet([encodeNull(), inner]));
        expect(encodeSpec({ type: 'set-of', children: [{ type: 'integer', value: 2 }, { type: 'integer', value: 1 }] }, ctx)).toEqual(encodeSetOf([encodeInteger(2n), inner]));
        expect(encodeSpec({ type: 'explicit', tag: 0, inner: { type: 'integer', value: 1 } }, ctx)).toEqual(encodeExplicit(0, inner, { tagClass: 'context' }));
        expect(encodeSpec({ type: 'explicit', tag: 3, class: 'application', inner: { type: 'integer', value: 1 } }, ctx)).toEqual(encodeExplicit(3, inner, { tagClass: 'application' }));
        expect(encodeSpec({ type: 'implicit', tag: 2, inner: { type: 'integer', value: 1 } }, ctx)).toEqual(encodeImplicit(2, inner, { tagClass: 'context' }));
        expect(encodeSpec({ type: 'implicit', tag: 1, class: 'private', inner: { type: 'octet-string', hex: 'ab' } }, ctx)).toEqual(encodeImplicit(1, encodeOctetString(new Uint8Array([0xab])), { tagClass: 'private' }));
        expect(encodeSpec({ type: 'tlv', class: 'universal', tag: 4, constructed: false, hex: '0102' }, ctx)).toEqual(encodeTlv('universal', 4, false, new Uint8Array([1, 2])));
        expect(encodeSpec({ type: 'tlv', class: 'context', tag: 0, constructed: true, hex: '0500' }, ctx)).toEqual(encodeTlv('context', 0, true, new Uint8Array([5, 0])));
        expect(encodeSpec({ type: 'der', hex: '0500' }, ctx)).toEqual(new Uint8Array([5, 0]));
        const der = fixtureBytes('leaf.crt.der');
        expect(encodeSpec({ type: 'der', hex: Buffer.from(der).toString('hex') }, ctx)).toEqual(der);
        // A nested structure, compared whole.
        const spec = { type: 'sequence', children: [{ type: 'oid', value: '2.5.4.3' }, { type: 'explicit', tag: 0, inner: { type: 'set', children: [{ type: 'string', stringType: 'utf8', value: 'x' }] } }] };
        expect(encodeSpec(spec, ctx)).toEqual(encodeSequence([encodeObjectIdentifier('2.5.4.3'), encodeExplicit(0, encodeSet([encodeString('utf8', 'x')]), { tagClass: 'context' })]));
    });
});

describe('encodeSpec — refusals', () => {
    it('nesting past limits.maxDepth is PKI_LIMIT_EXCEEDED naming maxDepth (the engine default applies otherwise)', () => {
        const nest = (depth: number): unknown => {
            let node: unknown = { type: 'null' };
            for (let i = 0; i < depth; i++) node = { type: 'sequence', children: [node] };
            return node;
        };
        const shallow = createParseContext({ limits: { maxDepth: 2 } });
        expect(() => encodeSpec(nest(2), shallow)).not.toThrow();
        const err = thrown(() => encodeSpec(nest(3), shallow));
        expect(err.code).toBe('PKI_LIMIT_EXCEEDED');
        expect(err.message).toBe('asn1 spec $.children[0].children[0].children[0]: nesting exceeds maxDepth (2).');
        expect(err.data).toEqual({ errorClass: 'limit', limit: 'maxDepth', configured: 2, observed: 3, remedy: 'limits.maxDepth (trusted input only)' });
        // Tagged wrappers count as a level too.
        expect(thrown(() => encodeSpec({ type: 'explicit', tag: 0, inner: { type: 'explicit', tag: 0, inner: { type: 'implicit', tag: 0, inner: { type: 'null' } } } }, shallow)).data).toMatchObject({ limit: 'maxDepth', observed: 3 });
        expect(() => encodeSpec(nest(DEFAULT_PKI_LIMITS.maxDepth), ctx)).not.toThrow();
        expect(thrown(() => encodeSpec(nest(DEFAULT_PKI_LIMITS.maxDepth + 1), ctx)).data).toMatchObject({ limit: 'maxDepth', configured: DEFAULT_PKI_LIMITS.maxDepth });
    });

    it('a malformed node is VALIDATION_ERROR naming the JSON path of the faulty member', () => {
        const cases: Array<[unknown, string, string]> = [
            [null, '$', 'expected an object with a "type"'],
            ['boolean', '$', 'expected an object with a "type"'],
            [{}, '$.type', 'expected a string'],
            [{ type: 'bogus' }, '$.type', 'unknown type "bogus"'],
            [{ type: 'boolean', value: 'true' }, '$.value', 'expected a boolean'],
            [{ type: 'integer', value: 1.5 }, '$.value', 'expected a safe integer'],
            [{ type: 'integer', value: 'twelve' }, '$.value', 'expected a safe integer'],
            [{ type: 'integer' }, '$.value', 'expected a safe integer'],
            [{ type: 'bit-string', hex: 'xyz' }, '$.hex', 'expected a hexadecimal string'],
            [{ type: 'bit-string', hex: '00', unusedBits: 8 }, '$.unusedBits', 'expected an integer from 0 to 7'],
            [{ type: 'bit-string', hex: '00', unusedBits: -1 }, '$.unusedBits', 'expected an integer from 0 to 7'],
            [{ type: 'named-bits', bits: [0, 'x'] }, '$.bits', 'expected an array of bit numbers'],
            [{ type: 'named-bits' }, '$.bits', 'expected an array of bit numbers'],
            [{ type: 'octet-string' }, '$.hex', 'expected a hexadecimal string'],
            [{ type: 'octet-string', hex: 'abc' }, '$.hex', 'expected a hexadecimal string'],
            [{ type: 'oid', value: 1 }, '$.value', 'expected a dotted OID'],
            [{ type: 'relative-oid' }, '$.value', 'expected a dotted relative OID'],
            [{ type: 'string', stringType: 'ascii', value: 'x' }, '$.stringType', 'expected one of utf8|numeric|printable|teletex|ia5|visible|universal|bmp'],
            [{ type: 'string', value: 'x' }, '$.stringType', 'expected one of'],
            [{ type: 'string', stringType: 'utf8', value: 1 }, '$.value', 'expected a string'],
            [{ type: 'time', value: '2027-02-31' }, '$.value', 'expects an ISO 8601 date-time'],
            [{ type: 'time', value: AT, timeType: 'Unix' }, '$.timeType', 'expected one of UTCTime|GeneralizedTime|rfc5280'],
            [{ type: 'time', value: true }, '$.value', 'expected an instant'],
            [{ type: 'sequence' }, '$.children', 'expected an array'],
            [{ type: 'set', children: {} }, '$.children', 'expected an array'],
            [{ type: 'sequence', children: [{ type: 'null' }, { type: 'boolean', value: 1 }] }, '$.children[1].value', 'expected a boolean'],
            [{ type: 'explicit', inner: { type: 'null' } }, '$.tag', 'expected a tag number'],
            [{ type: 'explicit', tag: -1, inner: { type: 'null' } }, '$.tag', 'expected a tag number'],
            [{ type: 'explicit', tag: 0, class: 'universal2', inner: { type: 'null' } }, '$.class', 'expected one of universal|application|context|private'],
            [{ type: 'implicit', tag: 0 }, '$.inner', 'expected an object with a "type"'],
            [{ type: 'implicit', tag: 0, inner: { type: 'sequence', children: [{ type: 'oid' }] } }, '$.inner.children[0].value', 'expected a dotted OID'],
            [{ type: 'tlv', tag: 4, constructed: false, hex: '00' }, '$.class', 'expected one of'],
            [{ type: 'tlv', class: 'universal', tag: 4, hex: '00' }, '$.constructed', 'expected a boolean'],
            [{ type: 'tlv', class: 'universal', tag: 4, constructed: false }, '$.hex', 'expected a hexadecimal string'],
            [{ type: 'der' }, '$.hex', 'expected a hexadecimal string'],
        ];
        for (const [spec, path, message] of cases) {
            const err = thrown(() => encodeSpec(spec, ctx));
            expect(err.code, JSON.stringify(spec)).toBe('VALIDATION_ERROR');
            // A time value is parsed by parseInstant, whose data names the `field`; every other member is a spec `path`.
            expect(err.data?.['path'] ?? err.data?.['field'], JSON.stringify(spec)).toBe(path);
            expect(err.message, JSON.stringify(spec)).toContain(message);
        }
    });

    it('a der node is validated as exactly one DER object; engine refusals carry the PKI_* code and the path', () => {
        const truncated = thrown(() => encodeSpec({ type: 'der', hex: '3005' }, ctx));
        expect(truncated.code).toMatch(/^PKI_ASN1_/);
        expect(truncated.message).toContain('asn1 spec $');
        expect(truncated.data).toMatchObject({ errorClass: 'parse', engineError: 'PkiEncodingError' });
        const trailing = thrown(() => encodeSpec({ type: 'sequence', children: [{ type: 'der', hex: '05000500' }] }, ctx));
        expect(trailing.code).toBe('PKI_ASN1_TRAILING_DATA');
        expect(trailing.message).toContain('asn1 spec $.children[0]');
        expect(trailing.data?.['remedy']).toContain('decode_asn1');
        // Other engine-side refusals keep their code too.
        expect(thrown(() => encodeSpec({ type: 'oid', value: '1.2.3.x' }, ctx)).code).toMatch(/^PKI_/);
        expect(thrown(() => encodeSpec({ type: 'string', stringType: 'printable', value: 'é' }, ctx)).code).toMatch(/^PKI_/);
        // BER input to a der node is accepted under encodingRules:'ber' and refused under der.
        const ber = createParseContext({ encodingRules: 'ber' });
        expect(() => encodeSpec({ type: 'der', hex: '2480040100' + '0000' }, ber)).not.toThrow();
        expect(thrown(() => encodeSpec({ type: 'der', hex: '2480040100' + '0000' }, ctx)).code).toMatch(/^PKI_ASN1_/);
    });
});

describe('ASN1_NODE_SPEC_SCHEMA', () => {
    it('enumerates every node type and the member enums', () => {
        expect(ASN1_NODE_TYPES).toHaveLength(18);
        expect(ASN1_NODE_SPEC_SCHEMA.type).toBe('object');
        expect(ASN1_NODE_SPEC_SCHEMA.required).toEqual(['type']);
        expect(ASN1_NODE_SPEC_SCHEMA.properties.type.enum).toEqual([...ASN1_NODE_TYPES]);
        expect(Object.keys(ASN1_NODE_SPEC_SCHEMA.properties)).toEqual(['type', 'value', 'hex', 'unusedBits', 'bits', 'stringType', 'timeType', 'children', 'tag', 'class', 'constructed', 'inner']);
        expect(ASN1_NODE_SPEC_SCHEMA.properties.stringType.enum).toEqual(['utf8', 'numeric', 'printable', 'teletex', 'ia5', 'visible', 'universal', 'bmp']);
        expect(ASN1_NODE_SPEC_SCHEMA.properties.timeType.enum).toEqual(['UTCTime', 'GeneralizedTime', 'rfc5280']);
        expect(ASN1_NODE_SPEC_SCHEMA.properties.class.enum).toEqual(['universal', 'application', 'context', 'private']);
        expect(ASN1_NODE_SPEC_SCHEMA.properties.unusedBits).toMatchObject({ type: 'integer', minimum: 0, maximum: 7 });
        expect(ASN1_NODE_SPEC_SCHEMA.properties.tag).toMatchObject({ type: 'integer', minimum: 0 });
        for (const type of ASN1_NODE_TYPES) expect(ASN1_NODE_SPEC_SCHEMA.description, type).toContain(type);
        expect(ASN1_NODE_SPEC_SCHEMA.description).toContain('limits.maxDepth');
    });
});
