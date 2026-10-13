/**
 * Tests for `src/names.ts` — names and addresses as an agent writes them,
 * turned into what the engine takes: attribute type OIDs, RDN lists and the
 * octets of an IP address.
 */
import { describe, expect, it } from 'vitest';
import { encodeDistinguishedName, OID_REGISTRY } from 'pkinative';

import { ToolError } from '../src/errors.js';
import { attributeType, NAME_ALIASES, NAME_SPEC_SCHEMA, parseIp, parseNameAttribute, parseNameSpec, specError } from '../src/names.js';

function thrown(fn: () => unknown): ToolError {
    try {
        fn();
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to throw');
}

describe('specError', () => {
    it('is VALIDATION_ERROR prefixed with the path and carrying it as data', () => {
        const err = specError('subject.CN', 'expected a string');
        expect(err).toBeInstanceOf(ToolError);
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.message).toBe('spec subject.CN: expected a string');
        expect(err.data).toEqual({ path: 'subject.CN' });
    });
});

describe('attributeType', () => {
    it('resolves RFC 4514 short names case-insensitively, registry names, and passes dotted OIDs through', () => {
        expect(attributeType('CN', 'p')).toBe('2.5.4.3');
        expect(attributeType('cn', 'p')).toBe('2.5.4.3');
        expect(attributeType('Cn', 'p')).toBe('2.5.4.3');
        expect(attributeType('O', 'p')).toBe('2.5.4.10');
        expect(attributeType('OU', 'p')).toBe('2.5.4.11');
        expect(attributeType('C', 'p')).toBe('2.5.4.6');
        expect(attributeType('ST', 'p')).toBe('2.5.4.8');
        expect(attributeType('L', 'p')).toBe('2.5.4.7');
        expect(attributeType('DC', 'p')).toBe('0.9.2342.19200300.100.1.25');
        expect(attributeType('UID', 'p')).toBe('0.9.2342.19200300.100.1.1');
        expect(attributeType('E', 'p')).toBe('1.2.840.113549.1.9.1');
        expect(attributeType('emailAddress', 'p')).toBe('1.2.840.113549.1.9.1');
        expect(attributeType('serialNumber', 'p')).toBe('2.5.4.5');
        expect(attributeType('organizationIdentifier', 'p')).toBe('2.5.4.97');
        expect(attributeType('commonName', 'p')).toBe('2.5.4.3');
        expect(attributeType('COMMONNAME', 'p')).toBe('2.5.4.3');
        expect(attributeType('organizationName', 'p')).toBe('2.5.4.10');
        expect(attributeType('2.5.4.3', 'p')).toBe('2.5.4.3');
        expect(attributeType('1.2.3.4.5', 'p')).toBe('1.2.3.4.5');
        for (const [alias, oid] of Object.entries(NAME_ALIASES)) expect(attributeType(alias.toLowerCase(), 'p'), alias).toBe(oid);
        expect(OID_REGISTRY.some((e) => e.name === 'commonName' && e.oid === '2.5.4.3')).toBe(true);
    });

    it('an unknown name is VALIDATION_ERROR with data.path', () => {
        const err = thrown(() => attributeType('nope', 'subject[0][0].type'));
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.message).toBe('spec subject[0][0].type: unknown attribute type "nope" (use CN, O, OU, C, …, a registered name, or a dotted OID)');
        expect(err.data).toEqual({ path: 'subject[0][0].type' });
        expect(thrown(() => attributeType('', 'p')).code).toBe('VALIDATION_ERROR');
        expect(attributeType('2.5', 'p')).toBe('2.5'); // two arcs are enough to be dotted; the engine validates the OID later
        expect(thrown(() => attributeType('1.2.', 'p')).code).toBe('VALIDATION_ERROR');
        expect(thrown(() => attributeType('5', 'p')).code).toBe('VALIDATION_ERROR');
    });
});

describe('parseNameAttribute', () => {
    it('reads { type, value, stringType? } and resolves the type', () => {
        expect(parseNameAttribute({ type: 'CN', value: 'example.test' }, 'p')).toEqual({ type: '2.5.4.3', value: 'example.test' });
        expect(parseNameAttribute({ type: 'C', value: 'FR', stringType: 'printable' }, 'p')).toEqual({ type: '2.5.4.6', value: 'FR', stringType: 'printable' });
        for (const stringType of ['utf8', 'printable', 'ia5', 'numeric']) expect(parseNameAttribute({ type: 'CN', value: 'x', stringType }, 'p')).toMatchObject({ stringType });
    });

    it('refuses a non-object, an unknown member, non-string members and an unknown stringType, naming the path', () => {
        expect(thrown(() => parseNameAttribute('CN=x', 'p')).data).toEqual({ path: 'p' });
        expect(thrown(() => parseNameAttribute(['CN', 'x'], 'p')).data).toEqual({ path: 'p' });
        expect(thrown(() => parseNameAttribute(null, 'p')).data).toEqual({ path: 'p' });
        expect(thrown(() => parseNameAttribute({ type: 'CN', value: 'x', extra: 1 }, 'p')).data).toEqual({ path: 'p.extra' });
        expect(thrown(() => parseNameAttribute({ type: 'CN' }, 'p')).message).toContain('"type" and "value" must be strings');
        expect(thrown(() => parseNameAttribute({ type: 'CN', value: 1 }, 'p')).data).toEqual({ path: 'p' });
        expect(thrown(() => parseNameAttribute({ type: 'CN', value: 'x', stringType: 'bmp' }, 'p')).data).toEqual({ path: 'p.stringType' });
        expect(thrown(() => parseNameAttribute({ type: 'nope', value: 'x' }, 'p')).data).toEqual({ path: 'p.type' });
    });
});

describe('parseNameSpec', () => {
    it('object form: one attribute per RDN, most significant first, in insertion order', () => {
        const name = parseNameSpec({ C: 'FR', O: 'Acme', CN: 'example.test' }, 'subject');
        expect(name).toEqual([[{ type: '2.5.4.6', value: 'FR' }], [{ type: '2.5.4.10', value: 'Acme' }], [{ type: '2.5.4.3', value: 'example.test' }]]);
        expect(parseNameSpec({ '2.5.4.3': 'x' }, 'subject')).toEqual([[{ type: '2.5.4.3', value: 'x' }]]);
        expect(() => encodeDistinguishedName(name)).not.toThrow();
    });

    it('RDN array form: explicit multi-valued RDNs with stringType', () => {
        const name = parseNameSpec([[{ type: 'C', value: 'FR', stringType: 'printable' }], [{ type: 'O', value: 'Acme' }, { type: 'OU', value: 'Lab' }]], 'issuer');
        expect(name).toEqual([[{ type: '2.5.4.6', value: 'FR', stringType: 'printable' }], [{ type: '2.5.4.10', value: 'Acme' }, { type: '2.5.4.11', value: 'Lab' }]]);
        expect(() => encodeDistinguishedName(name)).not.toThrow();
    });

    it('refuses an empty name, an empty RDN, a non-string value, an unknown type and a non-object spec, naming the path', () => {
        expect(thrown(() => parseNameSpec({}, 'subject')).message).toBe('spec subject: a name needs at least one RDN');
        expect(thrown(() => parseNameSpec([], 'subject')).data).toEqual({ path: 'subject' });
        expect(thrown(() => parseNameSpec([[]], 'subject')).data).toEqual({ path: 'subject[0]' });
        expect(thrown(() => parseNameSpec([{ type: 'CN', value: 'x' }], 'subject')).data).toEqual({ path: 'subject[0]' });
        expect(thrown(() => parseNameSpec([[{ type: 'CN', value: 1 }]], 'subject')).data).toEqual({ path: 'subject[0][0]' });
        expect(thrown(() => parseNameSpec({ CN: 1 }, 'subject')).data).toEqual({ path: 'subject.CN' });
        expect(thrown(() => parseNameSpec({ CN: 'x', nope: 'y' }, 'subject')).data).toEqual({ path: 'subject.nope' });
        expect(thrown(() => parseNameSpec('CN=x', 'subject')).message).toContain('expected an object such as');
        expect(thrown(() => parseNameSpec(null, 'subject')).data).toEqual({ path: 'subject' });
        expect(thrown(() => parseNameSpec(42, 'subject')).code).toBe('VALIDATION_ERROR');
    });
});

describe('parseIp', () => {
    it('IPv4 → 4 octets', () => {
        expect(parseIp('192.0.2.1', 'ip')).toEqual(new Uint8Array([192, 0, 2, 1]));
        expect(parseIp('0.0.0.0', 'ip')).toEqual(new Uint8Array([0, 0, 0, 0]));
        expect(parseIp('255.255.255.255', 'ip')).toEqual(new Uint8Array([255, 255, 255, 255]));
    });

    it('IPv6 → 16 octets, with :: expansion, mixed case, and an embedded IPv4 suffix', () => {
        expect(parseIp('::1', 'ip')).toEqual(new Uint8Array([...new Array<number>(15).fill(0), 1]));
        expect(parseIp('::', 'ip')).toEqual(new Uint8Array(16));
        expect(parseIp('2001:db8::1', 'ip')).toEqual(new Uint8Array([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        expect(parseIp('2001:DB8:0:0:0:0:0:1', 'ip')).toEqual(parseIp('2001:db8::1', 'ip'));
        expect(parseIp('fe80::', 'ip')).toEqual(new Uint8Array([0xfe, 0x80, ...new Array<number>(14).fill(0)]));
        expect(parseIp('::ffff:192.0.2.1', 'ip')).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1]));
        expect(parseIp('1:2:3:4:5:6:7:8', 'ip')).toEqual(new Uint8Array([0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8]));
        // Node accepts a zone-scoped address; the zone is not part of the octets and is dropped.
        expect(parseIp('fe80::1%eth0', 'ip')).toEqual(new Uint8Array([0xfe, 0x80, ...new Array<number>(13).fill(0), 1]));
    });

    it('anything else is VALIDATION_ERROR with data.path', () => {
        for (const bad of ['example.test', '300.1.1.1', '192.0.2', '192.0.2.1/24', '', ' 192.0.2.1', ':::1', '2001:db8::1::2', '192.0.2.1:443']) {
            const err = thrown(() => parseIp(bad, 'extensions.subjectAltName.ip'));
            expect(err.code, bad).toBe('VALIDATION_ERROR');
            expect(err.message, bad).toContain(`"${bad}" is not an IPv4 or IPv6 address`);
            expect(err.data, bad).toEqual({ path: 'extensions.subjectAltName.ip' });
        }
    });
});

describe('NAME_SPEC_SCHEMA', () => {
    it('offers the object shorthand and the explicit RDN array', () => {
        expect(NAME_SPEC_SCHEMA.anyOf).toHaveLength(2);
        expect(NAME_SPEC_SCHEMA.anyOf[0]).toEqual({ type: 'object', minProperties: 1, additionalProperties: { type: 'string' } });
        expect(NAME_SPEC_SCHEMA.anyOf[1]).toMatchObject({ type: 'array', minItems: 1, items: { type: 'array', minItems: 1, items: { type: 'object', additionalProperties: false, required: ['type', 'value'] } } });
        expect(NAME_SPEC_SCHEMA.anyOf[1].items.items.properties.stringType.enum).toEqual(['utf8', 'printable', 'ia5', 'numeric']);
        expect(NAME_SPEC_SCHEMA.description).toContain('most significant RDN first');
    });
});
