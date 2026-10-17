/**
 * Tests for `src/x509-spec.ts` — the JSON spec of create_certificate /
 * create_csr turned into pkinative descriptions: every extension kind
 * (decoded back with the engine's own decoder), serial numbers, validity
 * resolution and the spec-member guards.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { computeKeyIdentifier, decodeExtensionValue, decodePem, parseCertificate, type Extension, type ExtensionDescription } from 'pkinative';

import { ToolError } from '../src/errors.js';
import { AT_ENV } from '../src/time.js';
import {
    buildExtensions,
    critical,
    EXTENSION_OIDS,
    EXTENSIONS_SPEC_SCHEMA,
    generalNames,
    hexValue,
    isSpec,
    keyUsages,
    nameOf,
    onlyMembers,
    serialNumber,
    validity,
    type KeyIdentifiers,
} from '../src/x509-spec.js';
import { AT, fixtureText } from './_pki-fixtures.js';

const SILENT = { onDiagnostic: () => undefined };
const leaf = parseCertificate(decodePem(fixtureText('leaf.crt.pem'))[0]?.bytes as Uint8Array, SILENT);
const LEAF_BITS = leaf.subjectPublicKeyInfo.publicKey.bytes;
const ISSUER_KEY_ID = new Uint8Array(20).fill(0xab);
const NO_IDS: KeyIdentifiers = { subjectKeyBits: undefined, issuerKeyId: undefined, defaults: { ski: false, aki: false } };
const IDS: KeyIdentifiers = { subjectKeyBits: LEAF_BITS, issuerKeyId: ISSUER_KEY_ID, defaults: { ski: true, aki: true } };

function thrown(fn: () => unknown): ToolError {
    try {
        fn();
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to throw');
}

function decode(ext: { oid: string; value: Uint8Array }): Extension {
    return decodeExtensionValue(ext.oid, ext.value, SILENT);
}

describe('helpers', () => {
    it('isSpec / onlyMembers / critical / hexValue / keyUsages / nameOf', () => {
        expect(isSpec({})).toBe(true);
        expect(isSpec([])).toBe(false);
        expect(isSpec(null)).toBe(false);
        expect(isSpec('x')).toBe(false);
        expect(onlyMembers({ a: 1, b: 2 }, ['a', 'b', 'c'], 'p')).toEqual({ a: 1, b: 2 });
        expect(thrown(() => onlyMembers({ a: 1, zz: 2 }, ['a'], 'p')).data).toEqual({ path: 'p.zz' });
        expect(thrown(() => onlyMembers({ zz: 2 }, ['a'], '')).data).toEqual({ path: 'zz' });
        expect(thrown(() => onlyMembers({ zz: 2 }, ['a', 'b'], 'p')).message).toBe('spec p.zz: unknown member (a, b)');
        expect(critical({}, 'p', true)).toBe(true);
        expect(critical({}, 'p', false)).toBe(false);
        expect(critical({ critical: false }, 'p', true)).toBe(false);
        expect(thrown(() => critical({ critical: 'yes' }, 'p', true)).data).toEqual({ path: 'p.critical' });
        expect(thrown(() => critical({ critical: 1 }, '', true)).data).toEqual({ path: 'critical' });
        expect(hexValue('0xDE:AD', 'p')).toEqual(new Uint8Array([0xde, 0xad]));
        expect(thrown(() => hexValue('xyz', 'p')).data).toEqual({ path: 'p' });
        expect(thrown(() => hexValue(42, 'p')).message).toBe('spec p: expected a hexadecimal string');
        expect(keyUsages(['digitalSignature', 'keyCertSign'], 'p')).toEqual(['digitalSignature', 'keyCertSign']);
        expect(thrown(() => keyUsages(['digitalSignature', 'signing'], 'p')).message).toContain('unknown key usage "signing"');
        expect(nameOf({ subject: { CN: 'x' } }, 'subject')).toEqual([[{ type: '2.5.4.3', value: 'x' }]]);
        expect(nameOf({}, 'issuer')).toBeUndefined();
        expect(thrown(() => nameOf({ subject: {} }, 'subject')).data).toEqual({ path: 'spec subject' });
    });

    it('generalNames: every kind, critical only where the names are an extension', () => {
        const names = generalNames({ dns: ['a.test'], email: ['a@a.test'], uri: ['https://a.test/'], ip: ['192.0.2.1', '::1'], registeredId: ['1.2.3'], directoryName: [{ CN: 'dir' }] }, 'extensions.subjectAltName', true);
        expect(names.map((n) => n.kind)).toEqual(['dNSName', 'rfc822Name', 'uniformResourceIdentifier', 'iPAddress', 'iPAddress', 'registeredID', 'directoryNameDer']);
        expect(names[3]?.value).toEqual(new Uint8Array([192, 0, 2, 1]));
        expect((names[6]?.value as Uint8Array)[0]).toBe(0x30);
        expect(generalNames({ critical: true, dns: ['x'] }, 'extensions.issuerAltName', true)).toHaveLength(1);
        expect(thrown(() => generalNames({ critical: true, dns: ['x'] }, 'p')).data).toEqual({ path: 'p.critical' });
        expect(thrown(() => generalNames({ dns: 'x' }, 'p')).data).toEqual({ path: 'p.dns' });
        expect(thrown(() => generalNames({ ip: ['nope'] }, 'p')).data).toEqual({ path: 'p.ip' });
        expect(thrown(() => generalNames({ directoryName: { CN: 'x' } }, 'p')).data).toEqual({ path: 'p.directoryName' });
        expect(thrown(() => generalNames({ directoryName: [{}] }, 'p')).data).toEqual({ path: 'spec p.directoryName[0]' });
        expect(thrown(() => generalNames(['a.test'], 'p')).message).toContain('expected { "dns"');
        expect(generalNames({}, 'p')).toEqual([]);
    });
});

describe('buildExtensions', () => {
    it('nothing in, nothing out (defaults off); the ids defaults add SKI / AKI when the spec is silent', () => {
        expect(buildExtensions(undefined, NO_IDS)).toEqual([]);
        expect(buildExtensions({}, NO_IDS)).toEqual([]);
        const defaults = buildExtensions({}, IDS);
        expect(defaults.map((e) => [e.oid, e.critical])).toEqual([[EXTENSION_OIDS.subjectKeyIdentifier, false], [EXTENSION_OIDS.authorityKeyIdentifier, false]]);
        const ski = decode(defaults[0] as ExtensionDescription);
        expect(ski.kind).toBe('subjectKeyIdentifier');
        if (ski.kind === 'subjectKeyIdentifier') {
            expect(ski.keyIdentifier).toEqual(computeKeyIdentifier(LEAF_BITS));
            // OpenSSL derived the leaf's own SKI the same way (SHA-1 of the key bits).
            const own = leaf.extensions.find((e) => e.kind === 'subjectKeyIdentifier');
            expect(own?.kind === 'subjectKeyIdentifier' ? own.keyIdentifier : undefined).toEqual(ski.keyIdentifier);
        }
        const aki = decode(defaults[1] as ExtensionDescription);
        expect(aki.kind === 'authorityKeyIdentifier' ? aki.keyIdentifier : undefined).toEqual(ISSUER_KEY_ID);
    });

    it('basicConstraints: critical by default, pathLen optional, the members checked', () => {
        const [ca] = buildExtensions({ basicConstraints: { ca: true, pathLen: 0 } }, NO_IDS);
        expect(ca).toMatchObject({ oid: EXTENSION_OIDS.basicConstraints, critical: true });
        expect(decode(ca as ExtensionDescription)).toMatchObject({ kind: 'basicConstraints', cA: true, pathLenConstraint: 0 });
        const [ee] = buildExtensions({ basicConstraints: { ca: false, critical: false } }, NO_IDS);
        expect(ee?.critical).toBe(false);
        expect(decode(ee as ExtensionDescription)).toMatchObject({ kind: 'basicConstraints', cA: false, pathLenConstraint: undefined });
        expect(thrown(() => buildExtensions({ basicConstraints: { ca: 'yes' } }, NO_IDS)).data).toEqual({ path: 'extensions.basicConstraints' });
        expect(thrown(() => buildExtensions({ basicConstraints: true }, NO_IDS)).data).toEqual({ path: 'extensions.basicConstraints' });
        expect(thrown(() => buildExtensions({ basicConstraints: { ca: true, pathLen: '0' } }, NO_IDS)).data).toEqual({ path: 'extensions.basicConstraints.pathLen' });
        expect(thrown(() => buildExtensions({ basicConstraints: { ca: true, pathlen: 0 } }, NO_IDS)).data).toEqual({ path: 'extensions.basicConstraints.pathlen' });
        expect(thrown(() => buildExtensions({ basicConstraints: { ca: true, pathLen: -1 } }, NO_IDS)).code).toMatch(/^PKI_|^VALIDATION_ERROR$/);
    });

    it('keyUsage: array shorthand (critical) or { usages, critical }', () => {
        const [arr] = buildExtensions({ keyUsage: ['digitalSignature', 'keyEncipherment'] }, NO_IDS);
        expect(arr).toMatchObject({ oid: EXTENSION_OIDS.keyUsage, critical: true });
        expect(decode(arr as ExtensionDescription)).toMatchObject({ kind: 'keyUsage', usages: ['digitalSignature', 'keyEncipherment'] });
        const [obj] = buildExtensions({ keyUsage: { usages: ['keyCertSign', 'cRLSign'], critical: false } }, NO_IDS);
        expect(obj?.critical).toBe(false);
        expect(decode(obj as ExtensionDescription)).toMatchObject({ kind: 'keyUsage', usages: ['keyCertSign', 'cRLSign'] });
        expect(thrown(() => buildExtensions({ keyUsage: ['bogus'] }, NO_IDS)).data).toEqual({ path: 'extensions.keyUsage' });
        expect(thrown(() => buildExtensions({ keyUsage: { usages: ['keyCertSign'], extra: 1 } }, NO_IDS)).data).toEqual({ path: 'extensions.keyUsage.extra' });
        expect(thrown(() => buildExtensions({ keyUsage: { critical: true } }, NO_IDS)).data).toEqual({ path: 'extensions.keyUsage.usages' });
        expect(thrown(() => buildExtensions({ keyUsage: 'digitalSignature' }, NO_IDS)).message).toContain('expected an array, or { "usages"');
    });

    it('extendedKeyUsage: purpose names, any and dotted OIDs; not critical by default', () => {
        const [eku] = buildExtensions({ extendedKeyUsage: ['serverAuth', 'any', '1.3.6.1.5.5.7.3.9'] }, NO_IDS);
        expect(eku).toMatchObject({ oid: EXTENSION_OIDS.extendedKeyUsage, critical: false });
        expect(decode(eku as ExtensionDescription)).toMatchObject({ kind: 'extendedKeyUsage', purposes: ['1.3.6.1.5.5.7.3.1', '2.5.29.37.0', '1.3.6.1.5.5.7.3.9'] });
        const [obj] = buildExtensions({ extendedKeyUsage: { purposes: ['timeStamping'], critical: true } }, NO_IDS);
        expect(obj?.critical).toBe(true);
        expect(decode(obj as ExtensionDescription)).toMatchObject({ purposes: ['1.3.6.1.5.5.7.3.8'] });
        expect(thrown(() => buildExtensions({ extendedKeyUsage: ['surfing'] }, NO_IDS)).data).toEqual({ path: 'spec extensions.extendedKeyUsage' });
    });

    it('subjectAltName / issuerAltName: every GeneralName kind including directoryName; critical opt-in', () => {
        const spec = { dns: ['example.test', '*.wild.example.test'], email: ['leaf@example.test'], uri: ['https://example.test/'], ip: ['192.0.2.1', '2001:db8::1'], registeredId: ['1.2.3.4'], directoryName: [{ C: 'FR', CN: 'dir.test' }, [[{ type: 'O', value: 'Acme' }]]] };
        const [san] = buildExtensions({ subjectAltName: spec }, NO_IDS);
        expect(san).toMatchObject({ oid: EXTENSION_OIDS.subjectAltName, critical: false });
        const decoded = decode(san as ExtensionDescription);
        expect(decoded.kind).toBe('subjectAltName');
        if (decoded.kind === 'subjectAltName') {
            expect(decoded.names.map((n) => n.kind)).toEqual(['dNSName', 'dNSName', 'rfc822Name', 'uniformResourceIdentifier', 'iPAddress', 'iPAddress', 'registeredID', 'directoryName', 'directoryName']);
            expect(decoded.names.map((n) => (n.kind === 'dNSName' || n.kind === 'rfc822Name' || n.kind === 'uniformResourceIdentifier' ? n.value : n.kind === 'iPAddress' ? n.address : n.kind === 'registeredID' ? n.oid : n.kind === 'directoryName' ? n.name.rdns.map((r) => r.map((a) => a.value?.value)) : null)))
                .toEqual(['example.test', '*.wild.example.test', 'leaf@example.test', 'https://example.test/', '192.0.2.1', '2001:db8::1', '1.2.3.4', [['FR'], ['dir.test']], [['Acme']]]);
        }
        const [ian] = buildExtensions({ issuerAltName: { dns: ['ca.test'], critical: true } }, NO_IDS);
        expect(ian).toMatchObject({ oid: EXTENSION_OIDS.issuerAltName, critical: true });
        expect(decode(ian as ExtensionDescription)).toMatchObject({ kind: 'issuerAltName' });
        expect(thrown(() => buildExtensions({ subjectAltName: { dns: ['x'], critical: 'no' } }, NO_IDS)).data).toEqual({ path: 'extensions.subjectAltName.critical' });
        expect(thrown(() => buildExtensions({ subjectAltName: { ip: ['999.1.1.1'] } }, NO_IDS)).data).toEqual({ path: 'extensions.subjectAltName.ip' });
        expect(thrown(() => buildExtensions({ subjectAltName: ['x'] }, NO_IDS)).data).toEqual({ path: 'extensions.subjectAltName' });
        expect(thrown(() => buildExtensions({ issuerAltName: { dns: ['x'], other: [] } }, NO_IDS)).data).toEqual({ path: 'extensions.issuerAltName.other' });
    });

    it('subjectKeyIdentifier / authorityKeyIdentifier: true computes, false omits, hex is taken as given; true without an id is refused', () => {
        const computed = buildExtensions({ subjectKeyIdentifier: true, authorityKeyIdentifier: true }, { ...IDS, defaults: { ski: false, aki: false } });
        expect(computed.map((e) => e.oid)).toEqual([EXTENSION_OIDS.subjectKeyIdentifier, EXTENSION_OIDS.authorityKeyIdentifier]);
        expect(computed.every((e) => !e.critical)).toBe(true);
        expect(decode(computed[0] as ExtensionDescription)).toMatchObject({ keyIdentifier: computeKeyIdentifier(LEAF_BITS) });
        expect(decode(computed[1] as ExtensionDescription)).toMatchObject({ keyIdentifier: ISSUER_KEY_ID });
        expect(buildExtensions({ subjectKeyIdentifier: false, authorityKeyIdentifier: false }, IDS)).toEqual([]);
        const hex = buildExtensions({ subjectKeyIdentifier: '0102', authorityKeyIdentifier: 'aa:bb:cc' }, NO_IDS);
        expect(decode(hex[0] as ExtensionDescription)).toMatchObject({ keyIdentifier: new Uint8Array([1, 2]) });
        expect(decode(hex[1] as ExtensionDescription)).toMatchObject({ keyIdentifier: new Uint8Array([0xaa, 0xbb, 0xcc]) });
        const noSki = thrown(() => buildExtensions({ subjectKeyIdentifier: true }, NO_IDS));
        expect(noSki.data).toEqual({ path: 'extensions.subjectKeyIdentifier' });
        expect(noSki.message).toContain('give it as hex');
        expect(thrown(() => buildExtensions({ authorityKeyIdentifier: true }, NO_IDS)).data).toEqual({ path: 'extensions.authorityKeyIdentifier' });
        expect(thrown(() => buildExtensions({}, { ...NO_IDS, defaults: { ski: true, aki: false } })).data).toEqual({ path: 'extensions.subjectKeyIdentifier' });
        expect(thrown(() => buildExtensions({ subjectKeyIdentifier: 'zz' }, NO_IDS)).data).toEqual({ path: 'extensions.subjectKeyIdentifier' });
        expect(thrown(() => buildExtensions({ subjectKeyIdentifier: 1 }, NO_IDS)).data).toEqual({ path: 'extensions.subjectKeyIdentifier' });
    });

    it('raw: { oid, critical?, value: hex } written as given, after the named ones', () => {
        const out = buildExtensions({ raw: [{ oid: '1.3.6.1.5.5.7.1.1', value: '3000' }, { oid: '2.5.29.32', critical: true, value: '0x30:00' }], basicConstraints: { ca: false } }, NO_IDS);
        expect(out.map((e) => [e.oid, e.critical])).toEqual([[EXTENSION_OIDS.basicConstraints, true], ['1.3.6.1.5.5.7.1.1', false], ['2.5.29.32', true]]);
        expect(out[1]?.value).toEqual(new Uint8Array([0x30, 0x00]));
        expect(out[2]?.value).toEqual(new Uint8Array([0x30, 0x00]));
        expect(thrown(() => buildExtensions({ raw: { oid: '1.2', value: '00' } }, NO_IDS)).data).toEqual({ path: 'extensions.raw' });
        expect(thrown(() => buildExtensions({ raw: [{ value: '00' }] }, NO_IDS)).data).toEqual({ path: 'extensions.raw[0]' });
        expect(thrown(() => buildExtensions({ raw: [{ oid: '1.2', value: 'zz' }] }, NO_IDS)).data).toEqual({ path: 'extensions.raw[0].value' });
        expect(thrown(() => buildExtensions({ raw: [{ oid: '1.2', value: '00', hex: '00' }] }, NO_IDS)).data).toEqual({ path: 'extensions.raw[0].hex' });
        expect(thrown(() => buildExtensions({ raw: [{ oid: '1.2', value: '00' }, { oid: '1.3', critical: 'x', value: '00' }] }, NO_IDS)).data).toEqual({ path: 'extensions.raw[1].critical' });
    });

    it('an unknown extension key or a non-object spec is VALIDATION_ERROR naming it; the order of the output is stable', () => {
        const unknown = thrown(() => buildExtensions({ nameConstraints: {} }, NO_IDS));
        expect(unknown.code).toBe('VALIDATION_ERROR');
        expect(unknown.data).toEqual({ path: 'extensions.nameConstraints' });
        expect(unknown.message).toContain('raw');
        expect(thrown(() => buildExtensions([], NO_IDS)).data).toEqual({ path: 'extensions' });
        expect(thrown(() => buildExtensions('x', NO_IDS)).data).toEqual({ path: 'extensions' });
        const all = buildExtensions({ raw: [{ oid: '1.2.3', value: '0500' }], subjectAltName: { dns: ['x'] }, extendedKeyUsage: ['clientAuth'], keyUsage: ['digitalSignature'], basicConstraints: { ca: false } }, IDS);
        expect(all.map((e) => e.oid)).toEqual([EXTENSION_OIDS.basicConstraints, EXTENSION_OIDS.keyUsage, EXTENSION_OIDS.extendedKeyUsage, EXTENSION_OIDS.subjectAltName, EXTENSION_OIDS.subjectKeyIdentifier, EXTENSION_OIDS.authorityKeyIdentifier, '1.2.3']);
    });
});

describe('serialNumber', () => {
    it("'random' (and absent) is a positive 127-bit serial flagged random", () => {
        for (const value of [undefined, 'random']) {
            const { serial, random } = serialNumber(value);
            expect(random).toBe(true);
            expect(serial).toBeGreaterThan(0n);
            expect(serial).toBeLessThan(2n ** 127n);
        }
        expect(serialNumber('random').serial).not.toBe(serialNumber('random').serial);
    });

    it('decimal / hex strings and safe integers are taken as given', () => {
        expect(serialNumber('4097')).toEqual({ serial: 4097n, random: false });
        expect(serialNumber('0x1001')).toEqual({ serial: 4097n, random: false });
        expect(serialNumber('0X1001')).toEqual({ serial: 4097n, random: false });
        expect(serialNumber(4097)).toEqual({ serial: 4097n, random: false });
        expect(serialNumber('1')).toEqual({ serial: 1n, random: false });
        expect(serialNumber('340282366920938463463374607431768211455')).toEqual({ serial: 2n ** 128n - 1n, random: false });
    });

    it('zero, negatives, fractions and anything else are VALIDATION_ERROR at serialNumber', () => {
        for (const bad of [0, '0', '0x0', -1, '-1', 1.5, '1.5', 'abc', '0xzz', '', true, 2 ** 53, 4097n, { value: 1 }]) {
            const err = thrown(() => serialNumber(bad));
            expect(err.code, String(bad)).toBe('VALIDATION_ERROR');
            expect(err.data, String(bad)).toEqual({ path: 'serialNumber' });
        }
    });
});

describe('validity', () => {
    afterEach(() => {
        delete process.env[AT_ENV];
    });

    const AT_MS = Date.UTC(2027, 0, 1);
    const DAY = 86_400_000;

    it('notBefore from the input (ISO or epoch ms, floored to whole seconds); validityDays defaults to 365', () => {
        expect(validity({ notBefore: AT })).toEqual({ notBefore: AT_MS, notAfter: AT_MS + 365 * DAY, notBeforeSource: 'input' });
        expect(validity({ notBefore: AT_MS + 999 })).toEqual({ notBefore: AT_MS, notAfter: AT_MS + 365 * DAY, notBeforeSource: 'input' });
        expect(validity({ notBefore: '2027-01-01T00:00:00.750Z', validityDays: 1 })).toEqual({ notBefore: AT_MS, notAfter: AT_MS + DAY, notBeforeSource: 'input' });
        expect(validity({ notBefore: AT, notAfter: '2028-01-01T00:00:00Z' })).toEqual({ notBefore: AT_MS, notAfter: Date.UTC(2028, 0, 1), notBeforeSource: 'input' });
        expect(validity({ notBefore: AT, notAfter: AT_MS + 1000 }).notAfter).toBe(AT_MS + 1000);
        // An explicit notBefore wins over the pin.
        process.env[AT_ENV] = '2030-01-01T00:00:00Z';
        expect(validity({ notBefore: AT }).notBeforeSource).toBe('input');
    });

    it('notBefore omitted: the operator pin, else the clock (whole seconds)', () => {
        process.env[AT_ENV] = AT;
        expect(validity({})).toEqual({ notBefore: AT_MS, notAfter: AT_MS + 365 * DAY, notBeforeSource: 'pinned' });
        delete process.env[AT_ENV];
        const before = Date.now();
        const clock = validity({ validityDays: 10 });
        expect(clock.notBeforeSource).toBe('clock');
        expect(clock.notBefore % 1000).toBe(0);
        expect(clock.notBefore).toBeGreaterThanOrEqual(Math.floor(before / 1000) * 1000);
        expect(clock.notBefore).toBeLessThanOrEqual(Date.now());
        expect(clock.notAfter).toBe(clock.notBefore + 10 * DAY);
    });

    it('refuses notAfter together with validityDays, a notAfter at or before notBefore, a bad validityDays and a bad instant, naming the member', () => {
        expect(thrown(() => validity({ notBefore: AT, notAfter: '2028-01-01', validityDays: 1 })).data).toEqual({ path: 'notAfter' });
        expect(thrown(() => validity({ notBefore: AT, notAfter: AT })).message).toBe('spec notAfter: must be after notBefore');
        expect(thrown(() => validity({ notBefore: AT, notAfter: '2026-12-31' })).data).toEqual({ path: 'notAfter' });
        for (const days of [0, -1, 1.5, '365', 2 ** 53]) expect(thrown(() => validity({ notBefore: AT, validityDays: days })).data, String(days)).toEqual({ path: 'validityDays' });
        const bad = thrown(() => validity({ notBefore: '2027-02-31' }));
        expect(bad.data).toEqual({ path: 'notBefore' });
        expect(bad.message).toContain('"2027-02-31"');
        // 'now' is an accepted instant form: it resolves to the clock but is reported as an explicit input.
        const now = validity({ notBefore: 'now' });
        expect(now.notBeforeSource).toBe('input');
        expect(now.notBefore % 1000).toBe(0);
        expect(thrown(() => validity({ notBefore: true })).data).toEqual({ path: 'notBefore' });
        expect(thrown(() => validity({ notBefore: 1.5 })).data).toEqual({ path: 'notBefore' });
        expect(thrown(() => validity({ notBefore: AT, notAfter: 'later' })).data).toEqual({ path: 'notAfter' });
    });
});

describe('EXTENSIONS_SPEC_SCHEMA', () => {
    it('is a closed object naming every extension key of EXTENSION_OIDS plus raw', () => {
        expect(EXTENSIONS_SPEC_SCHEMA.type).toBe('object');
        expect(EXTENSIONS_SPEC_SCHEMA.additionalProperties).toBe(false);
        expect(Object.keys(EXTENSIONS_SPEC_SCHEMA.properties)).toEqual([...Object.keys(EXTENSION_OIDS), 'raw']);
        expect(EXTENSIONS_SPEC_SCHEMA.properties.basicConstraints).toMatchObject({ required: ['ca'], properties: { critical: { default: true } } });
        expect(EXTENSIONS_SPEC_SCHEMA.properties.keyUsage.anyOf[1]).toMatchObject({ required: ['usages'], properties: { critical: { default: true } } });
        expect(EXTENSIONS_SPEC_SCHEMA.properties.extendedKeyUsage.anyOf[1]).toMatchObject({ required: ['purposes'], properties: { critical: { default: false } } });
        expect(Object.keys(EXTENSIONS_SPEC_SCHEMA.properties.subjectAltName.properties)).toEqual(['dns', 'email', 'uri', 'ip', 'registeredId', 'directoryName', 'critical']);
        expect(EXTENSIONS_SPEC_SCHEMA.properties.issuerAltName.properties).toEqual(EXTENSIONS_SPEC_SCHEMA.properties.subjectAltName.properties);
        expect(EXTENSIONS_SPEC_SCHEMA.properties.raw.items).toMatchObject({ required: ['oid', 'value'], additionalProperties: false });
        // The raw oid pattern must accept dotted OIDs and refuse anything else (a `\d` in a single-quoted string is just `d`).
        const oidPattern = new RegExp(EXTENSIONS_SPEC_SCHEMA.properties.raw.items.properties.oid.pattern);
        expect(oidPattern.test('1.3.6.1.5.5.7.1.1')).toBe(true);
        expect(oidPattern.test('2.5.29.32')).toBe(true);
        expect(oidPattern.test('ddd')).toBe(false);
        expect(oidPattern.test('basicConstraints')).toBe(false);
        expect(EXTENSION_OIDS).toEqual({ basicConstraints: '2.5.29.19', keyUsage: '2.5.29.15', extendedKeyUsage: '2.5.29.37', subjectAltName: '2.5.29.17', issuerAltName: '2.5.29.18', subjectKeyIdentifier: '2.5.29.14', authorityKeyIdentifier: '2.5.29.35' });
    });
});
