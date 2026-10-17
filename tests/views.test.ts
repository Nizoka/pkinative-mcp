/**
 * Tests for `src/views.ts` — the wire views of the engine's parsed objects:
 * raw DER echoes dropped unless asked for, names and instants rendered, and
 * the shared JSON Schema fragments.
 */
import { describe, expect, it } from 'vitest';
import { parseCertificate, parseCertificationRequest, type DistinguishedName, type PkiReason } from 'pkinative';

import {
    ALGORITHM_VIEW_SCHEMA,
    algorithmView,
    CERTIFICATE_REF_SCHEMA,
    CERTIFICATE_VIEW_PROPERTIES,
    certificateRef,
    certificateView,
    csrView,
    dn,
    EXTENSION_VIEW_SCHEMA,
    extensionView,
    NAME_VIEW_SCHEMA,
    nameView,
    reasonsView,
    SPKI_VIEW_SCHEMA,
    spkiView,
    stripRaw,
    TIME_VIEW_SCHEMA,
    timeView,
} from '../src/views.js';
import { fixtureBytes } from './_pki-fixtures.js';

const SILENT = { onDiagnostic: () => undefined };
const leaf = parseCertificate(fixtureBytes('leaf.crt.der'), SILENT);
const root = parseCertificate(fixtureBytes('root.crt.der'), SILENT);
const rsa = parseCertificate(fixtureBytes('rsa.crt.der'), SILENT);
const ed25519 = parseCertificate(fixtureBytes('ed25519.crt.der'), SILENT);
const csr = parseCertificationRequest(fixtureBytes('leaf.csr.der'), SILENT);
const RAW_KEYS = ['der', 'tbsDer', 'valueDer', 'raw'];

/** Every key named anywhere in a value (deep). */
function keysOf(value: unknown, out = new Set<string>()): Set<string> {
    if (Array.isArray(value)) for (const v of value) keysOf(v, out);
    else if (value !== null && typeof value === 'object') {
        for (const [k, v] of Object.entries(value)) {
            out.add(k);
            keysOf(v, out);
        }
    }
    return out;
}

describe('stripRaw', () => {
    it('removes der / tbsDer / valueDer / raw at every level, keeps what `keep` names, and goes through toWire', () => {
        const value = { der: new Uint8Array([1]), serial: 7n, nested: { tbsDer: new Uint8Array([2]), list: [{ valueDer: new Uint8Array([3]), raw: 'x', ok: 'y' }] } };
        expect(stripRaw(value)).toEqual({ serial: '7', nested: { list: [{ ok: 'y' }] } });
        expect(stripRaw(value, new Set(['valueDer']))).toEqual({ serial: '7', nested: { list: [{ valueDer: '03', ok: 'y' }] } });
        expect(stripRaw([{ der: 'x' }, 1n, null])).toEqual([{}, '1', null]);
        expect(stripRaw('s')).toBe('s');
        expect(stripRaw(null)).toBeNull();
    });
});

describe('certificateView', () => {
    it('leaf: every member rendered, no raw DER key anywhere, selfIssued false', () => {
        const view = certificateView(leaf);
        expect(view.version).toBe(3);
        expect(view.serialNumber).toEqual({ hex: '1001', decimal: '4097' });
        expect(view.signatureAlgorithm).toEqual({ oid: '1.2.840.10045.4.3.2', name: 'ecdsa-with-SHA256', hasParameters: false });
        expect(view.subject.string).toBe('CN=example.test,O=pkinative-cli test,C=FR');
        expect(view.issuer.string).toContain('CN=Test Intermediate CA');
        expect(view.validity.notBefore).toEqual({ type: expect.any(String), epochMilliseconds: Date.UTC(2026, 0, 1), iso: '2026-01-01T00:00:00.000Z', text: expect.any(String) });
        expect(view.validity.notAfter.iso).toBe('2046-01-01T00:00:00.000Z');
        expect(view.subjectPublicKeyInfo).toMatchObject({ kind: 'ec', curve: 'P-256', publicKeyBits: 520 });
        expect(view.extensions.map((e) => e['kind'])).toEqual(['basicConstraints', 'keyUsage', 'extendedKeyUsage', 'subjectAltName', 'subjectKeyIdentifier', 'authorityKeyIdentifier', 'crlDistributionPoints', 'authorityInfoAccess']);
        expect(view.selfIssued).toBe(false);
        expect(view.sizeBytes).toBe(701);
        const keys = keysOf(view);
        for (const raw of RAW_KEYS) expect(keys.has(raw), raw).toBe(false);
        expect(() => JSON.stringify(view)).not.toThrow();
        expect(Object.keys(view)).toEqual(Object.keys(CERTIFICATE_VIEW_PROPERTIES));
    });

    it('includeRaw keeps valueDer (as hex) on every extension and nothing else', () => {
        const view = certificateView(leaf, true);
        expect(view.extensions.every((e) => typeof e['valueDer'] === 'string' && /^[0-9a-f]+$/.test(e['valueDer'] as string))).toBe(true);
        const keys = keysOf(view);
        expect(keys.has('der')).toBe(false);
        expect(keys.has('tbsDer')).toBe(false);
        expect(keys.has('raw')).toBe(false);
    });

    it('a self-signed root is selfIssued', () => {
        const view = certificateView(root);
        expect(view.selfIssued).toBe(true);
        expect(view.subject).toEqual(view.issuer);
        expect(view.serialNumber).toEqual({ hex: '01', decimal: '1' });
    });
});

describe('certificateRef / csrView / nameView / dn', () => {
    it('certificateRef is the compact identity', () => {
        expect(certificateRef(leaf)).toEqual({ subject: 'CN=example.test,O=pkinative-cli test,C=FR', issuer: expect.stringContaining('CN=Test Intermediate CA'), serialNumber: '1001', notAfter: '2046-01-01T00:00:00.000Z' });
        expect(Object.keys(certificateRef(root))).toEqual(CERTIFICATE_REF_SCHEMA.required);
    });

    it('csrView renders the request without raw DER; includeRaw keeps valueDer', () => {
        const view = csrView(csr);
        expect(view).toMatchObject({ version: 0, challengePassword: false, sizeBytes: fixtureBytes('leaf.csr.der').length });
        expect((view['subject'] as { string: string }).string).toContain('CN=csr.example.test');
        expect(view['subjectPublicKeyInfo']).toMatchObject({ kind: 'ec', curve: 'P-256' });
        expect(view['attributes']).toEqual([{ oid: '1.2.840.113549.1.9.14', name: 'extensionRequest', valueCount: 1 }]);
        expect((view['extensions'] as Array<Record<string, unknown>>).map((e) => e['kind'])).toEqual(['subjectAltName']);
        expect(view['signatureAlgorithm']).toEqual({ oid: '1.2.840.10045.4.3.2', name: 'ecdsa-with-SHA256', hasParameters: false });
        for (const raw of RAW_KEYS) expect(keysOf(view).has(raw), raw).toBe(false);
        expect((csrView(csr, true)['extensions'] as Array<Record<string, unknown>>)[0]?.['valueDer']).toMatch(/^[0-9a-f]+$/);
    });

    it('nameView lists every attribute with its registry name and string type; dn renders RFC 4514 and (empty)', () => {
        const view = nameView(leaf.subject);
        expect(view.string).toBe('CN=example.test,O=pkinative-cli test,C=FR');
        expect(view.rdns).toEqual([
            [{ type: '2.5.4.6', name: 'countryName', value: 'FR', stringType: 'printable' }],
            [{ type: '2.5.4.10', name: 'organizationName', value: 'pkinative-cli test', stringType: expect.any(String) }],
            [{ type: '2.5.4.3', name: 'commonName', value: 'example.test', stringType: expect.any(String) }],
        ]);
        expect(Object.keys(view)).toEqual(NAME_VIEW_SCHEMA.required);
        expect(dn(leaf.subject)).toBe(view.string);
        const empty: DistinguishedName = { rdns: [], der: new Uint8Array([0x30, 0x00]) };
        expect(dn(empty)).toBe('(empty)');
        expect(nameView(empty)).toEqual({ string: '(empty)', rdns: [] });
    });
});

describe('spkiView', () => {
    it('ec / rsa / ed25519 members', () => {
        expect(spkiView(leaf.subjectPublicKeyInfo)).toEqual({ kind: 'ec', algorithm: { oid: '1.2.840.10045.2.1', name: 'ecPublicKey', hasParameters: true }, publicKeyBits: 520, curve: 'P-256', namedCurve: '1.2.840.10045.3.1.7', pointFormat: 'uncompressed' });
        expect(spkiView(rsa.subjectPublicKeyInfo)).toEqual({ kind: 'rsa', algorithm: { oid: '1.2.840.113549.1.1.1', name: 'rsaEncryption', hasParameters: true }, publicKeyBits: expect.any(Number), modulusBits: 2048, publicExponent: '65537' });
        expect(spkiView(ed25519.subjectPublicKeyInfo)).toEqual({ kind: 'ed25519', algorithm: { oid: '1.3.101.112', name: 'Ed25519', hasParameters: false }, publicKeyBits: 256, keyBytes: 32 });
        for (const spki of [leaf, rsa, ed25519].map((c) => spkiView(c.subjectPublicKeyInfo))) {
            for (const key of SPKI_VIEW_SCHEMA.required) expect(spki, key).toHaveProperty(key);
            for (const key of Object.keys(spki)) expect(Object.keys(SPKI_VIEW_SCHEMA.properties), key).toContain(key);
        }
    });
});

describe('extensionView / timeView / algorithmView / reasonsView', () => {
    it('extensionView: kind, oid, name, critical and the decoded members; valueDer only with includeRaw', () => {
        const san = leaf.extensions.find((e) => e.kind === 'subjectAltName');
        expect(san).toBeDefined();
        const view = extensionView(san as NonNullable<typeof san>);
        expect(view).toMatchObject({ kind: 'subjectAltName', oid: '2.5.29.17', name: 'subjectAltName', critical: false });
        expect((view['names'] as Array<Record<string, unknown>>).map((n) => n['value'] ?? n['address'])).toEqual(['example.test', '*.wild.example.test', '192.0.2.1', 'leaf@example.test']);
        expect(view).not.toHaveProperty('valueDer');
        for (const raw of RAW_KEYS) expect(keysOf(view).has(raw), raw).toBe(false);
        const withRaw = extensionView(san as NonNullable<typeof san>, true);
        expect(withRaw['valueDer']).toBe(Buffer.from((san as NonNullable<typeof san>).valueDer).toString('hex'));
        expect(Object.keys(view).slice(0, 4)).toEqual(EXTENSION_VIEW_SCHEMA.required);
        const bc = extensionView(leaf.extensions[0] as NonNullable<typeof san>);
        expect(bc).toMatchObject({ kind: 'basicConstraints', name: 'basicConstraints', cA: false });
    });

    it('timeView and algorithmView', () => {
        expect(timeView(leaf.validity.notBefore)).toEqual({ type: leaf.validity.notBefore.type, epochMilliseconds: Date.UTC(2026, 0, 1), iso: '2026-01-01T00:00:00.000Z', text: leaf.validity.notBefore.text });
        expect(Object.keys(timeView(leaf.validity.notAfter))).toEqual(TIME_VIEW_SCHEMA.required);
        expect(algorithmView(leaf.signatureAlgorithm)).toEqual({ oid: '1.2.840.10045.4.3.2', name: 'ecdsa-with-SHA256', hasParameters: false });
        expect(algorithmView({ oid: '1.2.3.4.5.6.7', parameters: undefined, der: new Uint8Array(0) })).toEqual({ oid: '1.2.3.4.5.6.7', name: null, hasParameters: false });
        expect(Object.keys(algorithmView(rsa.signatureAlgorithm))).toEqual(ALGORITHM_VIEW_SCHEMA.required);
    });

    it('reasonsView keeps the engine members verbatim and the optional ones only when present', () => {
        const reasons: PkiReason[] = [
            { code: 'PKI_REASON_EXPIRED', message: 'expired', standard: 'RFC 5280 §6.1.3', path: 'certificates[0]' },
            { code: 'PKI_REASON_INPUT_MALFORMED', message: 'bad', standard: 'RFC 5280', path: 'crls[0]', errorCode: 'PKI_ASN1_TRUNCATED' },
            { code: 'PKI_REASON_LIMIT_EXCEEDED', message: 'limit', standard: 'pkinative', path: '', limit: 'maxPathsExplored' },
        ];
        expect(reasonsView(reasons)).toEqual([
            { code: 'PKI_REASON_EXPIRED', message: 'expired', standard: 'RFC 5280 §6.1.3', path: 'certificates[0]' },
            { code: 'PKI_REASON_INPUT_MALFORMED', message: 'bad', standard: 'RFC 5280', path: 'crls[0]', errorCode: 'PKI_ASN1_TRUNCATED' },
            { code: 'PKI_REASON_LIMIT_EXCEEDED', message: 'limit', standard: 'pkinative', path: '', limit: 'maxPathsExplored' },
        ]);
        expect(reasonsView([])).toEqual([]);
        expect(reasonsView([{ ...reasons[0] as PkiReason, errorCode: undefined, limit: undefined }])[0]).not.toHaveProperty('errorCode');
    });
});

describe('the JSON Schema fragments', () => {
    it('are closed where the view is closed and name the required members', () => {
        expect(TIME_VIEW_SCHEMA).toMatchObject({ type: 'object', additionalProperties: false, required: ['type', 'epochMilliseconds', 'iso', 'text'] });
        expect(ALGORITHM_VIEW_SCHEMA).toMatchObject({ type: 'object', additionalProperties: false, required: ['oid', 'name', 'hasParameters'] });
        expect(NAME_VIEW_SCHEMA).toMatchObject({ type: 'object', additionalProperties: false, required: ['string', 'rdns'] });
        expect(SPKI_VIEW_SCHEMA).toMatchObject({ type: 'object', additionalProperties: true, required: ['kind', 'algorithm', 'publicKeyBits'] });
        expect(EXTENSION_VIEW_SCHEMA).toMatchObject({ type: 'object', additionalProperties: true, required: ['kind', 'oid', 'name', 'critical'] });
        expect(CERTIFICATE_REF_SCHEMA).toMatchObject({ type: 'object', additionalProperties: false, required: ['subject', 'issuer', 'serialNumber', 'notAfter'] });
        expect(Object.keys(CERTIFICATE_VIEW_PROPERTIES)).toEqual(['version', 'serialNumber', 'signatureAlgorithm', 'issuer', 'subject', 'validity', 'subjectPublicKeyInfo', 'extensions', 'selfIssued', 'sizeBytes']);
        expect(CERTIFICATE_VIEW_PROPERTIES.version.enum).toEqual([1, 2, 3]);
        expect(CERTIFICATE_VIEW_PROPERTIES.issuer).toBe(NAME_VIEW_SCHEMA);
        expect(CERTIFICATE_VIEW_PROPERTIES.subjectPublicKeyInfo).toBe(SPKI_VIEW_SCHEMA);
        expect(CERTIFICATE_VIEW_PROPERTIES.extensions.items).toBe(EXTENSION_VIEW_SCHEMA);
    });
});
