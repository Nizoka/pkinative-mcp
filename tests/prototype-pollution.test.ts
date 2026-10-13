/**
 * Prototype-pollution resistance: an input carrying `__proto__`,
 * `constructor` or `prototype` keys — at the top level, inside a PKI input,
 * inside the loose `spec` objects the hand-written parsers validate
 * (create_certificate, create_csr, encode_x509_structure, encode_asn1), a
 * name, the limits block or a projection — never reaches `Object.prototype`
 * and is refused or ignored with a documented code. The inputs are built
 * with JSON.parse so `__proto__` is an OWN property, exactly as a JSON-RPC
 * frame delivers it.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { prepareSandbox, removeSandbox } from '../scripts/helpers/io.js';
import { PKI_ERROR_CODES } from '../src/pki-errors.js';
import { callToolDirect, ensureEngineReady, toolNames } from '../src/server.js';
import { WRAPPER_CODE_NAMES } from '../src/wrapper-codes.js';
import { errorCodeOf } from './_pki-assert.js';
import { AT, fixtureInput } from './_pki-fixtures.js';

const DOCUMENTED = new Set<string>([...WRAPPER_CODE_NAMES, ...PKI_ERROR_CODES]);
const POISON = '{"__proto__":{"polluted":"yes"},"constructor":{"prototype":{"polluted":"yes"}}}';
const poison = (): Record<string, unknown> => JSON.parse(POISON) as Record<string, unknown>;
/** Wrap a JSON value so that `__proto__` appears as an own key at the given place. */
function withPoison(value: Record<string, unknown>): Record<string, unknown> {
    return JSON.parse(`${JSON.stringify(value).slice(0, -1)},${POISON.slice(1)}`) as Record<string, unknown>;
}

const LEAF = fixtureInput('leaf.crt.pem');
const ROOT = fixtureInput('root.crt.pem');
const INTER = fixtureInput('inter.crt.pem');
const ED = { key: fixtureInput('ed25519.key.pem') };

const PROTO_SNAPSHOT = Object.getOwnPropertyNames(Object.prototype).sort();
const ARRAY_SNAPSHOT = Object.getOwnPropertyNames(Array.prototype).sort();

function assertUnpolluted(label: string): void {
    expect(({} as Record<string, unknown>)['polluted'], label).toBeUndefined();
    expect(([] as unknown as Record<string, unknown>)['polluted'], label).toBeUndefined();
    expect(Object.getOwnPropertyNames(Object.prototype).sort(), label).toEqual(PROTO_SNAPSHOT);
    expect(Object.getOwnPropertyNames(Array.prototype).sort(), label).toEqual(ARRAY_SNAPSHOT);
}

async function call(tool: string, args: Record<string, unknown>, label: string): Promise<string | null> {
    const result = await callToolDirect(tool, args);
    assertUnpolluted(`${label}: after ${tool}`);
    const code = errorCodeOf(result);
    if (result.isError === true) {
        expect(code, label).not.toBeNull();
        expect(DOCUMENTED.has(code!), `${label}: ${code}`).toBe(true);
    }
    return code;
}

let sandbox: string | null = null;

beforeAll(async () => {
    await ensureEngineReady();
    sandbox = prepareSandbox('pkinative-mcp-pollution-');
});

afterAll(() => {
    removeSandbox(sandbox);
    sandbox = null;
});

describe('prototype pollution', () => {
    it('a poisoned top-level object is VALIDATION_ERROR for every tool (strict objects refuse unknown keys)', async () => {
        for (const tool of toolNames()) {
            const code = await call(tool, poison(), tool);
            expect(code, tool).toBe('VALIDATION_ERROR');
        }
    });

    it('a poisoned PKI input / bundle item is refused without touching Object.prototype', async () => {
        expect(await call('inspect_certificate', { certificate: withPoison(LEAF) }, 'certificate')).toBe('VALIDATION_ERROR');
        expect(await call('verify_certificate_chain', { leaf: LEAF, candidates: [withPoison(INTER)], trustAnchors: [ROOT], at: AT }, 'candidates[0]')).toBe('VALIDATION_ERROR');
        expect(await call('verify_certificate_chain', { leaf: LEAF, trustAnchors: [ROOT], at: AT, policy: poison() }, 'policy')).toBe('VALIDATION_ERROR');
        expect(await call('verify_certificate_chain', { leaf: LEAF, trustAnchors: [ROOT], at: AT, serverName: poison() }, 'serverName')).toBe('VALIDATION_ERROR');
    });

    it('a poisoned limits block, signer or projection is refused', async () => {
        expect(await call('inspect_certificate', { certificate: LEAF, limits: poison() }, 'limits')).toBe('VALIDATION_ERROR');
        expect(await call('create_certificate', { spec: { subject: { CN: 'x' }, notBefore: AT }, signer: withPoison(ED) }, 'signer')).toBe('VALIDATION_ERROR');
        expect(await call('inspect_certificate', { certificate: LEAF, fields: ['__proto__', 'constructor.prototype'] }, 'fields')).toBeNull();
        expect(await call('inspect_certificate', { certificate: LEAF, verbosity: '__proto__' }, 'verbosity')).toBe('VALIDATION_ERROR');
    });

    it('the loose spec objects: a poisoned certificate / CSR / X.509 / ASN.1 spec never pollutes, and is refused or ignored by the parser', async () => {
        const certSpec = withPoison({ subject: { CN: 'x' }, notBefore: AT });
        const c1 = await call('create_certificate', { spec: certSpec, signer: ED }, 'certificate spec');
        expect(c1 === null || c1 === 'VALIDATION_ERROR').toBe(true);
        const c2 = await call('create_certificate', { spec: { subject: withPoison({ CN: 'x' }), notBefore: AT }, signer: ED }, 'subject');
        expect(c2 === null || c2 === 'VALIDATION_ERROR').toBe(true);
        const c3 = await call('create_certificate', { spec: { subject: { CN: 'x' }, notBefore: AT, extensions: withPoison({ basicConstraints: { ca: false } }) }, signer: ED }, 'extensions');
        expect(c3 === null || c3 === 'VALIDATION_ERROR').toBe(true);
        const c4 = await call('create_csr', { spec: withPoison({ subject: { CN: 'x' } }), signer: ED }, 'csr spec');
        expect(c4 === null || c4 === 'VALIDATION_ERROR').toBe(true);
        const c5 = await call('encode_x509_structure', { structure: 'name', spec: withPoison({ CN: 'x' }) }, 'x509 name spec');
        expect(c5 === null || c5 === 'VALIDATION_ERROR').toBe(true);
        const c6 = await call('encode_asn1', { spec: withPoison({ type: 'sequence', children: [withPoison({ type: 'null' })] }) }, 'asn1 spec');
        expect(c6 === null || c6 === 'VALIDATION_ERROR').toBe(true);
        const c7 = await call('encode_asn1', { spec: { type: '__proto__' } }, 'asn1 type');
        expect(c7).toBe('VALIDATION_ERROR');
    });

    it('a poisoned name attribute array and a poisoned attribute type are refused', async () => {
        const spec = { subject: [[withPoison({ type: 'CN', value: 'x' })]], notBefore: AT };
        const c = await call('create_certificate', { spec, signer: ED }, 'rdn attribute');
        expect(c).toBe('VALIDATION_ERROR');
        const d = await call('create_certificate', { spec: { subject: { __proto__: 'x' }, notBefore: AT }, signer: ED }, 'attribute type');
        expect(d).toBe('VALIDATION_ERROR');
    });

    it('explain_code and resolve_oid treat prototype names as ordinary unknown strings', async () => {
        const e = await call('explain_code', { code: '__proto__' }, 'explain');
        expect(e === null || e === 'VALIDATION_ERROR' || e === 'NOT_FOUND').toBe(true);
        const o = await call('resolve_oid', { mode: 'name', oids: ['constructor', '__proto__'] }, 'oid');
        expect(o === null || o === 'VALIDATION_ERROR' || o === 'PKI_OID_INVALID').toBe(true);
    });
});
