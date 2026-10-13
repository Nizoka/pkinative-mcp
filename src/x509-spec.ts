/**
 * The JSON spec of `create_certificate`, `create_csr` and
 * `encode_x509_structure`, turned into pkinative's descriptions through its
 * structural encoders (vendored from pkinative-cli `src/utils/x509-spec.ts`).
 *
 *   {
 *     "serialNumber": "0x1001" | "4097" | 4097 | "random",     default random (127 bits, node:crypto)
 *     "subject": { "C": "FR", "O": "Acme", "CN": "example.test" },   or explicit RDNs
 *     "issuer":  { ... },              default: the issuer certificate's subject DER, else the subject
 *     "notBefore": "2027-01-01T00:00:00Z",  default PKINATIVE_MCP_AT, else now (whole seconds)
 *     "notAfter":  "...",  or  "validityDays": 365
 *     "extensions": {
 *       "basicConstraints": { "ca": true, "pathLen": 0, "critical": true },
 *       "keyUsage": ["digitalSignature"]  |  { "usages": [...], "critical": true },
 *       "extendedKeyUsage": ["serverAuth", "1.3.6.1.5.5.7.3.2"]  |  { "purposes": [...], "critical": false },
 *       "subjectAltName" | "issuerAltName": { "dns": [], "email": [], "uri": [], "ip": [],
 *                                             "registeredId": [], "directoryName": [ <name> ], "critical": false },
 *       "subjectKeyIdentifier": true | false | "hex",
 *       "authorityKeyIdentifier": true | false | "hex",
 *       "raw": [ { "oid": "1.2.3", "critical": false, "value": "hex of the extnValue content" } ]
 *     }
 *   }
 */
import {
    KEY_USAGE_BITS,
    computeKeyIdentifier,
    encodeAuthorityKeyIdentifier,
    encodeBasicConstraints,
    encodeDistinguishedName,
    encodeExtendedKeyUsage,
    encodeKeyUsage,
    encodeSubjectAltName,
    encodeSubjectKeyIdentifier,
    type ExtensionDescription,
    type GeneralNameDescription,
    type NameDescription,
} from 'pkinative';

import { NAME_SPEC_SCHEMA, parseIp, parseNameSpec, specError } from './names.js';
import { guard } from './pki-errors.js';
import { randomSerialNumber } from './random.js';
import { resolveInstant } from './time.js';
import { purposeOid } from './trust.js';
import { fromHex } from './wire.js';

export type Spec = Readonly<Record<string, unknown>>;

export const EXTENSION_OIDS = {
    basicConstraints: '2.5.29.19',
    keyUsage: '2.5.29.15',
    extendedKeyUsage: '2.5.29.37',
    subjectAltName: '2.5.29.17',
    issuerAltName: '2.5.29.18',
    subjectKeyIdentifier: '2.5.29.14',
    authorityKeyIdentifier: '2.5.29.35',
} as const;

const KNOWN_EXTENSION_KEYS = [...Object.keys(EXTENSION_OIDS), 'raw'];

export function isSpec(value: unknown): value is Spec {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Refuse a member the structure does not define: a misspelt key would otherwise be dropped silently. */
export function onlyMembers(spec: Spec, allowed: readonly string[], path: string): Spec {
    for (const key of Object.keys(spec)) {
        if (!allowed.includes(key)) throw specError(path === '' ? key : `${path}.${key}`, `unknown member (${allowed.join(', ')})`);
    }
    return spec;
}

function stringArray(value: unknown, path: string): string[] {
    if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) throw specError(path, 'expected an array of strings');
    return value;
}

export function critical(spec: Spec, path: string, fallback: boolean): boolean {
    const c = spec['critical'];
    if (c === undefined) return fallback;
    if (typeof c !== 'boolean') throw specError(path === '' ? 'critical' : `${path}.critical`, 'expected a boolean');
    return c;
}

/** Array shorthand or `{ <key>: [...], critical }`. */
function listForm(value: unknown, path: string, key: string, criticalDefault: boolean): { items: string[]; critical: boolean } {
    if (Array.isArray(value)) return { items: stringArray(value, path), critical: criticalDefault };
    if (!isSpec(value)) throw specError(path, `expected an array, or { "${key}": [...], "critical": ... }`);
    onlyMembers(value, [key, 'critical'], path);
    return { items: stringArray(value[key], `${path}.${key}`), critical: critical(value, path, criticalDefault) };
}

export function keyUsages(names: readonly string[], path: string): string[] {
    for (const n of names) {
        if (!KEY_USAGE_BITS.has(n)) throw specError(path, `unknown key usage "${n}" (${[...KEY_USAGE_BITS.keys()].join(', ')})`);
    }
    return [...names];
}

const GENERAL_NAME_KINDS = ['dns', 'email', 'uri', 'ip', 'registeredId', 'directoryName'];

/** GeneralNames; `critical` is a member only where the names are an extension. */
export function generalNames(spec: unknown, path: string, extension = false): GeneralNameDescription[] {
    if (!isSpec(spec)) throw specError(path, 'expected { "dns": [...], "ip": [...], ... }');
    onlyMembers(spec, extension ? [...GENERAL_NAME_KINDS, 'critical'] : GENERAL_NAME_KINDS, path === '$' ? '' : path);
    const out: GeneralNameDescription[] = [];
    const list = (key: string): string[] => (spec[key] === undefined ? [] : stringArray(spec[key], `${path}.${key}`));
    for (const v of list('dns')) out.push({ kind: 'dNSName', value: v });
    for (const v of list('email')) out.push({ kind: 'rfc822Name', value: v });
    for (const v of list('uri')) out.push({ kind: 'uniformResourceIdentifier', value: v });
    for (const v of list('ip')) out.push({ kind: 'iPAddress', value: parseIp(v, `${path}.ip`) });
    for (const v of list('registeredId')) out.push({ kind: 'registeredID', value: v });
    const dirs = spec['directoryName'];
    if (dirs !== undefined) {
        if (!Array.isArray(dirs)) throw specError(`${path}.directoryName`, 'expected an array of names');
        dirs.forEach((d: unknown, i) => {
            const name = parseNameSpec(d, `spec ${path}.directoryName[${i}]`);
            out.push({ kind: 'directoryNameDer', value: guard(`spec ${path}.directoryName[${i}]`, () => encodeDistinguishedName(name)) });
        });
    }
    return out;
}

export function hexValue(value: unknown, path: string): Uint8Array {
    const bytes = typeof value === 'string' ? fromHex(value) : undefined;
    if (bytes === undefined) throw specError(path, 'expected a hexadecimal string');
    return bytes;
}

export interface KeyIdentifiers {
    /** The subject's public key bits (for an automatic subjectKeyIdentifier); none when no key is at hand. */
    readonly subjectKeyBits: Uint8Array | undefined;
    /** The issuer's key identifier (for an automatic authorityKeyIdentifier). */
    readonly issuerKeyId: Uint8Array | undefined;
    /** Whether SKI / AKI are added when the spec does not mention them. */
    readonly defaults: { readonly ski: boolean; readonly aki: boolean };
}

function keyIdentifier(value: unknown, path: string, auto: () => Uint8Array | undefined): Uint8Array | undefined {
    if (value === false) return undefined;
    if (value === true) {
        const id = auto();
        if (id === undefined) throw specError(path, 'cannot be computed here: give it as hex');
        return id;
    }
    return hexValue(value, path);
}

/** Build the extension descriptions of a spec, in a stable order. */
export function buildExtensions(spec: unknown, ids: KeyIdentifiers): ExtensionDescription[] {
    if (spec !== undefined && !isSpec(spec)) throw specError('extensions', 'expected an object');
    const ext: Spec = spec ?? {};
    for (const key of Object.keys(ext)) {
        if (!KNOWN_EXTENSION_KEYS.includes(key)) throw specError(`extensions.${key}`, `unknown extension (${KNOWN_EXTENSION_KEYS.join(', ')})`);
    }
    const out: ExtensionDescription[] = [];
    const push = (oid: string, isCritical: boolean, value: Uint8Array): void => {
        out.push({ oid, critical: isCritical, value });
    };
    const bc = ext['basicConstraints'];
    if (bc !== undefined) {
        if (!isSpec(bc) || typeof bc['ca'] !== 'boolean') throw specError('extensions.basicConstraints', 'expected { "ca": boolean, "pathLen"?: n }');
        onlyMembers(bc, ['ca', 'pathLen', 'critical'], 'extensions.basicConstraints');
        const pathLen = bc['pathLen'];
        if (pathLen !== undefined && typeof pathLen !== 'number') throw specError('extensions.basicConstraints.pathLen', 'expected a number');
        push(EXTENSION_OIDS.basicConstraints, critical(bc, 'extensions.basicConstraints', true),
            guard('spec extensions.basicConstraints', () => encodeBasicConstraints({ cA: bc['ca'] as boolean, ...(pathLen !== undefined ? { pathLenConstraint: pathLen } : {}) })));
    }
    if (ext['keyUsage'] !== undefined) {
        const ku = listForm(ext['keyUsage'], 'extensions.keyUsage', 'usages', true);
        push(EXTENSION_OIDS.keyUsage, ku.critical, guard('spec extensions.keyUsage', () => encodeKeyUsage(keyUsages(ku.items, 'extensions.keyUsage'))));
    }
    if (ext['extendedKeyUsage'] !== undefined) {
        const eku = listForm(ext['extendedKeyUsage'], 'extensions.extendedKeyUsage', 'purposes', false);
        const oids = eku.items.map((p) => purposeOid(p, 'spec extensions.extendedKeyUsage'));
        push(EXTENSION_OIDS.extendedKeyUsage, eku.critical, guard('spec extensions.extendedKeyUsage', () => encodeExtendedKeyUsage(oids)));
    }
    for (const key of ['subjectAltName', 'issuerAltName'] as const) {
        const san = ext[key];
        if (san === undefined) continue;
        const names = generalNames(san, `extensions.${key}`, true);
        push(EXTENSION_OIDS[key], critical(san as Spec, `extensions.${key}`, false), guard(`spec extensions.${key}`, () => encodeSubjectAltName(names)));
    }
    const ski = keyIdentifier(ext['subjectKeyIdentifier'] ?? ids.defaults.ski, 'extensions.subjectKeyIdentifier', () => (ids.subjectKeyBits === undefined ? undefined : computeKeyIdentifier(ids.subjectKeyBits)));
    if (ski !== undefined) push(EXTENSION_OIDS.subjectKeyIdentifier, false, encodeSubjectKeyIdentifier(ski));
    const aki = keyIdentifier(ext['authorityKeyIdentifier'] ?? ids.defaults.aki, 'extensions.authorityKeyIdentifier', () => ids.issuerKeyId);
    if (aki !== undefined) push(EXTENSION_OIDS.authorityKeyIdentifier, false, encodeAuthorityKeyIdentifier(aki));
    const raw = ext['raw'];
    if (raw !== undefined) {
        if (!Array.isArray(raw)) throw specError('extensions.raw', 'expected an array');
        raw.forEach((r: unknown, i) => {
            const path = `extensions.raw[${i}]`;
            if (!isSpec(r) || typeof r['oid'] !== 'string') throw specError(path, 'expected { "oid", "critical"?, "value": hex }');
            onlyMembers(r, ['oid', 'critical', 'value'], path);
            push(r['oid'], critical(r, path, false), hexValue(r['value'], `${path}.value`));
        });
    }
    return out;
}

/** A serial number: "random" (default), a decimal or 0x-hex string, or a safe integer. Returns whether it was random. */
export function serialNumber(value: unknown): { serial: bigint; random: boolean } {
    if (value === undefined || value === 'random') return { serial: randomSerialNumber(), random: true };
    const serial = typeof value === 'number' && Number.isSafeInteger(value) ? BigInt(value)
        : typeof value === 'string' && /^(\d+|0x[0-9a-f]+)$/i.test(value) ? BigInt(value) : undefined;
    if (serial === undefined || serial < 1n) throw specError('serialNumber', 'expected "random", or a positive decimal or 0x-hex string or integer');
    return { serial, random: false };
}

/** notBefore / notAfter from the spec, in whole seconds; reports where notBefore came from. */
export function validity(spec: Spec): { notBefore: number; notAfter: number; notBeforeSource: 'input' | 'pinned' | 'clock' } {
    const instant = (key: string): number | undefined => {
        const v = spec[key];
        if (v === undefined) return undefined;
        if (typeof v === 'number' && Number.isSafeInteger(v)) return v;
        if (typeof v === 'string') {
            try {
                return resolveInstant(v, key).ms;
            } catch {
                throw specError(key, `expected an instant (ISO 8601 or epoch milliseconds), got "${v}"`);
            }
        }
        throw specError(key, 'expected an instant (ISO 8601 or epoch milliseconds)');
    };
    const explicit = instant('notBefore');
    const resolved = explicit !== undefined ? { ms: explicit, source: 'input' as const } : resolveInstant(undefined, 'notBefore');
    const notBefore = Math.floor(resolved.ms / 1000) * 1000;
    const days = spec['validityDays'] ?? 365;
    if (typeof days !== 'number' || !Number.isSafeInteger(days) || days < 1) throw specError('validityDays', 'expected a positive integer');
    if (spec['notAfter'] !== undefined && spec['validityDays'] !== undefined) throw specError('notAfter', 'give notAfter or validityDays, not both');
    const notAfter = instant('notAfter') ?? notBefore + days * 86_400_000;
    if (notAfter <= notBefore) throw specError('notAfter', 'must be after notBefore');
    return { notBefore, notAfter, notBeforeSource: resolved.source };
}

/** A name from a spec member, required or optional. */
export function nameOf(spec: Spec, key: string): NameDescription | undefined {
    return spec[key] === undefined ? undefined : parseNameSpec(spec[key], `spec ${key}`);
}

/** JSON Schema of the `extensions` member (closed object; every extension optional). */
export const EXTENSIONS_SPEC_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    description: 'The extensions to write. subjectKeyIdentifier / authorityKeyIdentifier: true (computed), false (omitted) or a hex value; defaults depend on the tool.',
    properties: {
        basicConstraints: { type: 'object', additionalProperties: false, required: ['ca'], properties: { ca: { type: 'boolean' }, pathLen: { type: 'integer', minimum: 0 }, critical: { type: 'boolean', default: true } } },
        keyUsage: { anyOf: [{ type: 'array', items: { type: 'string' } }, { type: 'object', additionalProperties: false, required: ['usages'], properties: { usages: { type: 'array', items: { type: 'string' } }, critical: { type: 'boolean', default: true } } }], description: `Key usage names: ${[...KEY_USAGE_BITS.keys()].join(', ')}.` },
        extendedKeyUsage: { anyOf: [{ type: 'array', items: { type: 'string' } }, { type: 'object', additionalProperties: false, required: ['purposes'], properties: { purposes: { type: 'array', items: { type: 'string' } }, critical: { type: 'boolean', default: false } } }], description: 'serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, ocspSigning, any, or dotted OIDs.' },
        subjectAltName: { type: 'object', additionalProperties: false, properties: { dns: { type: 'array', items: { type: 'string' } }, email: { type: 'array', items: { type: 'string' } }, uri: { type: 'array', items: { type: 'string' } }, ip: { type: 'array', items: { type: 'string' } }, registeredId: { type: 'array', items: { type: 'string' } }, directoryName: { type: 'array', items: NAME_SPEC_SCHEMA }, critical: { type: 'boolean', default: false } } },
        issuerAltName: { type: 'object', additionalProperties: false, properties: { dns: { type: 'array', items: { type: 'string' } }, email: { type: 'array', items: { type: 'string' } }, uri: { type: 'array', items: { type: 'string' } }, ip: { type: 'array', items: { type: 'string' } }, registeredId: { type: 'array', items: { type: 'string' } }, directoryName: { type: 'array', items: NAME_SPEC_SCHEMA }, critical: { type: 'boolean', default: false } } },
        subjectKeyIdentifier: { anyOf: [{ type: 'boolean' }, { type: 'string' }] },
        authorityKeyIdentifier: { anyOf: [{ type: 'boolean' }, { type: 'string' }] },
        raw: { type: 'array', maxItems: 64, items: { type: 'object', additionalProperties: false, required: ['oid', 'value'], properties: { oid: { type: 'string', pattern: '^\\d+(\\.\\d+)+$' }, critical: { type: 'boolean', default: false }, value: { type: 'string', description: 'Hex of the extnValue content (the DER inside the OCTET STRING).' } } } },
    },
} as const;
