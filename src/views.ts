/**
 * Wire views of the engine's parsed objects, shared by every read and verdict
 * tool. The engine results are frozen values holding `bigint`, `Uint8Array`
 * and the raw DER of every sub-structure; a view is `toWire()` with the raw
 * DER echoes dropped (`der`, `tbsDer`, `valueDer`, `raw`) and the names and
 * instants rendered for an agent — the input is already in the caller's
 * hands, and a 4 KiB certificate must not come back as 40 KiB of hex.
 */
import {
    formatDistinguishedName,
    getOidName,
    type AlgorithmIdentifier,
    type Certificate,
    type CertificationRequest,
    type DistinguishedName,
    type Extension,
    type PkiReason,
    type PkiTime,
    type SubjectPublicKeyInfo,
} from 'pkinative';

import { formatInstant } from './time.js';
import { toHex, toWire, type Wire } from './wire.js';

const RAW_KEYS: ReadonlySet<string> = new Set(['der', 'tbsDer', 'valueDer', 'raw']);

/** `toWire` with the raw DER echoes removed at every level (unless `keep` names a key to retain). */
export function stripRaw(value: unknown, keep: ReadonlySet<string> = new Set()): Wire {
    const walk = (w: Wire): Wire => {
        if (Array.isArray(w)) return (w as readonly Wire[]).map(walk);
        if (w !== null && typeof w === 'object') {
            const out: Record<string, Wire> = {};
            for (const [k, v] of Object.entries(w as Record<string, Wire>)) {
                if (RAW_KEYS.has(k) && !keep.has(k)) continue;
                out[k] = walk(v);
            }
            return out;
        }
        return w;
    };
    return walk(toWire(value));
}

/** An instant as both epoch milliseconds (the engine's form) and ISO 8601. */
export function timeView(t: PkiTime): { readonly type: string; readonly epochMilliseconds: number; readonly iso: string; readonly text: string } {
    return { type: t.type, epochMilliseconds: t.epochMilliseconds, iso: formatInstant(t.epochMilliseconds), text: t.text };
}

export function algorithmView(a: AlgorithmIdentifier): { readonly oid: string; readonly name: string | null; readonly hasParameters: boolean } {
    return { oid: a.oid, name: getOidName(a.oid) ?? null, hasParameters: a.parameters !== undefined };
}

/** RFC 4514 rendering of a name, `(empty)` for an empty one. */
export function dn(name: DistinguishedName): string {
    const text = formatDistinguishedName(name);
    return text === '' ? '(empty)' : text;
}

export function nameView(name: DistinguishedName): { readonly string: string; readonly rdns: ReadonlyArray<ReadonlyArray<{ readonly type: string; readonly name: string | null; readonly value: string | null; readonly stringType: string | null }>> } {
    return {
        string: dn(name),
        rdns: name.rdns.map((rdn) => rdn.map((atv) => ({
            type: atv.type,
            name: getOidName(atv.type) ?? null,
            value: atv.value?.value ?? null,
            stringType: atv.value?.stringType ?? null,
        }))),
    };
}

export function spkiView(spki: SubjectPublicKeyInfo): Record<string, Wire> {
    const base: Record<string, Wire> = { kind: spki.kind, algorithm: algorithmView(spki.algorithm) as unknown as Wire, publicKeyBits: spki.publicKey.bytes.length * 8 - spki.publicKey.unusedBits };
    switch (spki.kind) {
        case 'rsa':
        case 'rsa-pss':
            return { ...base, modulusBits: spki.modulusBits, publicExponent: spki.publicExponent.toString(10) };
        case 'ec':
            return { ...base, curve: spki.curve ?? null, namedCurve: spki.namedCurve ?? null, pointFormat: spki.pointFormat };
        case 'unknown':
            return base;
        default:
            return { ...base, keyBytes: spki.key.length };
    }
}

/** An extension: kind, oid, critical and the decoded members (raw DER dropped unless `includeRaw`). */
export function extensionView(e: Extension, includeRaw = false): Record<string, Wire> {
    const stripped = stripRaw(e, includeRaw ? new Set(['valueDer']) : new Set()) as Record<string, Wire>;
    const out: Record<string, Wire> = { kind: e.kind, oid: e.oid, name: getOidName(e.oid) ?? null, critical: e.critical, ...stripped };
    if (includeRaw) out['valueDer'] = toHex(e.valueDer);
    return out;
}

export interface CertificateView {
    readonly version: number;
    readonly serialNumber: { readonly hex: string; readonly decimal: string };
    readonly signatureAlgorithm: ReturnType<typeof algorithmView>;
    readonly issuer: ReturnType<typeof nameView>;
    readonly subject: ReturnType<typeof nameView>;
    readonly validity: { readonly notBefore: ReturnType<typeof timeView>; readonly notAfter: ReturnType<typeof timeView> };
    readonly subjectPublicKeyInfo: Record<string, Wire>;
    readonly extensions: ReadonlyArray<Record<string, Wire>>;
    readonly selfIssued: boolean;
    readonly sizeBytes: number;
}

export function certificateView(cert: Certificate, includeRaw = false): CertificateView {
    return {
        version: cert.version,
        serialNumber: { hex: cert.serialNumber.hex, decimal: cert.serialNumber.value.toString(10) },
        signatureAlgorithm: algorithmView(cert.signatureAlgorithm),
        issuer: nameView(cert.issuer),
        subject: nameView(cert.subject),
        validity: { notBefore: timeView(cert.validity.notBefore), notAfter: timeView(cert.validity.notAfter) },
        subjectPublicKeyInfo: spkiView(cert.subjectPublicKeyInfo),
        extensions: cert.extensions.map((e) => extensionView(e, includeRaw)),
        selfIssued: toHex(cert.issuer.der) === toHex(cert.subject.der),
        sizeBytes: cert.der.length,
    };
}

/** The compact identity of a certificate (for path rows and summaries). */
export function certificateRef(cert: Certificate): { readonly subject: string; readonly issuer: string; readonly serialNumber: string; readonly notAfter: string } {
    return { subject: dn(cert.subject), issuer: dn(cert.issuer), serialNumber: cert.serialNumber.hex, notAfter: formatInstant(cert.validity.notAfter.epochMilliseconds) };
}

export function csrView(csr: CertificationRequest, includeRaw = false): Record<string, Wire> {
    return {
        version: csr.version,
        subject: nameView(csr.subject) as unknown as Wire,
        subjectPublicKeyInfo: spkiView(csr.subjectPublicKeyInfo),
        attributes: csr.attributes.map((a) => ({ oid: a.oid, name: getOidName(a.oid) ?? null, valueCount: a.values.length })),
        extensions: csr.extensions === undefined ? null : csr.extensions.map((e) => extensionView(e, includeRaw)),
        challengePassword: csr.challengePassword !== undefined,
        signatureAlgorithm: algorithmView(csr.signatureAlgorithm) as unknown as Wire,
        sizeBytes: csr.der.length,
    };
}

/** The wire form of the engine's reasons (verbatim members). */
export function reasonsView(reasons: readonly PkiReason[]): ReadonlyArray<Record<string, string>> {
    return reasons.map((r) => ({
        code: r.code,
        message: r.message,
        standard: r.standard,
        path: r.path,
        ...(r.errorCode !== undefined ? { errorCode: r.errorCode } : {}),
        ...(r.limit !== undefined ? { limit: r.limit } : {}),
    }));
}

/** JSON Schema fragments of the shared views (inlined, never $ref). */
export const TIME_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['type', 'epochMilliseconds', 'iso', 'text'],
    properties: { type: { type: 'string' }, epochMilliseconds: { type: 'integer' }, iso: { type: 'string' }, text: { type: 'string' } },
} as const;

export const ALGORITHM_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['oid', 'name', 'hasParameters'],
    properties: { oid: { type: 'string' }, name: { type: ['string', 'null'] }, hasParameters: { type: 'boolean' } },
} as const;

export const NAME_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['string', 'rdns'],
    properties: {
        string: { type: 'string', description: 'RFC 4514 rendering.' },
        rdns: { type: 'array', items: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { type: { type: 'string' }, name: { type: ['string', 'null'] }, value: { type: ['string', 'null'] }, stringType: { type: ['string', 'null'] } } } } },
    },
} as const;

export const SPKI_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: true,
    required: ['kind', 'algorithm', 'publicKeyBits'],
    properties: {
        kind: { type: 'string', description: 'rsa, rsa-pss, ec, ed25519, ed448, x25519, x448, ml-dsa-44/65/87 or unknown.' },
        algorithm: ALGORITHM_VIEW_SCHEMA,
        publicKeyBits: { type: 'integer' },
        modulusBits: { type: 'integer' },
        publicExponent: { type: 'string' },
        curve: { type: ['string', 'null'] },
        namedCurve: { type: ['string', 'null'] },
        pointFormat: { type: 'string' },
        keyBytes: { type: 'integer' },
    },
} as const;

export const EXTENSION_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: true,
    required: ['kind', 'oid', 'name', 'critical'],
    description: 'One extension: kind (one of the 19 decoded kinds, raw or unknown), oid, critical and the decoded members (bytes as lowercase hex; valueDer only with rawExtensions:true).',
    properties: { kind: { type: 'string' }, oid: { type: 'string' }, name: { type: ['string', 'null'] }, critical: { type: 'boolean' } },
} as const;

export const CERTIFICATE_VIEW_PROPERTIES = {
    version: { type: 'integer', enum: [1, 2, 3] },
    serialNumber: { type: 'object', additionalProperties: false, required: ['hex', 'decimal'], properties: { hex: { type: 'string' }, decimal: { type: 'string' } } },
    signatureAlgorithm: ALGORITHM_VIEW_SCHEMA,
    issuer: NAME_VIEW_SCHEMA,
    subject: NAME_VIEW_SCHEMA,
    validity: { type: 'object', additionalProperties: false, required: ['notBefore', 'notAfter'], properties: { notBefore: TIME_VIEW_SCHEMA, notAfter: TIME_VIEW_SCHEMA } },
    subjectPublicKeyInfo: SPKI_VIEW_SCHEMA,
    extensions: { type: 'array', items: EXTENSION_VIEW_SCHEMA },
    selfIssued: { type: 'boolean', description: 'issuer DER equals subject DER (self-issued; a self-SIGNATURE is a separate check).' },
    sizeBytes: { type: 'integer' },
} as const;

export const CERTIFICATE_REF_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['subject', 'issuer', 'serialNumber', 'notAfter'],
    properties: { subject: { type: 'string' }, issuer: { type: 'string' }, serialNumber: { type: 'string' }, notAfter: { type: 'string' } },
} as const;
