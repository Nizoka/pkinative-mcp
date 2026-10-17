/**
 * Curated, secret-free views of key material for the key and PKCS#12 tools
 * (vendored from pkinative-cli `src/utils/key-views.ts`).
 *
 * The engine results here carry secret bytes: `PrivateKeyInfo.der` is the
 * plaintext key, a PKCS#12 keyBag or secretBag holds plaintext in
 * `valueDer`, and `Pkcs12.authenticatedSafe` holds every unencrypted bag.
 * Unlike every other tool, these reports are therefore built field by field
 * from an allow-list, never by serialising the engine object through
 * `toWire`: no secret byte can reach `structuredContent`, a message or a
 * log, whatever a future engine adds. The interfaces below ARE the allow-list.
 */
import type { webcrypto } from 'node:crypto';
import {
    formatDistinguishedName,
    getOidName,
    parseCertificate,
    type EncryptedPrivateKeyInfo,
    type PasswordEncryption,
    type Pkcs12Mac,
    type PkiParseOptions,
    type PrivateKeyInfo,
    type SafeBag,
    type SigningKey,
} from 'pkinative';

import { toHex } from './wire.js';

export interface EncryptionView {
    readonly scheme: PasswordEncryption['scheme'];
    readonly algorithm: string;
    readonly pbes2?: {
        readonly iterations: number;
        readonly prf: string;
        readonly keyBits: number;
        readonly cipher: string;
        readonly saltBytes: number;
    };
}

export interface PrivateKeyView {
    readonly format: 'pkcs8';
    readonly version: PrivateKeyInfo['version'];
    readonly kind: PrivateKeyInfo['kind'];
    readonly curve?: NonNullable<PrivateKeyInfo['curve']>;
    readonly algorithm: string;
    readonly attributes: readonly string[];
    readonly publicKey: boolean;
}

export interface EncryptedKeyView {
    readonly format: 'encrypted-pkcs8';
    readonly encryption: EncryptionView;
    readonly encryptedBytes: number;
}

export interface MacView {
    readonly kind: Pkcs12Mac['kind'];
    readonly algorithm: string;
    readonly iterations: number;
    readonly pbmac1?: { readonly iterations: number; readonly prf: string; readonly hmac: string; readonly keyLength: number };
}

export interface BagView {
    readonly path: string;
    readonly kind: SafeBag['kind'];
    readonly oid: string;
    readonly friendlyName?: string;
    readonly localKeyId?: string;
    readonly certificate?: { readonly subject: string; readonly issuer: string; readonly serialNumber: string } | { readonly unreadable: true; readonly bytes: number };
    readonly crlBytes?: number;
    readonly key?: PrivateKeyView | EncryptedKeyView;
}

/** A Web Crypto key handle, described and never exported. */
export interface CryptoKeyView {
    readonly type: string;
    readonly algorithm: string;
    readonly extractable: boolean;
    readonly usages: readonly string[];
}

export interface SigningKeyView {
    readonly algorithm: SigningKey['algorithm'];
    readonly key: CryptoKeyView;
}

export function encryptionView(e: PasswordEncryption): EncryptionView {
    return {
        scheme: e.scheme,
        algorithm: e.algorithm.oid,
        ...(e.pbes2 !== undefined ? {
            pbes2: {
                iterations: e.pbes2.iterations,
                prf: e.pbes2.prf,
                keyBits: e.pbes2.keyBits,
                cipher: getOidName(e.pbes2.cipherOid) ?? e.pbes2.cipherOid,
                saltBytes: e.pbes2.salt.length,
            },
        } : {}),
    };
}

export function privateKeyView(info: PrivateKeyInfo): PrivateKeyView {
    return {
        format: 'pkcs8',
        version: info.version,
        kind: info.kind,
        ...(info.curve !== undefined ? { curve: info.curve } : {}),
        algorithm: info.algorithm.oid,
        attributes: info.attributes.map((a) => a.oid),
        publicKey: info.publicKey !== undefined,
    };
}

export function encryptedKeyView(e: EncryptedPrivateKeyInfo): EncryptedKeyView {
    return { format: 'encrypted-pkcs8', encryption: encryptionView(e.encryption), encryptedBytes: e.encryptedData.length };
}

export function macView(mac: Pkcs12Mac | undefined): MacView | null {
    if (mac === undefined) return null;
    return {
        kind: mac.kind,
        algorithm: mac.algorithm.oid,
        iterations: mac.iterations,
        ...(mac.pbmac1 !== undefined ? { pbmac1: { iterations: mac.pbmac1.iterations, prf: mac.pbmac1.prf, hmac: mac.pbmac1.hmac, keyLength: mac.pbmac1.keyLength } } : {}),
    };
}

/** RFC 4514 rendering of a name, `(empty)` for an empty one. */
export function dn(name: Parameters<typeof formatDistinguishedName>[0]): string {
    const text = formatDistinguishedName(name);
    return text === '' ? '(empty)' : text;
}

function certificateView(der: Uint8Array, opts: PkiParseOptions): NonNullable<BagView['certificate']> {
    try {
        const cert = parseCertificate(der, opts);
        return { subject: dn(cert.subject), issuer: dn(cert.issuer), serialNumber: cert.serialNumber.hex };
    } catch {
        return { unreadable: true, bytes: der.length };
    }
}

/** A bag without its secret bytes: certificates by subject, keys by their algorithm only. */
export function bagView(bag: SafeBag, opts: PkiParseOptions): BagView {
    return {
        path: bag.path,
        kind: bag.kind,
        oid: bag.oid,
        ...(bag.friendlyName !== undefined ? { friendlyName: bag.friendlyName } : {}),
        ...(bag.localKeyId !== undefined ? { localKeyId: toHex(bag.localKeyId) } : {}),
        ...(bag.certificateDer !== undefined ? { certificate: certificateView(bag.certificateDer, opts) } : {}),
        ...(bag.crlDer !== undefined ? { crlBytes: bag.crlDer.length } : {}),
        ...(bag.privateKey !== undefined ? { key: privateKeyView(bag.privateKey) } : {}),
        ...(bag.encryptedKey !== undefined ? { key: encryptedKeyView(bag.encryptedKey) } : {}),
    };
}

/** A signing key: its algorithm and the Web Crypto handle described (type, extractable, usages), never exported. */
export function signingKeyView(key: SigningKey): SigningKeyView {
    // pkinative types the handle opaquely; at runtime it is Web Crypto's CryptoKey.
    const handle = key.key as unknown as webcrypto.CryptoKey;
    return { algorithm: key.algorithm, key: { type: handle.type, algorithm: handle.algorithm.name, extractable: handle.extractable, usages: [...handle.usages] } };
}

/** JSON Schema of the shared key views (referenced inline by the key tools — no $ref). */
export const ENCRYPTION_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['scheme', 'algorithm'],
    properties: {
        scheme: { type: 'string' },
        algorithm: { type: 'string' },
        pbes2: {
            type: 'object',
            additionalProperties: false,
            required: ['iterations', 'prf', 'keyBits', 'cipher', 'saltBytes'],
            properties: { iterations: { type: 'integer' }, prf: { type: 'string' }, keyBits: { type: 'integer' }, cipher: { type: 'string' }, saltBytes: { type: 'integer' } },
        },
    },
} as const;

export const KEY_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    description: 'A private key described without any secret byte: a plain PKCS#8 key (format pkcs8) or an encrypted one (format encrypted-pkcs8).',
    properties: {
        format: { type: 'string', enum: ['pkcs8', 'encrypted-pkcs8'] },
        version: { type: 'integer' },
        kind: { type: 'string' },
        curve: { type: 'string' },
        algorithm: { type: 'string' },
        attributes: { type: 'array', items: { type: 'string' } },
        publicKey: { type: 'boolean' },
        encryption: ENCRYPTION_VIEW_SCHEMA,
        encryptedBytes: { type: 'integer' },
    },
} as const;

export const SIGNING_KEY_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    description: 'A non-extractable Web Crypto signing key, described and never exported.',
    required: ['algorithm', 'key'],
    properties: {
        algorithm: { type: 'object', additionalProperties: true },
        key: {
            type: 'object',
            additionalProperties: false,
            required: ['type', 'algorithm', 'extractable', 'usages'],
            properties: { type: { type: 'string' }, algorithm: { type: 'string' }, extractable: { type: 'boolean', enum: [false] }, usages: { type: 'array', items: { type: 'string' } } },
        },
    },
} as const;
