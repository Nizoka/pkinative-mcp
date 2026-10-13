/**
 * A public key from whatever the caller has at hand: a certificate, a
 * PKCS#10 request, or a bare SubjectPublicKeyInfo (`PUBLIC KEY` PEM).
 * pkinative never exports a key, so the wrapper takes the public half from
 * one of these, and reads the key's type from its SPKI algorithm identifier
 * (RFC 5480, 8410, 4055). Vendored from pkinative-cli `src/utils/spki.ts`.
 */
import { decodeAsn1, parseCertificate, parseCertificationRequest, readBitString, readObjectIdentifier, type EcCurve } from 'pkinative';

import { ToolError } from './errors.js';
import type { ParseContext } from './parse-context.js';
import { guard, mapPkiError } from './pki-errors.js';
import { LABELS, loadPkiObject, type PkiInputFields, type PkiObject } from './pki-input.js';

export type KeyKind = 'ec' | 'ed25519' | 'ed448' | 'rsa' | 'rsa-pss';

export interface KeyType {
    readonly kind: KeyKind;
    readonly curve?: EcCurve | undefined;
}

export interface PublicKey {
    /** The SubjectPublicKeyInfo DER. */
    readonly spki: Uint8Array;
    /** The BIT STRING content of the key (what computeKeyIdentifier hashes). */
    readonly bits: Uint8Array;
    /** Where it came from. */
    readonly from: 'certificate' | 'csr' | 'spki';
    /** The signing key type, when Web Crypto can sign with such a key. */
    readonly type: KeyType | undefined;
}

const ALGORITHMS: Readonly<Record<string, KeyKind>> = {
    '1.2.840.10045.2.1': 'ec',
    '1.2.840.113549.1.1.1': 'rsa',
    '1.2.840.113549.1.1.10': 'rsa-pss',
    '1.3.101.112': 'ed25519',
    '1.3.101.113': 'ed448',
};

const CURVES: Readonly<Record<string, EcCurve>> = {
    '1.2.840.10045.3.1.7': 'P-256',
    '1.3.132.0.34': 'P-384',
    '1.3.132.0.35': 'P-521',
};

/** Decode an SPKI: its key bits and, when Web Crypto can sign with it, its type. */
export function readSpki(der: Uint8Array, ctx: ParseContext): { bits: Uint8Array; type: KeyType | undefined } {
    const opts = ctx.options;
    return guard('Cannot read the public key', () => {
        const node = decodeAsn1(der, opts);
        const [algorithm, bitString] = node.children;
        const oidNode = algorithm?.children[0];
        if (node.children.length !== 2 || bitString === undefined || oidNode === undefined) {
            throw new ToolError('PKI_X509_SPKI_INVALID', 'Cannot read the public key: not a SubjectPublicKeyInfo (SEQUENCE { algorithm, subjectPublicKey }).', { errorClass: 'parse' });
        }
        const bits = readBitString(bitString, opts).bytes;
        const kind = ALGORITHMS[readObjectIdentifier(oidNode, opts)];
        if (kind !== 'ec') return { bits, type: kind === undefined ? undefined : { kind } };
        const params = algorithm?.children[1];
        const curve = params?.tagNumber === 6 ? CURVES[readObjectIdentifier(params, opts)] : undefined;
        return { bits, type: curve === undefined ? undefined : { kind, curve } };
    });
}

function from(spki: Uint8Array, source: PublicKey['from'], ctx: ParseContext): PublicKey {
    return { spki, ...readSpki(spki, ctx), from: source };
}

/** Extract the public key of a certificate, a CSR or an SPKI object. */
export function publicKeyOf(obj: PkiObject, ctx: ParseContext): PublicKey {
    const label = obj.label;
    if (label !== undefined && (LABELS.publicKey as readonly string[]).includes(label)) return from(obj.der, 'spki', ctx);
    if (label !== undefined && (LABELS.csr as readonly string[]).includes(label)) {
        return from(guard('Cannot read the request', () => parseCertificationRequest(obj.der, ctx.options)).subjectPublicKeyInfo.der, 'csr', ctx);
    }
    if (label !== undefined) {
        return from(guard('Cannot read the certificate', () => parseCertificate(obj.der, ctx.options)).subjectPublicKeyInfo.der, 'certificate', ctx);
    }
    // DER of unknown kind: an SPKI has two top-level members, a certificate and
    // a request three; a request is tried when the certificate reader refuses.
    const top = guard('Cannot read the public key', () => decodeAsn1(obj.der, ctx.options));
    if (top.children.length === 2) return from(obj.der, 'spki', ctx);
    try {
        return from(parseCertificate(obj.der, ctx.options).subjectPublicKeyInfo.der, 'certificate', ctx);
    } catch (certError) {
        try {
            return from(parseCertificationRequest(obj.der, ctx.options).subjectPublicKeyInfo.der, 'csr', ctx);
        } catch {
            throw mapPkiError(certError, `${obj.source} is not a certificate, a request or a public key`);
        }
    }
}

/** Load an input holding a certificate, a CSR or a public key, and return its key. */
export async function loadPublicKey(input: PkiInputFields, what: string, ctx: ParseContext): Promise<PublicKey> {
    return publicKeyOf(await loadPkiObject(input, what, [...LABELS.certificate, ...LABELS.csr, ...LABELS.publicKey], ctx), ctx);
}

/** The key type of an SPKI DER (a certificate's issuer key, for the signer hint). */
export function keyTypeOfSpki(spki: Uint8Array, ctx: ParseContext): KeyType | undefined {
    return readSpki(spki, ctx).type;
}
