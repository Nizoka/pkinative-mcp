/**
 * The `SIGNER` fragment of `create_certificate`, `create_csr`, `sign_cms`
 * and `encode_x509_structure` (signature-algorithm): a PKCS#8 key (plain or
 * PBES2-encrypted, PEM or DER) or a PKCS#12 file, imported through pkinative
 * into a non-extractable Web Crypto key. Vendored from pkinative-cli
 * `src/utils/signer.ts`.
 *
 * The signature algorithm is chosen from the key, never guessed:
 *   EC        ECDSA on the key's curve; hash SHA-256/384/512 for P-256/384/521
 *             unless `hash` says otherwise
 *   Ed25519 / Ed448   no hash (`hash` is refused)
 *   RSA       `rsaScheme: 'pkcs1' | 'pss'` is REQUIRED: pkinative has no default
 *             RSA scheme (its ADR 0015), and neither does this server; hash
 *             SHA-256 unless `hash`
 * An encrypted key reveals its type only once decrypted, and pkinative
 * decrypts into a key for one algorithm, so the type comes from the matching
 * certificate or public key the tool already has, or from `keyType`.
 * SHA-1 signatures are produced only under `allowSha1: true`.
 *
 * The password is held in the call frame only: never in a message, in
 * `ToolError.data`, in a cache key or in a log.
 */
import { createPrivateKey, createPublicKey } from 'node:crypto';
import {
    decryptPrivateKey,
    importPrivateKey,
    openPkcs12,
    parseEncryptedPrivateKeyInfo,
    parsePrivateKeyInfo,
    type Certificate,
    type EcCurve,
    type SignatureAlgorithm,
    type SignatureHash,
    type SigningKey,
} from 'pkinative';
import { z } from 'zod';

import { ToolError } from './errors.js';
import type { ParseContext } from './parse-context.js';
import { guard, guardAsync, LEGACY_PKCS8_REMEDY, mapPkiError, pkcs12Failure } from './pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema, type PkiInputFields } from './pki-input.js';
import { PASSWORD_INPUT_PROPERTY, PasswordSchema, resolvePassword, secretRequired } from './secrets.js';
import type { KeyKind, KeyType } from './spki.js';

export const KEY_TYPES = ['ec-p256', 'ec-p384', 'ec-p521', 'ed25519', 'ed448', 'rsa', 'rsa-pss'] as const;
export type KeyTypeName = (typeof KEY_TYPES)[number];
const KEY_TYPE_MAP: Readonly<Record<KeyTypeName, KeyType>> = {
    'ec-p256': { kind: 'ec', curve: 'P-256' },
    'ec-p384': { kind: 'ec', curve: 'P-384' },
    'ec-p521': { kind: 'ec', curve: 'P-521' },
    ed25519: { kind: 'ed25519' },
    ed448: { kind: 'ed448' },
    rsa: { kind: 'rsa' },
    'rsa-pss': { kind: 'rsa-pss' },
};

const CURVE_HASH: Readonly<Record<EcCurve, SignatureHash>> = { 'P-256': 'SHA-256', 'P-384': 'SHA-384', 'P-521': 'SHA-512' };
export const HASHES = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'] as const;

/** JSON Schema of the `signer` input object. */
export const SIGNER_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    description: "The signing key: exactly one of `key` (a PKCS#8 private key, plain or PBES2-encrypted, PEM or DER) or `p12` (a PKCS#12 file, PBES2 + PBMAC1 only). The key is imported into a NON-EXTRACTABLE Web Crypto key and never leaves the engine; no result ever carries a key byte. The algorithm follows the key: ECDSA on the key's curve, Ed25519/Ed448 (no hash), RSA REQUIRES rsaScheme ('pkcs1' | 'pss' — pkinative has no default). SHA-1 only with the tool's allowSha1:true.",
    properties: {
        key: pkiInputSchema('The PKCS#8 private key (PRIVATE KEY or ENCRYPTED PRIVATE KEY; SEC1 / PKCS#1 keys must be converted with openssl pkcs8 -topk8 first)', ' Exclusive with p12.'),
        p12: pkiInputSchema('The PKCS#12 file (.p12 / .pfx; PBES2 and PBMAC1 only — a legacy RC2 / 3DES file is refused with the OpenSSL 3.4 conversion remedy)', ' Exclusive with key.'),
        ...PASSWORD_INPUT_PROPERTY,
        keyType: { type: 'string', enum: [...KEY_TYPES], description: 'The type of an ENCRYPTED PKCS#8 key (it reveals its type only once decrypted); not needed when the tool has the matching certificate or public key.' },
        hash: { type: 'string', enum: [...HASHES], description: "Signature hash. Default: the curve's hash for ECDSA (SHA-256/384/512), SHA-256 for RSA; refused for Ed25519 / Ed448 (which hash internally). 'SHA-1' needs allowSha1:true." },
        rsaScheme: { type: 'string', enum: ['pkcs1', 'pss'], description: "REQUIRED for an RSA key: 'pkcs1' (RSASSA-PKCS1-v1_5) or 'pss' (RSA-PSS). An id-RSASSA-PSS key signs with 'pss' only. Refused for non-RSA keys." },
        saltLength: { type: 'integer', minimum: 0, maximum: 512, description: "RSA-PSS salt length in bytes (rsaScheme:'pss' only; default: the hash length)." },
    },
} as const;

/** Zod twin of {@link SIGNER_INPUT_SCHEMA}. */
export const SignerSchema = z.strictObject({
    key: PkiInputSchema.optional(),
    p12: PkiInputSchema.optional(),
    password: PasswordSchema.optional(),
    keyType: z.enum(KEY_TYPES).optional(),
    hash: z.enum(HASHES).optional(),
    rsaScheme: z.enum(['pkcs1', 'pss']).optional(),
    saltLength: z.number().int().min(0).max(512).optional(),
}).superRefine((v, ctx) => {
    if ((v.key === undefined) === (v.p12 === undefined)) {
        ctx.addIssue({ code: 'custom', message: 'pass exactly one of signer.key / signer.p12', path: ['key'] });
    }
    if (v.saltLength !== undefined && v.rsaScheme !== 'pss') {
        ctx.addIssue({ code: 'custom', message: "signer.saltLength applies to rsaScheme:'pss' only", path: ['saltLength'] });
    }
});

export type SignerInput = z.infer<typeof SignerSchema>;

/** JSON Schema property for `allowSha1` (top-level, next to `signer`). */
export const ALLOW_SHA1_INPUT_PROPERTY = {
    allowSha1: {
        type: 'boolean',
        default: false,
        description: 'Accept or produce SHA-1 signatures (legacy material you already trust only). Default false: a SHA-1 signature is refused with PKI_CRYPTO_ALGORITHM_REFUSED on read, and at the boundary on write.',
    },
} as const;

function hashOf(input: SignerInput, allowSha1: boolean): SignatureHash | undefined {
    if (input.hash === 'SHA-1' && !allowSha1) {
        throw new ToolError('VALIDATION_ERROR', "signer.hash 'SHA-1' produces a signature every current verifier refuses; pass allowSha1:true to make one anyway.", { path: 'signer.hash', remedy: 'allowSha1:true' });
    }
    return input.hash;
}

/** The signature algorithm for a key of `kind` (and `curve`), under the signer inputs. */
export function signatureAlgorithm(input: SignerInput, allowSha1: boolean, kind: KeyKind, curve: EcCurve | undefined): SignatureAlgorithm {
    const hash = hashOf(input, allowSha1);
    const scheme = input.rsaScheme;
    const salt = input.saltLength;
    if (kind !== 'rsa' && kind !== 'rsa-pss' && (scheme !== undefined || salt !== undefined)) {
        throw new ToolError('VALIDATION_ERROR', 'signer.rsaScheme and signer.saltLength apply to RSA keys only.', { path: 'signer.rsaScheme' });
    }
    switch (kind) {
        case 'ec':
            if (curve === undefined) throw new ToolError('UNSUPPORTED_KEY', 'The EC key is on a curve Web Crypto does not sign with (P-256, P-384, P-521 only).', { errorClass: 'unsupported' });
            return { name: 'ECDSA', hash: hash ?? CURVE_HASH[curve], namedCurve: curve };
        case 'ed25519':
        case 'ed448':
            if (hash !== undefined) throw new ToolError('VALIDATION_ERROR', `signer.hash does not apply to ${kind === 'ed25519' ? 'Ed25519' : 'Ed448'}, which hashes internally.`, { path: 'signer.hash' });
            return { name: kind === 'ed25519' ? 'Ed25519' : 'Ed448' };
        default: {
            const effective = scheme ?? (kind === 'rsa-pss' ? 'pss' : undefined);
            if (effective === undefined) {
                throw new ToolError('RSA_SCHEME_REQUIRED', "An RSA key needs signer.rsaScheme:'pkcs1'|'pss': pkinative has no default RSA signature scheme.", { path: 'signer.rsaScheme', remedy: "rsaScheme:'pkcs1'|'pss'" });
            }
            if (kind === 'rsa-pss' && effective === 'pkcs1') throw new ToolError('VALIDATION_ERROR', "An id-RSASSA-PSS key signs with rsaScheme:'pss' only.", { path: 'signer.rsaScheme' });
            if (effective === 'pkcs1' && salt !== undefined) throw new ToolError('VALIDATION_ERROR', "signer.saltLength applies to rsaScheme:'pss' only.", { path: 'signer.saltLength' });
            return effective === 'pkcs1'
                ? { name: 'RSASSA-PKCS1-v1_5', hash: hash ?? 'SHA-256' }
                : { name: 'RSA-PSS', hash: hash ?? 'SHA-256', ...(salt !== undefined ? { saltLength: salt } : {}) };
        }
    }
}

export interface LoadedSigner {
    readonly signer: SigningKey;
    /** The certificate that came with the key (a PKCS#12 bag). */
    readonly certificate: Certificate | undefined;
    /** Other certificates of a PKCS#12 file. */
    readonly chain: readonly Certificate[];
    /** The SPKI DER of the key, when it can be derived (plain PKCS#8 or a PKCS#12 certificate). */
    readonly publicKey: Uint8Array | undefined;
    /** Whether a password was used (the caller decides what to cache — nothing). */
    readonly encrypted: boolean;
}

/** Load `signer.key` or `signer.p12` into a signing key. `hint` is the key type the tool already knows. */
export async function loadSigner(input: SignerInput, allowSha1: boolean, hint: KeyType | undefined, ctx: ParseContext): Promise<LoadedSigner> {
    const password = resolvePassword(input.password);
    if (input.p12 !== undefined) return loadPkcs12(input, allowSha1, password, ctx);
    const key = await importKeyInput(input, allowSha1, password, hint, ctx);
    return { signer: key.signer, certificate: undefined, chain: [], publicKey: key.publicKey, encrypted: key.encrypted };
}

export interface ImportedKey {
    readonly signer: SigningKey;
    readonly encrypted: boolean;
    /** The SPKI DER, derived for an unencrypted key. */
    readonly publicKey: Uint8Array | undefined;
}

/** Import a PKCS#8 input (plain, or PBES2-encrypted with `password`) into a signing key. */
export async function importKeyInput(input: SignerInput, allowSha1: boolean, password: string | undefined, hint: KeyType | undefined, ctx: ParseContext): Promise<ImportedKey> {
    const obj = await loadPkiObject(input.key as PkiInputFields, 'signer.key', [...LABELS.privateKey, ...LABELS.encryptedPrivateKey], ctx);
    const encrypted = obj.label === undefined ? isEncryptedPkcs8(obj.der, ctx) : (LABELS.encryptedPrivateKey as readonly string[]).includes(obj.label);
    if (!encrypted) {
        const info = guard('Cannot read the private key', () => parsePrivateKeyInfo(obj.der, ctx.options));
        if (info.kind === 'unknown') throw new ToolError('UNSUPPORTED_KEY', `The private key algorithm ${info.algorithm.oid} cannot sign through Web Crypto.`, { errorClass: 'unsupported', algorithm: info.algorithm.oid });
        const algorithm = signatureAlgorithm(input, allowSha1, info.kind, info.curve);
        const signer = await guardAsync('Cannot import the private key', () => importPrivateKey(obj.der, { ...ctx.options, algorithm }));
        return { signer, encrypted, publicKey: derivePublicKey(obj.der) };
    }
    if (password === undefined) throw secretRequired('The key is encrypted and');
    const type = input.keyType !== undefined ? KEY_TYPE_MAP[input.keyType] : hint;
    if (type === undefined) {
        throw new ToolError('KEY_TYPE_REQUIRED', `An encrypted key needs its type before it can be decrypted: pass signer.keyType (${KEY_TYPES.join('|')}), or the matching certificate / public key input.`, { path: 'signer.keyType', remedy: 'keyType' });
    }
    const algorithm = signatureAlgorithm(input, allowSha1, type.kind, type.curve);
    // A legacy PKCS#8 key needs the PKCS#8 conversion, not the PKCS#12 one.
    const signer = await guardAsync('Cannot decrypt the private key', () => decryptPrivateKey(obj.der, { ...ctx.options, password, algorithm }),
        { PKI_KEY_ENCRYPTION_UNSUPPORTED: LEGACY_PKCS8_REMEDY });
    return { signer, encrypted, publicKey: undefined };
}

/** A DER key is encrypted when parseEncryptedPrivateKeyInfo reads it; one neither reader reads is refused with the PKCS#8 cause. */
export function isEncryptedPkcs8(der: Uint8Array, ctx: ParseContext): boolean {
    try {
        parsePrivateKeyInfo(der, ctx.options);
        return false;
    } catch (plainError) {
        try {
            parseEncryptedPrivateKeyInfo(der, ctx.options);
            return true;
        } catch {
            throw mapPkiError(plainError, 'Cannot read the private key (PKCS#8 expected; convert a SEC1 or PKCS#1 key with openssl pkcs8 -topk8)');
        }
    }
}

/** The SPKI of a plain PKCS#8 key, derived by Node's own crypto (pkinative never exports a key). */
export function derivePublicKey(pkcs8: Uint8Array): Uint8Array {
    return guard('Cannot derive the public key', () => {
        const privateKey = createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
        return new Uint8Array(createPublicKey(privateKey).export({ type: 'spki', format: 'der' }));
    });
}

async function loadPkcs12(input: SignerInput, allowSha1: boolean, password: string | undefined, ctx: ParseContext): Promise<LoadedSigner> {
    if (password === undefined) throw secretRequired('A PKCS#12 file');
    const obj = await loadPkiObject(input.p12 as PkiInputFields, 'signer.p12', LABELS.any, ctx);
    const scheme = input.rsaScheme;
    const hash = hashOf(input, allowSha1);
    const salt = input.saltLength;
    const rsaAlgorithm = scheme === undefined ? undefined : scheme === 'pkcs1'
        ? { name: 'RSASSA-PKCS1-v1_5' as const, hash: hash ?? 'SHA-256' }
        : { name: 'RSA-PSS' as const, hash: hash ?? 'SHA-256', ...(salt !== undefined ? { saltLength: salt } : {}) };
    const report = await guardAsync('Cannot open the PKCS#12 file', () => openPkcs12(obj.der, {
        ...ctx.options,
        password,
        ...(rsaAlgorithm !== undefined ? { rsaAlgorithm } : {}),
    }));
    if (!report.valid) throw pkcs12Failure(report);
    const keys = report.keys.filter((k) => k.signingKey !== undefined);
    const [first] = keys;
    if (first === undefined || keys.length > 1) {
        throw new ToolError('VALIDATION_ERROR', `The PKCS#12 file holds ${keys.length} usable keys; exactly one is needed to sign.`, { path: 'signer.p12' });
    }
    let signer = first.signingKey as SigningKey;
    // The key's algorithm is known only once the file is open: hold the
    // signing inputs to it as signatureAlgorithm() does for a PKCS#8 key.
    const name = signer.algorithm.name;
    if (name !== 'RSASSA-PKCS1-v1_5' && name !== 'RSA-PSS' && scheme !== undefined) throw new ToolError('VALIDATION_ERROR', 'signer.rsaScheme and signer.saltLength apply to RSA keys only.', { path: 'signer.rsaScheme' });
    if ((name === 'Ed25519' || name === 'Ed448') && hash !== undefined) throw new ToolError('VALIDATION_ERROR', `signer.hash does not apply to ${name}, which hashes internally.`, { path: 'signer.hash' });
    // ECDSA keys are not bound to a hash in Web Crypto: `hash` re-targets them.
    if (signer.algorithm.name === 'ECDSA' && hash !== undefined) signer = { key: signer.key, algorithm: { ...signer.algorithm, hash } };
    const chain = report.certificates.filter((c) => c !== first.certificate);
    return { signer, certificate: first.certificate, chain, publicKey: first.certificate?.subjectPublicKeyInfo.der, encrypted: true };
}
