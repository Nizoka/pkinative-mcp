/**
 * The PKI object input every tool shares: exactly one of `pem` (RFC 7468
 * text), `derBase64` (the DER bytes as base64, exactly once) or `path` (a
 * relative path inside the sandbox, PEM or DER sniffed by its first bytes).
 *
 * pkinative does no I/O and has no PEM-to-object shortcut by design, so the
 * wrapper owns the sniffing and the label discipline (vendored from
 * pkinative-cli `src/utils/pki-input.ts`): an input whose first non-blank
 * bytes are `-----BEGIN ` is PEM text, decoded with `decodePem` in the call's
 * `pemMode`; anything else is DER. A PEM text holding several matching
 * blocks where ONE object is expected is refused rather than silently
 * reduced to its first block; a bundle input takes every block of every item.
 */
import { decodePem, parseEncryptedPrivateKeyInfo, parsePkcs12, parsePrivateKeyInfo, type PkiParseOptions } from 'pkinative';
import { z } from 'zod';

import { decodeDerBase64 } from './base64.js';
import { assertInputWithin, MAX_BUNDLE_ITEMS } from './caps.js';
import { createDiagnosticSink } from './diagnostics.js';
import { SecurityError, ToolError } from './errors.js';
import type { ParseContext } from './parse-context.js';
import { guard } from './pki-errors.js';
import { PKI_INPUT_EXTENSIONS, readInputFile } from './sandbox.js';

/** PEM labels by object kind (RFC 7468 §5–§13, plus the common legacy forms). */
export const LABELS = {
    certificate: ['CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'],
    csr: ['CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST'],
    crl: ['X509 CRL'],
    cms: ['CMS', 'PKCS7'],
    privateKey: ['PRIVATE KEY'],
    encryptedPrivateKey: ['ENCRYPTED PRIVATE KEY'],
    publicKey: ['PUBLIC KEY'],
    any: [] as readonly string[],
} as const;

/** PEM labels that carry secret material; never extracted, dumped or served. */
export const SECRET_LABELS: readonly string[] = [
    'PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY', 'PGP PRIVATE KEY BLOCK',
];

export interface PkiInputFields {
    readonly pem?: string | undefined;
    readonly derBase64?: string | undefined;
    readonly path?: string | undefined;
}

/** JSON Schema for one PKI input (an object with exactly one of the three members). */
export function pkiInputSchema(what: string, extra = ''): Record<string, unknown> {
    return {
        type: 'object',
        additionalProperties: false,
        description: `${what}: exactly one of pem / derBase64 / path.${extra}`,
        properties: {
            pem: { type: 'string', minLength: 20, description: 'RFC 7468 PEM text (starts with -----BEGIN).' },
            derBase64: { type: 'string', minLength: 4, description: 'DER bytes as base64, exactly once (not PEM text).' },
            path: { type: 'string', minLength: 1, description: 'Relative path of a PEM / DER file inside the PKINATIVE_MCP_OUTPUT_DIR sandbox (never cached).' },
        },
    };
}

/** JSON Schema for a bundle of PKI inputs (trust anchors, candidates, CRLs, …). */
export function pkiBundleSchema(what: string, extra = ''): Record<string, unknown> {
    return { type: 'array', minItems: 1, maxItems: MAX_BUNDLE_ITEMS, description: `${what} (every PEM block of every item is taken).${extra}`, items: pkiInputSchema(what) };
}

function refineOne(value: PkiInputFields, ctx: z.RefinementCtx): void {
    const n = (value.pem !== undefined ? 1 : 0) + (value.derBase64 !== undefined ? 1 : 0) + (value.path !== undefined ? 1 : 0);
    if (n !== 1) ctx.addIssue({ code: 'custom', message: 'pass exactly one of pem / derBase64 / path', path: ['pem'] });
    if (value.pem !== undefined && !looksLikePem(new TextEncoder().encode(value.pem))) {
        ctx.addIssue({ code: 'custom', message: 'pem must be RFC 7468 text starting with -----BEGIN (base64 DER belongs in derBase64)', path: ['pem'] });
    }
}

/** Zod twin of {@link pkiInputSchema}. */
export const PkiInputSchema = z.strictObject({
    pem: z.string().min(20).optional(),
    derBase64: z.string().min(4).optional(),
    path: z.string().min(1).optional(),
}).superRefine(refineOne);

/** Zod twin of {@link pkiBundleSchema}. */
export const PkiBundleSchema = z.array(PkiInputSchema).min(1).max(MAX_BUNDLE_ITEMS);

export type PkiInput = z.infer<typeof PkiInputSchema>;

const BEGIN = new TextEncoder().encode('-----BEGIN ');

/** True when the bytes are PEM text: optional UTF-8 BOM and whitespace, then `-----BEGIN `. */
export function looksLikePem(bytes: Uint8Array): boolean {
    let i = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
    while (bytes[i] === 0x20 || bytes[i] === 0x09 || bytes[i] === 0x0a || bytes[i] === 0x0d) i++;
    return BEGIN.every((b, k) => bytes[i + k] === b);
}

export interface PkiObject {
    readonly der: Uint8Array;
    /** The PEM label, or undefined for a DER input. */
    readonly label: string | undefined;
    /** The source, for messages (`pem`, `derBase64`, or the relative path). */
    readonly source: string;
}

/** True when a raw input object references a sandbox file anywhere (deep walk) — such a call is never cached. */
export function isPathInput(input: unknown, depth = 0): boolean {
    if (input === null || typeof input !== 'object' || depth > 8) return false;
    if (Array.isArray(input)) return input.some((e) => isPathInput(e, depth + 1));
    const o = input as Record<string, unknown>;
    if (typeof o['path'] === 'string') return true;
    return Object.values(o).some((v) => isPathInput(v, depth + 1));
}

async function readBytes(input: PkiInputFields, what: string, ctx: ParseContext): Promise<{ bytes: Uint8Array; source: string }> {
    if (input.pem !== undefined) {
        const bytes = new TextEncoder().encode(input.pem);
        assertInputWithin(bytes.byteLength, ctx.maxInputBytes, `${what} (pem)`);
        ctx.charge(bytes.byteLength, what);
        return { bytes, source: 'pem' };
    }
    if (input.derBase64 !== undefined) {
        const bytes = decodeDerBase64(input.derBase64, `${what}.derBase64`);
        assertInputWithin(bytes.byteLength, ctx.maxInputBytes, `${what} (derBase64, decoded)`);
        ctx.charge(bytes.byteLength, what);
        return { bytes, source: 'derBase64' };
    }
    if (input.path === undefined) {
        throw new ToolError('VALIDATION_ERROR', `${what}: pass exactly one of pem / derBase64 / path`, { path: what });
    }
    const { bytes } = await readInputFile(input.path, PKI_INPUT_EXTENSIONS, `${what}.path`, (size) => assertInputWithin(size, ctx.maxInputBytes, `${what}.path '${input.path}'`));
    return { bytes, source: input.path };
}

/** Decode every PEM block of a text, under the call's PEM mode and limits. */
export function decodePemBlocks(text: string, what: string, ctx: ParseContext): ReturnType<typeof decodePem> {
    return guard(`Cannot decode ${what} as PEM`, () => decodePem(text, { ...ctx.options, mode: ctx.pemMode }));
}

/**
 * The DER objects of an input: the matching PEM blocks, or the DER bytes as
 * one object. `labels` lists the acceptable PEM labels; an empty list accepts
 * every block.
 */
export async function loadPkiObjects(input: PkiInputFields, what: string, labels: readonly string[], ctx: ParseContext): Promise<readonly PkiObject[]> {
    const { bytes, source } = await readBytes(input, what, ctx);
    if (!looksLikePem(bytes)) return [{ der: bytes, label: undefined, source }];
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const blocks = decodePemBlocks(text, what, ctx);
    const matching = labels.length === 0 ? blocks : blocks.filter((b) => (labels as readonly string[]).includes(b.label));
    if (matching.length === 0) {
        const present = [...new Set(blocks.map((b) => b.label))].join(', ');
        throw new ToolError('PKI_PEM_UNEXPECTED_LABEL', `${what} (${source}) holds no ${labels.join(' or ')} PEM block (labels present: ${present}).`, { errorClass: 'input', path: what, remedy: "convert_pem mode:'decode' (lists the labels present)" });
    }
    return matching.map((b) => ({ der: b.bytes, label: b.label, source }));
}

/**
 * Exactly one DER object. A PEM file holding several matching blocks is
 * refused rather than silently reduced to its first block.
 */
export async function loadPkiObject(input: PkiInputFields, what: string, labels: readonly string[], ctx: ParseContext): Promise<PkiObject> {
    const objects = await loadPkiObjects(input, what, labels, ctx);
    const first = objects[0] as PkiObject;
    if (objects.length > 1) {
        throw new ToolError('VALIDATION_ERROR', `${what} (${first.source}) holds ${objects.length} ${labels.length === 0 ? '' : `${labels.join('/')} `}blocks where one object is expected.`, { path: what, remedy: 'convert_pem extractIndex' });
    }
    return first;
}

/** Every object of every item of a bundle (trust anchors, candidates, CRLs, OCSP responses, a path). */
export async function loadPkiBundle(inputs: readonly PkiInputFields[] | undefined, what: string, labels: readonly string[], ctx: ParseContext): Promise<readonly PkiObject[]> {
    const out: PkiObject[] = [];
    for (const [i, input] of (inputs ?? []).entries()) out.push(...await loadPkiObjects(input, `${what}[${i}]`, labels, ctx));
    return out;
}

/** True when a PEM label (or an undefined one for DER) names secret material. */
export function isSecretLabel(label: string | undefined): boolean {
    return label !== undefined && SECRET_LABELS.includes(label);
}

/**
 * Refuse bytes that parse as a PKCS#8 private key (plain or encrypted) or a
 * PKCS#12 file, wherever a tool would re-emit, wrap, embed or dump them:
 * decode_asn1 (a node tree), convert_pem encode (a PEM block under any
 * label), encode_asn1 (the value produced). Cheap structural probes with a
 * throwaway sink (their diagnostics are not the caller's) and BER tolerance.
 *
 * @throws {SecurityError} SECURITY_VIOLATION naming the remedy tool.
 */
const parses = (fn: () => unknown): boolean => {
    try {
        fn();
        return true;
    } catch {
        return false;
    }
};

/** 'pkcs8' when the DER parses as a PKCS#8 private key (plain or encrypted), 'pkcs12' for a PKCS#12 file, else null. */
function secretKindOfDer(der: Uint8Array, probe: PkiParseOptions): 'pkcs8' | 'pkcs12' | null {
    if (parses(() => parsePrivateKeyInfo(der, probe)) || parses(() => parseEncryptedPrivateKeyInfo(der, probe))) return 'pkcs8';
    if (parses(() => parsePkcs12(der, probe))) return 'pkcs12';
    return null;
}

/** A throwaway probe: BER-tolerant, non-strict, diagnostics discarded (they are not the caller's). */
function probeOptions(base?: PkiParseOptions): PkiParseOptions {
    return { ...(base ?? {}), ...createDiagnosticSink(false).options, encodingRules: 'ber', strict: false };
}

export type SecretKind = 'pkcs8' | 'pkcs12' | 'private-key-pem';

/** The exact DER value that starts at `offset` (short or long-form length), or null when the header is not a DER SEQUENCE. */
function derValueAt(bytes: Uint8Array, offset: number): Uint8Array | null {
    if (bytes[offset] !== 0x30) return null;
    const first = bytes[offset + 1];
    if (first === undefined) return null;
    let length = 0;
    let header = 2;
    if (first < 0x80) {
        length = first;
    } else {
        const octets = first & 0x7f;
        if (octets === 0 || octets > 4) return null;
        for (let i = 0; i < octets; i++) {
            const b = bytes[offset + 2 + i];
            if (b === undefined) return null;
            length = length * 256 + b;
        }
        header = 2 + octets;
    }
    const end = offset + header + length;
    if (end > bytes.length) return null;
    return bytes.subarray(offset, end);
}

const ARMOURED_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
const ARMOUR_HEADER = /-----BEGIN ([A-Z0-9 ]+)-----/g;
const BASE64_RUN = /[A-Za-z0-9+/]{64,}={0,2}/g;
/** How far into a buffer an embedded DER key is looked for (a key is never larger; a prefix is never longer). */
const EMBEDDED_SCAN_BYTES = 64 * 1024;

/**
 * Key material anywhere in raw bytes, found by CONTENT (A2-040 / A2-042 /
 * A2-043): an armoured block at any position (not only at byte 0, any
 * number of blocks, no engine limit) with a private-key label or a body that
 * parses as a PKCS#8 key or a PKCS#12 file; the whole buffer as DER; a DER
 * key behind a prefix (every SEQUENCE header in the first 64 KiB); an
 * unarmoured base64 run that decodes to one. Returns the kind found, or
 * null. Used wherever bytes are served, wrapped or embedded by name only.
 */
export function findSecretMaterial(bytes: Uint8Array): SecretKind | null {
    const probe = probeOptions();
    const text = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('latin1');
    if (text.includes('-----BEGIN ')) {
        for (const m of text.matchAll(ARMOUR_HEADER)) if (isSecretLabel(m[1])) return 'private-key-pem';
        for (const m of text.matchAll(ARMOURED_BLOCK)) {
            const body = Buffer.from((m[2] ?? '').replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
            if (body.length > 16) {
                const kind = secretKindOfDer(new Uint8Array(body), probe);
                if (kind !== null) return kind;
            }
        }
    }
    const whole = secretKindOfDer(bytes, probe);
    if (whole !== null) return whole;
    for (const m of text.matchAll(BASE64_RUN)) {
        const kind = secretKindOfDer(new Uint8Array(Buffer.from(m[0], 'base64')), probe);
        if (kind !== null) return kind;
    }
    const limit = Math.min(bytes.length - 1, EMBEDDED_SCAN_BYTES);
    for (let i = 1; i < limit; i++) {
        if (bytes[i] !== 0x30) continue;
        const value = derValueAt(bytes, i);
        if (value === null || value.length < 32) continue;
        const kind = secretKindOfDer(value, probe);
        if (kind !== null) return kind;
    }
    return null;
}

/** True when raw bytes hold key material in any form (see {@link findSecretMaterial}). */
export function isSecretMaterial(bytes: Uint8Array): boolean {
    return findSecretMaterial(bytes) !== null;
}

export function refuseSecretDer(der: Uint8Array, source: string, ctx: ParseContext, consequence: string): void {
    const probe = probeOptions(ctx.options);
    if (secretKindOfDer(der, probe) === 'pkcs8') {
        throw new SecurityError(`${source} parses as a PKCS#8 private key: ${consequence}; describe it with inspect_private_key instead.`, { remedy: 'inspect_private_key' });
    }
    if (secretKindOfDer(der, probe) === 'pkcs12') {
        throw new SecurityError(`${source} parses as a PKCS#12 file: ${consequence}; describe it with inspect_pkcs12 instead.`, { remedy: 'inspect_pkcs12' });
    }
}

/** {@link refuseSecretDer} for a loaded object: its PEM label is checked first. */
export function refuseSecretObject(obj: PkiObject, ctx: ParseContext, consequence: string): void {
    if (isSecretLabel(obj.label)) {
        throw new SecurityError(`input (${obj.source}) is a ${obj.label ?? ''} block: ${consequence}; describe it with inspect_private_key instead.`, { label: obj.label, remedy: 'inspect_private_key' });
    }
    refuseSecretDer(obj.der, `input (${obj.source})`, ctx, consequence);
}
