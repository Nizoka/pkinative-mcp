/**
 * Tool: compute_fingerprint — the digest of an object's exact DER (what
 * certificate tools print as the fingerprint), the RFC 5280 §4.2.1.2 key
 * identifier of its public key (certificate, CSR or SPKI), or SHAKE256
 * output of any length (the digest of an Ed448 CMS signer). Any PEM label is
 * accepted — a digest reveals nothing of its input, so even a private key
 * may be fingerprinted — but the result never carries an input byte.
 */
import { computeFingerprint, computeFingerprintAsync, computeKeyIdentifier, formatFingerprint, shake256, type FingerprintAlgorithm } from 'pkinative';
import { z } from 'zod';

import { MAX_SHAKE_OUTPUT_BYTES } from '../caps.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { publicKeyOf } from '../spki.js';
import { toHex } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';

export const COMPUTE_FINGERPRINT_NAME = 'compute_fingerprint';

const MODES = ['fingerprint', 'key-id', 'shake256'] as const;
const ALGORITHMS = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'] as const satisfies readonly FingerprintAlgorithm[];
const KEY_ID_ALGORITHMS = ['SHA-1', 'SHA-256'] as const;
const DEFAULT_SHAKE_OUTPUT_BYTES = 32;
const MAX_SEPARATOR_LENGTH = 8;

export const COMPUTE_FINGERPRINT_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['input'],
    properties: {
        input: pkiInputSchema('The object to digest (any PEM label, or DER)', ' A bundle of several blocks is refused: extract one with convert_pem.'),
        mode: { type: 'string', enum: [...MODES], default: 'fingerprint', description: "'fingerprint' (default): the digest of the exact DER. 'key-id': the RFC 5280 §4.2.1.2 identifier of the public key of a certificate, a CSR or a PUBLIC KEY. 'shake256': SHAKE256 output of `outputLength` bytes." },
        algorithm: { type: 'string', enum: [...ALGORITHMS], description: "fingerprint: SHA-1 | SHA-256 (default) | SHA-384 | SHA-512. key-id: SHA-1 (default, RFC 5280 method 1) | SHA-256. Not for shake256." },
        webcrypto: { type: 'boolean', default: false, description: 'fingerprint only: digest through Web Crypto instead of the pure-TypeScript hashes (identical result).' },
        outputLength: { type: 'integer', minimum: 1, maximum: MAX_SHAKE_OUTPUT_BYTES, description: `shake256 only: output bytes (default ${DEFAULT_SHAKE_OUTPUT_BYTES}, ≤ ${MAX_SHAKE_OUTPUT_BYTES}; 64 for an Ed448 CMS signer).` },
        separator: { type: 'string', maxLength: MAX_SEPARATOR_LENGTH, default: ':', description: "Placed between octets of `formatted` (default ':'; '' for none)." },
        letterCase: { type: 'string', enum: ['upper', 'lower'], default: 'upper', description: 'Hex case of `formatted` (`hex` is always lowercase).' },
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    input: PkiInputSchema,
    mode: z.enum(MODES).default('fingerprint'),
    algorithm: z.enum(ALGORITHMS).optional(),
    webcrypto: z.boolean().default(false),
    outputLength: z.number().int().min(1).max(MAX_SHAKE_OUTPUT_BYTES).optional(),
    separator: z.string().max(MAX_SEPARATOR_LENGTH).default(':'),
    letterCase: z.enum(['upper', 'lower']).default('upper'),
    ...ParseShape,
    ...ProjectionShape,
}).superRefine((v, ctx) => {
    if (v.mode === 'key-id' && v.algorithm !== undefined && !(KEY_ID_ALGORITHMS as readonly string[]).includes(v.algorithm)) {
        ctx.addIssue({ code: 'custom', message: 'a key identifier is SHA-1 (RFC 5280 §4.2.1.2 method 1) or SHA-256', path: ['algorithm'] });
    }
    if (v.mode === 'shake256' && v.algorithm !== undefined) ctx.addIssue({ code: 'custom', message: 'shake256 is the algorithm of this mode; drop algorithm', path: ['algorithm'] });
    if (v.mode !== 'shake256' && v.outputLength !== undefined) ctx.addIssue({ code: 'custom', message: 'outputLength applies to shake256', path: ['outputLength'] });
    if (v.mode !== 'fingerprint' && v.webcrypto) ctx.addIssue({ code: 'custom', message: 'webcrypto applies to the fingerprint mode', path: ['webcrypto'] });
});

export interface ComputeFingerprintResult extends DiagnosticsReport {
    readonly mode: (typeof MODES)[number];
    readonly algorithm: string;
    /** Lowercase hex, no separator. */
    readonly hex: string;
    /** The digest rendered with `separator` and `letterCase`. */
    readonly formatted: string;
    /** Bytes digested (the DER of the input, or the public key bits for key-id). */
    readonly sizeBytes: number;
    readonly label: string | null;
    readonly from?: 'certificate' | 'csr' | 'spki';
    readonly outputLength?: number;
}

export const COMPUTE_FINGERPRINT_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode', 'algorithm', 'hex', 'formatted', 'sizeBytes', 'label', 'diagnostics', 'diagnosticCounts'],
    properties: {
        mode: { type: 'string', enum: [...MODES] },
        algorithm: { type: 'string', description: "SHA-1 | SHA-256 | SHA-384 | SHA-512, or 'SHAKE256'." },
        hex: { type: 'string', description: 'The digest as lowercase hex, no separator.' },
        formatted: { type: 'string', description: 'The digest with the separator and case asked for (AB:CD:… by default).' },
        sizeBytes: { type: 'integer', minimum: 0, description: 'Bytes digested: the DER of the input (fingerprint, shake256) or the public key bits (key-id).' },
        label: { type: ['string', 'null'], description: 'The PEM label of the input, null for DER.' },
        from: { type: 'string', enum: ['certificate', 'csr', 'spki'], description: 'key-id: where the public key came from.' },
        outputLength: { type: 'integer', minimum: 1, description: 'shake256: the output length in bytes.' },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const COMPUTE_FINGERPRINT_SUMMARY_PROPERTIES = {
    diagnosticCount: { type: 'integer' },
} as const;

export async function computeFingerprintTool(rawInput: unknown): Promise<ComputeFingerprintResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const obj = await loadPkiObject(input.input, 'input', LABELS.any, ctx);
    const label = obj.label ?? null;
    const format = (digest: Uint8Array): string => guard('Cannot format the digest', () => formatFingerprint(digest, { separator: input.separator, letterCase: input.letterCase }));
    if (input.mode === 'shake256') {
        const outputLength = input.outputLength ?? DEFAULT_SHAKE_OUTPUT_BYTES;
        const out = guard('Cannot compute SHAKE256', () => shake256(obj.der, outputLength));
        return withDiagnostics({ mode: 'shake256' as const, algorithm: 'SHAKE256', hex: toHex(out), formatted: format(out), sizeBytes: obj.der.byteLength, label, outputLength }, ctx.sink.report());
    }
    if (input.mode === 'key-id') {
        const algorithm = (input.algorithm ?? 'SHA-1') as (typeof KEY_ID_ALGORITHMS)[number];
        const key = publicKeyOf(obj, ctx);
        const id = guard('Cannot compute the key identifier', () => computeKeyIdentifier(key.bits, algorithm));
        return withDiagnostics({ mode: 'key-id' as const, algorithm, hex: toHex(id), formatted: format(id), sizeBytes: key.bits.byteLength, label, from: key.from }, ctx.sink.report());
    }
    const algorithm = input.algorithm ?? 'SHA-256';
    const digest = input.webcrypto
        ? await guardAsync('Cannot compute the fingerprint', () => computeFingerprintAsync(obj.der, algorithm))
        : guard('Cannot compute the fingerprint', () => computeFingerprint(obj.der, algorithm));
    return withDiagnostics({ mode: 'fingerprint' as const, algorithm, hex: toHex(digest), formatted: format(digest), sizeBytes: obj.der.byteLength, label }, ctx.sink.report());
}

export function computeFingerprintSummary(r: ComputeFingerprintResult): Record<string, unknown> {
    return { mode: r.mode, algorithm: r.algorithm, hex: r.hex, diagnosticCount: diagnosticCount(r) };
}

export const COMPUTE_FINGERPRINT_TOOL = defineTool<ComputeFingerprintResult>({
    name: COMPUTE_FINGERPRINT_NAME,
    title: 'Compute fingerprint (DER digest, key identifier, SHAKE256)',
    kind: 'read',
    description:
        `Read-only digest of ONE object. mode:'fingerprint' (default) hashes the exact DER of the input (SHA-256 by default; SHA-1 / SHA-384 / SHA-512; webcrypto:true uses Web Crypto, same result) — what openssl x509 -fingerprint prints; mode:'key-id' computes the RFC 5280 §4.2.1.2 key identifier (SHA-1 by default, or SHA-256) of the public key found in a certificate, a CSR or a PUBLIC KEY, reporting where it came from; mode:'shake256' squeezes outputLength bytes (default ${DEFAULT_SHAKE_OUTPUT_BYTES}, ≤ ${MAX_SHAKE_OUTPUT_BYTES}) of SHAKE256 — the digest of an Ed448 CMS signer. \`hex\` is lowercase without separators, \`formatted\` follows separator (':' default) and letterCase (upper default). Any PEM label or DER is accepted (a private key may be digested: the digest reveals nothing and no input byte is returned); a bundle of several blocks is refused (extract one with convert_pem). Refuses: an algorithm outside its mode, SHA-384/512 for a key identifier, outputLength or webcrypto outside their mode (VALIDATION_ERROR); key-id on an object that holds no public key (PKI_X509_* / PKI_ASN1_*). Token-frugal: verbosity:'summary', fields:[…].`,
    inputSchema: COMPUTE_FINGERPRINT_INPUT_SCHEMA,
    rawOutputSchema: COMPUTE_FINGERPRINT_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(COMPUTE_FINGERPRINT_OUTPUT_SCHEMA, COMPUTE_FINGERPRINT_SUMMARY_PROPERTIES, `The digest, formatted and as hex.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'SHA-256 fingerprint of a certificate in the sandbox', input: { input: { path: 'fixtures/leaf.crt.pem' } } },
        { title: 'The RFC 5280 key identifier of a CSR public key', input: { input: { path: 'fixtures/leaf.csr.pem' }, mode: 'key-id', fields: ['formatted', 'from'] } },
    ],
    handler: computeFingerprintTool,
    text: (r) => `${COMPUTE_FINGERPRINT_NAME}: ${r.algorithm}${r.mode === 'key-id' ? ` key identifier (${r.from ?? ''})` : r.mode === 'shake256' ? ` (${r.outputLength ?? 0} bytes)` : ''} of ${r.label ?? 'DER'} (${r.sizeBytes} bytes) = ${r.formatted.length > 160 ? `${r.formatted.slice(0, 160)}…` : r.formatted}`,
    summary: computeFingerprintSummary,
});
