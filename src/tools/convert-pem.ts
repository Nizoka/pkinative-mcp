/**
 * Tool: convert_pem — the RFC 7468 layer, both ways. `decode` lists every
 * block of a PEM text (label, size, offset, headers, SHA-256) and can hand one
 * block out as a DER / hex / PEM artefact; `encode` wraps DER bytes into one
 * PEM block under the label the caller names. A block whose label carries
 * secret material (PRIVATE KEY, ENCRYPTED PRIVATE KEY, …) is listed but never
 * extracted, and never produced: the key tools are the only way to a key.
 */
import { promises as fs } from 'node:fs';
import { z } from 'zod';

import { decodeAsn1 } from 'pkinative';

import { decodeDerBase64 } from '../base64.js';
import { assertInputWithin } from '../caps.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { SecurityError, ToolError } from '../errors.js';
import { ARTEFACT_OUTPUT_PROPERTIES, emitArtefact, outputInputProperties, outputShape, type ArtefactEncoding } from '../output.js';
import { createParseContext, PARSE_INPUT_PROPERTIES, type ParseContext } from '../parse-context.js';
import { guard } from '../pki-errors.js';
import { decodePemBlocks, isSecretLabel, isSecretMaterial, LABELS, looksLikePem, pkiInputSchema, PkiInputSchema, refuseSecretDer, type PkiInputFields } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { PKI_INPUT_EXTENSIONS, resolveInputFile } from '../sandbox.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, WRITES, type ArtefactAttachment } from './_definition.js';
import { diagnosticCount, parseInput, ParseShape, ProjectionShape, sha256Hex, withDiagnostics } from './_shared.js';

export const CONVERT_PEM_NAME = 'convert_pem';

/** The RFC 7468 label grammar this server accepts: upper-case words and digits, single spaces between them. */
export const PEM_LABEL_PATTERN = '^[A-Z0-9]+( [A-Z0-9]+)*$';
export const MAX_PEM_LABEL_LENGTH = 64;

/** JSON Schema of an artefact attachment carried by a read result (what server.ts puts under `artefact`). */
export const ARTEFACT_ATTACHMENT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    description: 'The artefact delivered alongside the report: its facts here, its bytes once as the embedded resource (or the resource_link in file mode).',
    properties: {
        ...ARTEFACT_OUTPUT_PROPERTIES,
        summary: { type: 'object', additionalProperties: true },
    },
} as const;

const MIME_BY_LABEL: Readonly<Record<string, string>> = {
    ...Object.fromEntries(LABELS.certificate.map((l) => [l, 'application/pkix-cert'])),
    ...Object.fromEntries(LABELS.csr.map((l) => [l, 'application/pkcs10'])),
    ...Object.fromEntries(LABELS.crl.map((l) => [l, 'application/pkix-crl'])),
    ...Object.fromEntries(LABELS.cms.map((l) => [l, 'application/pkcs7-mime'])),
};

/** The MIME type of the DER form of a PEM block, by label. */
export function mimeTypeForLabel(label: string): string {
    return MIME_BY_LABEL[label] ?? 'application/octet-stream';
}

/** Refuse a label that names key material: this server never produces or serves a private key. */
export function assertProducibleLabel(label: string, what: string): void {
    if (isSecretLabel(label)) {
        throw new SecurityError(`${what} '${label}' names private-key material: this server never produces, extracts or serves a private key.`, { label, remedy: 'inspect_private_key' });
    }
}

export const CONVERT_PEM_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode', 'input'],
    properties: {
        mode: { type: 'string', enum: ['decode', 'encode'], description: "'decode' lists the blocks of a PEM text (and extracts one with extractIndex); 'encode' wraps DER bytes into one PEM block." },
        input: pkiInputSchema('The PEM text (decode: pem or a path to a PEM file) or the DER bytes (encode: derBase64 or a path to a DER file)'),
        label: { type: 'string', minLength: 1, maxLength: MAX_PEM_LABEL_LENGTH, pattern: PEM_LABEL_PATTERN, description: "decode: list only the blocks with this label. encode: the label of the block (required; e.g. 'CERTIFICATE'). Upper-case words and digits separated by single spaces; a private-key label is refused (SECURITY_VIOLATION)." },
        extractIndex: { type: 'integer', minimum: 0, description: 'decode: also deliver the block with this index (its position in the text, as listed) as an artefact in `encoding`. A private-key block cannot be extracted (SECURITY_VIOLATION).' },
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
        ...outputInputProperties('der', '.der .crt .cer .csr .crl .p7s .bin … for der; .pem for pem'),
        encoding: {
            type: 'string',
            enum: ['pem', 'der', 'hex'],
            description: "Artefact encoding. decode + extractIndex: 'der' (default, raw bytes), 'pem' (the block re-emitted strictly) or 'hex' (inline only, ≤ 64 KiB). encode: always 'pem' (anything else is VALIDATION_ERROR).",
        },
    },
} as const;

const InputSchema = z.strictObject({
    mode: z.enum(['decode', 'encode']),
    input: PkiInputSchema,
    label: z.string().min(1).max(MAX_PEM_LABEL_LENGTH).regex(new RegExp(PEM_LABEL_PATTERN)).optional(),
    extractIndex: z.number().int().min(0).optional(),
    ...ParseShape,
    ...ProjectionShape,
    ...outputShape('der'),
    encoding: z.enum(['pem', 'der', 'hex']).optional(),
}).superRefine((v, ctx) => {
    if (v.mode === 'encode') {
        if (v.label === undefined) ctx.addIssue({ code: 'custom', message: "label is required to encode (e.g. 'CERTIFICATE')", path: ['label'] });
        if (v.extractIndex !== undefined) ctx.addIssue({ code: 'custom', message: 'extractIndex applies to decode', path: ['extractIndex'] });
        if (v.encoding !== undefined && v.encoding !== 'pem') ctx.addIssue({ code: 'custom', message: "encode produces PEM text: encoding must be 'pem' or omitted (decode with extractIndex delivers DER / hex)", path: ['encoding'] });
        if (v.input.pem !== undefined) ctx.addIssue({ code: 'custom', message: 'encode wraps DER bytes (derBase64 or a DER file path); the input is already PEM text — decode it instead', path: ['input', 'pem'] });
    } else {
        if (v.input.derBase64 !== undefined) ctx.addIssue({ code: 'custom', message: 'a PEM text is expected: pass it as pem (or a path to a PEM file); encode wraps DER bytes', path: ['input', 'derBase64'] });
        if (v.extractIndex === undefined) {
            if (v.encoding !== undefined) ctx.addIssue({ code: 'custom', message: 'encoding applies to the extracted block: pass extractIndex', path: ['encoding'] });
            if (v.outputMode === 'file' || v.outputPath !== undefined) ctx.addIssue({ code: 'custom', message: 'a file output needs extractIndex: without it, decode lists the blocks', path: ['outputPath'] });
        }
    }
});

export interface PemBlockView {
    readonly index: number;
    readonly label: string;
    readonly sizeBytes: number;
    readonly offset: number;
    readonly headers: ReadonlyArray<readonly [string, string]>;
    readonly sha256: string;
}

export interface ConvertPemResult extends ArtefactAttachment, DiagnosticsReport {
    readonly mode: 'decode' | 'encode';
    /** decode */
    readonly blocks?: readonly PemBlockView[];
    readonly count?: number;
    readonly extracted?: { readonly index: number; readonly label: string };
    /** encode */
    readonly label?: string;
    readonly sizeBytes?: number;
    readonly sha256?: string;
}

export const CONVERT_PEM_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode', 'diagnostics', 'diagnosticCounts'],
    properties: {
        mode: { type: 'string', enum: ['decode', 'encode'] },
        blocks: {
            type: 'array',
            description: 'decode: every block of the text (or those with `label`), in order. A private-key block is listed by label and size only.',
            items: {
                type: 'object',
                additionalProperties: false,
                required: ['index', 'label', 'sizeBytes', 'offset', 'headers', 'sha256'],
                properties: {
                    index: { type: 'integer', minimum: 0, description: 'Position in the text (what extractIndex takes).' },
                    label: { type: 'string' },
                    sizeBytes: { type: 'integer', minimum: 0, description: 'Decoded DER size.' },
                    offset: { type: 'integer', minimum: 0, description: 'Character offset of the -----BEGIN line.' },
                    headers: { type: 'array', items: { type: 'array', minItems: 2, maxItems: 2, items: { type: 'string' } }, description: "RFC 1421 headers as [name, value] pairs (only under pemMode:'lax')." },
                    sha256: { type: 'string', description: 'SHA-256 of the decoded DER (lowercase hex).' },
                },
            },
        },
        count: { type: 'integer', minimum: 0, description: 'decode: number of blocks listed.' },
        extracted: { type: 'object', additionalProperties: false, required: ['index', 'label'], properties: { index: { type: 'integer' }, label: { type: 'string' } }, description: 'decode: the block delivered as the artefact.' },
        label: { type: 'string', description: 'encode: the label written.' },
        sizeBytes: { type: 'integer', minimum: 0, description: 'encode: the DER size wrapped.' },
        sha256: { type: 'string', description: 'encode: SHA-256 of the DER wrapped (lowercase hex).' },
        artefact: ARTEFACT_ATTACHMENT_SCHEMA,
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const CONVERT_PEM_SUMMARY_PROPERTIES = {
    labels: { type: 'array', items: { type: 'string' }, description: 'decode: the label of every block listed.' },
    diagnosticCount: { type: 'integer' },
} as const;

async function readInputBytes(input: PkiInputFields, ctx: ParseContext): Promise<{ bytes: Uint8Array; source: string }> {
    const what = 'input';
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
    const { resolved, size } = await resolveInputFile(input.path, PKI_INPUT_EXTENSIONS, `${what}.path`);
    assertInputWithin(size, ctx.maxInputBytes, `${what}.path '${input.path ?? ''}'`);
    const buf = await fs.readFile(resolved);
    return { bytes: new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength), source: input.path ?? '' };
}

async function decode(input: z.infer<typeof InputSchema>, ctx: ParseContext): Promise<ConvertPemResult> {
    const { bytes, source } = await readInputBytes(input.input, ctx);
    if (!looksLikePem(bytes)) {
        throw new ToolError('VALIDATION_ERROR', `input (${source}) is not PEM text (no -----BEGIN line): a PEM text is expected — mode:'encode' wraps DER bytes.`, { path: 'input', remedy: "mode:'encode'" });
    }
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const all = decodePemBlocks(text, 'input', ctx);
    const listed = all.map((b, index) => ({ block: b, index })).filter(({ block }) => input.label === undefined || block.label === input.label);
    if (input.label !== undefined && listed.length === 0) {
        const present = [...new Set(all.map((b) => b.label))].join(', ') || 'none';
        throw new ToolError('PKI_PEM_UNEXPECTED_LABEL', `input (${source}) holds no ${input.label} block (labels present: ${present}).`, { errorClass: 'input', path: 'input', label: input.label, present: [...new Set(all.map((b) => b.label))] });
    }
    const blocks: PemBlockView[] = [];
    for (const { block, index } of listed) {
        blocks.push({ index, label: block.label, sizeBytes: block.bytes.byteLength, offset: block.offset, headers: block.headers.map(([k, v]) => [k, v] as const), sha256: await sha256Hex(block.bytes) });
    }
    let extracted: ConvertPemResult['extracted'];
    let artefact: ConvertPemResult['artefact'];
    if (input.extractIndex !== undefined) {
        const hit = listed.find(({ index }) => index === input.extractIndex);
        if (hit === undefined) {
            const available = listed.map(({ index }) => index);
            throw new ToolError('NOT_FOUND', `extractIndex ${input.extractIndex} names no ${input.label !== undefined ? `${input.label} ` : ''}block: the text holds ${all.length} block(s)${available.length > 0 ? ` (indexes available: ${available.join(', ')})` : ''}.`, { extractIndex: input.extractIndex, count: all.length, available });
        }
        assertProducibleLabel(hit.block.label, `the block at index ${hit.index}`);
        const encoding: ArtefactEncoding = input.encoding ?? 'der';
        artefact = await emitArtefact(hit.block.bytes, {
            mode: input.outputMode,
            encoding,
            outputPath: input.outputPath,
            pemLabel: hit.block.label,
            mimeType: mimeTypeForLabel(hit.block.label),
        });
        extracted = { index: hit.index, label: hit.block.label };
    }
    return withDiagnostics({
        mode: 'decode' as const,
        blocks,
        count: blocks.length,
        ...(extracted !== undefined ? { extracted } : {}),
        ...(artefact !== undefined ? { artefact } : {}),
    }, ctx.sink.report());
}

async function encode(input: z.infer<typeof InputSchema>, ctx: ParseContext): Promise<ConvertPemResult> {
    const label = input.label ?? '';
    assertProducibleLabel(label, 'label');
    const { bytes, source } = await readInputBytes(input.input, ctx);
    if (looksLikePem(bytes)) {
        throw new ToolError('VALIDATION_ERROR', `input (${source}) is already PEM text: encode wraps DER bytes — decode it with mode:'decode' (extractIndex delivers a block as DER).`, { path: 'input', remedy: "mode:'decode'" });
    }
    // A2-042: exactly one DER value is wrapped (a prefix or trailing bytes are a PKI_ASN1_* refusal), and
    // nothing that holds key material anywhere in it.
    guard(`Cannot read input (${source}) as one DER value`, () => decodeAsn1(bytes, ctx.options));
    refuseSecretDer(bytes, `input (${source})`, ctx, 'a PEM block would carry private-key bytes under any label');
    if (isSecretMaterial(bytes)) {
        throw new SecurityError(`input (${source}) holds private-key material: this server never wraps, extracts or serves a private key.`, { remedy: 'inspect_private_key' });
    }
    const artefact = await emitArtefact(bytes, {
        mode: input.outputMode,
        encoding: 'pem',
        outputPath: input.outputPath,
        pemLabel: label,
        mimeType: mimeTypeForLabel(label),
    });
    return withDiagnostics({ mode: 'encode' as const, label, sizeBytes: artefact.sizeBytes, sha256: artefact.sha256, artefact }, ctx.sink.report());
}

export async function convertPem(rawInput: unknown): Promise<ConvertPemResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    return input.mode === 'decode' ? decode(input, ctx) : encode(input, ctx);
}

export function convertPemSummary(r: ConvertPemResult): Record<string, unknown> {
    return {
        mode: r.mode,
        ...(r.blocks !== undefined ? { count: r.count, labels: r.blocks.map((b) => b.label) } : {}),
        ...(r.extracted !== undefined ? { extracted: r.extracted } : {}),
        ...(r.label !== undefined ? { label: r.label, sizeBytes: r.sizeBytes, sha256: r.sha256 } : {}),
        diagnosticCount: diagnosticCount(r),
    };
}

export const CONVERT_PEM_TOOL = defineTool<ConvertPemResult>({
    name: CONVERT_PEM_NAME,
    title: 'Convert PEM (list and extract blocks, or wrap DER)',
    kind: 'read',
    description:
        "The RFC 7468 layer. mode:'decode' lists every block of a PEM text (index, label, DER size, offset, RFC 1421 headers under pemMode:'lax', SHA-256 of the DER) — `label` keeps one kind, `extractIndex` also delivers that block as an artefact (encoding 'der' by default, 'pem' or 'hex'; inline as an embedded resource, or as a sandbox file with outputMode:'file' + outputPath, never overwritten). mode:'encode' wraps DER bytes (derBase64 or a DER file path) into one strict PEM block under `label` (required) and delivers it as the artefact (64-character lines, LF). A private-key block (PRIVATE KEY, ENCRYPTED PRIVATE KEY, RSA/EC/DSA PRIVATE KEY) is listed by label and size but never extracted, and never produced: SECURITY_VIOLATION (use inspect_private_key) — DER that parses as a PKCS#8 key or a PKCS#12 file is refused under ANY label. Refuses: derBase64 in decode, pem in encode, an encoding other than 'pem' in encode, a file output without extractIndex (VALIDATION_ERROR); an index past the last block (NOT_FOUND); a label absent from the text (PKI_PEM_UNEXPECTED_LABEL); a malformed text (PKI_PEM_* — pemMode:'lax' tolerates whitespace, line length and headers; a missing base64 padding is refused in both modes). Token-frugal: verbosity:'summary' (count + labels), fields:[…].",
    inputSchema: CONVERT_PEM_INPUT_SCHEMA,
    rawOutputSchema: CONVERT_PEM_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(CONVERT_PEM_OUTPUT_SCHEMA, CONVERT_PEM_SUMMARY_PROPERTIES, `The blocks of a PEM text (decode) or the PEM artefact facts (encode).${PROJECTION_NOTE}`),
    annotations: WRITES,
    cacheable: true,
    examples: [
        { title: 'The blocks of a PEM file in the sandbox', input: { mode: 'decode', input: { path: 'fixtures/inter.crt.pem' }, verbosity: 'summary' } },
        { title: 'Wrap a DER certificate into PEM', input: { mode: 'encode', input: { path: 'fixtures/leaf.crt.der' }, label: 'CERTIFICATE' } },
    ],
    handler: convertPem,
    text: (r) => r.mode === 'decode'
        ? `${CONVERT_PEM_NAME}: ${r.count ?? 0} block(s) [${(r.blocks ?? []).map((b) => `#${b.index} ${b.label} ${b.sizeBytes} B`).join(', ')}]${r.extracted !== undefined ? `; block #${r.extracted.index} (${r.extracted.label}) delivered as ${r.artefact?.encoding ?? 'der'}${r.artefact?.mode === 'file' ? ` at ${r.artefact.filePath ?? ''}` : ''}` : ''}, ${r.diagnostics.length} diagnostic(s).`
        : `${CONVERT_PEM_NAME}: ${r.sizeBytes ?? 0} DER bytes wrapped as ${r.label ?? ''} (sha256 ${(r.sha256 ?? '').slice(0, 16)}…)${r.artefact?.mode === 'file' ? `, written to ${r.artefact.filePath ?? ''}` : ', delivered as the embedded resource'}, ${r.diagnostics.length} diagnostic(s).`,
    summary: convertPemSummary,
});
