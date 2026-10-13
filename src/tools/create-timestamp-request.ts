/**
 * Tool: create_timestamp_request — an RFC 3161 TimeStampReq over the digest
 * of `data` or over `digestHex`, with an optional nonce (random from
 * node:crypto on request — the engine generates nothing), policy and
 * certReq. The request is what the caller POSTs to a TSA (this server never
 * does): Content-Type application/timestamp-query.
 */
import { computeFingerprint, createTimeStampRequest, type TimeStampHashAlgorithm } from 'pkinative';
import { z } from 'zod';

import { ContentInputSchema, contentInputSchema, HexSchema, hexSchema, loadContent } from '../content-input.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { ARTEFACT_OUTPUT_PROPERTIES, emitArtefact, outputInputProperties, outputShape, type OutputResult } from '../output.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard } from '../pki-errors.js';
import { randomNonceInteger } from '../random.js';
import { fromHex, toHex } from '../wire.js';
import { defineTool, PRODUCES } from './_definition.js';
import { parseInput, ParseShape, withDiagnostics } from './_shared.js';

export const CREATE_TIMESTAMP_REQUEST_NAME = 'create_timestamp_request';

const HASHES = ['SHA-256', 'SHA-384', 'SHA-512'] as const satisfies readonly TimeStampHashAlgorithm[];
const DIGEST_BYTES: Readonly<Record<TimeStampHashAlgorithm, number>> = { 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 };
const NONCE_PATTERN = '^(random|\\d+|0x[0-9a-fA-F]+)$';
const OID_PATTERN = '^\\d+(\\.\\d+)+$';

export const CREATE_TIMESTAMP_REQUEST_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    properties: {
        data: contentInputSchema('The data to time-stamp (hashed here with hashAlgorithm; for a counter time-stamp, the signer\'s signature value from inspect_cms)'),
        digestHex: hexSchema('The digest to stamp, already computed with hashAlgorithm (its length must match). Exclusive with data.'),
        hashAlgorithm: { type: 'string', enum: [...HASHES], default: 'SHA-256', description: 'The message imprint algorithm.' },
        nonce: { type: 'string', pattern: NONCE_PATTERN, description: "A nonce the TSA must echo (RFC 3161 §2.4.1): 'random' (63 bits from node:crypto — summary.randomNonce reports it; such a call is never cached), a decimal or an 0x-hex integer. Without one, nothing ties a response to THIS request." },
        policy: { type: 'string', pattern: OID_PATTERN, description: 'The TSA policy to issue under (dotted OID); the TSA\'s default when absent.' },
        certReq: { type: 'boolean', default: true, description: 'Ask the TSA to include its certificate in the token (what verify_timestamp needs unless you pass candidates).' },
        ...PARSE_INPUT_PROPERTIES,
        ...outputInputProperties('der', '.tsq .der .bin for der; .pem for pem'),
    },
} as const;

const InputSchema = z.strictObject({
    data: ContentInputSchema.optional(),
    digestHex: HexSchema.optional(),
    hashAlgorithm: z.enum(HASHES).default('SHA-256'),
    nonce: z.string().regex(new RegExp(NONCE_PATTERN)).optional(),
    policy: z.string().regex(new RegExp(OID_PATTERN)).optional(),
    certReq: z.boolean().default(true),
    ...ParseShape,
    ...outputShape('der'),
}).superRefine((v, ctx) => {
    if ((v.data === undefined) === (v.digestHex === undefined)) ctx.addIssue({ code: 'custom', message: 'pass exactly one of data / digestHex', path: ['data'] });
});

export interface CreateTimestampRequestResult extends OutputResult, DiagnosticsReport {
    readonly summary: {
        readonly hashAlgorithm: TimeStampHashAlgorithm;
        readonly imprintHex: string;
        readonly nonce: string | null;
        readonly randomNonce: boolean;
        readonly policy: string | null;
        readonly certReq: boolean;
        readonly dataBytes: number | null;
    };
}

export const CREATE_TIMESTAMP_REQUEST_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode', 'encoding', 'sizeBytes', 'sha256', 'summary', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...ARTEFACT_OUTPUT_PROPERTIES,
        summary: {
            type: 'object',
            additionalProperties: false,
            required: ['hashAlgorithm', 'imprintHex', 'nonce', 'randomNonce', 'policy', 'certReq', 'dataBytes'],
            properties: {
                hashAlgorithm: { type: 'string', enum: [...HASHES] },
                imprintHex: { type: 'string', description: 'The message imprint written (hex) — keep it to check the token against.' },
                nonce: { type: ['string', 'null'], description: 'The nonce written, decimal — keep it (or the request bytes) for verify_timestamp.' },
                randomNonce: { type: 'boolean', description: 'true when the nonce came from the wrapper RNG (node:crypto).' },
                policy: { type: ['string', 'null'] },
                certReq: { type: 'boolean' },
                dataBytes: { type: ['integer', 'null'], description: 'Bytes hashed; null when a digest was given.' },
            },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

function nonceOf(raw: string | undefined): { value: bigint | undefined; random: boolean } {
    if (raw === undefined) return { value: undefined, random: false };
    if (raw === 'random') return { value: randomNonceInteger(), random: true };
    return { value: BigInt(raw), random: false };
}

export async function createTimestampRequestTool(rawInput: unknown): Promise<CreateTimestampRequestResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const expected = DIGEST_BYTES[input.hashAlgorithm];
    let digest: Uint8Array;
    let dataBytes: number | null = null;
    if (input.data !== undefined) {
        const { bytes } = await loadContent(input.data, 'data');
        digest = guard('Cannot hash the data', () => computeFingerprint(bytes, input.hashAlgorithm));
        dataBytes = bytes.length;
    } else {
        const bytes = fromHex(input.digestHex as string);
        if (bytes === undefined || bytes.length !== expected) {
            throw new ToolError('VALIDATION_ERROR', `digestHex must be ${expected} bytes for ${input.hashAlgorithm}, got ${bytes?.length ?? 'invalid hex'}.`, { path: 'digestHex', expectedBytes: expected, remedy: 'hashAlgorithm' });
        }
        digest = bytes;
    }
    const nonce = nonceOf(input.nonce);
    const der = guard('Cannot create the time-stamp request', () => createTimeStampRequest(digest, {
        hashAlgorithm: input.hashAlgorithm,
        ...(nonce.value !== undefined ? { nonce: nonce.value } : {}),
        ...(input.policy !== undefined ? { policy: input.policy } : {}),
        certReq: input.certReq,
    }));
    const artefact = await emitArtefact(der, {
        mode: input.outputMode,
        encoding: input.encoding,
        outputPath: input.outputPath,
        pemLabel: 'TIMESTAMP REQUEST',
        mimeType: 'application/timestamp-query',
        derExtensions: ['.tsq', '.der', '.bin'],
    });
    return withDiagnostics({
        ...artefact,
        summary: {
            hashAlgorithm: input.hashAlgorithm,
            imprintHex: toHex(digest),
            nonce: nonce.value === undefined ? null : nonce.value.toString(10),
            randomNonce: nonce.random,
            policy: input.policy ?? null,
            certReq: input.certReq,
            dataBytes,
        },
    }, ctx.sink.report());
}

export const CREATE_TIMESTAMP_REQUEST_TOOL = defineTool<CreateTimestampRequestResult>({
    name: CREATE_TIMESTAMP_REQUEST_NAME,
    title: 'Create time-stamp request (RFC 3161 TimeStampReq over data or a digest)',
    kind: 'artefact',
    description:
        "Build the RFC 3161 TimeStampReq you POST to a TSA yourself (Content-Type application/timestamp-query; this server never talks to a network): the message imprint is `hashAlgorithm` (SHA-256 default, SHA-384, SHA-512) over `data`, or `digestHex` already computed with it (wrong length → VALIDATION_ERROR). `nonce:'random'` draws 63 bits from node:crypto (summary.randomNonce:true; never cached) — without a nonce nothing ties the response to THIS request; a decimal or 0x-hex value pins it. `policy` names the TSA policy, `certReq` (default true) asks for the TSA certificate in the token. For a counter time-stamp over a CMS signature, the data is the signer's SIGNATURE VALUE (inspect_cms fields:['signerInfos.signature']), never the document. Keep the request bytes (or summary.imprintHex and nonce): verify_timestamp checks the response against them. Output DER (default; .tsq), PEM or hex, inline or as a sandbox file (never overwritten).",
    inputSchema: CREATE_TIMESTAMP_REQUEST_INPUT_SCHEMA,
    outputSchema: CREATE_TIMESTAMP_REQUEST_OUTPUT_SCHEMA,
    annotations: PRODUCES,
    cacheable: true,
    examples: [
        { title: 'A request over a file with a random nonce (ready to POST)', input: { data: { path: 'fixtures/content.txt' }, nonce: 'random' } },
        { title: 'A SHA-384 request over a precomputed digest, pinned nonce and policy, as hex', input: { digestHex: '00'.repeat(48), hashAlgorithm: 'SHA-384', nonce: '42', policy: '1.3.6.1.4.1.99999.1', certReq: false, encoding: 'hex' } },
    ],
    handler: createTimestampRequestTool,
    text: (r) => `${CREATE_TIMESTAMP_REQUEST_NAME}: TimeStampReq ${r.summary.hashAlgorithm} ${r.summary.imprintHex.slice(0, 16)}…${r.summary.nonce !== null ? `, nonce ${r.summary.nonce}${r.summary.randomNonce ? ' (random)' : ''}` : ', no nonce'}${r.summary.policy !== null ? `, policy ${r.summary.policy}` : ''}, certReq ${r.summary.certReq}, ${r.sizeBytes} bytes DER, sha256 ${r.sha256.slice(0, 16)}…${r.mode === 'file' ? `, written to ${r.filePath ?? ''}` : ` (${r.encoding} delivered as the embedded resource below)`}. POST it to your TSA as application/timestamp-query.`,
});
