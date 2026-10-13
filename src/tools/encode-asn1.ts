/**
 * Tool: encode_asn1 — a JSON node spec → DER through the engine's own
 * encoders (every node type pkinative encodes: the primitives, the three
 * constructed forms, explicit / implicit tagging, a raw TLV and pre-encoded
 * DER). The result is decoded back for the summary, so a spec that encodes
 * is also a spec that parses.
 */
import { decodeAsn1 } from 'pkinative';
import { z } from 'zod';

import { ASN1_NODE_SPEC_SCHEMA, encodeSpec } from '../asn1-spec.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ARTEFACT_OUTPUT_PROPERTIES, emitArtefact, outputInputProperties, outputShape, type OutputResult } from '../output.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard } from '../pki-errors.js';
import { defineTool, WRITES } from './_definition.js';
import { parseInput, ParseShape, withDiagnostics } from './_shared.js';
import { assertProducibleLabel, MAX_PEM_LABEL_LENGTH, PEM_LABEL_PATTERN } from './convert-pem.js';
import { tagName } from './decode-asn1.js';

export const ENCODE_ASN1_NAME = 'encode_asn1';

export const ENCODE_ASN1_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['spec'],
    properties: {
        spec: ASN1_NODE_SPEC_SCHEMA,
        label: { type: 'string', minLength: 1, maxLength: MAX_PEM_LABEL_LENGTH, pattern: PEM_LABEL_PATTERN, description: "The PEM label for encoding:'pem' (required then; upper-case words and digits). A private-key label is refused." },
        ...PARSE_INPUT_PROPERTIES,
        ...outputInputProperties('der', '.der .bin .asn1 for der; .pem for pem'),
    },
} as const;

const InputSchema = z.strictObject({
    spec: z.looseObject({ type: z.string() }),
    label: z.string().min(1).max(MAX_PEM_LABEL_LENGTH).regex(new RegExp(PEM_LABEL_PATTERN)).optional(),
    ...ParseShape,
    ...outputShape('der'),
}).superRefine((v, ctx) => {
    if (v.encoding === 'pem' && v.label === undefined) ctx.addIssue({ code: 'custom', message: "encoding:'pem' needs a label (e.g. 'ASN1 VALUE')", path: ['label'] });
    if (v.encoding !== 'pem' && v.label !== undefined) ctx.addIssue({ code: 'custom', message: "label applies to encoding:'pem'", path: ['label'] });
});

export interface EncodeAsn1Result extends OutputResult, DiagnosticsReport {
    readonly summary: {
        readonly rootTag: string;
        readonly nodeCount: number;
        readonly sizeBytes: number;
    };
}

export const ENCODE_ASN1_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode', 'encoding', 'sizeBytes', 'sha256', 'summary', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...ARTEFACT_OUTPUT_PROPERTIES,
        summary: {
            type: 'object',
            additionalProperties: false,
            required: ['rootTag', 'nodeCount', 'sizeBytes'],
            properties: {
                rootTag: { type: 'string', description: "The tag name of the root value ('SEQUENCE', '[0]', …)." },
                nodeCount: { type: 'integer', minimum: 1, description: 'Nodes of the encoded value, decoded back.' },
                sizeBytes: { type: 'integer', minimum: 0 },
            },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export async function encodeAsn1Tool(rawInput: unknown): Promise<EncodeAsn1Result> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    if (input.label !== undefined) assertProducibleLabel(input.label, 'label');
    const der = encodeSpec(input.spec, ctx);
    const root = guard('Cannot decode the value just encoded', () => decodeAsn1(der, ctx.options));
    let nodeCount = 0;
    const count = (node: typeof root): void => {
        nodeCount += 1;
        for (const child of node.children) count(child);
    };
    count(root);
    const artefact = await emitArtefact(der, {
        mode: input.outputMode,
        encoding: input.encoding,
        outputPath: input.outputPath,
        pemLabel: input.label ?? '',
        mimeType: 'application/octet-stream',
        derExtensions: ['.der', '.bin', '.asn1'],
    });
    return withDiagnostics({
        ...artefact,
        summary: { rootTag: tagName(root), nodeCount, sizeBytes: der.byteLength },
    }, ctx.sink.report());
}

export const ENCODE_ASN1_TOOL = defineTool<EncodeAsn1Result>({
    name: ENCODE_ASN1_NAME,
    title: 'Encode ASN.1 (JSON node spec to DER)',
    kind: 'artefact',
    description:
        "Encode a JSON node spec into DER through the engine's own encoders: `spec` is one node { type, … } — boolean (value), integer / enumerated (value: integer, decimal or 0x-hex string, negative allowed), null, bit-string (hex, unusedBits), named-bits (bits[]), octet-string (hex), oid / relative-oid (value), string (stringType utf8|numeric|printable|teletex|ia5|visible|universal|bmp, value), time (value: ISO instant or epoch ms; timeType UTCTime|GeneralizedTime|rfc5280 — the RFC 5280 rule by default), sequence / set / set-of (children[]; set-of is sorted as DER requires), explicit / implicit (tag, class universal|application|context|private, inner), tlv (class, tag, constructed, hex) and der (hex of one pre-encoded value, checked). Nesting is bounded by limits.maxDepth (PKI_LIMIT_EXCEEDED). The bytes are decoded back for the summary (root tag, node count). Output DER (default), hex (inline, ≤ 64 KiB) or PEM under `label`, inline as an embedded resource or as a sandbox file (never overwritten). Refuses a malformed node naming its JSON path ($.children[1].value …), a PEM encoding without label, a private-key label (SECURITY_VIOLATION); a value the engine cannot encode is PKI_ASN1_* / PKI_OID_INVALID. Deterministic: the same spec gives the same bytes. The inverse of decode_asn1 (its tree uses the same vocabulary).",
    inputSchema: ENCODE_ASN1_INPUT_SCHEMA,
    outputSchema: ENCODE_ASN1_OUTPUT_SCHEMA,
    annotations: WRITES,
    cacheable: true,
    examples: [
        { title: 'An AlgorithmIdentifier for ecdsa-with-SHA256, as hex', input: { spec: { type: 'sequence', children: [{ type: 'oid', value: '1.2.840.10045.4.3.2' }] }, encoding: 'hex' } },
        { title: 'A GeneralName [2] dNSName inside a SEQUENCE, as PEM', input: { spec: { type: 'sequence', children: [{ type: 'implicit', tag: 2, class: 'context', inner: { type: 'string', stringType: 'ia5', value: 'example.test' } }] }, encoding: 'pem', label: 'GENERAL NAMES' } },
    ],
    handler: encodeAsn1Tool,
    text: (r) => `${ENCODE_ASN1_NAME}: ${r.summary.rootTag} of ${r.summary.nodeCount} node(s), ${r.sizeBytes} bytes DER, sha256 ${r.sha256.slice(0, 16)}…${r.mode === 'file' ? `, written to ${r.filePath ?? ''}` : r.encoding === 'hex' ? ' (hex in structuredContent)' : ` (${r.encoding} delivered as the embedded resource below)`}.`,
});
