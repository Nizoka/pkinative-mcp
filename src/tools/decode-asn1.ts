/**
 * Tool: decode_asn1 — the X.690 layer of pkinative, exposed: the node tree
 * of any DER / BER object (like `openssl asn1parse`), one node read with a
 * typed reader, or a node re-encoded byte for byte as an artefact. Private
 * keys and PKCS#12 files are refused before any tree is built: a tree would
 * dump their bytes as hex previews.
 */
import {
    decodeAsn1,
    decodeAsn1Sequence,
    encodeAsn1Node,
    getOidName,
    readBitString,
    readBoolean,
    readEnumerated,
    readInteger,
    readNull,
    readObjectIdentifier,
    readOctetString,
    readRelativeOid,
    readSmallInteger,
    readString,
    readTime,
    type Asn1Node,
    type Asn1StringType,
    type PkiParseOptions,
    type TimeType,
} from 'pkinative';
import { z } from 'zod';

import { MAX_PREVIEW_BYTES, MAX_TREE_NODES } from '../caps.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { emitArtefact, outputInputProperties, outputShape } from '../output.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema, refuseSecretObject } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { TIME_VIEW_SCHEMA, timeView } from '../views.js';
import { toHex, type Wire } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY, type ArtefactAttachment } from './_definition.js';
import { diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';
import { ARTEFACT_ATTACHMENT_SCHEMA, mimeTypeForLabel } from './convert-pem.js';

export const DECODE_ASN1_NAME = 'decode_asn1';

export const READ_TYPES = ['boolean', 'integer', 'small-integer', 'enumerated', 'null', 'bit-string', 'octet-string', 'oid', 'relative-oid', 'string', 'time'] as const;
export type ReadType = (typeof READ_TYPES)[number];
const STRING_TYPES = ['utf8', 'numeric', 'printable', 'teletex', 'ia5', 'visible', 'universal', 'bmp'] as const satisfies readonly Asn1StringType[];
const TIME_TYPES = ['UTCTime', 'GeneralizedTime'] as const satisfies readonly TimeType[];
const NODE_PATH_PATTERN = '^\\d+(\\.\\d+)*$';

const UNIVERSAL_NAMES: Readonly<Record<number, string>> = {
    0: 'END OF CONTENTS', 1: 'BOOLEAN', 2: 'INTEGER', 3: 'BIT STRING', 4: 'OCTET STRING', 5: 'NULL', 6: 'OBJECT IDENTIFIER',
    7: 'ObjectDescriptor', 8: 'EXTERNAL', 9: 'REAL', 10: 'ENUMERATED', 11: 'EMBEDDED PDV', 12: 'UTF8String', 13: 'RELATIVE-OID',
    14: 'TIME', 16: 'SEQUENCE', 17: 'SET', 18: 'NumericString', 19: 'PrintableString', 20: 'TeletexString', 21: 'VideotexString',
    22: 'IA5String', 23: 'UTCTime', 24: 'GeneralizedTime', 25: 'GraphicString', 26: 'VisibleString', 27: 'GeneralString',
    28: 'UniversalString', 29: 'CHARACTER STRING', 30: 'BMPString', 31: 'DATE', 32: 'TIME-OF-DAY', 33: 'DATE-TIME', 34: 'DURATION',
};

/** `SEQUENCE`, `[0]`, `[APPLICATION 3]`, `[PRIVATE 0]`, `UNIVERSAL 99`. */
export function tagName(node: Pick<Asn1Node, 'tagClass' | 'tagNumber'>): string {
    switch (node.tagClass) {
        case 'universal': return UNIVERSAL_NAMES[node.tagNumber] ?? `UNIVERSAL ${node.tagNumber}`;
        case 'context': return `[${node.tagNumber}]`;
        default: return `[${node.tagClass.toUpperCase()} ${node.tagNumber}]`;
    }
}

export const DECODE_ASN1_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['input'],
    properties: {
        input: pkiInputSchema('The DER / BER object (any PEM label except a private key, or DER)', ' A private key or a PKCS#12 file is refused (SECURITY_VIOLATION).'),
        sequence: { type: 'boolean', default: false, description: 'The input is several top-level values back to back: decode each (exclusive with nodePath / read / reencode).' },
        nodePath: { type: 'string', pattern: NODE_PATH_PATTERN, maxLength: 256, description: "Child indices from the root, dot-separated ('0.2.1' = children[0].children[2].children[1]): the subtree listed, read or re-encoded. Omitted: the root. NOT_FOUND names the available range." },
        read: { type: 'string', enum: [...READ_TYPES], description: 'Apply this typed reader to the selected node (the root without nodePath) and return `value`; a wrong tag is PKI_ASN1_UNEXPECTED_TAG.' },
        stringType: { type: 'string', enum: [...STRING_TYPES], description: "read:'string' on an IMPLICIT-tagged node: the charset to decode with (required then — PKI_API_MISUSE otherwise)." },
        timeType: { type: 'string', enum: [...TIME_TYPES], description: "read:'time' on an IMPLICIT-tagged node: the time type (required then)." },
        reencode: { type: 'boolean', default: false, description: 'Re-encode the selected node through the engine encoder and deliver it as an artefact (`encoding` der by default, hex, or pem for a labelled whole input); `reencode.identical` says whether the bytes are the input bytes.' },
        allowTrailingData: { type: 'boolean', default: false, description: 'Accept bytes after the outermost value instead of PKI_ASN1_TRAILING_DATA (single value only; sequence:true decodes them instead).' },
        maxPreviewBytes: { type: 'integer', minimum: 0, maximum: 256, default: MAX_PREVIEW_BYTES, description: `Content bytes of a primitive shown in \`preview\` (hex; 0 hides previews; default ${MAX_PREVIEW_BYTES}).` },
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
        ...outputInputProperties('der', '.der .bin .asn1 for der; .pem for pem'),
    },
} as const;

const InputSchema = z.strictObject({
    input: PkiInputSchema,
    sequence: z.boolean().default(false),
    nodePath: z.string().max(256).regex(new RegExp(NODE_PATH_PATTERN)).optional(),
    read: z.enum(READ_TYPES).optional(),
    stringType: z.enum(STRING_TYPES).optional(),
    timeType: z.enum(TIME_TYPES).optional(),
    reencode: z.boolean().default(false),
    allowTrailingData: z.boolean().default(false),
    maxPreviewBytes: z.number().int().min(0).max(256).default(MAX_PREVIEW_BYTES),
    ...ParseShape,
    ...ProjectionShape,
    ...outputShape('der'),
}).superRefine((v, ctx) => {
    if (v.sequence && (v.nodePath !== undefined || v.read !== undefined || v.reencode)) ctx.addIssue({ code: 'custom', message: 'sequence lists every top-level value; nodePath, read and reencode work on one tree', path: ['sequence'] });
    if (v.read !== undefined && v.reencode) ctx.addIssue({ code: 'custom', message: 'read and reencode are separate modes; pass one', path: ['read'] });
    if (v.stringType !== undefined && v.read !== 'string') ctx.addIssue({ code: 'custom', message: "stringType applies to read:'string'", path: ['stringType'] });
    if (v.timeType !== undefined && v.read !== 'time') ctx.addIssue({ code: 'custom', message: "timeType applies to read:'time'", path: ['timeType'] });
    if (!v.reencode && (v.outputMode === 'file' || v.outputPath !== undefined)) ctx.addIssue({ code: 'custom', message: 'a file output needs reencode:true', path: ['outputPath'] });
});

export interface Asn1NodeView {
    /** Index of the top-level value (0 unless sequence:true). */
    readonly root: number;
    /** Child indices from the root, dot-separated; '' for the root itself (what nodePath takes). */
    readonly path: string;
    readonly depth: number;
    readonly offset: number;
    readonly headerLength: number;
    readonly contentLength: number;
    readonly indefinite: boolean;
    readonly tagClass: Asn1Node['tagClass'];
    readonly tagNumber: number;
    readonly tagName: string;
    readonly constructed: boolean;
    readonly childCount: number;
    readonly preview?: string;
    readonly previewTruncated?: true;
    readonly oid?: string;
    readonly oidName?: string | null;
}

export interface DecodeAsn1Result extends ArtefactAttachment, DiagnosticsReport {
    readonly label: string | null;
    readonly sizeBytes: number;
    readonly nodes: readonly Asn1NodeView[];
    readonly nodeCount: number;
    readonly truncated: boolean;
    readonly value?: { readonly type: ReadType; readonly value: Wire; readonly name?: string | null };
    readonly reencode?: { readonly identical: boolean };
}

const NODE_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['root', 'path', 'depth', 'offset', 'headerLength', 'contentLength', 'indefinite', 'tagClass', 'tagNumber', 'tagName', 'constructed', 'childCount'],
    properties: {
        root: { type: 'integer', minimum: 0, description: 'Index of the top-level value (0 unless sequence:true).' },
        path: { type: 'string', description: "Child indices from the root ('' for the root, '0.2' for children[0].children[2]) — what nodePath takes." },
        depth: { type: 'integer', minimum: 0 },
        offset: { type: 'integer', minimum: 0, description: 'Offset of the identifier octet in the input.' },
        headerLength: { type: 'integer', minimum: 0 },
        contentLength: { type: 'integer', minimum: 0 },
        indefinite: { type: 'boolean', description: 'BER indefinite length (never under DER).' },
        tagClass: { type: 'string', enum: ['universal', 'application', 'context', 'private'] },
        tagNumber: { type: 'integer', minimum: 0 },
        tagName: { type: 'string', description: "'SEQUENCE', 'INTEGER', …, '[0]', '[APPLICATION 3]'." },
        constructed: { type: 'boolean' },
        childCount: { type: 'integer', minimum: 0 },
        preview: { type: 'string', description: 'Primitive only: the first maxPreviewBytes content bytes as hex.' },
        previewTruncated: { type: 'boolean', description: 'Present when the content is longer than the preview.' },
        oid: { type: 'string', description: 'OBJECT IDENTIFIER only: the dotted value.' },
        oidName: { type: ['string', 'null'], description: 'OBJECT IDENTIFIER only: the registered name.' },
    },
} as const;

export const DECODE_ASN1_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['label', 'sizeBytes', 'nodes', 'nodeCount', 'truncated', 'diagnostics', 'diagnosticCounts'],
    properties: {
        label: { type: ['string', 'null'], description: 'The PEM label of the input, null for DER.' },
        sizeBytes: { type: 'integer', minimum: 0, description: 'Bytes of the input object.' },
        nodes: { type: 'array', items: NODE_VIEW_SCHEMA, description: 'The selected subtree (or every top-level tree with sequence:true), depth-first in input order.' },
        nodeCount: { type: 'integer', minimum: 0 },
        truncated: { type: 'boolean', description: `true when the listing stopped at ${MAX_TREE_NODES} nodes (use nodePath to walk the rest).` },
        value: {
            type: 'object',
            additionalProperties: false,
            required: ['type', 'value'],
            description: 'read: the typed value. boolean → boolean; integer / enumerated → decimal string; small-integer → number; null → null; bit-string → { hex, unusedBits }; octet-string → hex; oid / relative-oid → dotted string (name for a registered OID); string → { stringType, value }; time → { type, epochMilliseconds, iso, text }.',
            properties: {
                type: { type: 'string', enum: [...READ_TYPES] },
                value: {
                    anyOf: [
                        { type: 'boolean' }, { type: 'string' }, { type: 'number' }, { type: 'null' },
                        { type: 'object', additionalProperties: false, required: ['hex', 'unusedBits'], properties: { hex: { type: 'string' }, unusedBits: { type: 'integer', minimum: 0, maximum: 7 } } },
                        { type: 'object', additionalProperties: false, required: ['stringType', 'value'], properties: { stringType: { type: 'string', enum: [...STRING_TYPES] }, value: { type: 'string' } } },
                        TIME_VIEW_SCHEMA,
                    ],
                },
                name: { type: ['string', 'null'] },
            },
        },
        reencode: { type: 'object', additionalProperties: false, required: ['identical'], properties: { identical: { type: 'boolean', description: 'The re-encoded bytes equal the input bytes of the node.' } } },
        artefact: ARTEFACT_ATTACHMENT_SCHEMA,
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const DECODE_ASN1_SUMMARY_PROPERTIES = {
    label: DECODE_ASN1_OUTPUT_SCHEMA.properties.label,
    sizeBytes: DECODE_ASN1_OUTPUT_SCHEMA.properties.sizeBytes,
    nodeCount: DECODE_ASN1_OUTPUT_SCHEMA.properties.nodeCount,
    rootTag: { type: ['string', 'null'], description: 'tagName of the first node listed (null when nothing was listed).' },
    truncated: DECODE_ASN1_OUTPUT_SCHEMA.properties.truncated,
    value: DECODE_ASN1_OUTPUT_SCHEMA.properties.value,
    identical: { type: 'boolean', description: 'reencode: the bytes are identical.' },
    diagnosticCount: { type: 'integer' },
} as const;

/** Follow `nodePath` through the children; NOT_FOUND names the range available at the failing step. */
export function selectNode(root: Asn1Node, nodePath: string): Asn1Node {
    let node = root;
    const steps = nodePath.split('.');
    for (const [i, step] of steps.entries()) {
        const child = node.children[Number(step)];
        if (child === undefined) {
            const at = steps.slice(0, i).join('.');
            throw new ToolError('NOT_FOUND', `nodePath '${nodePath}': the node at '${at || '(root)'}' (${tagName(node)}) has ${node.children.length} child(ren)${node.children.length > 0 ? ` (0..${node.children.length - 1})` : ''}; step ${step} does not exist.`, { nodePath, step: Number(step), at, childCount: node.children.length });
        }
        node = child;
    }
    return node;
}

function nodeView(node: Asn1Node, root: number, path: string, depth: number, maxPreviewBytes: number, opts: PkiParseOptions): Asn1NodeView {
    const base = {
        root,
        path,
        depth,
        offset: node.offset,
        headerLength: node.headerLength,
        contentLength: node.contentLength,
        indefinite: node.indefinite,
        tagClass: node.tagClass,
        tagNumber: node.tagNumber,
        tagName: tagName(node),
        constructed: node.constructed,
        childCount: node.children.length,
    };
    if (node.constructed) return base;
    const preview = maxPreviewBytes > 0 ? { preview: toHex(node.content.subarray(0, maxPreviewBytes)), ...(node.content.byteLength > maxPreviewBytes ? { previewTruncated: true as const } : {}) } : {};
    let oid: { oid: string; oidName: string | null } | undefined;
    if (node.tagClass === 'universal' && node.tagNumber === 6) {
        try {
            const dotted = readObjectIdentifier(node, opts);
            oid = { oid: dotted, oidName: getOidName(dotted) ?? null };
        } catch {
            oid = undefined;
        }
    }
    return { ...base, ...preview, ...(oid !== undefined ? oid : {}) };
}

/** Depth-first listing of the subtrees, bounded by MAX_TREE_NODES. */
function listNodes(roots: ReadonlyArray<{ node: Asn1Node; root: number; path: string }>, maxPreviewBytes: number, opts: PkiParseOptions): { nodes: Asn1NodeView[]; truncated: boolean } {
    const nodes: Asn1NodeView[] = [];
    let truncated = false;
    const walk = (node: Asn1Node, root: number, path: string, depth: number): void => {
        if (truncated) return;
        if (nodes.length >= MAX_TREE_NODES) {
            truncated = true;
            return;
        }
        nodes.push(nodeView(node, root, path, depth, maxPreviewBytes, opts));
        node.children.forEach((child, i) => walk(child, root, path === '' ? String(i) : `${path}.${i}`, depth + 1));
    };
    for (const r of roots) walk(r.node, r.root, r.path, 0);
    return { nodes, truncated };
}

type ReadValue = NonNullable<DecodeAsn1Result['value']>;

function readValue(node: Asn1Node, type: ReadType, input: { stringType?: Asn1StringType | undefined; timeType?: TimeType | undefined }, opts: PkiParseOptions): ReadValue {
    return guard(`Cannot read the node as ${type}`, (): ReadValue => {
        switch (type) {
            case 'boolean': return { type, value: readBoolean(node, opts) };
            case 'integer': return { type, value: readInteger(node, opts).toString(10) };
            case 'small-integer': return { type, value: readSmallInteger(node) };
            case 'enumerated': return { type, value: readEnumerated(node, opts).toString(10) };
            case 'null': return { type, value: readNull(node) };
            case 'bit-string': {
                const bits = readBitString(node, opts);
                return { type, value: { hex: toHex(bits.bytes), unusedBits: bits.unusedBits } };
            }
            case 'octet-string': return { type, value: toHex(readOctetString(node, opts)) };
            case 'oid': {
                const oid = readObjectIdentifier(node, opts);
                return { type, value: oid, name: getOidName(oid) ?? null };
            }
            case 'relative-oid': return { type, value: readRelativeOid(node, opts) };
            case 'string': {
                const s = readString(node, { ...opts, ...(input.stringType !== undefined ? { stringType: input.stringType } : {}) });
                return { type, value: { stringType: s.stringType, value: s.value } };
            }
            case 'time': return { type, value: timeView(readTime(node, { ...opts, ...(input.timeType !== undefined ? { timeType: input.timeType } : {}) })) };
        }
    });
}

export async function decodeAsn1Tool(rawInput: unknown): Promise<DecodeAsn1Result> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const obj = await loadPkiObject(input.input, 'input', LABELS.any, ctx);
    refuseSecretObject(obj, ctx, 'a node tree would dump its bytes');
    const opts = { ...ctx.options, allowTrailingData: input.allowTrailingData };
    const common = { label: obj.label ?? null, sizeBytes: obj.der.byteLength };

    if (input.sequence) {
        const roots = guard('Cannot decode the input', () => decodeAsn1Sequence(obj.der, opts));
        const { nodes, truncated } = listNodes(roots.map((node, root) => ({ node, root, path: '' })), input.maxPreviewBytes, ctx.options);
        return withDiagnostics({ ...common, nodes, nodeCount: nodes.length, truncated }, ctx.sink.report());
    }

    const root = guard('Cannot decode the input', () => decodeAsn1(obj.der, opts));
    const node = input.nodePath === undefined ? root : selectNode(root, input.nodePath);
    const { nodes, truncated } = listNodes([{ node, root: 0, path: input.nodePath ?? '' }], input.maxPreviewBytes, ctx.options);
    let value: DecodeAsn1Result['value'];
    let reencode: DecodeAsn1Result['reencode'];
    let artefact: DecodeAsn1Result['artefact'];
    if (input.read !== undefined) {
        value = readValue(node, input.read, input, ctx.options);
    } else if (input.reencode) {
        const der = guard('Cannot re-encode the node', () => encodeAsn1Node(node));
        const identical = der.byteLength === node.bytes.byteLength && der.every((b, i) => b === node.bytes[i]);
        if (input.encoding === 'pem' && (obj.label === undefined || input.nodePath !== undefined)) {
            throw new ToolError('VALIDATION_ERROR', "encoding:'pem' re-emits a whole labelled PEM input: this input has no label or nodePath selects a sub-node — use encoding:'der' or 'hex'.", { path: 'encoding', remedy: "encoding:'der'" });
        }
        artefact = await emitArtefact(der, {
            mode: input.outputMode,
            encoding: input.encoding,
            outputPath: input.outputPath,
            pemLabel: obj.label ?? '',
            mimeType: obj.label !== undefined && input.nodePath === undefined ? mimeTypeForLabel(obj.label) : 'application/octet-stream',
            derExtensions: ['.der', '.bin', '.asn1'],
        });
        reencode = { identical };
    }
    return withDiagnostics({
        ...common,
        nodes,
        nodeCount: nodes.length,
        truncated,
        ...(value !== undefined ? { value } : {}),
        ...(reencode !== undefined ? { reencode } : {}),
        ...(artefact !== undefined ? { artefact } : {}),
    }, ctx.sink.report());
}

export function decodeAsn1Summary(r: DecodeAsn1Result): Record<string, unknown> {
    return {
        label: r.label,
        sizeBytes: r.sizeBytes,
        nodeCount: r.nodeCount,
        rootTag: r.nodes[0]?.tagName ?? null,
        truncated: r.truncated,
        ...(r.value !== undefined ? { value: r.value } : {}),
        ...(r.reencode !== undefined ? { identical: r.reencode.identical } : {}),
        diagnosticCount: diagnosticCount(r),
    };
}

export const DECODE_ASN1_TOOL = defineTool<DecodeAsn1Result>({
    name: DECODE_ASN1_NAME,
    title: 'Decode ASN.1 (node tree, typed read, re-encode)',
    kind: 'read',
    description:
        `Read-only X.690 view of any DER object (BER with encodingRules:'ber'): the node tree — offset, header and content lengths, tag class / number / name, constructed flag, child count, a hex preview of each primitive (maxPreviewBytes, default ${MAX_PREVIEW_BYTES}) and the dotted value + registered name of every OBJECT IDENTIFIER — depth-first, capped at ${MAX_TREE_NODES} nodes (truncated:true). \`nodePath\` ('0.2.1' = child indices from the root; each node's \`path\` is what to pass) narrows to a subtree; \`read\` applies a typed reader to the selected node (boolean, integer, small-integer, enumerated, null, bit-string, octet-string, oid, relative-oid, string with stringType for an IMPLICIT tag, time with timeType) and returns \`value\` in wire form (bigint as decimal string, bytes as hex, time as epoch ms + ISO); \`reencode:true\` re-encodes the selected node through the engine and delivers it as an artefact (der / hex / pem for a labelled whole input; inline or a sandbox file) with reencode.identical; \`sequence:true\` decodes several top-level values back to back; allowTrailingData:true tolerates bytes after a single value. Refuses a private key or a PKCS#12 file — by PEM label, or when the DER parses as PKCS#8 / PKCS#12 — with SECURITY_VIOLATION (inspect_private_key / inspect_pkcs12 report them safely); a missing nodePath step is NOT_FOUND naming the range; a wrong reader tag is PKI_ASN1_UNEXPECTED_TAG; an IMPLICIT string / time without stringType / timeType is PKI_API_MISUSE; X.690 violations are PKI_ASN1_* (BER forms: encodingRules:'ber'). Token-frugal: verbosity:'summary' (node count, root tag, value), fields:['nodes.path','nodes.tagName'].`,
    inputSchema: DECODE_ASN1_INPUT_SCHEMA,
    rawOutputSchema: DECODE_ASN1_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(DECODE_ASN1_OUTPUT_SCHEMA, DECODE_ASN1_SUMMARY_PROPERTIES, `The ASN.1 node tree, a typed value, or the re-encoded artefact facts.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'The shape of a certificate (paths and tags only)', input: { input: { path: 'fixtures/leaf.crt.pem' }, fields: ['nodes.path', 'nodes.tagName', 'nodes.oidName', 'nodeCount'] } },
        { title: 'Read the serial number of a certificate (tbsCertificate.serialNumber)', input: { input: { path: 'fixtures/leaf.crt.der' }, nodePath: '0.1', read: 'integer', verbosity: 'summary' } },
    ],
    handler: decodeAsn1Tool,
    text: (r) => {
        const first = r.nodes[0];
        const head = `${DECODE_ASN1_NAME}: ${r.label ?? 'DER'} (${r.sizeBytes} bytes), ${r.nodeCount} node(s)${r.truncated ? ' (truncated)' : ''}, root ${first?.tagName ?? '—'}`;
        if (r.value !== undefined) return `${head}; ${r.value.type} = ${typeof r.value.value === 'object' && r.value.value !== null ? JSON.stringify(r.value.value) : String(r.value.value)}${r.value.name !== undefined && r.value.name !== null ? ` (${r.value.name})` : ''}.`;
        if (r.reencode !== undefined) return `${head}; re-encoded ${r.artefact?.sizeBytes ?? 0} bytes (${r.reencode.identical ? 'identical' : 'DIFFERENT'})${r.artefact?.mode === 'file' ? `, written to ${r.artefact.filePath ?? ''}` : ' delivered as the embedded resource'}.`;
        return `${head}, ${r.diagnostics.length} diagnostic(s).`;
    },
    summary: decodeAsn1Summary,
});
