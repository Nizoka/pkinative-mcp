/**
 * Tool: decode_extension — one extension value (the DER inside extnValue's
 * OCTET STRING) decoded by its OID through pkinative's extension dispatcher,
 * exactly as a certificate's extensions are: the 19 known kinds get their
 * members, any other OID is reported as kind `unknown` with its size.
 */
import { decodeExtensionValue, getOidName } from 'pkinative';
import { z } from 'zod';

import { HexSchema, hexSchema } from '../content-input.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { extensionView } from '../views.js';
import { fromHex, type Wire } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';

export const DECODE_EXTENSION_NAME = 'decode_extension';

export const DECODE_EXTENSION_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['oid'],
    properties: {
        oid: { type: 'string', pattern: '^\\d+(\\.\\d+)+$', description: 'The extension OID (2.5.29.19 basicConstraints, 2.5.29.17 subjectAltName, …) — it selects the decoder.' },
        valueHex: hexSchema('The extnValue content (the DER inside the OCTET STRING) as hex. Exclusive with value.'),
        value: pkiInputSchema('The extnValue content as DER bytes (derBase64, or a sandbox .der / .bin / .asn1 file)', ' Exclusive with valueHex.'),
        critical: { type: 'boolean', default: false, description: 'The criticality to report and to check against the kind (a kind RFC 5280 requires critical or non-critical gets a diagnostic).' },
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    oid: z.string().regex(/^\d+(\.\d+)+$/),
    valueHex: HexSchema.optional(),
    value: PkiInputSchema.optional(),
    critical: z.boolean().default(false),
    ...ParseShape,
    ...ProjectionShape,
}).superRefine((v, ctx) => {
    if ((v.valueHex === undefined) === (v.value === undefined)) ctx.addIssue({ code: 'custom', message: 'pass exactly one of valueHex / value', path: ['valueHex'] });
});

export interface DecodeExtensionResult extends DiagnosticsReport {
    readonly kind: string;
    readonly oid: string;
    readonly name: string | null;
    readonly critical: boolean;
    readonly sizeBytes: number;
    /** The decoded members (bytes as lowercase hex); empty for an unknown OID. */
    readonly decoded: Record<string, Wire>;
}

export const DECODE_EXTENSION_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['kind', 'oid', 'name', 'critical', 'sizeBytes', 'decoded', 'diagnostics', 'diagnosticCounts'],
    properties: {
        kind: { type: 'string', description: 'One of the 19 decoded kinds, or unknown.' },
        oid: { type: 'string' },
        name: { type: ['string', 'null'], description: 'The registry name of the OID.' },
        critical: { type: 'boolean' },
        sizeBytes: { type: 'integer', minimum: 0, description: 'Size of the value DER.' },
        decoded: { type: 'object', additionalProperties: true, description: 'The decoded members of the kind (cA / pathLenConstraint, usages, purposes, names, keyIdentifier, …); empty for an unknown OID.' },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const DECODE_EXTENSION_SUMMARY_PROPERTIES = {
    diagnosticCount: { type: 'integer' },
} as const;

const HEADER_KEYS: ReadonlySet<string> = new Set(['kind', 'oid', 'name', 'critical']);

const MALFORMED_REMEDY = 'the value is not a well-formed extension of that OID: check the hex (the extnValue CONTENT, not the whole Extension), or decode it as plain ASN.1 with decode_asn1';

export async function decodeExtension(rawInput: unknown): Promise<DecodeExtensionResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    let bytes: Uint8Array;
    if (input.valueHex !== undefined) {
        const parsed = fromHex(input.valueHex);
        if (parsed === undefined || parsed.length === 0) throw new ToolError('VALIDATION_ERROR', 'valueHex: expected an even number of hexadecimal digits.', { path: 'valueHex' });
        bytes = parsed;
    } else {
        bytes = (await loadPkiObject(input.value as z.infer<typeof PkiInputSchema>, 'value', LABELS.any, ctx)).der;
    }
    const ext = guard('Cannot decode the extension', () => decodeExtensionValue(input.oid, bytes, { ...ctx.options, critical: input.critical }), { PKI_X509_EXTENSION_MALFORMED: MALFORMED_REMEDY });
    const decoded = Object.fromEntries(Object.entries(extensionView(ext)).filter(([k]) => !HEADER_KEYS.has(k)));
    return withDiagnostics({
        kind: ext.kind,
        oid: ext.oid,
        name: getOidName(ext.oid) ?? null,
        critical: ext.critical,
        sizeBytes: bytes.length,
        decoded,
    }, ctx.sink.report());
}

export function decodeExtensionSummary(r: DecodeExtensionResult): Record<string, unknown> {
    return { kind: r.kind, oid: r.oid, name: r.name, critical: r.critical, sizeBytes: r.sizeBytes, diagnosticCount: diagnosticCount(r) };
}

export const DECODE_EXTENSION_TOOL = defineTool<DecodeExtensionResult>({
    name: DECODE_EXTENSION_NAME,
    title: 'Decode extension (one extnValue by OID, the 19 known kinds)',
    kind: 'read',
    description:
        "Read-only decode of ONE X.509 extension value by its OID — the bytes INSIDE extnValue's OCTET STRING, as `valueHex` or `value` (DER by derBase64 / sandbox path) — exactly as inspect_certificate decodes a certificate's extensions: the 19 known kinds (basicConstraints, keyUsage, extendedKeyUsage, subjectAltName, nameConstraints, certificatePolicies, crlDistributionPoints, authorityInfoAccess, SCT list, …) come back with their members, any other OID as kind 'unknown' with its size; `critical` (default false) is reported and checked against the kind's RFC 5280 rule (a diagnostic, not a refusal). A value that is not well-formed for that OID is refused with PKI_X509_EXTENSION_MALFORMED (remedy: decode_asn1 for the plain tree). Token-frugal: verbosity:'summary', fields:[…]. The input is not a whole Extension SEQUENCE: pass the extnValue content, as inspect_certificate rawExtensions:true reports it in valueDer.",
    inputSchema: DECODE_EXTENSION_INPUT_SCHEMA,
    rawOutputSchema: DECODE_EXTENSION_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(DECODE_EXTENSION_OUTPUT_SCHEMA, DECODE_EXTENSION_SUMMARY_PROPERTIES, `One decoded extension.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'A critical basicConstraints value', input: { oid: '2.5.29.19', valueHex: '30030101ff', critical: true } },
        { title: 'An extendedKeyUsage value, members only', input: { oid: '2.5.29.37', valueHex: '300a06082b06010505070301', fields: ['kind', 'decoded.purposes'] } },
    ],
    handler: decodeExtension,
    text: (r) => `${DECODE_EXTENSION_NAME}: ${r.oid}${r.name !== null ? ` (${r.name})` : ''} decoded as ${r.kind}${r.critical ? ', critical' : ''}, ${r.sizeBytes} bytes, ${r.diagnostics.length} diagnostic(s).`,
    summary: decodeExtensionSummary,
});
