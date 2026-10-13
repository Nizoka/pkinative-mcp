/**
 * Tool: resolve_oid — object identifiers: the registered name of dotted
 * OIDs, their X.660 validity, the registry listing (paged, filtered), and
 * the X.690 encoding both ways (content octets or a whole TLV, OBJECT
 * IDENTIFIER or RELATIVE-OID).
 */
import {
    decodeAsn1,
    decodeOid,
    encodeObjectIdentifier,
    encodeOid,
    encodeRelativeOid,
    getOidName,
    isValidOid,
    OID_REGISTRY,
    readObjectIdentifier,
    readRelativeOid,
} from 'pkinative';
import { z } from 'zod';

import { DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, MAX_OIDS_PER_CALL } from '../caps.js';
import { hexSchema, HexSchema } from '../content-input.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard } from '../pki-errors.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { fromHex, toHex } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';

export const RESOLVE_OID_NAME = 'resolve_oid';

export const OID_MODES = ['name', 'validate', 'list', 'encode', 'decode'] as const;
export type OidMode = (typeof OID_MODES)[number];
const FORMS = ['content', 'tlv'] as const;
const MAX_OID_TEXT_LENGTH = 1024;
const MAX_FILTER_LENGTH = 200;

export const RESOLVE_OID_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode'],
    properties: {
        mode: { type: 'string', enum: [...OID_MODES], description: "'name' (registered names), 'validate' (X.660 validity), 'list' (the registry, paged), 'encode' (dotted → hex), 'decode' (hex → dotted + name)." },
        oids: { type: 'array', minItems: 1, maxItems: MAX_OIDS_PER_CALL, items: { type: 'string', minLength: 1, maxLength: MAX_OID_TEXT_LENGTH }, description: `name / validate / encode: the dotted OIDs (≤ ${MAX_OIDS_PER_CALL}).` },
        filter: { type: 'string', minLength: 1, maxLength: MAX_FILTER_LENGTH, description: 'list: case-insensitive substring of the name or the dotted OID.' },
        offset: { type: 'integer', minimum: 0, default: 0, description: 'list: first entry returned.' },
        limit: { type: 'integer', minimum: 1, maximum: MAX_LIST_LIMIT, default: DEFAULT_LIST_LIMIT, description: `list: page size (≤ ${MAX_LIST_LIMIT}).` },
        form: { type: 'string', enum: [...FORMS], default: 'content', description: "encode / decode: 'content' (the base-128 content octets only) or 'tlv' (tag + length + content, i.e. the whole DER value)." },
        relative: { type: 'boolean', default: false, description: "encode / decode: a RELATIVE-OID (X.690 §8.20, universal tag 13) instead of an OBJECT IDENTIFIER — needs form:'tlv' (the engine encodes a relative OID as a whole TLV only)." },
        hex: hexSchema('decode: the octets to decode (content octets, or the whole TLV with form:\'tlv\').'),
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    mode: z.enum(OID_MODES),
    oids: z.array(z.string().min(1).max(MAX_OID_TEXT_LENGTH)).min(1).max(MAX_OIDS_PER_CALL).optional(),
    filter: z.string().min(1).max(MAX_FILTER_LENGTH).optional(),
    offset: z.number().int().min(0).default(0),
    limit: z.number().int().min(1).max(MAX_LIST_LIMIT).default(DEFAULT_LIST_LIMIT),
    form: z.enum(FORMS).default('content'),
    relative: z.boolean().default(false),
    hex: HexSchema.optional(),
    ...ParseShape,
    ...ProjectionShape,
}).superRefine((v, ctx) => {
    const needsOids = v.mode === 'name' || v.mode === 'validate' || v.mode === 'encode';
    if (needsOids && v.oids === undefined) ctx.addIssue({ code: 'custom', message: `oids is required for mode '${v.mode}'`, path: ['oids'] });
    if (!needsOids && v.oids !== undefined) ctx.addIssue({ code: 'custom', message: 'oids applies to name / validate / encode', path: ['oids'] });
    if (v.mode === 'decode' && v.hex === undefined) ctx.addIssue({ code: 'custom', message: "hex is required for mode 'decode'", path: ['hex'] });
    if (v.mode !== 'decode' && v.hex !== undefined) ctx.addIssue({ code: 'custom', message: 'hex applies to decode', path: ['hex'] });
    if (v.mode !== 'list' && v.filter !== undefined) ctx.addIssue({ code: 'custom', message: 'filter applies to list', path: ['filter'] });
    const codec = v.mode === 'encode' || v.mode === 'decode';
    if (!codec && v.relative) ctx.addIssue({ code: 'custom', message: 'relative applies to encode / decode', path: ['relative'] });
    if (codec && v.relative && v.form !== 'tlv') ctx.addIssue({ code: 'custom', message: "relative needs form:'tlv': pkinative encodes and decodes a RELATIVE-OID as a whole TLV only", path: ['relative'] });
});

export interface OidRegistryRow {
    readonly oid: string;
    readonly name: string;
    readonly standard: string;
}

export interface ResolveOidResult extends DiagnosticsReport {
    readonly mode: OidMode;
    /** name / validate / encode */
    readonly oids?: ReadonlyArray<{ readonly oid: string; readonly name?: string | null; readonly valid?: boolean; readonly hex?: string }>;
    readonly allValid?: boolean;
    /** list */
    readonly entries?: readonly OidRegistryRow[];
    readonly total?: number;
    readonly offset?: number;
    readonly limit?: number;
    readonly hasMore?: boolean;
    /** decode */
    readonly oid?: string;
    readonly name?: string | null;
}

export const RESOLVE_OID_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode', 'diagnostics', 'diagnosticCounts'],
    properties: {
        mode: { type: 'string', enum: [...OID_MODES] },
        oids: {
            type: 'array',
            description: 'name: { oid, name|null }; validate: { oid, valid }; encode: { oid, hex }.',
            items: {
                type: 'object',
                additionalProperties: false,
                required: ['oid'],
                properties: {
                    oid: { type: 'string' },
                    name: { type: ['string', 'null'], description: 'The registered name, null when the registry does not list it.' },
                    valid: { type: 'boolean' },
                    hex: { type: 'string', description: 'Lowercase hex of the content octets (form content) or of the whole TLV (form tlv).' },
                },
            },
        },
        allValid: { type: 'boolean', description: 'validate: true when every OID is valid.' },
        entries: {
            type: 'array',
            description: 'list: the page of registry entries.',
            items: { type: 'object', additionalProperties: false, required: ['oid', 'name', 'standard'], properties: { oid: { type: 'string' }, name: { type: 'string' }, standard: { type: 'string' } } },
        },
        total: { type: 'integer', minimum: 0, description: 'list: entries matching the filter.' },
        offset: { type: 'integer', minimum: 0 },
        limit: { type: 'integer', minimum: 1 },
        hasMore: { type: 'boolean' },
        oid: { type: 'string', description: 'decode: the dotted OID.' },
        name: { type: ['string', 'null'], description: 'decode: the registered name (null when unregistered or relative).' },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const RESOLVE_OID_SUMMARY_PROPERTIES = {
    count: { type: 'integer', description: 'Number of OIDs / entries in the result.' },
    diagnosticCount: { type: 'integer' },
} as const;

export async function resolveOid(rawInput: unknown): Promise<ResolveOidResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const report = (body: Omit<ResolveOidResult, 'mode' | keyof DiagnosticsReport>): ResolveOidResult => withDiagnostics({ mode: input.mode, ...body }, ctx.sink.report());
    const oids = input.oids ?? [];
    switch (input.mode) {
        case 'name':
            return report({ oids: oids.map((oid) => ({ oid, name: getOidName(oid) ?? null })) });
        case 'validate': {
            const rows = oids.map((oid) => ({ oid, valid: isValidOid(oid) }));
            return report({ oids: rows, allValid: rows.every((r) => r.valid) });
        }
        case 'list': {
            const needle = input.filter?.toLowerCase();
            const matching = needle === undefined ? OID_REGISTRY : OID_REGISTRY.filter((e) => e.oid.toLowerCase().includes(needle) || e.name.toLowerCase().includes(needle));
            const page = matching.slice(input.offset, input.offset + input.limit).map((e) => ({ oid: e.oid, name: e.name, standard: e.standard }));
            return report({ entries: page, total: matching.length, offset: input.offset, limit: input.limit, hasMore: input.offset + page.length < matching.length });
        }
        case 'encode': {
            const rows = oids.map((oid) => ({
                oid,
                hex: toHex(guard(`Cannot encode ${oid}`, () => (input.relative ? encodeRelativeOid(oid) : input.form === 'tlv' ? encodeObjectIdentifier(oid) : encodeOid(oid)))),
            }));
            return report({ oids: rows });
        }
        case 'decode': {
            const bytes = fromHex(input.hex ?? '') ?? new Uint8Array(0);
            const opts = ctx.options;
            const oid = guard('Cannot decode the OID', () => {
                if (input.form === 'content') return decodeOid(bytes, opts);
                const node = decodeAsn1(bytes, opts);
                return input.relative ? readRelativeOid(node, opts) : readObjectIdentifier(node, opts);
            });
            return report({ oid, name: input.relative ? null : getOidName(oid) ?? null });
        }
    }
}

function countOf(r: ResolveOidResult): number {
    return r.oids?.length ?? r.entries?.length ?? (r.oid !== undefined ? 1 : 0);
}

export function resolveOidSummary(r: ResolveOidResult): Record<string, unknown> {
    return {
        mode: r.mode,
        count: countOf(r),
        ...(r.allValid !== undefined ? { allValid: r.allValid } : {}),
        ...(r.total !== undefined ? { total: r.total, hasMore: r.hasMore } : {}),
        ...(r.oid !== undefined ? { oid: r.oid, name: r.name } : {}),
        diagnosticCount: diagnosticCount(r),
    };
}

export const RESOLVE_OID_TOOL = defineTool<ResolveOidResult>({
    name: RESOLVE_OID_NAME,
    title: 'Resolve OID (name, validate, list, encode, decode)',
    kind: 'read',
    description:
        `Object identifiers in one call. mode:'name' → the registered name of each dotted OID (null when unregistered; ≤ ${MAX_OIDS_PER_CALL} per call); 'validate' → X.660 validity of each (at least two arcs, first arc 0–2, second ≤ 39 under 0 and 1, no leading zeros — reported, never an error); 'list' → the engine's registry (oid, name, standard), filtered by a case-insensitive substring of the name or the OID, paged with offset / limit (default ${DEFAULT_LIST_LIMIT}, ≤ ${MAX_LIST_LIMIT}); 'encode' → the X.690 bytes of each OID as hex, form 'content' (base-128 content octets, default) or 'tlv' (tag + length + content), relative:true for a RELATIVE-OID (tlv only); 'decode' → the dotted OID of hex octets (content, or a whole TLV with form:'tlv') with its name. Refuses: a member outside its mode, relative without form:'tlv' (VALIDATION_ERROR); an invalid OID in encode (PKI_OID_INVALID — validate reports it instead); malformed octets in decode (PKI_OID_INVALID, PKI_ASN1_*). Token-frugal: verbosity:'summary', fields:[…].`,
    inputSchema: RESOLVE_OID_INPUT_SCHEMA,
    rawOutputSchema: RESOLVE_OID_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(RESOLVE_OID_OUTPUT_SCHEMA, RESOLVE_OID_SUMMARY_PROPERTIES, `OID names, validity, registry page or encoding.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'Name the algorithm and extension OIDs of a certificate', input: { mode: 'name', oids: ['1.2.840.10045.4.3.2', '2.5.29.17', '1.3.6.1.5.5.7.3.1'] } },
        { title: 'Decode the TLV of an OID', input: { mode: 'decode', hex: '06062a864886f70d', form: 'tlv' } },
    ],
    handler: resolveOid,
    text: (r) => {
        switch (r.mode) {
            case 'name': return `${RESOLVE_OID_NAME}: ${(r.oids ?? []).map((o) => `${o.oid} = ${o.name ?? '(unregistered)'}`).join(', ')}.`;
            case 'validate': return `${RESOLVE_OID_NAME}: ${r.allValid === true ? 'all valid' : `invalid: ${(r.oids ?? []).filter((o) => o.valid === false).map((o) => o.oid).join(', ')}`} (${countOf(r)} checked).`;
            case 'list': return `${RESOLVE_OID_NAME}: ${countOf(r)} of ${r.total ?? 0} registry entries (offset ${r.offset ?? 0}${r.hasMore === true ? ', more follow' : ''}).`;
            case 'encode': return `${RESOLVE_OID_NAME}: ${(r.oids ?? []).map((o) => `${o.oid} → ${o.hex ?? ''}`).join(', ')}.`;
            case 'decode': return `${RESOLVE_OID_NAME}: ${r.oid ?? ''}${r.name !== undefined && r.name !== null ? ` (${r.name})` : ''}.`;
        }
    },
    summary: resolveOidSummary,
});
