/**
 * Tool: inspect_timestamp — the RFC 3161 report of a TimeStampResp (status,
 * failure info, the token when granted), a bare TimeStampToken, or a bare
 * TSTInfo: policy, message imprint, serial, genTime, accuracy, ordering,
 * nonce, the TSA name as stated, extensions, and the token's CMS envelope
 * (signer count, embedded certificates). Parsing proves nothing:
 * verify_timestamp is the verdict.
 */
import { getOidName, parseCertificate, parseTimeStampResponse, parseTimeStampToken, parseTstInfo, type TimeStampToken, type TstInfo } from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { createParseContext, PARSE_INPUT_PROPERTIES, type ParseContext } from '../parse-context.js';
import { guard, mapPkiError } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { ALGORITHM_VIEW_SCHEMA, algorithmView, CERTIFICATE_REF_SCHEMA, certificateRef, EXTENSION_VIEW_SCHEMA, extensionView, TIME_VIEW_SCHEMA, timeView } from '../views.js';
import { toHex, type Wire } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';
import { GENERAL_NAME_VIEW_SCHEMA, generalNameView } from './inspect-cms.js';

export const INSPECT_TIMESTAMP_NAME = 'inspect_timestamp';

const AS_KINDS = ['response', 'token', 'tstinfo'] as const;
type AsKind = (typeof AS_KINDS)[number];

export const INSPECT_TIMESTAMP_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['input'],
    properties: {
        input: pkiInputSchema('The time-stamp object: a TimeStampResp (.tsr), a TimeStampToken (.tst) or a bare TSTInfo (DER, or any PEM block)'),
        as: { type: 'string', enum: [...AS_KINDS], description: "Read the input as this structure. Omitted: auto-detected in the order response, token, tstinfo (the result's `as` says which)." },
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    input: PkiInputSchema,
    as: z.enum(AS_KINDS).optional(),
    ...ParseShape,
    ...ProjectionShape,
});

export interface TstInfoView {
    readonly version: number;
    readonly policy: { readonly oid: string; readonly name: string | null };
    readonly messageImprint: { readonly hashAlgorithm: ReturnType<typeof algorithmView>; readonly hashedMessage: string };
    readonly serialNumber: { readonly hex: string; readonly decimal: string };
    readonly genTime: ReturnType<typeof timeView>;
    readonly accuracy: { readonly seconds: number; readonly millis: number; readonly micros: number } | null;
    readonly ordering: boolean;
    readonly nonce: string | null;
    readonly tsa: Record<string, Wire> | null;
    readonly extensions: ReadonlyArray<Record<string, Wire>>;
}

export function tstInfoView(t: TstInfo): TstInfoView {
    return {
        version: t.version,
        policy: { oid: t.policy, name: getOidName(t.policy) ?? null },
        messageImprint: { hashAlgorithm: algorithmView(t.messageImprint.hashAlgorithm), hashedMessage: toHex(t.messageImprint.hashedMessage) },
        serialNumber: { hex: t.serialNumber.hex, decimal: t.serialNumber.value.toString(10) },
        genTime: timeView(t.genTime),
        accuracy: t.accuracy === undefined ? null : { seconds: t.accuracy.seconds, millis: t.accuracy.millis, micros: t.accuracy.micros },
        ordering: t.ordering,
        nonce: t.nonce === undefined ? null : t.nonce.toString(10),
        tsa: t.tsa === undefined ? null : generalNameView(t.tsa),
        extensions: t.extensions.map((e) => extensionView(e)),
    };
}

export const TST_INFO_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['version', 'policy', 'messageImprint', 'serialNumber', 'genTime', 'accuracy', 'ordering', 'nonce', 'tsa', 'extensions'],
    properties: {
        version: { type: 'integer' },
        policy: { type: 'object', additionalProperties: false, required: ['oid', 'name'], properties: { oid: { type: 'string' }, name: { type: ['string', 'null'] } } },
        messageImprint: { type: 'object', additionalProperties: false, required: ['hashAlgorithm', 'hashedMessage'], properties: { hashAlgorithm: ALGORITHM_VIEW_SCHEMA, hashedMessage: { type: 'string', description: 'Hex.' } } },
        serialNumber: { type: 'object', additionalProperties: false, required: ['hex', 'decimal'], properties: { hex: { type: 'string' }, decimal: { type: 'string' } } },
        genTime: TIME_VIEW_SCHEMA,
        accuracy: { type: ['object', 'null'], additionalProperties: false, properties: { seconds: { type: 'integer' }, millis: { type: 'integer' }, micros: { type: 'integer' } }, description: 'null when the TSA declared none (unknown, not exact).' },
        ordering: { type: 'boolean' },
        nonce: { type: ['string', 'null'], description: 'Decimal, or null when the request carried none.' },
        tsa: { ...GENERAL_NAME_VIEW_SCHEMA, type: ['object', 'null'], description: 'The TSA name as it chose to state it — a hint, never an identity.' },
        extensions: { type: 'array', items: EXTENSION_VIEW_SCHEMA },
    },
} as const;

export interface TokenView {
    readonly tstInfo: TstInfoView;
    readonly signerInfos: number;
    readonly certificates: ReadonlyArray<ReturnType<typeof certificateRef>>;
}

export function tokenView(token: TimeStampToken, ctx: ParseContext): TokenView {
    return {
        tstInfo: tstInfoView(token.tstInfo),
        signerInfos: token.signedData.signerInfos.length,
        certificates: token.signedData.certificates.map((der, i) => certificateRef(guard(`Cannot read the embedded certificate certificates[${i}]`, () => parseCertificate(der, ctx.options)))),
    };
}

export interface InspectTimestampResult extends DiagnosticsReport {
    readonly as: AsKind;
    readonly status?: { readonly status: string; readonly statusStrings: readonly string[]; readonly failInfo: readonly string[] };
    readonly token?: TokenView;
    readonly tstInfo?: TstInfoView;
    readonly sizeBytes: number;
}

export const INSPECT_TIMESTAMP_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['as', 'sizeBytes', 'diagnostics', 'diagnosticCounts'],
    properties: {
        as: { type: 'string', enum: [...AS_KINDS], description: 'What the input was read as.' },
        status: {
            type: 'object',
            additionalProperties: false,
            required: ['status', 'statusStrings', 'failInfo'],
            description: 'The PKIStatusInfo of a response. Only granted / grantedWithMods carry a token.',
            properties: {
                status: { type: 'string', enum: ['granted', 'grantedWithMods', 'rejection', 'waiting', 'revocationWarning', 'revocationNotification'] },
                statusStrings: { type: 'array', items: { type: 'string' } },
                failInfo: { type: 'array', items: { type: 'string', enum: ['badAlg', 'badRequest', 'badDataFormat', 'timeNotAvailable', 'unacceptedPolicy', 'unacceptedExtension', 'addInfoNotAvailable', 'systemFailure'] } },
            },
        },
        token: {
            type: 'object',
            additionalProperties: false,
            required: ['tstInfo', 'signerInfos', 'certificates'],
            description: 'The token (of a granted response, or the input itself): what it asserts and its CMS envelope.',
            properties: { tstInfo: TST_INFO_VIEW_SCHEMA, signerInfos: { type: 'integer' }, certificates: { type: 'array', items: CERTIFICATE_REF_SCHEMA } },
        },
        tstInfo: { ...TST_INFO_VIEW_SCHEMA, description: "The bare TSTInfo (as:'tstinfo')." },
        sizeBytes: { type: 'integer' },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const INSPECT_TIMESTAMP_SUMMARY_PROPERTIES = {
    statusCode: { type: 'string' },
    genTime: { type: 'string' },
    serialNumber: { type: 'string' },
    imprintHex: { type: 'string' },
    hashAlgorithm: { type: ['string', 'null'] },
    diagnosticCount: { type: 'integer' },
} as const;

type Parsed = Omit<InspectTimestampResult, 'sizeBytes' | keyof DiagnosticsReport>;

function parseAs(der: Uint8Array, as: AsKind, ctx: ParseContext): Parsed {
    switch (as) {
        case 'response': {
            const r = parseTimeStampResponse(der, ctx.options);
            return { as, status: { status: r.status, statusStrings: r.statusStrings, failInfo: r.failInfo }, ...(r.token !== undefined ? { token: tokenView(r.token, ctx) } : {}) };
        }
        case 'token':
            return { as, token: tokenView(parseTimeStampToken(der, ctx.options), ctx) };
        default:
            return { as, tstInfo: tstInfoView(parseTstInfo(der, ctx.options)) };
    }
}

export async function inspectTimestamp(rawInput: unknown): Promise<InspectTimestampResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const obj = await loadPkiObject(input.input, 'input', LABELS.any, ctx);
    let parsed: Parsed | undefined;
    if (input.as !== undefined) {
        const forced = input.as;
        parsed = guard(`Cannot read the input as a ${forced}`, () => parseAs(obj.der, forced, ctx));
    } else {
        // A response, a token and a bare TSTInfo are tried in that order; the first failure names the cause.
        let first: ToolError | undefined;
        for (const as of AS_KINDS) {
            try {
                parsed = parseAs(obj.der, as, ctx);
                break;
            } catch (e) {
                const mapped = mapPkiError(e, `Cannot read the input as a ${as}`);
                // A strict refusal is the answer, not a detection failure to try past.
                if (mapped.code === 'PKI_STRICT_DIAGNOSTIC') throw mapped;
                first ??= mapped;
            }
        }
        if (parsed === undefined) {
            const cause = first as ToolError;
            throw new ToolError(cause.code, `The input is not a TimeStampResp, a TimeStampToken or a TSTInfo: ${cause.message}`, { ...(cause.data ?? {}), remedy: "as:'response'|'token'|'tstinfo' to see the exact refusal of one reading; decode_asn1 for the structure" });
        }
    }
    return withDiagnostics({ ...parsed, sizeBytes: obj.der.length }, ctx.sink.report());
}

export function inspectTimestampSummary(r: InspectTimestampResult): Record<string, unknown> {
    const info = r.tstInfo ?? r.token?.tstInfo;
    return {
        as: r.as,
        ...(r.status !== undefined ? { statusCode: r.status.status } : {}),
        ...(info !== undefined ? { genTime: info.genTime.iso, serialNumber: info.serialNumber.hex, imprintHex: info.messageImprint.hashedMessage, hashAlgorithm: info.messageImprint.hashAlgorithm.name } : {}),
        diagnosticCount: diagnosticCount(r),
    };
}

export const INSPECT_TIMESTAMP_TOOL = defineTool<InspectTimestampResult>({
    name: INSPECT_TIMESTAMP_NAME,
    title: 'Inspect time-stamp (RFC 3161 response, token or TSTInfo)',
    kind: 'read',
    description:
        "Read-only RFC 3161 report of a TimeStampResp (.tsr: status, statusStrings, failInfo, and the token when granted), a TimeStampToken (.tst) or a bare TSTInfo — auto-detected in that order unless `as` names one. The TSTInfo view: policy, message imprint (algorithm + hex), serial, genTime (epoch ms + ISO), accuracy (null = undeclared), ordering, nonce (decimal), the TSA name as STATED (a hint, not an identity), extensions; the token view adds its CMS envelope (signer count, embedded certificates). Parsing proves nothing — verify_timestamp is the verdict (imprint, TSA signature, chain, revocation). Refuses with the PKI_* cause when the bytes are none of the three (as:'…' shows one reading's exact refusal); strict:true escalates the first engine warning (OpenSSL tokens carry PKI_DIAG_CMS_SET_NOT_SORTED). Token-frugal: verbosity:'summary' (status, genTime, serial, imprint).",
    inputSchema: INSPECT_TIMESTAMP_INPUT_SCHEMA,
    rawOutputSchema: INSPECT_TIMESTAMP_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(INSPECT_TIMESTAMP_OUTPUT_SCHEMA, INSPECT_TIMESTAMP_SUMMARY_PROPERTIES, `Structured time-stamp report.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'What a TSA answered', input: { input: { path: 'fixtures/content.tsr' }, verbosity: 'summary' } },
        { title: 'What a token asserts, and who signed it', input: { input: { path: 'fixtures/content.tst' }, as: 'token', fields: ['token.tstInfo.genTime.iso', 'token.tstInfo.messageImprint', 'token.certificates.subject'] } },
    ],
    handler: inspectTimestamp,
    text: (r) => {
        const info = r.tstInfo ?? r.token?.tstInfo;
        const head = r.as === 'response' ? `TimeStampResp ${r.status?.status ?? '?'}${(r.status?.failInfo.length ?? 0) > 0 ? ` (${r.status?.failInfo.join(', ')})` : ''}` : r.as === 'token' ? 'TimeStampToken' : 'TSTInfo';
        const body = info === undefined ? ', no token' : `: ${info.messageImprint.hashAlgorithm.name ?? info.messageImprint.hashAlgorithm.oid} ${info.messageImprint.hashedMessage.slice(0, 16)}… stamped at ${info.genTime.iso}, serial ${info.serialNumber.hex}, policy ${info.policy.oid}${r.token !== undefined ? `, ${r.token.certificates.length} certificate(s)` : ''}`;
        return `${INSPECT_TIMESTAMP_NAME}: ${head}${body}; ${r.diagnostics.length} diagnostic(s).`;
    },
    summary: inspectTimestampSummary,
});
