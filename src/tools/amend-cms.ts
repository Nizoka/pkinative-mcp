/**
 * Tool: amend_cms — the one edit a signed message legitimately receives
 * afterwards: an unsigned attribute on one signer, or an RFC 3161 counter
 * time-stamp (CAdES-T / PAdES B-T). Every signed octet stays unchanged; the
 * output is deterministic for the same inputs. A time-stamp token is checked
 * to stamp the signer's SIGNATURE VALUE before anything is written — a token
 * over the content (or anything else) would be attached and then fail
 * verify_cms, so it is refused here with the imprint reason.
 */
import { addTimeStampToken, addUnsignedAttribute, parseSignedData, parseTimeStampResponse, parseTimeStampToken, verifyTimeStampToken } from 'pkinative';
import { z } from 'zod';

import { HexSchema, hexSchema } from '../content-input.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { ARTEFACT_OUTPUT_PROPERTIES, emitArtefact, outputShape, type OutputResult } from '../output.js';
import { createParseContext, PARSE_INPUT_PROPERTIES, type ParseContext } from '../parse-context.js';
import { guard, guardAsync, mapPkiError } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { ALLOW_SHA1_INPUT_PROPERTY } from '../signer.js';
import { reasonsView } from '../views.js';
import { fromHex } from '../wire.js';
import { defineTool, WRITES } from './_definition.js';
import { AllowSha1Shape, parseInput, ParseShape, withDiagnostics } from './_shared.js';
import { loadSignedData, signerAt } from './inspect-cms.js';
import { CMS_DER_EXTENSIONS, CMS_MIME_TYPE, CMS_OUTPUT_INPUT_PROPERTIES, CMS_PEM_LABEL } from './sign-cms.js';

export const AMEND_CMS_NAME = 'amend_cms';

const OPERATIONS = ['add-unsigned-attribute', 'add-timestamp'] as const;
type Operation = (typeof OPERATIONS)[number];

export const TIMESTAMP_REMEDY = "request the token over the signature value: inspect_cms fields:['signerInfos.signature'] → hash it → create_timestamp_request digestHex (or data: those bytes)";

export const AMEND_CMS_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['signedData', 'operation'],
    properties: {
        signedData: pkiInputSchema('The CMS SignedData to amend (CMS / PKCS7 PEM, or DER: .p7s .p7m)'),
        signerIndex: { type: 'integer', minimum: 0, default: 0, description: 'Which signer receives the attribute (encoded order; NOT_FOUND past the last).' },
        operation: { type: 'string', enum: [...OPERATIONS], description: "'add-unsigned-attribute' writes `attribute` verbatim; 'add-timestamp' writes `token` as id-aa-signatureTimeStampToken after checking its imprint." },
        attribute: hexSchema('One DER Attribute (SEQUENCE { type, SET OF values }) for add-unsigned-attribute. A type RFC 5652 allows only signed is refused (PKI_API_MISUSE).'),
        token: pkiInputSchema('The time-stamp for add-timestamp: a TimeStampToken (.tst) or the whole TimeStampResp (.tsr, unwrapped to its token; a declined response is refused)'),
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...CMS_OUTPUT_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    signedData: PkiInputSchema,
    signerIndex: z.number().int().min(0).default(0),
    operation: z.enum(OPERATIONS),
    attribute: HexSchema.optional(),
    token: PkiInputSchema.optional(),
    ...AllowSha1Shape,
    ...ParseShape,
    ...outputShape('der'),
}).superRefine((v, ctx) => {
    if (v.operation === 'add-unsigned-attribute') {
        if (v.attribute === undefined) ctx.addIssue({ code: 'custom', message: 'add-unsigned-attribute needs attribute (the DER of one Attribute as hex)', path: ['attribute'] });
        if (v.token !== undefined) ctx.addIssue({ code: 'custom', message: 'token belongs to add-timestamp', path: ['token'] });
    } else {
        if (v.token === undefined) ctx.addIssue({ code: 'custom', message: 'add-timestamp needs token (a TimeStampToken or a TimeStampResp)', path: ['token'] });
        if (v.attribute !== undefined) ctx.addIssue({ code: 'custom', message: 'attribute belongs to add-unsigned-attribute', path: ['attribute'] });
    }
});

export interface AmendCmsResult extends OutputResult, DiagnosticsReport {
    readonly summary: {
        readonly operation: Operation;
        readonly signerIndex: number;
        readonly unsignedAttributes: number;
        readonly timeStampTokens: number;
        readonly tokenGenTime: string | null;
        readonly sizeBytesBefore: number;
    };
}

export const AMEND_CMS_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode', 'encoding', 'sizeBytes', 'sha256', 'summary', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...ARTEFACT_OUTPUT_PROPERTIES,
        summary: {
            type: 'object',
            additionalProperties: false,
            required: ['operation', 'signerIndex', 'unsignedAttributes', 'timeStampTokens', 'tokenGenTime', 'sizeBytesBefore'],
            properties: {
                operation: { type: 'string', enum: [...OPERATIONS] },
                signerIndex: { type: 'integer' },
                unsignedAttributes: { type: 'integer', description: 'Unsigned attributes of the signer after the edit.' },
                timeStampTokens: { type: 'integer', description: 'Counter time-stamps of the signer after the edit.' },
                tokenGenTime: { type: ['string', 'null'], description: 'The genTime the attached token asserts (ISO 8601); null for add-unsigned-attribute. Asserted, not yet verified: verify_cms judges it.' },
                sizeBytesBefore: { type: 'integer', description: 'Size of the input SignedData.' },
            },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

/** A TimeStampResp is unwrapped to its token; anything else is taken as the token itself. */
function unwrapToken(bytes: Uint8Array, ctx: ParseContext): Uint8Array {
    try {
        const response = parseTimeStampResponse(bytes, ctx.options);
        if (response.tokenDer === undefined) {
            throw new ToolError('VALIDATION_ERROR', `The time-stamp response status is "${response.status}": it carries no token${response.failInfo.length > 0 ? ` (${response.failInfo.join(', ')})` : ''}.`, { path: 'token', status: response.status, failInfo: response.failInfo, statusStrings: response.statusStrings });
        }
        return response.tokenDer;
    } catch (e) {
        if (e instanceof ToolError) throw e;
        const mapped = mapPkiError(e, 'Cannot read the time-stamp response');
        if (mapped.code === 'PKI_STRICT_DIAGNOSTIC') throw mapped;
        return bytes;
    }
}

export async function amendCmsTool(rawInput: unknown): Promise<AmendCmsResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const { der, signedData } = await loadSignedData(input.signedData, 'signedData', ctx);
    const signerInfo = signerAt(signedData, input.signerIndex);
    const limits = ctx.options.limits !== undefined ? { limits: ctx.options.limits } : {};
    let out: Uint8Array;
    let tokenGenTime: string | null = null;
    if (input.operation === 'add-unsigned-attribute') {
        const attribute = fromHex(input.attribute as string);
        if (attribute === undefined || attribute.length === 0) throw new ToolError('VALIDATION_ERROR', 'attribute: expected the DER of one Attribute as hex.', { path: 'attribute' });
        out = guard('Cannot add the attribute', () => addUnsignedAttribute(der, input.signerIndex, attribute, limits));
    } else {
        const obj = await loadPkiObject(input.token as NonNullable<typeof input.token>, 'token', LABELS.any, ctx);
        const token = unwrapToken(obj.der, ctx);
        const parsed = guard('Cannot read the time-stamp token', () => parseTimeStampToken(token, ctx.options));
        // A counter time-stamp stamps the signer's signature value (RFC 3161 Appendix A, RFC 5652 §11.4). The engine's
        // addTimeStampToken attaches any token, so the imprint is checked first — trust is verify_cms's business
        // (no anchors here: only the imprint reason is read).
        const check = await guardAsync('Cannot check the time-stamp token', () => verifyTimeStampToken({
            token, data: signerInfo.signature, trustAnchors: [], certificates: [], allowSha1: input.allowSha1, ...limits, onDiagnostic: ctx.options.onDiagnostic,
        }));
        const mismatch = check.reasons.filter((r) => r.code === 'PKI_REASON_TSP_IMPRINT_MISMATCH');
        if (mismatch.length > 0) {
            throw new ToolError('VALIDATION_ERROR', `The token does not stamp signer ${input.signerIndex}'s signature value: its imprint is over something else (PKI_REASON_TSP_IMPRINT_MISMATCH). Nothing was written.`, {
                path: 'token',
                detail: 'PKI_REASON_TSP_IMPRINT_MISMATCH',
                reasons: reasonsView(mismatch),
                remedy: TIMESTAMP_REMEDY,
            });
        }
        out = guard('Cannot add the time-stamp', () => addTimeStampToken(der, input.signerIndex, token, limits));
        tokenGenTime = new Date(parsed.tstInfo.genTime.epochMilliseconds).toISOString();
    }
    const after = signerAt(guard('Cannot read the SignedData just amended', () => parseSignedData(out, ctx.options)), input.signerIndex);
    const artefact = await emitArtefact(out, {
        mode: input.outputMode,
        encoding: input.encoding,
        outputPath: input.outputPath,
        pemLabel: CMS_PEM_LABEL,
        mimeType: CMS_MIME_TYPE,
        derExtensions: CMS_DER_EXTENSIONS,
    });
    return withDiagnostics({
        ...artefact,
        summary: {
            operation: input.operation,
            signerIndex: input.signerIndex,
            unsignedAttributes: after.unsignedAttributes?.length ?? 0,
            timeStampTokens: after.timeStampTokens.length,
            tokenGenTime,
            sizeBytesBefore: der.length,
        },
    }, ctx.sink.report());
}

export const AMEND_CMS_TOOL = defineTool<AmendCmsResult>({
    name: AMEND_CMS_NAME,
    title: 'Amend CMS (add an unsigned attribute or an RFC 3161 counter time-stamp)',
    kind: 'artefact',
    description:
        "The one edit a signed message legitimately receives afterwards, every signed octet unchanged: operation 'add-unsigned-attribute' appends `attribute` (one DER Attribute as hex) to signer `signerIndex`'s unsigned attributes; 'add-timestamp' appends `token` — a TimeStampToken, or the whole TimeStampResp a TSA returned (unwrapped; a declined response is refused) — as id-aa-signatureTimeStampToken (CAdES-T / PAdES B-T). A counter time-stamp stamps the signer's SIGNATURE VALUE, not the document: the token's imprint is checked against that value BEFORE anything is written and a token over anything else is refused with VALIDATION_ERROR (data.detail PKI_REASON_TSP_IMPRINT_MISMATCH, with the remedy: inspect_cms fields:['signerInfos.signature'] → hash → create_timestamp_request digestHex → POST to your TSA yourself → amend_cms). Trust is not judged here (verify_cms is). Deterministic for the same inputs. Refuses: NOT_FOUND for a signerIndex past the last signer, PKI_API_MISUSE for a signed-only attribute type, PKI_* for unreadable bytes. Output DER (default), PEM (CMS) or hex, inline or as a sandbox file (never overwritten).",
    inputSchema: AMEND_CMS_INPUT_SCHEMA,
    outputSchema: AMEND_CMS_OUTPUT_SCHEMA,
    annotations: WRITES,
    cacheable: true,
    examples: [
        { title: 'Add a private unsigned attribute (OID 1.2.3.4 with one OID value)', input: { signedData: { path: 'fixtures/attached.p7s' }, operation: 'add-unsigned-attribute', attribute: '300d06032a0304310606042a030405' } },
        { title: 'The same attribute on a detached signature, returned as PEM (a counter time-stamp goes through add-timestamp with the TSA response — see the amend-cms-add-timestamp-refused example for the imprint check)', input: { signedData: { path: 'fixtures/detached.p7s' }, operation: 'add-unsigned-attribute', attribute: '300d06032a0304310606042a030405', signerIndex: 0, encoding: 'pem' } },
    ],
    handler: amendCmsTool,
    text: (r) => `${AMEND_CMS_NAME}: ${r.summary.operation} on signer ${r.summary.signerIndex}${r.summary.tokenGenTime !== null ? ` (token asserts ${r.summary.tokenGenTime})` : ''}: ${r.summary.unsignedAttributes} unsigned attribute(s), ${r.summary.timeStampTokens} time-stamp(s) now; ${r.summary.sizeBytesBefore} → ${r.sizeBytes} bytes DER, sha256 ${r.sha256.slice(0, 16)}…${r.mode === 'file' ? `, written to ${r.filePath ?? ''}` : ` (${r.encoding} delivered as the embedded resource below)`}.`,
});
