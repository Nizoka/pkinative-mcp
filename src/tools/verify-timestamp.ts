/**
 * Tool: verify_timestamp — the RFC 3161 verdict: the token (or the whole
 * TimeStampResp) stamps what the caller says it stamps (the request, the
 * data, or its digest), the TSA's signature verifies, the TSA chains to one
 * of the caller's trust anchors at `at` with the time-stamping purpose, and
 * offline revocation evidence is judged. A negative verdict is `valid:false`
 * + `reasons[]`, never isError.
 */
import { verifyTimeStampToken, type VerifyTimeStampTokenReport } from 'pkinative';
import { z } from 'zod';

import { ContentInputSchema, contentInputSchema, HexSchema, hexSchema, loadContent } from '../content-input.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiBundle, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { ALLOW_SHA1_INPUT_PROPERTY } from '../signer.js';
import { formatInstant, resolveInstant } from '../time.js';
import { REASONS_OUTPUT_PROPERTY, TRUST_INPUT_PROPERTIES, TrustShape } from '../trust.js';
import { CERTIFICATE_REF_SCHEMA, certificateRef, reasonsView } from '../views.js';
import { fromHex } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { AllowSha1Shape, diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';
import { parseCertificates } from './verify-certificate-chain.js';

export const VERIFY_TIMESTAMP_NAME = 'verify_timestamp';

/** The TRUST fragment without the chain-only members (purposes, policy): a TSA chain is judged for timeStamping. */
export const TSP_TRUST_INPUT_PROPERTIES = {
    trustAnchors: TRUST_INPUT_PROPERTIES.trustAnchors,
    candidates: { ...TRUST_INPUT_PROPERTIES.candidates, description: 'Untrusted certificates the TSA\'s path may use (every PEM block of every item is taken). Optional; the certificates the token carries are also candidates.' },
    crls: TRUST_INPUT_PROPERTIES.crls,
    ocspResponses: TRUST_INPUT_PROPERTIES.ocspResponses,
    at: TRUST_INPUT_PROPERTIES.at,
    requireRevocation: TRUST_INPUT_PROPERTIES.requireRevocation,
} as const;

const TspTrustShape = {
    trustAnchors: TrustShape.trustAnchors,
    candidates: TrustShape.candidates,
    crls: TrustShape.crls,
    ocspResponses: TrustShape.ocspResponses,
    at: TrustShape.at,
    requireRevocation: TrustShape.requireRevocation,
};

export const VERIFY_TIMESTAMP_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['trustAnchors'],
    properties: {
        token: pkiInputSchema('The TimeStampToken (a ContentInfo over a TSTInfo; .tst)', ' Exclusive with response.'),
        response: pkiInputSchema('The whole TimeStampResp the TSA returned (.tsr)', ' Exclusive with token. A response that granted nothing is PKI_REASON_TSP_NOT_GRANTED.'),
        request: pkiInputSchema('The TimeStampReq you sent (.tsq)', ' The strongest statement of what was stamped: imprint, nonce and policy are all checked; the only way to catch a replayed response.'),
        data: contentInputSchema('The data that was stamped (hashed with the token\'s own imprint algorithm)'),
        digestHex: hexSchema('The digest that was stamped, when you hold that rather than the data. Exclusive with data.'),
        ...TSP_TRUST_INPUT_PROPERTIES,
        allowNonCriticalTimeStampingEku: { type: 'boolean', default: false, description: 'Accept a TSA whose extKeyUsage names timeStamping but is not critical (RFC 3161 §2.3 requires it critical; some deployed TSAs are not).' },
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    token: PkiInputSchema.optional(),
    response: PkiInputSchema.optional(),
    request: PkiInputSchema.optional(),
    data: ContentInputSchema.optional(),
    digestHex: HexSchema.optional(),
    ...TspTrustShape,
    allowNonCriticalTimeStampingEku: z.boolean().default(false),
    ...AllowSha1Shape,
    ...ParseShape,
    ...ProjectionShape,
}).superRefine((v, ctx) => {
    if ((v.token === undefined) === (v.response === undefined)) ctx.addIssue({ code: 'custom', message: 'pass exactly one of token / response', path: ['token'] });
    if (v.data !== undefined && v.digestHex !== undefined) ctx.addIssue({ code: 'custom', message: 'pass data or digestHex, not both', path: ['data'] });
    if (v.request === undefined && v.data === undefined && v.digestHex === undefined) {
        ctx.addIssue({ code: 'custom', message: 'say what was stamped: request, data or digestHex (a token verified without it proves only that some hash existed at some time)', path: ['request'] });
    }
});

export interface ChainVerdictView {
    readonly valid: boolean;
    readonly path: ReadonlyArray<ReturnType<typeof certificateRef>>;
    readonly reasons: ReadonlyArray<Record<string, string>>;
}

export interface TimeStampVerdictView {
    readonly valid: boolean;
    readonly reasons: ReadonlyArray<Record<string, string>>;
    readonly genTime: string | null;
    readonly earliest: string | null;
    readonly latest: string | null;
    readonly tsa: ReturnType<typeof certificateRef> | null;
    readonly chain: ChainVerdictView | null;
    readonly signatureVerifications: number;
}

/** The wire view of an engine time-stamp verdict (shared with verify_cms's per-signer time-stamps). */
export function timeStampVerdictView(r: VerifyTimeStampTokenReport): TimeStampVerdictView {
    return {
        valid: r.valid,
        reasons: reasonsView(r.reasons),
        genTime: r.genTime === undefined ? null : formatInstant(r.genTime.epochMilliseconds),
        earliest: r.earliest === undefined ? null : formatInstant(r.earliest),
        latest: r.latest === undefined ? null : formatInstant(r.latest),
        tsa: r.tsaCertificate === undefined ? null : certificateRef(r.tsaCertificate),
        chain: r.chain === undefined ? null : { valid: r.chain.valid, path: r.chain.path.map(certificateRef), reasons: reasonsView(r.chain.reasons) },
        signatureVerifications: r.signatureVerifications,
    };
}

export const CHAIN_VERDICT_VIEW_SCHEMA = {
    type: ['object', 'null'],
    additionalProperties: false,
    required: ['valid', 'path', 'reasons'],
    description: 'The chain judged by verify_certificate_chain, or null when there was no certificate to judge.',
    properties: { valid: { type: 'boolean' }, path: { type: 'array', items: CERTIFICATE_REF_SCHEMA }, ...REASONS_OUTPUT_PROPERTY },
} as const;

export const TIMESTAMP_VERDICT_PROPERTIES = {
    valid: { type: 'boolean', description: 'Whether the token is evidence that the expected hash existed at genTime. false is a negative verdict (reasons[]), never an error.' },
    ...REASONS_OUTPUT_PROPERTY,
    genTime: { type: ['string', 'null'], description: 'The time the TSA asserts (ISO 8601) — established only when valid.' },
    earliest: { type: ['string', 'null'], description: 'genTime minus the declared accuracy.' },
    latest: { type: ['string', 'null'], description: 'genTime plus the declared accuracy — the instant an LTV check compares against.' },
    tsa: { ...CERTIFICATE_REF_SCHEMA, type: ['object', 'null'], description: 'The TSA certificate whose key verified the token, or null.' },
    chain: CHAIN_VERDICT_VIEW_SCHEMA,
    signatureVerifications: { type: 'integer' },
} as const;

export interface TimeStampVerdict extends TimeStampVerdictView, DiagnosticsReport {
    readonly evaluatedAt: string;
    readonly evaluatedAtSource: 'input' | 'pinned' | 'clock';
}

export const VERIFY_TIMESTAMP_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['valid', 'reasons', 'genTime', 'earliest', 'latest', 'tsa', 'chain', 'signatureVerifications', 'evaluatedAt', 'evaluatedAtSource', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...TIMESTAMP_VERDICT_PROPERTIES,
        evaluatedAt: { type: 'string', description: 'The ISO instant the TSA chain was judged at — re-pass it as `at` to reproduce the verdict.' },
        evaluatedAtSource: { type: 'string', enum: ['input', 'pinned', 'clock'] },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const VERIFY_TIMESTAMP_SUMMARY_PROPERTIES = {
    reasonCodes: { type: 'array', items: { type: 'string' } },
    diagnosticCount: { type: 'integer' },
} as const;

export function digestBytes(hex: string | undefined, path: string): Uint8Array | undefined {
    if (hex === undefined) return undefined;
    const bytes = fromHex(hex);
    if (bytes === undefined || bytes.length === 0) throw new ToolError('VALIDATION_ERROR', `${path}: expected hexadecimal bytes.`, { path });
    return bytes;
}

export async function verifyTimestampTool(rawInput: unknown): Promise<TimeStampVerdict> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const isToken = input.token !== undefined;
    const subject = await loadPkiObject((isToken ? input.token : input.response) as NonNullable<typeof input.token>, isToken ? 'token' : 'response', LABELS.any, ctx);
    const request = input.request === undefined ? undefined : (await loadPkiObject(input.request, 'request', LABELS.any, ctx)).der;
    const data = input.data === undefined ? undefined : (await loadContent(input.data, 'data')).bytes;
    const imprint = digestBytes(input.digestHex, 'digestHex');
    const anchors = parseCertificates(await loadPkiBundle(input.trustAnchors, 'trustAnchors', LABELS.certificate, ctx), 'trust anchor', ctx);
    const candidates = parseCertificates(await loadPkiBundle(input.candidates, 'candidates', LABELS.certificate, ctx), 'candidate certificate', ctx);
    const crls = (await loadPkiBundle(input.crls, 'crls', LABELS.crl, ctx)).map((o) => o.der);
    const ocsp = (await loadPkiBundle(input.ocspResponses, 'ocspResponses', LABELS.any, ctx)).map((o) => o.der);
    const at = resolveInstant(input.at, 'at');
    const report = await guardAsync('Cannot verify the time-stamp', () => verifyTimeStampToken({
        ...(isToken ? { token: subject.der } : { response: subject.der }),
        ...(request !== undefined ? { request } : {}),
        ...(data !== undefined ? { data } : imprint !== undefined ? { imprint } : {}),
        certificates: candidates,
        trustAnchors: anchors,
        crls,
        ocspResponses: ocsp,
        requireRevocation: input.requireRevocation,
        at: at.ms,
        allowSha1: input.allowSha1,
        allowNonCriticalTimeStampingEku: input.allowNonCriticalTimeStampingEku,
        ...(ctx.options.limits !== undefined ? { limits: ctx.options.limits } : {}),
        onDiagnostic: ctx.options.onDiagnostic,
    }));
    return withDiagnostics({
        ...timeStampVerdictView(report),
        evaluatedAt: at.iso,
        evaluatedAtSource: at.source,
    }, ctx.sink.report());
}

export function verifyTimestampSummary(r: TimeStampVerdict): Record<string, unknown> {
    return { valid: r.valid, reasonCodes: r.reasons.map((x) => x['code']), genTime: r.genTime, evaluatedAt: r.evaluatedAt, diagnosticCount: diagnosticCount(r) };
}

export const VERIFY_TIMESTAMP_TOOL = defineTool<TimeStampVerdict>({
    name: VERIFY_TIMESTAMP_NAME,
    title: 'Verify time-stamp (the RFC 3161 verdict: imprint, TSA signature, chain, revocation)',
    kind: 'verdict',
    description:
        "The one-call verdict on an RFC 3161 time-stamp: exactly one of `token` (a TimeStampToken, .tst) or `response` (the whole TimeStampResp, .tsr — a declined response is PKI_REASON_TSP_NOT_GRANTED), judged against what YOU say was stamped — `request` (the .tsq you sent: imprint, nonce and policy are all checked, the only way to catch a replay), `data` (hashed with the token's own algorithm) or `digestHex`; at least one is required, because a token verified without what it stamps proves nothing (VALIDATION_ERROR otherwise). The TSA's signature is verified, its certificate must chain to one of YOUR `trustAnchors` (through `candidates` and the certificates the token carries) at `at` with a critical timeStamping EKU (allowNonCriticalTimeStampingEku:true for deployed TSAs that are not), and revocation is judged from the CRL / OCSP bytes YOU supply (`requireRevocation:true` demands evidence). A negative verdict is valid:false + reasons[] (PKI_REASON_* codes) — never isError. genTime / earliest / latest (accuracy applied) are established only when valid. Pin `at` for a reproducible, cacheable verdict. Token-frugal: verbosity:'summary'.",
    inputSchema: VERIFY_TIMESTAMP_INPUT_SCHEMA,
    rawOutputSchema: VERIFY_TIMESTAMP_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(VERIFY_TIMESTAMP_OUTPUT_SCHEMA, VERIFY_TIMESTAMP_SUMMARY_PROPERTIES, `Time-stamp verdict.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    instantInputs: ['at'],
    examples: [
        { title: 'A TSA response against the request that was sent and the data', input: { response: { path: 'fixtures/content.tsr' }, request: { path: 'fixtures/content.tsq' }, data: { path: 'fixtures/content.txt' }, trustAnchors: [{ path: 'fixtures/root.crt.pem' }], candidates: [{ path: 'fixtures/inter.crt.pem' }], at: '2027-01-01T00:00:00Z', verbosity: 'summary' } },
        { title: 'A bare token against the digest it stamps', input: { token: { path: 'fixtures/content.tst' }, digestHex: 'b1a1c762480b580288e0737422f01130e824c8014422371ae571880dfc642533', trustAnchors: [{ path: 'fixtures/root.crt.pem' }], at: '2027-01-01T00:00:00Z' } },
    ],
    handler: verifyTimestampTool,
    text: (r) => r.valid
        ? `${VERIFY_TIMESTAMP_NAME}: OK — the hash existed at ${r.genTime ?? '?'} (by ${r.latest ?? r.genTime ?? '?'}), TSA ${r.tsa?.subject ?? '(unnamed)'}, chain judged at ${r.evaluatedAt} (${r.signatureVerifications} signature(s) verified); ${r.diagnostics.length} diagnostic(s).`
        : `${VERIFY_TIMESTAMP_NAME}: NOT OK — ${r.reasons.map((x) => x['code']).join(', ')} (evaluated at ${r.evaluatedAt}).`,
    summary: verifyTimestampSummary,
});
