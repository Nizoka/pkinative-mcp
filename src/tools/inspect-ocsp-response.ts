/**
 * Tool: inspect_ocsp_response — the RFC 6960 §4.2 report of one OCSP
 * response: the response status, the BasicOCSPResponse (responder id,
 * producedAt, every SingleResponse with its CertID and status, extensions,
 * embedded certificates, signature algorithm), whether a nonce is echoed,
 * and an optional signature check against `responder` or the embedded
 * certificates. A valid signature is one key, not authorisation:
 * check_ocsp_status is the verdict.
 */
import { OCSP_NONCE_OID, parseCertificate, parseOcspResponse, verifyOcspSignature, type Certificate, type OcspBasicResponse, type OcspResponse, type OcspSingleResponse } from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { createParseContext, PARSE_INPUT_PROPERTIES, type ParseContext } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { ALGORITHM_VIEW_SCHEMA, algorithmView, CERTIFICATE_REF_SCHEMA, certificateRef, dn, EXTENSION_VIEW_SCHEMA, extensionView, stripRaw, TIME_VIEW_SCHEMA, timeView } from '../views.js';
import { toHex, type Wire } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';

export const INSPECT_OCSP_RESPONSE_NAME = 'inspect_ocsp_response';

export const OCSP_RESPONSE_STATUSES = ['successful', 'malformedRequest', 'internalError', 'tryLater', 'sigRequired', 'unauthorized'] as const;

export const INSPECT_OCSP_RESPONSE_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['response'],
    properties: {
        response: pkiInputSchema('The OCSP response (DER, as the responder returned it)'),
        responder: pkiInputSchema('The responder certificate to check the signature against', ' Omitted: the certificates embedded in the response are tried (signature.source embedded). A valid signature is NOT authorisation: check_ocsp_status judges the responder (RFC 6960 §4.2.2.2).'),
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    response: PkiInputSchema,
    responder: PkiInputSchema.optional(),
    ...ParseShape,
    ...ProjectionShape,
});

export interface OcspSingleResponseView {
    readonly certId: { readonly hashAlgorithm: ReturnType<typeof algorithmView>; readonly issuerNameHash: string; readonly issuerKeyHash: string; readonly serialNumber: string };
    readonly status: Record<string, Wire>;
    readonly thisUpdate: ReturnType<typeof timeView>;
    readonly nextUpdate: ReturnType<typeof timeView> | null;
    readonly extensions: ReadonlyArray<Record<string, Wire>>;
}

export interface OcspBasicResponseView {
    readonly responderId: Wire;
    readonly producedAt: ReturnType<typeof timeView>;
    readonly responses: readonly OcspSingleResponseView[];
    readonly extensions: ReadonlyArray<Record<string, Wire>>;
    readonly certificates: ReadonlyArray<ReturnType<typeof certificateRef>>;
    readonly signatureAlgorithm: ReturnType<typeof algorithmView>;
}

export interface InspectOcspResponseResult extends DiagnosticsReport {
    readonly status: OcspResponse['status'];
    readonly basicResponse: OcspBasicResponseView | null;
    readonly noncePresent: boolean;
    readonly sizeBytes: number;
    readonly signature?: { readonly valid: boolean; readonly signer: string | null; readonly source: 'responder' | 'embedded' };
}

export const OCSP_CERT_ID_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['hashAlgorithm', 'issuerNameHash', 'issuerKeyHash', 'serialNumber'],
    properties: { hashAlgorithm: ALGORITHM_VIEW_SCHEMA, issuerNameHash: { type: 'string', description: 'Hex.' }, issuerKeyHash: { type: 'string', description: 'Hex.' }, serialNumber: { type: 'string', description: 'Hex.' } },
} as const;

export const INSPECT_OCSP_RESPONSE_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['status', 'basicResponse', 'noncePresent', 'sizeBytes', 'diagnostics', 'diagnosticCounts'],
    properties: {
        status: { type: 'string', enum: [...OCSP_RESPONSE_STATUSES], description: 'OCSPResponseStatus (RFC 6960 §4.2.1). Only successful carries a signed answer.' },
        basicResponse: {
            type: ['object', 'null'],
            additionalProperties: false,
            required: ['responderId', 'producedAt', 'responses', 'extensions', 'certificates', 'signatureAlgorithm'],
            description: 'The BasicOCSPResponse; null when the status is not successful.',
            properties: {
                responderId: { type: 'object', additionalProperties: true, description: "{ kind:'byName', nameDer: hex } or { kind:'byKey', keyHash: hex } (RFC 6960 §4.2.2.3)." },
                producedAt: TIME_VIEW_SCHEMA,
                responses: {
                    type: 'array',
                    items: {
                        type: 'object',
                        additionalProperties: false,
                        required: ['certId', 'status', 'thisUpdate', 'nextUpdate', 'extensions'],
                        properties: {
                            certId: OCSP_CERT_ID_SCHEMA,
                            status: { type: 'object', additionalProperties: true, required: ['kind'], description: "kind good / revoked (revocationTime, reason) / unknown.", properties: { kind: { type: 'string', enum: ['good', 'revoked', 'unknown'] } } },
                            thisUpdate: TIME_VIEW_SCHEMA,
                            nextUpdate: { ...TIME_VIEW_SCHEMA, type: ['object', 'null'] },
                            extensions: { type: 'array', items: EXTENSION_VIEW_SCHEMA },
                        },
                    },
                },
                extensions: { type: 'array', items: EXTENSION_VIEW_SCHEMA, description: 'Response extensions (the RFC 8954 nonce is 1.3.6.1.5.5.7.48.1.2).' },
                certificates: { type: 'array', items: CERTIFICATE_REF_SCHEMA, description: 'The certificates the responder embedded (usually its own delegated certificate).' },
                signatureAlgorithm: ALGORITHM_VIEW_SCHEMA,
            },
        },
        noncePresent: { type: 'boolean', description: 'A nonce extension is present on the response.' },
        sizeBytes: { type: 'integer' },
        signature: {
            type: 'object',
            additionalProperties: false,
            required: ['valid', 'signer', 'source'],
            description: 'The signature check: against `responder`, or the first embedded certificate whose key verifies. ONE signature against ONE key — authorisation is judged by check_ocsp_status.',
            properties: { valid: { type: 'boolean' }, signer: { type: ['string', 'null'], description: 'The subject of the certificate that verified the signature, null when none did.' }, source: { type: 'string', enum: ['responder', 'embedded'] } },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const INSPECT_OCSP_RESPONSE_SUMMARY_PROPERTIES = {
    responses: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { serialNumber: { type: 'string' }, status: { type: 'string' } } } },
    signatureValid: { type: 'boolean' },
    diagnosticCount: { type: 'integer' },
} as const;

function singleResponseView(r: OcspSingleResponse): OcspSingleResponseView {
    const status: Record<string, Wire> = r.status.kind === 'revoked'
        ? { kind: 'revoked', revocationTime: timeView(r.status.revocationTime) as unknown as Wire, reason: r.status.reason ?? null }
        : { kind: r.status.kind };
    return {
        certId: { hashAlgorithm: algorithmView(r.certId.hashAlgorithm), issuerNameHash: toHex(r.certId.issuerNameHash), issuerKeyHash: toHex(r.certId.issuerKeyHash), serialNumber: r.certId.serialNumber.hex },
        status,
        thisUpdate: timeView(r.thisUpdate),
        nextUpdate: r.nextUpdate === undefined ? null : timeView(r.nextUpdate),
        extensions: r.extensions.map((e) => extensionView(e)),
    };
}

/** Parse the certificates a BasicOCSPResponse embeds, through the sink. */
export function embeddedCertificates(basic: OcspBasicResponse, ctx: ParseContext): Certificate[] {
    return basic.certificates.map((der, i) => guard(`Cannot read the certificate embedded in the response (certs[${i}])`, () => parseCertificate(der, ctx.options)));
}

/** The first candidate whose key verifies the response signature. */
export async function findOcspSigner(basic: OcspBasicResponse, candidates: readonly Certificate[]): Promise<Certificate | undefined> {
    for (const c of candidates) {
        if (await guardAsync('Cannot verify the OCSP signature', () => verifyOcspSignature(basic, c))) return c;
    }
    return undefined;
}

export function ocspBasicResponseView(basic: OcspBasicResponse, embedded: readonly Certificate[]): OcspBasicResponseView {
    return {
        responderId: stripRaw(basic.responderId),
        producedAt: timeView(basic.producedAt),
        responses: basic.responses.map(singleResponseView),
        extensions: basic.extensions.map((e) => extensionView(e)),
        certificates: embedded.map(certificateRef),
        signatureAlgorithm: algorithmView(basic.signatureAlgorithm),
    };
}

export async function inspectOcspResponse(rawInput: unknown): Promise<InspectOcspResponseResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const obj = await loadPkiObject(input.response, 'response', LABELS.any, ctx);
    const response = guard('Cannot read the OCSP response', () => parseOcspResponse(obj.der, ctx.options));
    const basic = response.basicResponse;
    const embedded = basic === undefined ? [] : embeddedCertificates(basic, ctx);
    let signature: InspectOcspResponseResult['signature'];
    if (basic !== undefined) {
        if (input.responder !== undefined) {
            const responderObj = await loadPkiObject(input.responder, 'responder', LABELS.certificate, ctx);
            const responder = guard('Cannot read the responder certificate', () => parseCertificate(responderObj.der, ctx.options));
            const signer = await findOcspSigner(basic, [responder]);
            signature = { valid: signer !== undefined, signer: signer === undefined ? null : dn(signer.subject), source: 'responder' };
        } else if (embedded.length > 0) {
            const signer = await findOcspSigner(basic, embedded);
            signature = { valid: signer !== undefined, signer: signer === undefined ? null : dn(signer.subject), source: 'embedded' };
        }
    }
    return withDiagnostics({
        status: response.status,
        basicResponse: basic === undefined ? null : ocspBasicResponseView(basic, embedded),
        noncePresent: basic !== undefined && basic.extensions.some((e) => e.oid === OCSP_NONCE_OID),
        sizeBytes: obj.der.length,
        ...(signature !== undefined ? { signature } : {}),
    }, ctx.sink.report());
}

export function inspectOcspResponseSummary(r: InspectOcspResponseResult): Record<string, unknown> {
    return {
        status: r.status,
        responses: (r.basicResponse?.responses ?? []).map((s) => ({ serialNumber: s.certId.serialNumber, status: s.status['kind'] })),
        noncePresent: r.noncePresent,
        ...(r.signature !== undefined ? { signatureValid: r.signature.valid } : {}),
        diagnosticCount: diagnosticCount(r),
    };
}

export const INSPECT_OCSP_RESPONSE_TOOL = defineTool<InspectOcspResponseResult>({
    name: INSPECT_OCSP_RESPONSE_NAME,
    title: 'Inspect OCSP response (RFC 6960 report, signature check)',
    kind: 'read',
    description:
        "Read-only RFC 6960 §4.2 report of ONE OCSP response (the DER a responder returned): the response status (only successful carries an answer), the BasicOCSPResponse — responder id (by name or by key hash), producedAt, every SingleResponse (CertID: hash algorithm, issuer name / key hashes, serial; status good / revoked with time and reason / unknown; thisUpdate, nextUpdate, extensions), response extensions, the embedded certificates, the signature algorithm — whether an RFC 8954 nonce is echoed, and diagnostics (bounded by limits.maxOcspSingleResponses). `responder` adds a signature check against that certificate; omitted, the embedded certificates are tried and the one that verifies is named. ONE signature against ONE key is NOT a status verdict: check_ocsp_status matches the CertID, judges the responder's authorisation (RFC 6960 §4.2.2.2), freshness and nonce. Token-frugal: verbosity:'summary' (status, responses[serialNumber, status], noncePresent, signatureValid). Input: derBase64 / path (or PEM).",
    inputSchema: INSPECT_OCSP_RESPONSE_INPUT_SCHEMA,
    rawOutputSchema: INSPECT_OCSP_RESPONSE_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(INSPECT_OCSP_RESPONSE_OUTPUT_SCHEMA, INSPECT_OCSP_RESPONSE_SUMMARY_PROPERTIES, `Structured OCSP response report.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'What does this response say, and who signed it?', input: { response: { path: 'fixtures/leaf.ocsp.der' }, verbosity: 'summary' } },
        { title: 'Signature against a known responder certificate', input: { response: { path: 'fixtures/revoked.ocsp.der' }, responder: { path: 'fixtures/ocsp.crt.pem' }, fields: ['signature', 'basicResponse.responses.status', 'basicResponse.responses.certId.serialNumber'] } },
    ],
    handler: inspectOcspResponse,
    text: (r) => `${INSPECT_OCSP_RESPONSE_NAME}: ${r.status}${r.basicResponse === null ? ' (no signed answer)' : `, produced ${r.basicResponse.producedAt.iso}, ${r.basicResponse.responses.map((s) => `serial ${s.certId.serialNumber} ${s.status['kind'] as string}`).join('; ')}, nonce ${r.noncePresent ? 'present' : 'absent'}, ${r.basicResponse.certificates.length} embedded certificate(s)`}${r.signature !== undefined ? `, signature ${r.signature.valid ? `valid (${r.signature.signer ?? ''}, ${r.signature.source})` : 'INVALID'}` : ''}, ${r.diagnostics.length} diagnostic(s).`,
    summary: inspectOcspResponseSummary,
});
