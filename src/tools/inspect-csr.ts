/**
 * Tool: inspect_csr — the full RFC 2986 report of one PKCS#10 certification
 * request (subject, public key, attributes, the requested extensions decoded
 * as a certificate's would be, challengePassword presence, signature
 * algorithm) and, by default, the proof of possession: the request's
 * signature verified under the key it carries.
 */
import { parseCertificationRequest, verifyCertificationRequest } from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { ALLOW_SHA1_INPUT_PROPERTY } from '../signer.js';
import { REASONS_OUTPUT_PROPERTY } from '../trust.js';
import { ALGORITHM_VIEW_SCHEMA, csrView, EXTENSION_VIEW_SCHEMA, NAME_VIEW_SCHEMA, reasonsView, SPKI_VIEW_SCHEMA, type algorithmView, type nameView } from '../views.js';
import type { Wire } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { AllowSha1Shape, diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';

export const INSPECT_CSR_NAME = 'inspect_csr';

export const INSPECT_CSR_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['request'],
    properties: {
        request: pkiInputSchema('The PKCS#10 request (CERTIFICATE REQUEST PEM or DER)'),
        rawExtensions: { type: 'boolean', default: false, description: 'Keep every requested extension undecoded (kind raw, valueDer as hex) — the way past PKI_X509_EXTENSION_MALFORMED.' },
        verify: { type: 'boolean', default: true, description: "Verify the request's signature under the key it carries (proof of possession; one Web Crypto verification). false skips it." },
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    request: PkiInputSchema,
    rawExtensions: z.boolean().default(false),
    verify: z.boolean().default(true),
    ...AllowSha1Shape,
    ...ParseShape,
    ...ProjectionShape,
});

/** The members `csrView` renders (a type alias so the wire record can be read as it). */
type CsrViewMembers = {
    readonly version: number;
    readonly subject: ReturnType<typeof nameView>;
    readonly subjectPublicKeyInfo: Record<string, Wire>;
    readonly attributes: ReadonlyArray<{ readonly oid: string; readonly name: string | null; readonly valueCount: number }>;
    readonly extensions: ReadonlyArray<Record<string, Wire>> | null;
    readonly challengePassword: boolean;
    readonly signatureAlgorithm: ReturnType<typeof algorithmView>;
    readonly sizeBytes: number;
};

export interface InspectCsrResult extends CsrViewMembers, DiagnosticsReport {
    readonly subjectString: string;
    readonly signature?: { readonly valid: boolean; readonly reasons: ReadonlyArray<Record<string, string>>; readonly signatureVerifications: number };
}

export const INSPECT_CSR_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['version', 'subject', 'subjectPublicKeyInfo', 'attributes', 'extensions', 'challengePassword', 'signatureAlgorithm', 'sizeBytes', 'subjectString', 'diagnostics', 'diagnosticCounts'],
    properties: {
        version: { type: 'integer', enum: [0], description: 'v1 (encoded 0), the only version RFC 2986 defines.' },
        subject: NAME_VIEW_SCHEMA,
        subjectPublicKeyInfo: SPKI_VIEW_SCHEMA,
        attributes: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['oid', 'name', 'valueCount'], properties: { oid: { type: 'string' }, name: { type: ['string', 'null'] }, valueCount: { type: 'integer' } } }, description: 'Every attribute in encoded order (extensionRequest, challengePassword, …).' },
        extensions: { type: ['array', 'null'], items: EXTENSION_VIEW_SCHEMA, description: 'The extensions requested through extensionRequest (RFC 2985 §5.4.2), decoded; null when the request asks for none. A CA is free to ignore them.' },
        challengePassword: { type: 'boolean', description: 'Whether a challengePassword attribute is present (its text is attacker-controlled and never reported).' },
        signatureAlgorithm: ALGORITHM_VIEW_SCHEMA,
        sizeBytes: { type: 'integer' },
        subjectString: { type: 'string', description: 'RFC 4514 subject.' },
        signature: {
            type: 'object',
            additionalProperties: false,
            required: ['valid', 'reasons', 'signatureVerifications'],
            description: 'The proof of possession (verify:true): the signature under the key the request carries. Not trust — a CSR is unsigned by any CA.',
            properties: { valid: { type: 'boolean' }, ...REASONS_OUTPUT_PROPERTY, signatureVerifications: { type: 'integer' } },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const INSPECT_CSR_SUMMARY_PROPERTIES = {
    publicKey: { type: 'string' },
    extensionKinds: { type: 'array', items: { type: 'string' } },
    signatureValid: { type: 'boolean' },
    diagnosticCount: { type: 'integer' },
} as const;

export async function inspectCsr(rawInput: unknown): Promise<InspectCsrResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const obj = await loadPkiObject(input.request, 'request', LABELS.csr, ctx);
    const csr = guard('Cannot read the request', () => parseCertificationRequest(obj.der, { ...ctx.options, decodeExtensions: !input.rawExtensions }));
    const view = csrView(csr, input.rawExtensions) as CsrViewMembers;
    let signature: InspectCsrResult['signature'];
    if (input.verify) {
        const report = await guardAsync('Cannot verify the request signature', () => verifyCertificationRequest(csr, { ...ctx.options, allowSha1: input.allowSha1 }));
        signature = { valid: report.valid, reasons: reasonsView(report.reasons), signatureVerifications: report.signatureVerifications };
    }
    return withDiagnostics({
        ...view,
        subjectString: view.subject.string,
        ...(signature !== undefined ? { signature } : {}),
    }, ctx.sink.report());
}

export function inspectCsrSummary(r: InspectCsrResult): Record<string, unknown> {
    return {
        subjectString: r.subjectString,
        publicKey: r.subjectPublicKeyInfo['kind'],
        extensionKinds: (r.extensions ?? []).map((e) => e['kind']),
        challengePassword: r.challengePassword,
        ...(r.signature !== undefined ? { signatureValid: r.signature.valid } : {}),
        diagnosticCount: diagnosticCount(r),
    };
}

export const INSPECT_CSR_TOOL = defineTool<InspectCsrResult>({
    name: INSPECT_CSR_NAME,
    title: 'Inspect CSR (RFC 2986 report, requested extensions, proof of possession)',
    kind: 'read',
    description:
        "Read-only RFC 2986 report of ONE PKCS#10 certification request: subject (RFC 4514 + RDNs), public key (kind, bits, curve / modulus), every attribute, the extensions requested through extensionRequest decoded as a certificate's would be (rawExtensions:true keeps them undecoded), whether a challengePassword is present (never its text), the signature algorithm, and — by default (`verify`, one Web Crypto verification) — the proof of possession: signature.valid tells whether the request was signed by the key it carries, with reasons[] (PKI_REASON_SIGNATURE_NOT_CHECKED for SHA-1 without allowSha1:true). That is NOT trust: no CA signed a CSR, and a CA is free to ignore every extension it asks for. Pair with create_certificate (subjectPublicKey = the request) to issue from it. Token-frugal: verbosity:'summary' (subject, key kind, extension kinds, signatureValid), fields:[…]. Input: pem / derBase64 / path (.csr .p10 .der .pem).",
    inputSchema: INSPECT_CSR_INPUT_SCHEMA,
    rawOutputSchema: INSPECT_CSR_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(INSPECT_CSR_OUTPUT_SCHEMA, INSPECT_CSR_SUMMARY_PROPERTIES, `Structured request report.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'What does this request ask for, and did its key sign it?', input: { request: { path: 'fixtures/leaf.csr.pem' }, verbosity: 'summary' } },
        { title: 'The requested SAN only, no signature check', input: { request: { path: 'fixtures/leaf.csr.pem' }, verify: false, fields: ['subjectString', 'extensions.names'] } },
    ],
    handler: inspectCsr,
    text: (r) => `${INSPECT_CSR_NAME}: ${r.subjectString} requests a ${String(r.subjectPublicKeyInfo['kind'])} key certified, ${r.extensions === null ? 'no extension' : `${r.extensions.length} extension(s) (${r.extensions.map((e) => String(e['kind'])).join(', ')})`}, ${r.attributes.length} attribute(s)${r.challengePassword ? ' incl. challengePassword' : ''}, signature ${r.signature === undefined ? 'not checked' : r.signature.valid ? 'valid (proof of possession)' : `INVALID (${r.signature.reasons.map((x) => x['code']).join(', ')})`}, ${r.diagnostics.length} diagnostic(s).`,
    summary: inspectCsrSummary,
});
