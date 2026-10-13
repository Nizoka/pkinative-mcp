/**
 * Tool: check_certificate_purpose — RFC 5280 §4.2.1.12 extended key usage
 * along a path: may this certificate be used for that purpose (serverAuth,
 * clientAuth, codeSigning, …, any, or a dotted OID), with its issuers'
 * extKeyUsage applied as every Web PKI validator does (`restrictIssuers`)?
 * A negative answer is `valid:false` + reasons[], never isError.
 */
import { checkExtendedKeyUsage, getOidName, parseCertificate } from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard } from '../pki-errors.js';
import { LABELS, loadPkiBundle, loadPkiObject, pkiBundleSchema, pkiInputSchema, PkiBundleSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { PURPOSE_NAMES, purposeOid, REASONS_OUTPUT_PROPERTY } from '../trust.js';
import { dn, reasonsView } from '../views.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';
import { parseCertificates } from './verify-certificate-chain.js';

export const CHECK_CERTIFICATE_PURPOSE_NAME = 'check_certificate_purpose';

export const CHECK_CERTIFICATE_PURPOSE_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['certificate', 'purpose'],
    properties: {
        certificate: pkiInputSchema('The end-entity certificate to judge'),
        chain: pkiBundleSchema('The issuing certificates, leaf\'s issuer first (the path is [certificate, ...chain])', ' Optional; their extKeyUsage restricts the leaf under restrictIssuers.'),
        purpose: { type: 'string', minLength: 1, description: `The purpose needed: ${PURPOSE_NAMES.join(', ')}, any, or a dotted KeyPurposeId OID.` },
        restrictIssuers: { type: 'boolean', default: true, description: "Apply a CA's own extKeyUsage to what it issued (what every Web PKI validator does; no sentence of RFC 5280 requires it). Default true; false is the literal-RFC reading." },
        requireExplicitPurpose: { type: 'boolean', default: false, description: 'Require the certificate to carry extKeyUsage and name the purpose explicitly (the stricter Web PKI reading); default false = no extKeyUsage means unrestricted (RFC 5280 §4.2.1.12).' },
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    certificate: PkiInputSchema,
    chain: PkiBundleSchema.optional(),
    purpose: z.string().min(1),
    restrictIssuers: z.boolean().default(true),
    requireExplicitPurpose: z.boolean().default(false),
    ...ParseShape,
    ...ProjectionShape,
});

export interface CheckCertificatePurposeResult extends DiagnosticsReport {
    readonly valid: boolean;
    readonly reasons: ReadonlyArray<Record<string, string>>;
    readonly purpose: string;
    readonly purposeOid: string;
    readonly purposeName: string | null;
    readonly subject: string;
    readonly pathLength: number;
}

export const CHECK_CERTIFICATE_PURPOSE_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['valid', 'reasons', 'purpose', 'purposeOid', 'purposeName', 'subject', 'pathLength', 'diagnostics', 'diagnosticCounts'],
    properties: {
        valid: { type: 'boolean', description: 'The verdict. false is a negative verdict (reasons[]), never an error.' },
        ...REASONS_OUTPUT_PROPERTY,
        purpose: { type: 'string', description: 'The purpose as given.' },
        purposeOid: { type: 'string', description: 'The KeyPurposeId OID judged.' },
        purposeName: { type: ['string', 'null'], description: 'The registry name of that OID.' },
        subject: { type: 'string', description: 'RFC 4514 subject of the certificate.' },
        pathLength: { type: 'integer', minimum: 1, description: '1 + the chain certificates (reasons name path[i]).' },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const CHECK_CERTIFICATE_PURPOSE_SUMMARY_PROPERTIES = {
    reasonCodes: { type: 'array', items: { type: 'string' } },
    diagnosticCount: { type: 'integer' },
} as const;

export async function checkCertificatePurpose(rawInput: unknown): Promise<CheckCertificatePurposeResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const oid = purposeOid(input.purpose, 'purpose');
    const obj = await loadPkiObject(input.certificate, 'certificate', LABELS.certificate, ctx);
    const certificate = guard('Cannot read the certificate', () => parseCertificate(obj.der, ctx.options));
    const chain = parseCertificates(await loadPkiBundle(input.chain, 'chain', LABELS.certificate, ctx), 'chain certificate', ctx);
    const path = [certificate, ...chain];
    const reasons = guard('Cannot check the purpose', () => checkExtendedKeyUsage(path, oid, {
        restrictIssuers: input.restrictIssuers,
        requireExplicitPurpose: input.requireExplicitPurpose,
    }));
    return withDiagnostics({
        valid: reasons.length === 0,
        reasons: reasonsView(reasons),
        purpose: input.purpose,
        purposeOid: oid,
        purposeName: getOidName(oid) ?? null,
        subject: dn(certificate.subject),
        pathLength: path.length,
    }, ctx.sink.report());
}

export function checkCertificatePurposeSummary(r: CheckCertificatePurposeResult): Record<string, unknown> {
    return { valid: r.valid, reasonCodes: r.reasons.map((x) => x['code']), purpose: r.purpose, purposeOid: r.purposeOid, subject: r.subject, pathLength: r.pathLength, diagnosticCount: diagnosticCount(r) };
}

export const CHECK_CERTIFICATE_PURPOSE_TOOL = defineTool<CheckCertificatePurposeResult>({
    name: CHECK_CERTIFICATE_PURPOSE_NAME,
    title: 'Check certificate purpose (extended key usage along the path)',
    kind: 'verdict',
    description:
        "The RFC 5280 §4.2.1.12 purpose verdict: may `certificate` be used for `purpose` (serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, ocspSigning, any, or a dotted KeyPurposeId OID)? The path judged is [certificate, ...chain] (issuers, leaf's issuer first): under `restrictIssuers` (default true, what every Web PKI validator does) a CA's own extKeyUsage restricts what it issued; `requireExplicitPurpose` (default false) refuses a certificate with no extKeyUsage instead of reading its absence as unrestricted. A negative verdict is valid:false + reasons[] (PKI_REASON_PURPOSE_NOT_PERMITTED with the path[i] element) in structuredContent — never isError; an unknown purpose name is VALIDATION_ERROR. The purpose only: not trust, validity, names or revocation (verify_certificate_chain with purposes is the full verdict). Token-frugal: verbosity:'summary'.",
    inputSchema: CHECK_CERTIFICATE_PURPOSE_INPUT_SCHEMA,
    rawOutputSchema: CHECK_CERTIFICATE_PURPOSE_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(CHECK_CERTIFICATE_PURPOSE_OUTPUT_SCHEMA, CHECK_CERTIFICATE_PURPOSE_SUMMARY_PROPERTIES, `Purpose verdict.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'May the leaf serve TLS, under its issuer?', input: { certificate: { path: 'fixtures/leaf.crt.pem' }, chain: [{ path: 'fixtures/inter.crt.pem' }], purpose: 'serverAuth', verbosity: 'summary' } },
        { title: 'May it sign code? (a negative verdict, not an error)', input: { certificate: { path: 'fixtures/leaf.crt.pem' }, purpose: 'codeSigning' } },
    ],
    handler: checkCertificatePurpose,
    text: (r) => r.valid
        ? `${CHECK_CERTIFICATE_PURPOSE_NAME}: OK — ${r.subject} may be used for ${r.purpose} (${r.purposeOid}); path of ${r.pathLength}; ${r.diagnostics.length} diagnostic(s).`
        : `${CHECK_CERTIFICATE_PURPOSE_NAME}: NOT OK — ${r.reasons.map((x) => x['code']).join(', ')} (${r.subject} for ${r.purpose}).`,
    summary: checkCertificatePurposeSummary,
});
