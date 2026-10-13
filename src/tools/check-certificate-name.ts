/**
 * Tool: check_certificate_name — RFC 6125 server identity: is this
 * certificate valid for that host name or IP address (the certificate form),
 * or does one presented dNSName match a reference name (the match form,
 * wildcard rules included)? A negative answer is `valid:false` + reasons[],
 * never isError. Name only: trust is verify_certificate_chain's verdict.
 */
import { checkServerName, matchDnsName, parseCertificate, type ServerIdentity } from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard } from '../pki-errors.js';
import { LABELS, loadPkiBundle, loadPkiObject, pkiBundleSchema, pkiInputSchema, PkiBundleSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { REASONS_OUTPUT_PROPERTY } from '../trust.js';
import { dn, reasonsView } from '../views.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';
import { parseCertificates, serverIdentity } from './verify-certificate-chain.js';

export const CHECK_CERTIFICATE_NAME_NAME = 'check_certificate_name';

export const CHECK_CERTIFICATE_NAME_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    properties: {
        certificate: pkiInputSchema('The certificate to judge (certificate form)', ' With exactly one of host / ip. Exclusive with presented / reference.'),
        host: { type: 'string', minLength: 1, description: 'The reference DNS name as it appeared in the URL (one trailing dot is ignored). Exclusive with ip.' },
        ip: { type: 'string', minLength: 1, description: 'The reference IPv4 or IPv6 address. Exclusive with host.' },
        chain: pkiBundleSchema('The issuing certificates, leaf\'s issuer first', ' Optional; read only by the commonName fallback, which holds a CN read as a host name to the dNSName name constraints of these CAs (without it the fallback refuses).'),
        allowCommonNameFallback: { type: 'boolean', default: false, description: 'Fall back to the subject commonName when the certificate carries no dNSName and no iPAddress (CA/Browser Forum forbids CN-only certificates since 2017; needs chain). Default false.' },
        allowWildcards: { type: 'boolean', default: true, description: 'Accept a wildcard name (*.example.test) at all. Default true; false is right for an internal PKI that issues none.' },
        presented: { type: 'string', minLength: 1, description: "Match form: the certificate's dNSName, possibly a wildcard. With reference; exclusive with certificate / host / ip / chain." },
        reference: { type: 'string', minLength: 1, description: 'Match form: the reference host name.' },
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    certificate: PkiInputSchema.optional(),
    host: z.string().min(1).optional(),
    ip: z.string().min(1).optional(),
    chain: PkiBundleSchema.optional(),
    allowCommonNameFallback: z.boolean().default(false),
    allowWildcards: z.boolean().default(true),
    presented: z.string().min(1).optional(),
    reference: z.string().min(1).optional(),
    ...ParseShape,
    ...ProjectionShape,
}).superRefine((v, ctx) => {
    if (v.presented !== undefined || v.reference !== undefined) {
        if (v.presented === undefined || v.reference === undefined) ctx.addIssue({ code: 'custom', message: 'the match form takes both presented and reference', path: ['presented'] });
        if (v.certificate !== undefined || v.host !== undefined || v.ip !== undefined || v.chain !== undefined) ctx.addIssue({ code: 'custom', message: 'presented / reference are exclusive with certificate / host / ip / chain', path: ['presented'] });
        return;
    }
    if (v.certificate === undefined) ctx.addIssue({ code: 'custom', message: 'pass certificate with host or ip (or presented + reference for the match form)', path: ['certificate'] });
    if ((v.host === undefined) === (v.ip === undefined)) ctx.addIssue({ code: 'custom', message: 'pass exactly one of host / ip', path: ['host'] });
});

export interface CheckCertificateNameResult extends DiagnosticsReport {
    readonly form: 'certificate' | 'match';
    readonly valid: boolean;
    readonly reasons: ReadonlyArray<Record<string, string>>;
    readonly reference: { readonly kind: 'dns' | 'ip'; readonly value: string };
    /** Certificate form: the subject judged. */
    readonly subject?: string;
    /** Match form: the presented name and the bare outcome. */
    readonly presented?: string;
    readonly match?: boolean;
}

export const CHECK_CERTIFICATE_NAME_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['form', 'valid', 'reasons', 'reference', 'diagnostics', 'diagnosticCounts'],
    properties: {
        form: { type: 'string', enum: ['certificate', 'match'] },
        valid: { type: 'boolean', description: 'The verdict (the match outcome in the match form). false is a negative verdict, never an error.' },
        ...REASONS_OUTPUT_PROPERTY,
        reference: { type: 'object', additionalProperties: false, required: ['kind', 'value'], properties: { kind: { type: 'string', enum: ['dns', 'ip'] }, value: { type: 'string' } }, description: 'The reference identity judged.' },
        subject: { type: 'string', description: 'Certificate form: RFC 4514 subject of the certificate.' },
        presented: { type: 'string', description: 'Match form: the presented name.' },
        match: { type: 'boolean', description: 'Match form: whether presented matches reference.' },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const CHECK_CERTIFICATE_NAME_SUMMARY_PROPERTIES = {
    reasonCodes: { type: 'array', items: { type: 'string' } },
    diagnosticCount: { type: 'integer' },
} as const;

export async function checkCertificateName(rawInput: unknown): Promise<CheckCertificateNameResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    if (input.presented !== undefined && input.reference !== undefined) {
        const presented = input.presented;
        const reference = input.reference;
        const match = guard('Cannot match the names', () => matchDnsName(presented, reference, { allowWildcards: input.allowWildcards }));
        return withDiagnostics({ form: 'match', valid: match, reasons: [], reference: { kind: 'dns', value: reference }, presented, match }, ctx.sink.report());
    }
    const obj = await loadPkiObject(input.certificate as z.infer<typeof PkiInputSchema>, 'certificate', LABELS.certificate, ctx);
    const certificate = guard('Cannot read the certificate', () => parseCertificate(obj.der, ctx.options));
    const chain = parseCertificates(await loadPkiBundle(input.chain, 'chain', LABELS.certificate, ctx), 'chain certificate', ctx);
    const identity = serverIdentity({ host: input.host, ip: input.ip }, '$') as ServerIdentity;
    const reasons = guard('Cannot check the name', () => checkServerName(certificate, identity, {
        allowCommonNameFallback: input.allowCommonNameFallback,
        allowWildcards: input.allowWildcards,
        ...(chain.length > 0 ? { path: [certificate, ...chain] } : {}),
    }));
    return withDiagnostics({
        form: 'certificate',
        valid: reasons.length === 0,
        reasons: reasonsView(reasons),
        reference: { kind: identity.kind, value: input.host ?? (input.ip as string) },
        subject: dn(certificate.subject),
    }, ctx.sink.report());
}

export function checkCertificateNameSummary(r: CheckCertificateNameResult): Record<string, unknown> {
    return {
        form: r.form,
        valid: r.valid,
        reasonCodes: r.reasons.map((x) => x['code']),
        reference: r.reference,
        ...(r.subject !== undefined ? { subject: r.subject } : {}),
        ...(r.presented !== undefined ? { presented: r.presented } : {}),
        ...(r.match !== undefined ? { match: r.match } : {}),
        diagnosticCount: diagnosticCount(r),
    };
}

export const CHECK_CERTIFICATE_NAME_TOOL = defineTool<CheckCertificateNameResult>({
    name: CHECK_CERTIFICATE_NAME_NAME,
    title: 'Check certificate name (RFC 6125 host / IP identity, or one name match)',
    kind: 'verdict',
    description:
        "The RFC 6125 identity verdict, two forms. Certificate form: `certificate` + exactly one of `host` (DNS name as it appeared in the URL) / `ip` — is the certificate valid for that identity (subjectAltName dNSName / iPAddress; wildcards under `allowWildcards`, default true; `allowCommonNameFallback`, default false, reads a CN-only certificate's commonName and then needs `chain` — the issuing CAs, leaf's issuer first — so the CN is held to their dNSName name constraints as a SAN would be). Match form: `presented` (the certificate's dNSName, possibly a wildcard) + `reference` — one RFC 6125 §6.4 name comparison, no certificate. A negative verdict is valid:false + reasons[] (PKI_REASON_NAME_MISMATCH, …) in structuredContent — never isError. The name only: it is not trust (verify_certificate_chain with serverName is the full verdict), not validity, not revocation. Token-frugal: verbosity:'summary'.",
    inputSchema: CHECK_CERTIFICATE_NAME_INPUT_SCHEMA,
    rawOutputSchema: CHECK_CERTIFICATE_NAME_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(CHECK_CERTIFICATE_NAME_OUTPUT_SCHEMA, CHECK_CERTIFICATE_NAME_SUMMARY_PROPERTIES, `Name verdict.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'Is the leaf valid for a.wild.example.test?', input: { certificate: { path: 'fixtures/leaf.crt.pem' }, host: 'a.wild.example.test', verbosity: 'summary' } },
        { title: 'Does a wildcard name match a host?', input: { presented: '*.example.test', reference: 'a.example.test' } },
    ],
    handler: checkCertificateName,
    text: (r) => r.form === 'match'
        ? `${CHECK_CERTIFICATE_NAME_NAME}: ${r.valid ? 'OK — ' : 'NOT OK — '}"${r.presented ?? ''}" ${r.valid ? 'matches' : 'does not match'} "${r.reference.value}".`
        : r.valid
            ? `${CHECK_CERTIFICATE_NAME_NAME}: OK — ${r.subject ?? ''} is valid for ${r.reference.kind} ${r.reference.value}; ${r.diagnostics.length} diagnostic(s).`
            : `${CHECK_CERTIFICATE_NAME_NAME}: NOT OK — ${r.reasons.map((x) => x['code']).join(', ')} (${r.subject ?? ''} for ${r.reference.kind} ${r.reference.value}).`,
    summary: checkCertificateNameSummary,
});
