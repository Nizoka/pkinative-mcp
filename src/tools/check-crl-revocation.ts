/**
 * Tool: check_crl_revocation — the RFC 5280 §6.3 revocation verdict of ONE
 * certificate against ONE CRL (and an optional delta): scope (issuer,
 * distribution point, reasons), freshness at `at` (nextUpdate, stale
 * tolerance), the delta's base number, and the entry itself. The CRL
 * signature is verified here against `issuer` when one is given and
 * reported to the engine, which refuses an unverified list by policy.
 */
import { checkRevocation, parseCertificate, verifyCrlSignature, type Certificate, type CertificateList } from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { ALLOW_SHA1_INPUT_PROPERTY } from '../signer.js';
import { resolveInstant } from '../time.js';
import { REASONS_OUTPUT_PROPERTY, TRUST_INPUT_PROPERTIES, TrustShape } from '../trust.js';
import { reasonsView } from '../views.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { AllowSha1Shape, diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';
import { loadCrl } from './inspect-crl.js';

export const CHECK_CRL_REVOCATION_NAME = 'check_crl_revocation';

export const STALE_TOLERANCE_INPUT_PROPERTY = {
    staleTolerance: { type: 'integer', minimum: 0, description: 'Milliseconds past nextUpdate the evidence is still accepted (default: the engine policy, none).' },
} as const;

export const CHECK_CRL_REVOCATION_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['certificate', 'crl'],
    properties: {
        certificate: pkiInputSchema('The certificate to check'),
        crl: pkiInputSchema('The base CRL (X509 CRL PEM or DER)'),
        delta: pkiInputSchema('A delta CRL applied over the base', ' Must carry a deltaCRLIndicator (VALIDATION_ERROR otherwise); its base CRL number is checked against the base.'),
        issuer: pkiInputSchema('The CRL issuer certificate', ' The base (and delta) signatures are verified against it and reported to the engine as signatureVerified. Omitted: the signatures are NOT verified and the engine refuses the list (PKI_REASON_CRL_SIGNATURE_UNVERIFIED) — the verdict is then only a dry run.'),
        at: TRUST_INPUT_PROPERTIES.at,
        ...STALE_TOLERANCE_INPUT_PROPERTY,
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    certificate: PkiInputSchema,
    crl: PkiInputSchema,
    delta: PkiInputSchema.optional(),
    issuer: PkiInputSchema.optional(),
    at: TrustShape.at,
    staleTolerance: z.number().int().min(0).optional(),
    ...AllowSha1Shape,
    ...ParseShape,
    ...ProjectionShape,
});

export interface CrlRevocationVerdict extends DiagnosticsReport {
    readonly valid: boolean;
    readonly reasons: ReadonlyArray<Record<string, string>>;
    readonly signatureVerified: boolean | null;
    readonly deltaSignatureVerified?: boolean | null;
    readonly evaluatedAt: string;
    readonly evaluatedAtSource: 'input' | 'pinned' | 'clock';
    readonly crlNumber: string | null;
    readonly isDelta: boolean;
    readonly deltaCrlNumber?: string | null;
}

export const CHECK_CRL_REVOCATION_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['valid', 'reasons', 'signatureVerified', 'evaluatedAt', 'evaluatedAtSource', 'crlNumber', 'isDelta', 'diagnostics', 'diagnosticCounts'],
    properties: {
        valid: { type: 'boolean', description: 'true = the certificate is not revoked according to fresh, in-scope, signature-verified evidence. false is a negative verdict (reasons[]), never an error.' },
        ...REASONS_OUTPUT_PROPERTY,
        signatureVerified: { type: ['boolean', 'null'], description: 'The base CRL signature against `issuer`; null when no issuer was given (then the engine reports the list as unverified).' },
        deltaSignatureVerified: { type: ['boolean', 'null'], description: 'The delta CRL signature against `issuer` (present only with `delta`).' },
        evaluatedAt: { type: 'string', description: 'The ISO instant used — re-pass it as `at` to reproduce the verdict.' },
        evaluatedAtSource: { type: 'string', enum: ['input', 'pinned', 'clock'] },
        crlNumber: { type: ['string', 'null'], description: 'The base CRL number (decimal), null when absent.' },
        isDelta: { type: 'boolean', description: 'Whether the BASE list itself carries a deltaCRLIndicator (false for a proper base CRL).' },
        deltaCrlNumber: { type: ['string', 'null'], description: 'The delta CRL number (present only with `delta`).' },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const CHECK_CRL_REVOCATION_SUMMARY_PROPERTIES = {
    reasonCodes: { type: 'array', items: { type: 'string' } },
    diagnosticCount: { type: 'integer' },
} as const;

export async function checkCrlRevocation(rawInput: unknown): Promise<CrlRevocationVerdict> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const certObj = await loadPkiObject(input.certificate, 'certificate', LABELS.certificate, ctx);
    const certificate = guard('Cannot read the certificate', () => parseCertificate(certObj.der, ctx.options));
    const base = await loadCrl(input.crl, 'crl', 'CRL', ctx);
    const delta = input.delta === undefined ? undefined : await loadCrl(input.delta, 'delta', 'delta CRL', ctx);
    if (delta !== undefined && !delta.crl.isDelta) {
        throw new ToolError('VALIDATION_ERROR', `delta (${delta.obj.source}) is not a delta CRL: it has no deltaCRLIndicator extension (CRL number ${delta.crl.crlNumber?.toString(10) ?? 'absent'}).`, { path: 'delta', remedy: 'pass the base CRL as crl and the delta CRL as delta' });
    }
    let issuer: Certificate | undefined;
    if (input.issuer !== undefined) {
        const issuerObj = await loadPkiObject(input.issuer, 'issuer', LABELS.certificate, ctx);
        issuer = guard('Cannot read the issuer certificate', () => parseCertificate(issuerObj.der, ctx.options));
    }
    const verify = async (list: CertificateList, what: string): Promise<boolean | undefined> => (issuer === undefined
        ? undefined
        : guardAsync(`Cannot verify the ${what} signature`, () => verifyCrlSignature(list, issuer as Certificate, { allowSha1: input.allowSha1 })));
    const signatureVerified = await verify(base.crl, 'CRL');
    const deltaVerified = delta === undefined ? undefined : await verify(delta.crl, 'delta CRL');
    const at = resolveInstant(input.at, 'at');
    const reasons = guard('Cannot check revocation', () => checkRevocation({
        certificate,
        crl: base.crl,
        crlDer: base.obj.der,
        at: at.ms,
        ...(signatureVerified !== undefined ? { signatureVerified } : {}),
        ...(input.staleTolerance !== undefined ? { staleTolerance: input.staleTolerance } : {}),
        ...(delta !== undefined ? { delta: { crl: delta.crl, crlDer: delta.obj.der, ...(deltaVerified !== undefined ? { signatureVerified: deltaVerified } : {}) } } : {}),
        ...(ctx.options.limits !== undefined ? { limits: ctx.options.limits } : {}),
        onDiagnostic: ctx.options.onDiagnostic,
    }));
    return withDiagnostics({
        valid: reasons.length === 0,
        reasons: reasonsView(reasons),
        signatureVerified: signatureVerified ?? null,
        ...(delta !== undefined ? { deltaSignatureVerified: deltaVerified ?? null, deltaCrlNumber: delta.crl.crlNumber?.toString(10) ?? null } : {}),
        evaluatedAt: at.iso,
        evaluatedAtSource: at.source,
        crlNumber: base.crl.crlNumber?.toString(10) ?? null,
        isDelta: base.crl.isDelta,
    }, ctx.sink.report());
}

export function checkCrlRevocationSummary(r: CrlRevocationVerdict): Record<string, unknown> {
    return {
        valid: r.valid,
        reasonCodes: r.reasons.map((x) => x['code']),
        signatureVerified: r.signatureVerified,
        ...(r.deltaSignatureVerified !== undefined ? { deltaSignatureVerified: r.deltaSignatureVerified } : {}),
        evaluatedAt: r.evaluatedAt,
        crlNumber: r.crlNumber,
        diagnosticCount: diagnosticCount(r),
    };
}

export const CHECK_CRL_REVOCATION_TOOL = defineTool<CrlRevocationVerdict>({
    name: CHECK_CRL_REVOCATION_NAME,
    title: 'Check CRL revocation (one certificate against one CRL, optional delta)',
    kind: 'verdict',
    description:
        "The RFC 5280 §6.3 revocation verdict of ONE `certificate` against ONE base `crl` you fetched (this server never fetches), evaluated at `at`: the list must be in scope for the certificate (issuer, issuing distribution point, reasons), fresh (nextUpdate, or `staleTolerance` ms past it), signature-verified, and the serial must not be listed (PKI_REASON_REVOKED with the reason otherwise). `delta` applies a delta CRL over the base (it must carry a deltaCRLIndicator — VALIDATION_ERROR otherwise — and name the base's number). `issuer` is the CRL issuer certificate: the base (and delta) signatures are verified against it and reported as signatureVerified / deltaSignatureVerified; without it the engine refuses the unverified list, so pass it for a real verdict. valid:false + reasons[] is a verdict, never isError. Pin `at` for a reproducible, cacheable verdict. SHA-1 signatures need allowSha1:true. Token-frugal: verbosity:'summary'. inspect_crl shows the list's facts; verify_certificate_chain with crls:[…] is the whole-chain form.",
    inputSchema: CHECK_CRL_REVOCATION_INPUT_SCHEMA,
    rawOutputSchema: CHECK_CRL_REVOCATION_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(CHECK_CRL_REVOCATION_OUTPUT_SCHEMA, CHECK_CRL_REVOCATION_SUMMARY_PROPERTIES, `CRL revocation verdict.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    instantInputs: ['at'],
    examples: [
        { title: 'Is the leaf revoked according to the intermediate CRL?', input: { certificate: { path: 'fixtures/leaf.crt.pem' }, crl: { path: 'fixtures/inter.crl.pem' }, issuer: { path: 'fixtures/inter.crt.pem' }, at: '2027-01-01T00:00:00Z', verbosity: 'summary' } },
        { title: 'Base plus delta CRL of the Ed25519 CA', input: { certificate: { path: 'fixtures/ed25519.crt.pem' }, crl: { path: 'fixtures/ed25519.crl.der' }, delta: { path: 'fixtures/ed25519-delta.crl.der' }, issuer: { path: 'fixtures/ed25519.crt.pem' }, at: '2027-01-01T00:00:00Z' } },
    ],
    handler: checkCrlRevocation,
    text: (r) => r.valid
        ? `${CHECK_CRL_REVOCATION_NAME}: OK — not revoked at ${r.evaluatedAt} (CRL number ${r.crlNumber ?? '(none)'}, signature ${r.signatureVerified === null ? 'not verified' : r.signatureVerified ? 'verified' : 'INVALID'}); ${r.diagnostics.length} diagnostic(s).`
        : `${CHECK_CRL_REVOCATION_NAME}: NOT OK — ${r.reasons.map((x) => x['code']).join(', ')} (evaluated at ${r.evaluatedAt}).`,
    summary: checkCrlRevocationSummary,
});
