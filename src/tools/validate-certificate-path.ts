/**
 * Tool: validate_certificate_path — RFC 5280 §6.1 validation of a path the
 * caller already ordered (leaf first) against the caller's trust anchors,
 * with every link's signature verified by this wrapper first (certificate i
 * against i+1, the last against the anchor whose subject is its issuer) and
 * handed to the engine as `signatures`. `checkSignatures:false` yields a
 * structural verdict that says so (`signaturesChecked:false`).
 */
import { validateCertificatePath, verifyCertificateSignature, type Certificate, type SignatureResult } from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiBundle, pkiBundleSchema, PkiBundleSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { ALLOW_SHA1_INPUT_PROPERTY } from '../signer.js';
import { resolveInstant } from '../time.js';
import { policyOptions, REASONS_OUTPUT_PROPERTY, TRUST_INPUT_PROPERTIES, TrustShape } from '../trust.js';
import { CERTIFICATE_REF_SCHEMA, certificateRef, dn, reasonsView } from '../views.js';
import { toHex } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { AllowSha1Shape, diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';
import { SIGNATURE_NOT_CHECKED } from './build-certificate-path.js';
import { CHAIN_SUMMARY_PROPERTIES, parseCertificates } from './verify-certificate-chain.js';

export const VALIDATE_CERTIFICATE_PATH_NAME = 'validate_certificate_path';

export const VALIDATE_CERTIFICATE_PATH_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['path', 'trustAnchors'],
    properties: {
        path: pkiBundleSchema('The path to validate, leaf FIRST, then each issuer up to (but not necessarily including) the anchor', ' Every PEM block of every item is taken, in order.'),
        trustAnchors: TRUST_INPUT_PROPERTIES.trustAnchors,
        at: TRUST_INPUT_PROPERTIES.at,
        checkSignatures: { type: 'boolean', default: true, description: 'Verify every link signature before validating (certificate i against i+1, the last against the anchor whose subject is its issuer). false = structural verdict only: PKI_REASON_SIGNATURE_NOT_CHECKED stays in reasons[], signaturesChecked:false.' },
        policy: TRUST_INPUT_PROPERTIES.policy,
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    path: PkiBundleSchema,
    trustAnchors: TrustShape.trustAnchors,
    at: TrustShape.at,
    checkSignatures: z.boolean().default(true),
    policy: TrustShape.policy,
    ...AllowSha1Shape,
    ...ParseShape,
    ...ProjectionShape,
});

export interface LinkSignatureView {
    readonly index: number;
    readonly subject: string;
    readonly issuer: string | null;
    readonly verdict: 'valid' | 'invalid' | 'not-checked';
}

export interface ValidatePathResult extends DiagnosticsReport {
    readonly valid: boolean;
    readonly reasons: ReadonlyArray<Record<string, string>>;
    readonly failingReasons: ReadonlyArray<Record<string, string>>;
    readonly path: ReadonlyArray<ReturnType<typeof certificateRef>>;
    readonly pathLength: number;
    readonly signaturesChecked: boolean;
    readonly signatures: readonly LinkSignatureView[];
    readonly evaluatedAt: string;
    readonly evaluatedAtSource: 'input' | 'pinned' | 'clock';
}

export const VALIDATE_CERTIFICATE_PATH_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['valid', 'reasons', 'failingReasons', 'path', 'pathLength', 'signaturesChecked', 'signatures', 'evaluatedAt', 'evaluatedAtSource', 'diagnostics', 'diagnosticCounts'],
    properties: {
        valid: { type: 'boolean', description: 'The engine verdict. With checkSignatures:false it is always false (every link is PKI_REASON_SIGNATURE_NOT_CHECKED): read failingReasons for the structural verdict.' },
        ...REASONS_OUTPUT_PROPERTY,
        failingReasons: { ...REASONS_OUTPUT_PROPERTY.reasons, description: 'The reasons that fail THIS call: reasons[] as is when the signatures were checked, minus the PKI_REASON_SIGNATURE_NOT_CHECKED markers otherwise. Empty = the path validates (structurally, when signaturesChecked is false).' },
        path: { type: 'array', items: CERTIFICATE_REF_SCHEMA, description: 'The path as validated, leaf first, up to (and including) the trust anchor it reached.' },
        pathLength: { type: 'integer' },
        signaturesChecked: { type: 'boolean' },
        signatures: {
            type: 'array',
            description: 'One row per certificate of the input path: the issuer it was verified against (the next certificate, or the matching anchor) and the verdict; not-checked when no issuer was found or checkSignatures is false.',
            items: {
                type: 'object',
                additionalProperties: false,
                required: ['index', 'subject', 'issuer', 'verdict'],
                properties: { index: { type: 'integer' }, subject: { type: 'string' }, issuer: { type: ['string', 'null'] }, verdict: { type: 'string', enum: ['valid', 'invalid', 'not-checked'] } },
            },
        },
        evaluatedAt: { type: 'string', description: 'The ISO instant used — re-pass it as `at` to reproduce the verdict.' },
        evaluatedAtSource: { type: 'string', enum: ['input', 'pinned', 'clock'] },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const VALIDATE_CERTIFICATE_PATH_SUMMARY_PROPERTIES = {
    ...CHAIN_SUMMARY_PROPERTIES,
    failingReasonCodes: { type: 'array', items: { type: 'string' } },
    signatureVerdicts: { type: 'array', items: { type: 'string' } },
} as const;

/** Verify each link: certificate i against i+1, the last against the anchor whose subject is its issuer. */
async function linkSignatures(path: readonly Certificate[], anchors: readonly Certificate[], allowSha1: boolean): Promise<{ results: SignatureResult[]; rows: LinkSignatureView[] }> {
    const results: SignatureResult[] = [];
    const rows: LinkSignatureView[] = [];
    for (const [i, certificate] of path.entries()) {
        const issuer = path[i + 1] ?? anchors.find((a) => toHex(a.subject.der) === toHex(certificate.issuer.der));
        if (issuer === undefined) {
            rows.push({ index: i, subject: dn(certificate.subject), issuer: null, verdict: 'not-checked' });
            continue;
        }
        const ok = await guardAsync(`Cannot verify the signature of path[${i}]`, () => verifyCertificateSignature(certificate, issuer, { allowSha1 }));
        results.push({ certificate, issuer, verdict: ok ? 'valid' : 'invalid' });
        rows.push({ index: i, subject: dn(certificate.subject), issuer: dn(issuer.subject), verdict: ok ? 'valid' : 'invalid' });
    }
    return { results, rows };
}

export async function validateCertificatePathTool(rawInput: unknown): Promise<ValidatePathResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const path = parseCertificates(await loadPkiBundle(input.path, 'path', LABELS.certificate, ctx), 'path certificate', ctx);
    const anchors = parseCertificates(await loadPkiBundle(input.trustAnchors, 'trustAnchors', LABELS.certificate, ctx), 'trust anchor', ctx);
    const at = resolveInstant(input.at, 'at');
    const links = input.checkSignatures
        ? await linkSignatures(path, anchors, input.allowSha1)
        : { results: [], rows: path.map((c, i) => ({ index: i, subject: dn(c.subject), issuer: null, verdict: 'not-checked' as const })) };
    // validateCertificatePath has no onDiagnostic: every certificate was parsed through the sink above.
    const report = guard('Cannot validate the path', () => validateCertificatePath({
        path,
        trustAnchors: anchors,
        at: at.ms,
        signatures: links.results,
        ...policyOptions(input.policy),
        ...(ctx.options.limits !== undefined ? { limits: ctx.options.limits } : {}),
    }));
    const failing = input.checkSignatures ? report.reasons : report.reasons.filter((r) => r.code !== SIGNATURE_NOT_CHECKED);
    return withDiagnostics({
        valid: report.valid,
        reasons: reasonsView(report.reasons),
        failingReasons: reasonsView(failing),
        path: report.path.map(certificateRef),
        pathLength: report.path.length,
        signaturesChecked: input.checkSignatures,
        signatures: links.rows,
        evaluatedAt: at.iso,
        evaluatedAtSource: at.source,
    }, ctx.sink.report());
}

export function validateCertificatePathSummary(r: ValidatePathResult): Record<string, unknown> {
    return {
        valid: r.valid,
        reasonCodes: r.reasons.map((x) => x['code']),
        failingReasonCodes: r.failingReasons.map((x) => x['code']),
        pathLength: r.pathLength,
        signaturesChecked: r.signaturesChecked,
        signatureVerdicts: r.signatures.map((s) => s.verdict),
        evaluatedAt: r.evaluatedAt,
        diagnosticCount: diagnosticCount(r),
    };
}

export const VALIDATE_CERTIFICATE_PATH_TOOL = defineTool<ValidatePathResult>({
    name: VALIDATE_CERTIFICATE_PATH_NAME,
    title: 'Validate certificate path (RFC 5280 §6.1 on an ordered path, link signatures)',
    kind: 'verdict',
    description:
        "RFC 5280 §6.1 validation of a path YOU ordered (`path`, leaf first, then each issuer) against YOUR `trustAnchors` at `at`: validity, basic constraints, key usage, name constraints and the `policy` inputs. By default every link signature is verified first — certificate i against i+1, the last against the anchor whose subject matches its issuer — and reported per link in signatures[] (PKI_REASON_SIGNATURE_INVALID fails the verdict). `checkSignatures:false` gives a structural verdict: `valid` stays false (PKI_REASON_SIGNATURE_NOT_CHECKED on every link) and `failingReasons` carries what actually fails; `signaturesChecked` says which one you got. No revocation here (verify_certificate_chain judges CRL / OCSP evidence; check_crl_revocation / check_ocsp_status judge one certificate). A negative verdict is valid:false + reasons[], never isError. Pin `at` for a reproducible, cacheable verdict. SHA-1 signatures need allowSha1:true. Token-frugal: verbosity:'summary'.",
    inputSchema: VALIDATE_CERTIFICATE_PATH_INPUT_SCHEMA,
    rawOutputSchema: VALIDATE_CERTIFICATE_PATH_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(VALIDATE_CERTIFICATE_PATH_OUTPUT_SCHEMA, VALIDATE_CERTIFICATE_PATH_SUMMARY_PROPERTIES, `Path validation verdict.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    instantInputs: ['at'],
    examples: [
        { title: 'Leaf then intermediate, against the root', input: { path: [{ path: 'fixtures/leaf.crt.pem' }, { path: 'fixtures/inter.crt.pem' }], trustAnchors: [{ path: 'fixtures/root.crt.pem' }], at: '2027-01-01T00:00:00Z', verbosity: 'summary' } },
        { title: 'Structure only (signatures deliberately skipped)', input: { path: [{ path: 'fixtures/leaf.crt.pem' }, { path: 'fixtures/inter.crt.pem' }], trustAnchors: [{ path: 'fixtures/root.crt.pem' }], at: '2027-01-01T00:00:00Z', checkSignatures: false, fields: ['failingReasons.code', 'signaturesChecked', 'path.subject'] } },
    ],
    handler: validateCertificatePathTool,
    text: (r) => r.failingReasons.length === 0
        ? `${VALIDATE_CERTIFICATE_PATH_NAME}: OK — path${r.signaturesChecked ? '' : ' structure (signatures NOT checked)'} valid at ${r.evaluatedAt}; path of ${r.pathLength}; ${r.diagnostics.length} diagnostic(s).`
        : `${VALIDATE_CERTIFICATE_PATH_NAME}: NOT OK — ${r.failingReasons.map((x) => x['code']).join(', ')}${r.signaturesChecked ? '' : ' (signatures NOT checked)'} (evaluated at ${r.evaluatedAt}).`,
    summary: validateCertificatePathSummary,
});
