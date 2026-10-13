/**
 * Tool: build_certificate_path — path discovery (RFC 5280 §6 path
 * building): from `leaf` through the untrusted `candidates` to one of the
 * caller's `trustAnchors`, under the validity, name-constraint, policy and
 * purpose rules, WITHOUT checking any signature. The engine always reports
 * PKI_REASON_SIGNATURE_NOT_CHECKED on such a path, so the tool's verdict is
 * the structural one: `found` says whether a path reached an anchor, and
 * `structuralReasons` leaves the not-checked marker out.
 */
import { buildCertificatePath, parseCertificate } from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard } from '../pki-errors.js';
import { LABELS, loadPkiBundle, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { resolveInstant } from '../time.js';
import { policyOptions, purposeOid, REASONS_OUTPUT_PROPERTY, TRUST_INPUT_PROPERTIES, TrustShape } from '../trust.js';
import { CERTIFICATE_REF_SCHEMA, certificateRef, reasonsView } from '../views.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';
import { CHAIN_SUMMARY_PROPERTIES, parseCertificates } from './verify-certificate-chain.js';

export const BUILD_CERTIFICATE_PATH_NAME = 'build_certificate_path';

/** The reason the engine attaches to every link whose signature was not verified. */
export const SIGNATURE_NOT_CHECKED = 'PKI_REASON_SIGNATURE_NOT_CHECKED';

export const BUILD_CERTIFICATE_PATH_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['leaf', 'trustAnchors'],
    properties: {
        leaf: pkiInputSchema('The end-entity certificate to start from'),
        candidates: TRUST_INPUT_PROPERTIES.candidates,
        trustAnchors: TRUST_INPUT_PROPERTIES.trustAnchors,
        at: TRUST_INPUT_PROPERTIES.at,
        purposes: TRUST_INPUT_PROPERTIES.purposes,
        policy: TRUST_INPUT_PROPERTIES.policy,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    leaf: PkiInputSchema,
    candidates: TrustShape.candidates,
    trustAnchors: TrustShape.trustAnchors,
    at: TrustShape.at,
    purposes: TrustShape.purposes,
    policy: TrustShape.policy,
    ...ParseShape,
    ...ProjectionShape,
});

export interface BuildPathResult extends DiagnosticsReport {
    readonly found: boolean;
    readonly valid: boolean;
    readonly reasons: ReadonlyArray<Record<string, string>>;
    readonly structuralReasons: ReadonlyArray<Record<string, string>>;
    readonly path: ReadonlyArray<ReturnType<typeof certificateRef>>;
    readonly pathLength: number;
    readonly explored: number;
    readonly signaturesChecked: false;
    readonly evaluatedAt: string;
    readonly evaluatedAtSource: 'input' | 'pinned' | 'clock';
}

export const BUILD_CERTIFICATE_PATH_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['found', 'valid', 'reasons', 'structuralReasons', 'path', 'pathLength', 'explored', 'signaturesChecked', 'evaluatedAt', 'evaluatedAtSource', 'diagnostics', 'diagnosticCounts'],
    properties: {
        found: { type: 'boolean', description: 'A path from the leaf to one of the trust anchors was found and passes the structural rules (structuralReasons empty). This is the verdict of THIS tool; the signatures are not checked.' },
        valid: { type: 'boolean', description: 'The engine verdict — always false here, because no signature was verified (PKI_REASON_SIGNATURE_NOT_CHECKED on every link). Read `found`.' },
        ...REASONS_OUTPUT_PROPERTY,
        structuralReasons: { ...REASONS_OUTPUT_PROPERTY.reasons, description: 'reasons[] without the PKI_REASON_SIGNATURE_NOT_CHECKED markers: what actually stopped the walk (empty when found).' },
        path: { type: 'array', items: CERTIFICATE_REF_SCHEMA, description: 'The path found, leaf first, up to (and including) the trust anchor; the leaf alone (with the reason) when no anchor was reached.' },
        pathLength: { type: 'integer' },
        explored: { type: 'integer', description: 'Candidate paths explored (bounded by limits.maxPathsExplored).' },
        signaturesChecked: { type: 'boolean', enum: [false], description: 'Always false: run validate_certificate_path or verify_certificate_chain for the signatures.' },
        evaluatedAt: { type: 'string', description: 'The ISO instant used — re-pass it as `at` to reproduce the result.' },
        evaluatedAtSource: { type: 'string', enum: ['input', 'pinned', 'clock'] },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const BUILD_CERTIFICATE_PATH_SUMMARY_PROPERTIES = {
    ...CHAIN_SUMMARY_PROPERTIES,
    structuralReasonCodes: { type: 'array', items: { type: 'string' } },
} as const;

export async function buildCertificatePathTool(rawInput: unknown): Promise<BuildPathResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const leafObj = await loadPkiObject(input.leaf, 'leaf', LABELS.certificate, ctx);
    const leaf = guard('Cannot read the leaf certificate', () => parseCertificate(leafObj.der, ctx.options));
    const candidates = parseCertificates(await loadPkiBundle(input.candidates, 'candidates', LABELS.certificate, ctx), 'candidate certificate', ctx);
    const anchors = parseCertificates(await loadPkiBundle(input.trustAnchors, 'trustAnchors', LABELS.certificate, ctx), 'trust anchor', ctx);
    const at = resolveInstant(input.at, 'at');
    const purposes = (input.purposes ?? []).map((p) => purposeOid(p, 'purposes'));
    // buildCertificatePath has no onDiagnostic: every certificate was parsed through the sink above.
    const report = guard('Cannot build the path', () => buildCertificatePath({
        leaf,
        candidates,
        trustAnchors: anchors,
        at: at.ms,
        purposes,
        ...policyOptions(input.policy),
        ...(ctx.options.limits !== undefined ? { limits: ctx.options.limits } : {}),
    }));
    const structural = report.reasons.filter((r) => r.code !== SIGNATURE_NOT_CHECKED);
    return withDiagnostics({
        found: structural.length === 0,
        valid: report.valid,
        reasons: reasonsView(report.reasons),
        structuralReasons: reasonsView(structural),
        path: report.path.map(certificateRef),
        pathLength: report.path.length,
        explored: report.explored,
        signaturesChecked: false,
        evaluatedAt: at.iso,
        evaluatedAtSource: at.source,
    }, ctx.sink.report());
}

export function buildCertificatePathSummary(r: BuildPathResult): Record<string, unknown> {
    return {
        found: r.found,
        valid: r.valid,
        reasonCodes: r.reasons.map((x) => x['code']),
        structuralReasonCodes: r.structuralReasons.map((x) => x['code']),
        pathLength: r.pathLength,
        explored: r.explored,
        signaturesChecked: false,
        evaluatedAt: r.evaluatedAt,
        diagnosticCount: diagnosticCount(r),
    };
}

export const BUILD_CERTIFICATE_PATH_TOOL = defineTool<BuildPathResult>({
    name: BUILD_CERTIFICATE_PATH_NAME,
    title: 'Build certificate path (discovery to a trust anchor, signatures NOT checked)',
    kind: 'verdict',
    description:
        "Path discovery only (RFC 5280 §6 path building): walks from `leaf` through the untrusted `candidates` to one of YOUR `trustAnchors` under the structural rules evaluated at `at` (validity, basic constraints, key usage, name constraints, the `policy` inputs; `purposes` steer discovery but the leaf's extended key usage is judged by verify_certificate_chain, not here) and reports the path it found, leaf first up to the anchor. NO signature is verified: the engine marks every link PKI_REASON_SIGNATURE_NOT_CHECKED, so `valid` is always false and the verdict of this tool is `found` (a path reached an anchor, `structuralReasons` empty); the leaf alone with PKI_REASON_NO_TRUST_ANCHOR when none did. Use it to learn which intermediates a chain needs, then validate_certificate_path (ordered path, signatures) or verify_certificate_chain (the full verdict with revocation). Never isError for a negative result. Pin `at` for a reproducible, cacheable result. Token-frugal: verbosity:'summary' (found, structuralReasonCodes, pathLength).",
    inputSchema: BUILD_CERTIFICATE_PATH_INPUT_SCHEMA,
    rawOutputSchema: BUILD_CERTIFICATE_PATH_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(BUILD_CERTIFICATE_PATH_OUTPUT_SCHEMA, BUILD_CERTIFICATE_PATH_SUMMARY_PROPERTIES, `Path discovery report (signatures not checked).${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    instantInputs: ['at'],
    examples: [
        { title: 'Which path leads from the leaf to the root?', input: { leaf: { path: 'fixtures/leaf.crt.pem' }, candidates: [{ path: 'fixtures/inter.crt.pem' }], trustAnchors: [{ path: 'fixtures/root.crt.pem' }], at: '2027-01-01T00:00:00Z', purposes: ['serverAuth'], verbosity: 'summary' } },
        { title: 'No candidate: the leaf alone, with the reason', input: { leaf: { path: 'fixtures/leaf.crt.pem' }, trustAnchors: [{ path: 'fixtures/root.crt.pem' }], at: '2027-01-01T00:00:00Z', fields: ['found', 'structuralReasons.code', 'path.subject'] } },
    ],
    handler: buildCertificatePathTool,
    text: (r) => r.found
        ? `${BUILD_CERTIFICATE_PATH_NAME}: OK — path of ${r.pathLength} found (signatures NOT checked; ${r.explored} explored, evaluated at ${r.evaluatedAt}); ${r.diagnostics.length} diagnostic(s).`
        : `${BUILD_CERTIFICATE_PATH_NAME}: NOT OK — ${r.structuralReasons.map((x) => x['code']).join(', ')} (signatures NOT checked; evaluated at ${r.evaluatedAt}).`,
    summary: buildCertificatePathSummary,
});
