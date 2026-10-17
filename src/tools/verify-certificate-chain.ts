/**
 * Tool: verify_certificate_chain — the one-call verdict of RFC 5280 §6:
 * path building through the candidates to one of the caller's trust
 * anchors, every signature, validity at `at`, name constraints, policies,
 * server name, purposes, and offline revocation from the CRL / OCSP bytes
 * the caller supplies. A negative verdict is `valid:false` + `reasons[]`,
 * never isError.
 */
import { parseCertificate, verifyCertificateChain, type Certificate, type ServerIdentity } from 'pkinative';
import { z } from 'zod';

import { HexSchema, hexSchema } from '../content-input.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { parseIp } from '../names.js';
import { createParseContext, PARSE_INPUT_PROPERTIES, type ParseContext } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiBundle, loadPkiObject, pkiInputSchema, PkiInputSchema, type PkiObject } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { ALLOW_SHA1_INPUT_PROPERTY } from '../signer.js';
import { resolveInstant } from '../time.js';
import { policyOptions, purposeOid, REASONS_OUTPUT_PROPERTY, TRUST_INPUT_PROPERTIES, TrustShape } from '../trust.js';
import { CERTIFICATE_REF_SCHEMA, certificateRef, reasonsView } from '../views.js';
import { fromHex } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { AllowSha1Shape, diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';

export const VERIFY_CERTIFICATE_CHAIN_NAME = 'verify_certificate_chain';

export const SERVER_NAME_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    description: 'The identity the leaf must be valid for (RFC 6125): exactly one of host / ip.',
    properties: {
        host: { type: 'string', minLength: 1, description: 'A DNS name as it appeared in the URL (one trailing dot is ignored).' },
        ip: { type: 'string', minLength: 1, description: 'An IPv4 or IPv6 address.' },
    },
} as const;

export const ServerNameSchema = z.strictObject({
    host: z.string().min(1).optional(),
    ip: z.string().min(1).optional(),
}).superRefine((v, ctx) => {
    if ((v.host === undefined) === (v.ip === undefined)) ctx.addIssue({ code: 'custom', message: 'pass exactly one of host / ip', path: ['host'] });
});

export function serverIdentity(v: z.infer<typeof ServerNameSchema> | undefined, path = 'serverName'): ServerIdentity | undefined {
    if (v === undefined) return undefined;
    if (v.host !== undefined) return { kind: 'dns', value: v.host };
    return { kind: 'ip', value: parseIp(v.ip as string, `${path}.ip`) };
}

export const VERIFY_CERTIFICATE_CHAIN_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['leaf', 'trustAnchors'],
    properties: {
        leaf: pkiInputSchema('The end-entity certificate to judge'),
        ...TRUST_INPUT_PROPERTIES,
        serverName: SERVER_NAME_INPUT_SCHEMA,
        ocspNonce: hexSchema('The nonce you put in the OCSP request (1–32 bytes), to be matched in the responses.'),
        requireOcspNonce: { type: 'boolean', default: false, description: 'Refuse an OCSP response that does not echo the nonce.' },
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    leaf: PkiInputSchema,
    ...TrustShape,
    serverName: ServerNameSchema.optional(),
    ocspNonce: HexSchema.optional(),
    requireOcspNonce: z.boolean().default(false),
    ...AllowSha1Shape,
    ...ParseShape,
    ...ProjectionShape,
});

export interface ChainVerdict extends DiagnosticsReport {
    readonly valid: boolean;
    readonly reasons: ReadonlyArray<Record<string, string>>;
    readonly path: ReadonlyArray<ReturnType<typeof certificateRef>>;
    readonly pathLength: number;
    readonly explored: number;
    readonly signatureVerifications: number;
    readonly evaluatedAt: string;
    readonly evaluatedAtSource: 'input' | 'pinned' | 'clock';
    readonly revocationEvidence: { readonly crls: number; readonly ocspResponses: number; readonly required: boolean };
}

export const CHAIN_VERDICT_PROPERTIES = {
    valid: { type: 'boolean', description: 'The verdict. false is a negative verdict (reasons[]), never an error.' },
    ...REASONS_OUTPUT_PROPERTY,
    path: { type: 'array', items: CERTIFICATE_REF_SCHEMA, description: 'The path found, leaf first, up to (and including) the trust anchor.' },
    pathLength: { type: 'integer' },
    explored: { type: 'integer', description: 'Candidate paths explored (bounded by limits.maxPathsExplored).' },
    signatureVerifications: { type: 'integer' },
    evaluatedAt: { type: 'string', description: 'The ISO instant the verdict was evaluated at — re-pass it as `at` to reproduce the verdict.' },
    evaluatedAtSource: { type: 'string', enum: ['input', 'pinned', 'clock'] },
    revocationEvidence: { type: 'object', additionalProperties: false, required: ['crls', 'ocspResponses', 'required'], properties: { crls: { type: 'integer' }, ocspResponses: { type: 'integer' }, required: { type: 'boolean' } } },
} as const;

export const VERIFY_CERTIFICATE_CHAIN_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['valid', 'reasons', 'path', 'pathLength', 'explored', 'signatureVerifications', 'evaluatedAt', 'evaluatedAtSource', 'revocationEvidence', 'diagnostics', 'diagnosticCounts'],
    properties: { ...CHAIN_VERDICT_PROPERTIES, ...DIAGNOSTICS_OUTPUT_PROPERTIES },
} as const;

export const CHAIN_SUMMARY_PROPERTIES = {
    reasonCodes: { type: 'array', items: { type: 'string' } },
    diagnosticCount: { type: 'integer' },
} as const;

/** Parse every certificate of a bundle of objects. */
export function parseCertificates(objects: readonly PkiObject[], what: string, ctx: ParseContext): Certificate[] {
    return objects.map((o) => guard(`Cannot read the ${what} (${o.source})`, () => parseCertificate(o.der, ctx.options)));
}

export function nonceBytes(hex: string | undefined, path: string): Uint8Array | undefined {
    if (hex === undefined) return undefined;
    const bytes = fromHex(hex);
    if (bytes === undefined || bytes.length < 1 || bytes.length > 32) {
        throw new ToolError('VALIDATION_ERROR', `${path}: expected 1 to 32 bytes of hex.`, { path });
    }
    return bytes;
}

export async function verifyCertificateChainTool(rawInput: unknown): Promise<ChainVerdict> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const leafObj = await loadPkiObject(input.leaf, 'leaf', LABELS.certificate, ctx);
    const leaf = guard('Cannot read the leaf certificate', () => parseCertificate(leafObj.der, ctx.options));
    const candidates = parseCertificates(await loadPkiBundle(input.candidates, 'candidates', LABELS.certificate, ctx), 'candidate certificate', ctx);
    const anchors = parseCertificates(await loadPkiBundle(input.trustAnchors, 'trustAnchors', LABELS.certificate, ctx), 'trust anchor', ctx);
    const crls = (await loadPkiBundle(input.crls, 'crls', LABELS.crl, ctx)).map((o) => o.der);
    const ocsp = (await loadPkiBundle(input.ocspResponses, 'ocspResponses', LABELS.any, ctx)).map((o) => o.der);
    const nonce = nonceBytes(input.ocspNonce, 'ocspNonce');
    const name = serverIdentity(input.serverName);
    const at = resolveInstant(input.at, 'at');
    const purposes = (input.purposes ?? []).map((p) => purposeOid(p, 'purposes'));
    const report = await guardAsync('Cannot verify the chain', () => verifyCertificateChain({
        leaf,
        candidates,
        trustAnchors: anchors,
        at: at.ms,
        ...(name !== undefined ? { serverName: name } : {}),
        purposes,
        crls,
        ocspResponses: ocsp,
        ...(nonce !== undefined ? { ocspNonce: nonce } : {}),
        requireOcspNonce: input.requireOcspNonce,
        requireRevocation: input.requireRevocation,
        allowSha1: input.allowSha1,
        ...policyOptions(input.policy),
        ...(ctx.options.limits !== undefined ? { limits: ctx.options.limits } : {}),
        onDiagnostic: ctx.options.onDiagnostic,
    }));
    return withDiagnostics({
        valid: report.valid,
        reasons: reasonsView(report.reasons),
        path: report.path.map(certificateRef),
        pathLength: report.path.length,
        explored: report.explored,
        signatureVerifications: report.signatureVerifications,
        evaluatedAt: at.iso,
        evaluatedAtSource: at.source,
        revocationEvidence: { crls: crls.length, ocspResponses: ocsp.length, required: input.requireRevocation },
    }, ctx.sink.report());
}

export function chainSummary(r: ChainVerdict): Record<string, unknown> {
    return { valid: r.valid, reasonCodes: r.reasons.map((x) => x['code']), pathLength: r.pathLength, evaluatedAt: r.evaluatedAt, revocationEvidence: r.revocationEvidence, diagnosticCount: diagnosticCount(r) };
}

export function verdictText(name: string, r: ChainVerdict, what: string): string {
    return r.valid
        ? `${name}: OK — ${what} valid at ${r.evaluatedAt}; path of ${r.pathLength} (${r.signatureVerifications} signature(s) verified, ${r.explored} explored); ${r.diagnostics.length} diagnostic(s).`
        : `${name}: NOT OK — ${r.reasons.map((x) => x['code']).join(', ')} (evaluated at ${r.evaluatedAt}).`;
}

export const VERIFY_CERTIFICATE_CHAIN_TOOL = defineTool<ChainVerdict>({
    name: VERIFY_CERTIFICATE_CHAIN_NAME,
    title: 'Verify certificate chain (the RFC 5280 §6 verdict, offline revocation)',
    kind: 'verdict',
    description:
        "The one-call trust verdict for a certificate: builds a path from `leaf` through `candidates` to one of YOUR `trustAnchors`, verifies every signature, validates the path at `at` (RFC 5280 §6: validity, basic constraints, key usage, name constraints, policies — `policy` inputs), checks `serverName` (RFC 6125 host or IP) and `purposes` (extended key usage along the path), and judges revocation from the CRL / OCSP bytes YOU supply (`crls`, `ocspResponses`; `requireRevocation:true` demands evidence for every certificate below the anchor; this server never fetches). A negative verdict is valid:false + reasons[] (PKI_REASON_* codes) in structuredContent — never isError; isError is reserved for inputs the engine refuses. Pin `at` (ISO 8601) for a reproducible, cacheable verdict; `evaluatedAt` echoes the instant used. Token-frugal: verbosity:'summary' (valid, reasonCodes, pathLength). Prefer it over inspect_certificate.signature for any trust question; build_certificate_path / validate_certificate_path explain a failing path.",
    inputSchema: VERIFY_CERTIFICATE_CHAIN_INPUT_SCHEMA,
    rawOutputSchema: VERIFY_CERTIFICATE_CHAIN_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(VERIFY_CERTIFICATE_CHAIN_OUTPUT_SCHEMA, CHAIN_SUMMARY_PROPERTIES, `Chain verdict.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    instantInputs: ['at'],
    examples: [
        { title: 'Is this server certificate trustworthy for example.test?', input: { leaf: { path: 'fixtures/leaf.crt.pem' }, candidates: [{ path: 'fixtures/inter.crt.pem' }], trustAnchors: [{ path: 'fixtures/root.crt.pem' }], at: '2027-01-01T00:00:00Z', serverName: { host: 'example.test' }, purposes: ['serverAuth'], verbosity: 'summary' } },
        { title: 'With offline CRL evidence (a revoked leaf)', input: { leaf: { path: 'fixtures/revoked.crt.pem' }, candidates: [{ path: 'fixtures/inter.crt.pem' }], trustAnchors: [{ path: 'fixtures/root.crt.pem' }], crls: [{ path: 'fixtures/inter.crl.pem' }], requireRevocation: true, at: '2027-01-01T00:00:00Z' } },
    ],
    handler: verifyCertificateChainTool,
    text: (r) => verdictText(VERIFY_CERTIFICATE_CHAIN_NAME, r, 'chain'),
    summary: chainSummary,
});
