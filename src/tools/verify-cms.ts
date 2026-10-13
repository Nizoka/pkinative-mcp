/**
 * Tool: verify_cms — the one-call RFC 5652 verdict: every signer's
 * attributes, digests and signature, its certificate's chain to one of the
 * caller's trust anchors at `at` (or at its verified time-stamp with
 * atTimeStamp), every counter time-stamp, and offline revocation. A negative
 * verdict is `valid:false` + `reasons[]`, never isError.
 *
 * `verifySignedData` has no diagnostic sink in pkinative 1.0.0: the message
 * is parsed once through the call's sink first (so strict:true can refuse
 * and the diagnostics reach the result), then handed to the verifier.
 */
import { parseSignedData, verifySignedData, type SignerReport } from 'pkinative';
import { z } from 'zod';

import { ContentInputSchema, contentInputSchema, HexSchema, hexSchema, loadContent } from '../content-input.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiBundle, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { ALLOW_SHA1_INPUT_PROPERTY } from '../signer.js';
import { formatInstant, resolveInstant } from '../time.js';
import { purposeOid, REASONS_OUTPUT_PROPERTY, TRUST_INPUT_PROPERTIES, TrustShape } from '../trust.js';
import { CERTIFICATE_REF_SCHEMA, certificateRef, reasonsView } from '../views.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { AllowSha1Shape, diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';
import { ALLOW_TRAILING_DATA_INPUT_PROPERTY } from './inspect-cms.js';
import { parseCertificates } from './verify-certificate-chain.js';
import { CHAIN_VERDICT_VIEW_SCHEMA, digestBytes, TIMESTAMP_VERDICT_PROPERTIES, timeStampVerdictView, type ChainVerdictView, type TimeStampVerdictView } from './verify-timestamp.js';

export const VERIFY_CMS_NAME = 'verify_cms';

/** The TRUST fragment as verifySignedData takes it (no RFC 5280 policy inputs). */
const CMS_TRUST_INPUT_PROPERTIES = {
    trustAnchors: TRUST_INPUT_PROPERTIES.trustAnchors,
    candidates: TRUST_INPUT_PROPERTIES.candidates,
    crls: { ...TRUST_INPUT_PROPERTIES.crls, description: 'CRLs (DER or X509 CRL PEM) for offline revocation, added to those the message carries. Optional; this server never fetches a CRL.' },
    ocspResponses: { ...TRUST_INPUT_PROPERTIES.ocspResponses, description: 'OCSP responses (DER), added to those the message carries. Optional; this server never queries a responder.' },
    at: TRUST_INPUT_PROPERTIES.at,
    requireRevocation: TRUST_INPUT_PROPERTIES.requireRevocation,
    purposes: { ...TRUST_INPUT_PROPERTIES.purposes, description: `Extended key usages every signer's chain must permit (emailProtection for S/MIME): ${TRUST_INPUT_PROPERTIES.purposes.description.split(': ')[1] ?? ''}` },
} as const;

const CmsTrustShape = {
    trustAnchors: TrustShape.trustAnchors,
    candidates: TrustShape.candidates,
    crls: TrustShape.crls,
    ocspResponses: TrustShape.ocspResponses,
    at: TrustShape.at,
    requireRevocation: TrustShape.requireRevocation,
    purposes: TrustShape.purposes,
};

export const VERIFY_CMS_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['signedData', 'trustAnchors'],
    properties: {
        signedData: pkiInputSchema('The CMS SignedData to judge (CMS / PKCS7 PEM, or DER: .p7s .p7m)'),
        content: contentInputSchema('The detached content (required for a detached signature; refused for an attached one)'),
        contentDigest: hexSchema('The detached content\'s digest (computed with the signer\'s digest algorithm) instead of the content — the PDF /ByteRange case. Exclusive with content.'),
        ...CMS_TRUST_INPUT_PROPERTIES,
        atTimeStamp: { type: 'boolean', default: false, description: "Judge each signer's chain at the time its own VERIFIED counter time-stamp proves (long-term validation) instead of `at`; a signer without a valid time-stamp is still judged at `at`, and the TSA's chain always is." },
        requireSigningCertificate: { type: 'boolean', default: false, description: 'Require every signer to name its certificate in an ESS signing-certificate attribute (CAdES / PAdES).' },
        requireAlgorithmProtection: { type: 'boolean', default: false, description: 'Require every signer to carry CMSAlgorithmProtection (RFC 6211).' },
        ...ALLOW_TRAILING_DATA_INPUT_PROPERTY,
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    signedData: PkiInputSchema,
    content: ContentInputSchema.optional(),
    contentDigest: HexSchema.optional(),
    ...CmsTrustShape,
    atTimeStamp: z.boolean().default(false),
    requireSigningCertificate: z.boolean().default(false),
    requireAlgorithmProtection: z.boolean().default(false),
    allowTrailingData: z.boolean().default(false),
    ...AllowSha1Shape,
    ...ParseShape,
    ...ProjectionShape,
}).superRefine((v, ctx) => {
    if (v.content !== undefined && v.contentDigest !== undefined) ctx.addIssue({ code: 'custom', message: 'pass content or contentDigest, not both', path: ['content'] });
});

export interface SignerVerdictView {
    readonly index: number;
    readonly valid: boolean;
    readonly intact: boolean;
    readonly certificate: ReturnType<typeof certificateRef> | null;
    readonly signingTime: string | null;
    readonly timeStamps: readonly TimeStampVerdictView[];
    readonly chain: ChainVerdictView | null;
    readonly reasons: ReadonlyArray<Record<string, string>>;
}

function signerVerdictView(s: SignerReport): SignerVerdictView {
    return {
        index: s.index,
        valid: s.valid,
        intact: s.intact,
        certificate: s.certificate === undefined ? null : certificateRef(s.certificate),
        signingTime: s.signingTime === undefined ? null : formatInstant(s.signingTime.epochMilliseconds),
        timeStamps: s.timeStamps.map(timeStampVerdictView),
        chain: s.chain === undefined ? null : { valid: s.chain.valid, path: s.chain.path.map(certificateRef), reasons: reasonsView(s.chain.reasons) },
        reasons: reasonsView(s.reasons),
    };
}

export interface CmsVerdict extends DiagnosticsReport {
    readonly valid: boolean;
    readonly reasons: ReadonlyArray<Record<string, string>>;
    readonly signers: readonly SignerVerdictView[];
    readonly signerCount: number;
    readonly signatureVerifications: number;
    readonly evaluatedAt: string;
    readonly evaluatedAtSource: 'input' | 'pinned' | 'clock';
    readonly atTimeStamp: boolean;
}

export const VERIFY_CMS_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['valid', 'reasons', 'signers', 'signerCount', 'signatureVerifications', 'evaluatedAt', 'evaluatedAtSource', 'atTimeStamp', 'diagnostics', 'diagnosticCounts'],
    properties: {
        valid: { type: 'boolean', description: 'At least one signer and EVERY signer valid. false is a negative verdict (reasons[]), never an error.' },
        ...REASONS_OUTPUT_PROPERTY,
        signers: {
            type: 'array',
            description: 'One verdict per signer, in encoded order.',
            items: {
                type: 'object',
                additionalProperties: false,
                required: ['index', 'valid', 'intact', 'certificate', 'signingTime', 'timeStamps', 'chain', 'reasons'],
                properties: {
                    index: { type: 'integer' },
                    valid: { type: 'boolean', description: 'Intact, time-stamps valid, and chaining to one of your anchors.' },
                    intact: { type: 'boolean', description: 'Every trust-free check passed (attributes, algorithms, content digest, signature, named certificate). true with valid:false = unaltered, but not by anybody you trust.' },
                    certificate: { ...CERTIFICATE_REF_SCHEMA, type: ['object', 'null'], description: 'The certificate that signed, or null when none could be established.' },
                    signingTime: { type: ['string', 'null'], description: 'The time the signer CLAIMS (ISO 8601); nothing vouches for it — see timeStamps.' },
                    timeStamps: { type: 'array', description: "Each RFC 3161 counter time-stamp over this signer's signature, verified.", items: { type: 'object', additionalProperties: false, required: ['valid', 'reasons', 'genTime', 'earliest', 'latest', 'tsa', 'chain', 'signatureVerifications'], properties: TIMESTAMP_VERDICT_PROPERTIES } },
                    chain: CHAIN_VERDICT_VIEW_SCHEMA,
                    ...REASONS_OUTPUT_PROPERTY,
                    reasonCodes: { type: 'array', items: { type: 'string' }, description: "The signer's reason codes (verbosity:'summary' only)." },
                },
            },
        },
        signerCount: { type: 'integer' },
        signatureVerifications: { type: 'integer', description: 'Signature verifications performed, chains and time-stamps included.' },
        evaluatedAt: { type: 'string', description: 'The ISO instant the chains were judged at — re-pass it as `at` to reproduce the verdict.' },
        evaluatedAtSource: { type: 'string', enum: ['input', 'pinned', 'clock'] },
        atTimeStamp: { type: 'boolean' },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const VERIFY_CMS_SUMMARY_PROPERTIES = {
    reasonCodes: { type: 'array', items: { type: 'string' } },
    diagnosticCount: { type: 'integer' },
} as const;

export async function verifyCmsTool(rawInput: unknown): Promise<CmsVerdict> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const der = (await loadPkiObject(input.signedData, 'signedData', LABELS.cms, ctx)).der;
    // verifySignedData has no diagnostic sink: parsing once first lets the warnings reach strict:true and diagnostics[].
    try {
        guard('Cannot read the SignedData', () => parseSignedData(der, { ...ctx.options, allowTrailingData: input.allowTrailingData }));
    } catch (e) {
        // Under strict:true the engine refuses at the first warning before any sink call: that refusal is the answer.
        // Otherwise the verdict below names the reason (PKI_REASON_INPUT_MALFORMED).
        if (e instanceof ToolError && e.code === 'PKI_STRICT_DIAGNOSTIC') throw e;
    }
    const content = input.content === undefined ? undefined : (await loadContent(input.content, 'content')).bytes;
    const contentDigest = digestBytes(input.contentDigest, 'contentDigest');
    const anchors = parseCertificates(await loadPkiBundle(input.trustAnchors, 'trustAnchors', LABELS.certificate, ctx), 'trust anchor', ctx);
    const candidates = parseCertificates(await loadPkiBundle(input.candidates, 'candidates', LABELS.certificate, ctx), 'candidate certificate', ctx);
    const crls = (await loadPkiBundle(input.crls, 'crls', LABELS.crl, ctx)).map((o) => o.der);
    const ocsp = (await loadPkiBundle(input.ocspResponses, 'ocspResponses', LABELS.any, ctx)).map((o) => o.der);
    const purposes = (input.purposes ?? []).map((p) => purposeOid(p, 'purposes'));
    const at = resolveInstant(input.at, 'at');
    const report = await guardAsync('Cannot verify the SignedData', () => verifySignedData({
        signedData: der,
        ...(content !== undefined ? { content } : {}),
        ...(contentDigest !== undefined ? { contentDigest } : {}),
        certificates: candidates,
        trustAnchors: anchors,
        purposes,
        crls,
        ocspResponses: ocsp,
        requireRevocation: input.requireRevocation,
        at: at.ms,
        atTimeStamp: input.atTimeStamp,
        allowSha1: input.allowSha1,
        requireSigningCertificate: input.requireSigningCertificate,
        requireAlgorithmProtection: input.requireAlgorithmProtection,
        allowTrailingData: input.allowTrailingData,
        encodingRules: input.encodingRules,
        ...(ctx.options.limits !== undefined ? { limits: ctx.options.limits } : {}),
    }));
    return withDiagnostics({
        valid: report.valid,
        reasons: reasonsView(report.reasons),
        signers: report.signers.map(signerVerdictView),
        signerCount: report.signers.length,
        signatureVerifications: report.signatureVerifications,
        evaluatedAt: at.iso,
        evaluatedAtSource: at.source,
        atTimeStamp: input.atTimeStamp,
    }, ctx.sink.report());
}

export function verifyCmsSummary(r: CmsVerdict): Record<string, unknown> {
    return {
        valid: r.valid,
        reasonCodes: r.reasons.map((x) => x['code']),
        signers: r.signers.map((s) => ({ index: s.index, valid: s.valid, intact: s.intact, reasonCodes: s.reasons.map((x) => x['code']) })),
        evaluatedAt: r.evaluatedAt,
        diagnosticCount: diagnosticCount(r),
    };
}

export const VERIFY_CMS_TOOL = defineTool<CmsVerdict>({
    name: VERIFY_CMS_NAME,
    title: 'Verify CMS SignedData (the RFC 5652 verdict: signers, chains, time-stamps, revocation)',
    kind: 'verdict',
    description:
        "The one-call verdict on a CMS SignedData (a .p7s, an S/MIME body, a PDF /Contents): for EVERY signer, the signed attributes (contentType, messageDigest, ESS signing-certificate, CMSAlgorithmProtection), the content digest (attached, or `content` / `contentDigest` for a detached signature — a detached signature without its content is NOT valid), the signature, the certificate's chain through `candidates` and the embedded certificates to one of YOUR `trustAnchors` at `at` (RFC 5280 §6, `purposes` along the path), every counter time-stamp (RFC 3161, verified like verify_timestamp), and revocation from the CRL / OCSP bytes YOU supply plus those the message carries (`requireRevocation:true` demands evidence; this server never fetches). `atTimeStamp:true` is long-term validation: a signer's chain is judged at its verified time-stamp instead of `at`. `requireSigningCertificate` / `requireAlgorithmProtection` enforce the CAdES / RFC 8933 profile. A negative verdict is valid:false + reasons[] (PKI_REASON_* codes, per signer too; `intact` tells unaltered from untrusted) — never isError; isError is for inputs the engine refuses (content given for an attached message, both content and contentDigest). Pin `at` for a reproducible, cacheable verdict. Token-frugal: verbosity:'summary' (valid, reasonCodes, per-signer codes).",
    inputSchema: VERIFY_CMS_INPUT_SCHEMA,
    rawOutputSchema: VERIFY_CMS_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(VERIFY_CMS_OUTPUT_SCHEMA, VERIFY_CMS_SUMMARY_PROPERTIES, `CMS verdict.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    instantInputs: ['at'],
    examples: [
        { title: 'A detached signature over a file, S/MIME purpose', input: { signedData: { path: 'fixtures/detached.p7s' }, content: { path: 'fixtures/content.txt' }, trustAnchors: [{ path: 'fixtures/root.crt.pem' }], candidates: [{ path: 'fixtures/inter.crt.pem' }], purposes: ['emailProtection'], at: '2027-01-01T00:00:00Z', verbosity: 'summary' } },
        { title: 'An attached message with offline revocation evidence', input: { signedData: { path: 'fixtures/attached.p7s' }, trustAnchors: [{ path: 'fixtures/root.crt.pem' }], crls: [{ path: 'fixtures/inter.crl.pem' }], requireRevocation: true, at: '2027-01-01T00:00:00Z' } },
    ],
    handler: verifyCmsTool,
    text: (r) => r.valid
        ? `${VERIFY_CMS_NAME}: OK — ${r.signerCount} signer(s) valid at ${r.evaluatedAt}${r.signers[0]?.certificate !== undefined && r.signers[0]?.certificate !== null ? ` (${r.signers.map((s) => s.certificate?.subject ?? '?').join('; ')})` : ''}, ${r.signatureVerifications} signature(s) verified; ${r.diagnostics.length} diagnostic(s).`
        : `${VERIFY_CMS_NAME}: NOT OK — ${[...new Set(r.reasons.map((x) => x['code']))].join(', ') || 'no signer'} (${r.signers.filter((s) => s.valid).length}/${r.signerCount} signer(s) valid, evaluated at ${r.evaluatedAt}).`,
    summary: verifyCmsSummary,
});
