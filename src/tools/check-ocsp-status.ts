/**
 * Tool: check_ocsp_status — the RFC 6960 verdict of ONE OCSP response for
 * ONE certificate: the CertID is recomputed from `certificate` and
 * `issuer` and matched, the responder signature is verified (against
 * `responder`, the embedded certificates, or the issuer itself), the
 * responder's authorisation is judged (§4.2.2.2: the CA, a delegate the CA
 * issued with id-kp-OCSPSigning, or `responderTrusted`), then the engine
 * judges status, freshness at `at`, and the nonce. Mirrors `pkinative ocsp
 * check` exactly.
 */
import {
    checkExtendedKeyUsage,
    checkOcspStatus,
    decodeAsn1,
    encodeOcspCertId,
    KEY_PURPOSES,
    parseCertificate,
    parseOcspResponse,
    readOctetString,
    verifyCertificateSignature,
    type Asn1Node,
    type Certificate,
    type OcspHashAlgorithm,
} from 'pkinative';
import { z } from 'zod';

import { HexSchema, hexSchema } from '../content-input.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { createParseContext, PARSE_INPUT_PROPERTIES, type ParseContext } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { ALLOW_SHA1_INPUT_PROPERTY } from '../signer.js';
import { resolveInstant } from '../time.js';
import { REASONS_OUTPUT_PROPERTY, TRUST_INPUT_PROPERTIES, TrustShape } from '../trust.js';
import { dn, reasonsView } from '../views.js';
import { toHex } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { AllowSha1Shape, diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';
import { STALE_TOLERANCE_INPUT_PROPERTY } from './check-crl-revocation.js';
import { OCSP_HASH_ALGORITHMS } from './create-ocsp-request.js';
import { embeddedCertificates, findOcspSigner } from './inspect-ocsp-response.js';
import { nonceBytes } from './verify-certificate-chain.js';

export const CHECK_OCSP_STATUS_NAME = 'check_ocsp_status';

/** The CertID hash OIDs the engine encodes (RFC 6960 §4.1.1). */
const HASH_OIDS: Readonly<Record<string, OcspHashAlgorithm>> = {
    '1.3.14.3.2.26': 'SHA-1',
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
};

export const CHECK_OCSP_STATUS_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['response', 'certificate', 'issuer'],
    properties: {
        response: pkiInputSchema('The OCSP response (DER, as the responder returned it)'),
        certificate: pkiInputSchema('The certificate whose status is asked'),
        issuer: pkiInputSchema('The CA certificate that issued it', ' Its name and key hashes form the CertID to match, and it is the authority a responder must be (or be delegated by).'),
        responder: pkiInputSchema('The responder certificate to verify the signature with', ' Omitted: the certificates embedded in the response are tried, then the issuer itself.'),
        responderTrusted: { type: 'boolean', default: false, description: 'State an out-of-band trust in the responder (RFC 6960 §4.2.2.2 third case): responderAuthorized is then true whatever its certificate says.' },
        hashAlgorithm: { type: 'string', enum: [...OCSP_HASH_ALGORITHMS], description: 'The CertID hash to recompute with. Default: the one the response used for this serial, else SHA-1.' },
        nonce: hexSchema('The nonce you put in the request (1–32 bytes; create_ocsp_request summary.nonceHex): the response must echo it.'),
        requireNonce: { type: 'boolean', default: false, description: 'Refuse a response that carries no nonce (RFC 8954).' },
        at: TRUST_INPUT_PROPERTIES.at,
        ...STALE_TOLERANCE_INPUT_PROPERTY,
        futureTolerance: { type: 'integer', minimum: 0, description: 'Milliseconds a thisUpdate / producedAt may lie after `at` (clock skew) and still be accepted (default: the engine policy).' },
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    response: PkiInputSchema,
    certificate: PkiInputSchema,
    issuer: PkiInputSchema,
    responder: PkiInputSchema.optional(),
    responderTrusted: z.boolean().default(false),
    hashAlgorithm: z.enum(OCSP_HASH_ALGORITHMS).optional(),
    nonce: HexSchema.optional(),
    requireNonce: z.boolean().default(false),
    at: TrustShape.at,
    staleTolerance: z.number().int().min(0).optional(),
    futureTolerance: z.number().int().min(0).optional(),
    ...AllowSha1Shape,
    ...ParseShape,
    ...ProjectionShape,
});

export interface OcspStatusVerdict extends DiagnosticsReport {
    readonly valid: boolean;
    readonly reasons: ReadonlyArray<Record<string, string>>;
    readonly status: 'good' | 'revoked' | 'unknown' | null;
    readonly signatureVerified: boolean;
    readonly responderAuthorized: boolean;
    readonly responder: string | null;
    readonly responderSource: 'input' | 'embedded' | 'issuer' | null;
    readonly hashAlgorithm: OcspHashAlgorithm;
    readonly certIdHex: string;
    readonly evaluatedAt: string;
    readonly evaluatedAtSource: 'input' | 'pinned' | 'clock';
}

export const CHECK_OCSP_STATUS_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['valid', 'reasons', 'status', 'signatureVerified', 'responderAuthorized', 'responder', 'responderSource', 'hashAlgorithm', 'certIdHex', 'evaluatedAt', 'evaluatedAtSource', 'diagnostics', 'diagnosticCounts'],
    properties: {
        valid: { type: 'boolean', description: 'true = a fresh, correctly signed, authorised answer says good. false is a negative verdict (reasons[]: revoked, unknown, stale, unauthorised, unverified, nonce …), never an error.' },
        ...REASONS_OUTPUT_PROPERTY,
        status: { type: ['string', 'null'], enum: ['good', 'revoked', 'unknown', null], description: 'The status the response gives for this serial; null when the response holds no answer for it.' },
        signatureVerified: { type: 'boolean', description: 'A responder candidate verified the response signature.' },
        responderAuthorized: { type: 'boolean', description: 'The signer is the CA itself, a delegate the CA issued with id-kp-OCSPSigning, or responderTrusted was set.' },
        responder: { type: ['string', 'null'], description: 'The subject of the certificate that verified the signature.' },
        responderSource: { type: ['string', 'null'], enum: ['input', 'embedded', 'issuer', null], description: 'Where the signer came from: the `responder` input, the certificates embedded in the response, or the issuer itself.' },
        hashAlgorithm: { type: 'string', enum: [...OCSP_HASH_ALGORITHMS], description: 'The hash the CertID was recomputed with.' },
        certIdHex: { type: 'string', description: 'The recomputed DER CertID (hex).' },
        evaluatedAt: { type: 'string', description: 'The ISO instant used — re-pass it as `at` to reproduce the verdict.' },
        evaluatedAtSource: { type: 'string', enum: ['input', 'pinned', 'clock'] },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const CHECK_OCSP_STATUS_SUMMARY_PROPERTIES = {
    reasonCodes: { type: 'array', items: { type: 'string' } },
    diagnosticCount: { type: 'integer' },
} as const;

/**
 * RFC 6960 §4.2.2.2: the CA itself, or a delegate the CA issued that carries
 * id-kp-OCSPSigning. `responderTrusted` states an out-of-band trust instead.
 */
async function authorized(signer: Certificate, issuer: Certificate, trusted: boolean, allowSha1: boolean): Promise<boolean> {
    if (trusted) return true;
    if (toHex(signer.der) === toHex(issuer.der)) return true;
    const issuedByCa = await guardAsync('Cannot verify the responder certificate', () => verifyCertificateSignature(signer, issuer, { allowSha1 }));
    const eku = guard('Cannot check the responder purpose', () => checkExtendedKeyUsage([signer], KEY_PURPOSES.ocspSigning, { restrictIssuers: false, requireExplicitPurpose: true }));
    return issuedByCa && eku.length === 0;
}

/** The CertID the response must answer, decoded from the engine's own encoder: SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }. */
function expectedCertId(certificate: Certificate, issuer: Certificate, hash: OcspHashAlgorithm, ctx: ParseContext): { der: Uint8Array; issuerNameHash: Uint8Array; issuerKeyHash: Uint8Array; serialNumber: Uint8Array } {
    const der = guard('Cannot compute the CertID', () => encodeOcspCertId(certificate, issuer, hash));
    const node = guard('Cannot decode the CertID', () => decodeAsn1(der, ctx.options));
    return {
        der,
        issuerNameHash: guard('Cannot read the CertID', () => readOctetString(node.children[1] as Asn1Node, ctx.options)),
        issuerKeyHash: guard('Cannot read the CertID', () => readOctetString(node.children[2] as Asn1Node, ctx.options)),
        serialNumber: certificate.serialNumber.bytes,
    };
}

export async function checkOcspStatusTool(rawInput: unknown): Promise<OcspStatusVerdict> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const responseObj = await loadPkiObject(input.response, 'response', LABELS.any, ctx);
    const response = guard('Cannot read the OCSP response', () => parseOcspResponse(responseObj.der, ctx.options));
    const certObj = await loadPkiObject(input.certificate, 'certificate', LABELS.certificate, ctx);
    const certificate = guard('Cannot read the certificate', () => parseCertificate(certObj.der, ctx.options));
    const issuerObj = await loadPkiObject(input.issuer, 'issuer', LABELS.certificate, ctx);
    const issuer = guard('Cannot read the issuer certificate', () => parseCertificate(issuerObj.der, ctx.options));
    const basic = response.basicResponse;
    // The CertID is recomputed with the hash the responder answered with, unless hashAlgorithm says otherwise.
    const answered = basic?.responses.find((r) => r.certId.serialNumber.hex === certificate.serialNumber.hex);
    const hash = input.hashAlgorithm ?? (answered === undefined ? undefined : HASH_OIDS[answered.certId.hashAlgorithm.oid]) ?? 'SHA-1';
    const expected = expectedCertId(certificate, issuer, hash, ctx);

    let signer: Certificate | undefined;
    let source: OcspStatusVerdict['responderSource'] = null;
    if (basic !== undefined) {
        if (input.responder !== undefined) {
            const responderObj = await loadPkiObject(input.responder, 'responder', LABELS.certificate, ctx);
            const responder = guard('Cannot read the responder certificate', () => parseCertificate(responderObj.der, ctx.options));
            signer = await findOcspSigner(basic, [responder]);
            source = signer === undefined ? null : 'input';
        } else {
            const embedded = embeddedCertificates(basic, ctx);
            signer = await findOcspSigner(basic, embedded);
            if (signer !== undefined) source = 'embedded';
            else {
                signer = await findOcspSigner(basic, [issuer]);
                source = signer === undefined ? null : 'issuer';
            }
        }
    }
    const responderAuthorized = signer === undefined ? undefined : await authorized(signer, issuer, input.responderTrusted, input.allowSha1);
    const nonce = nonceBytes(input.nonce, 'nonce');
    const at = resolveInstant(input.at, 'at');
    const reasons = guard('Cannot check the OCSP status', () => checkOcspStatus({
        response,
        expected: { issuerNameHash: expected.issuerNameHash, issuerKeyHash: expected.issuerKeyHash, serialNumber: expected.serialNumber },
        at: at.ms,
        ...(basic !== undefined ? { signatureVerified: signer !== undefined } : {}),
        ...(responderAuthorized !== undefined ? { responderAuthorized } : {}),
        ...(signer !== undefined ? { signer } : {}),
        ...(nonce !== undefined ? { nonce } : {}),
        requireNonce: input.requireNonce,
        ...(input.staleTolerance !== undefined ? { staleTolerance: input.staleTolerance } : {}),
        ...(input.futureTolerance !== undefined ? { futureTolerance: input.futureTolerance } : {}),
        onDiagnostic: ctx.options.onDiagnostic,
    }));
    return withDiagnostics({
        valid: reasons.length === 0,
        reasons: reasonsView(reasons),
        status: answered?.status.kind ?? null,
        signatureVerified: signer !== undefined,
        responderAuthorized: responderAuthorized ?? false,
        responder: signer === undefined ? null : dn(signer.subject),
        responderSource: source,
        hashAlgorithm: hash,
        certIdHex: toHex(expected.der),
        evaluatedAt: at.iso,
        evaluatedAtSource: at.source,
    }, ctx.sink.report());
}

export function checkOcspStatusSummary(r: OcspStatusVerdict): Record<string, unknown> {
    return {
        valid: r.valid,
        reasonCodes: r.reasons.map((x) => x['code']),
        status: r.status,
        signatureVerified: r.signatureVerified,
        responderAuthorized: r.responderAuthorized,
        responder: r.responder,
        evaluatedAt: r.evaluatedAt,
        diagnosticCount: diagnosticCount(r),
    };
}

export const CHECK_OCSP_STATUS_TOOL = defineTool<OcspStatusVerdict>({
    name: CHECK_OCSP_STATUS_NAME,
    title: 'Check OCSP status (one response for one certificate: CertID, responder, freshness, nonce)',
    kind: 'verdict',
    description:
        "The RFC 6960 verdict of ONE OCSP `response` you fetched (this server never queries a responder) for ONE `certificate`: the CertID is recomputed from `issuer` (with the hash the response used, or `hashAlgorithm`) and must be answered; the signature is verified with `responder`, else the certificates embedded in the response, else the issuer itself; the signer must be authorised (RFC 6960 §4.2.2.2: the CA, a delegate the CA issued carrying id-kp-OCSPSigning, or `responderTrusted:true` for a trust you hold out of band); then the engine judges the status (good; PKI_REASON_REVOKED / unknown otherwise), freshness at `at` (thisUpdate / nextUpdate / producedAt, `staleTolerance` and `futureTolerance` ms), and the nonce (`nonce` must be echoed; `requireNonce:true` refuses a response without one). A non-successful response status is a negative verdict with status null. valid:false + reasons[] is a verdict, never isError. Pin `at` for a reproducible, cacheable verdict. Token-frugal: verbosity:'summary' (valid, reasonCodes, status, signatureVerified, responderAuthorized, responder). create_ocsp_request builds the request you POST; inspect_ocsp_response shows the facts without a verdict.",
    inputSchema: CHECK_OCSP_STATUS_INPUT_SCHEMA,
    rawOutputSchema: CHECK_OCSP_STATUS_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(CHECK_OCSP_STATUS_OUTPUT_SCHEMA, CHECK_OCSP_STATUS_SUMMARY_PROPERTIES, `OCSP status verdict.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    instantInputs: ['at'],
    examples: [
        { title: 'Is the leaf good according to the delegated responder?', input: { response: { path: 'fixtures/leaf.ocsp.der' }, certificate: { path: 'fixtures/leaf.crt.pem' }, issuer: { path: 'fixtures/inter.crt.pem' }, at: '2027-01-01T00:00:00Z', verbosity: 'summary' } },
        { title: 'A revoked answer, nonce demanded', input: { response: { path: 'fixtures/revoked.ocsp.der' }, certificate: { path: 'fixtures/revoked.crt.pem' }, issuer: { path: 'fixtures/inter.crt.pem' }, responder: { path: 'fixtures/ocsp.crt.pem' }, requireNonce: true, at: '2027-01-01T00:00:00Z', fields: ['valid', 'reasons.code', 'status', 'responderAuthorized'] } },
    ],
    handler: checkOcspStatusTool,
    text: (r) => r.valid
        ? `${CHECK_OCSP_STATUS_NAME}: OK — status good at ${r.evaluatedAt}, signed by ${r.responder ?? '?'} (${r.responderSource ?? ''}, authorised); ${r.diagnostics.length} diagnostic(s).`
        : `${CHECK_OCSP_STATUS_NAME}: NOT OK — ${r.reasons.map((x) => x['code']).join(', ')} (status ${r.status ?? 'no answer'}, signature ${r.signatureVerified ? 'verified' : 'NOT verified'}, responder ${r.responderAuthorized ? 'authorised' : 'NOT authorised'}, evaluated at ${r.evaluatedAt}).`,
    summary: checkOcspStatusSummary,
});
