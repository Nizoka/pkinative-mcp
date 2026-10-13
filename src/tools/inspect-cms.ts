/**
 * Tool: inspect_cms — the RFC 5652 report of one SignedData: version,
 * content type, attached content length (or detached), digest algorithms,
 * the embedded certificates, every signer (identifier, algorithms, signed
 * and unsigned attributes, signing time, ESS signing-certificate, algorithm
 * protection, counter time-stamps, the signature value), and an optional
 * ONE-signer-against-ONE-certificate signature check. The check is a key
 * check, not the verdict: verify_cms is.
 *
 * Also exports the helpers every CMS tool shares: `loadSignedData`,
 * `signerAt`, `signerInfoView`, `signedDataView`, `generalNameView`.
 */
import { getOidName, parseCertificate, parseSignedData, verifySignerInfoSignature, type Attribute, type Certificate, type GeneralName, type SignedData, type SignerInfo } from 'pkinative';
import { z } from 'zod';

import { ContentInputSchema, contentInputSchema, loadContent } from '../content-input.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { createParseContext, PARSE_INPUT_PROPERTIES, type ParseContext } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema, type PkiInputFields } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { ALLOW_SHA1_INPUT_PROPERTY } from '../signer.js';
import { formatInstant } from '../time.js';
import { ALGORITHM_VIEW_SCHEMA, algorithmView, CERTIFICATE_REF_SCHEMA, certificateRef, dn } from '../views.js';
import { toHex, type Wire } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { AllowSha1Shape, diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';

export const INSPECT_CMS_NAME = 'inspect_cms';

export const ALLOW_TRAILING_DATA_INPUT_PROPERTY = {
    allowTrailingData: { type: 'boolean', default: false, description: 'Ignore bytes after the ContentInfo (the zero padding of a PDF /Contents). Default false: trailing bytes are PKI_ASN1_TRAILING_DATA.' },
} as const;

export const INSPECT_CMS_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['signedData'],
    properties: {
        signedData: pkiInputSchema('The CMS SignedData (CMS / PKCS7 PEM, or DER: .p7s .p7m .p7b)'),
        ...ALLOW_TRAILING_DATA_INPUT_PROPERTY,
        signerCertificate: pkiInputSchema('The certificate to check ONE signer\'s signature against', ' A valid signature is a key check, NOT trust: verify_cms is the verdict.'),
        signerIndex: { type: 'integer', minimum: 0, default: 0, description: 'Which signer the signature check targets (encoded order; NOT_FOUND past the last).' },
        content: contentInputSchema('The detached content, for a signer WITHOUT signed attributes (such a signer signs the content itself); ignored otherwise'),
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    signedData: PkiInputSchema,
    allowTrailingData: z.boolean().default(false),
    signerCertificate: PkiInputSchema.optional(),
    signerIndex: z.number().int().min(0).default(0),
    content: ContentInputSchema.optional(),
    ...AllowSha1Shape,
    ...ParseShape,
    ...ProjectionShape,
}).superRefine((v, ctx) => {
    if (v.content !== undefined && v.signerCertificate === undefined) ctx.addIssue({ code: 'custom', message: 'content serves the signature check: pass signerCertificate', path: ['content'] });
});

/** `{ oid, name }` of an OID. */
export function oidView(oid: string): { readonly oid: string; readonly name: string | null } {
    return { oid, name: getOidName(oid) ?? null };
}

/** A GeneralName for an agent: its kind and one rendered value (a DN, a text, an address, an OID). */
export function generalNameView(gn: GeneralName): Record<string, Wire> {
    switch (gn.kind) {
        case 'directoryName':
            return { kind: gn.kind, name: dn(gn.name) };
        case 'rfc822Name':
        case 'dNSName':
        case 'uniformResourceIdentifier':
            return { kind: gn.kind, value: gn.value };
        case 'otherName':
            return { kind: gn.kind, typeId: gn.typeId };
        case 'x400Address':
        case 'ediPartyName':
            return { kind: gn.kind };
        case 'iPAddress':
            return { kind: gn.kind, address: gn.address, ...(gn.mask !== undefined ? { mask: gn.mask } : {}) };
        default:
            return { kind: gn.kind, oid: gn.oid };
    }
}

export const GENERAL_NAME_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: true,
    required: ['kind'],
    properties: { kind: { type: 'string' }, name: { type: 'string' }, value: { type: 'string' }, typeId: { type: 'string' }, address: { type: 'string' }, mask: { type: 'string' }, oid: { type: 'string' } },
} as const;

export interface SidView {
    readonly kind: 'issuerAndSerialNumber' | 'subjectKeyIdentifier';
    readonly issuer?: string;
    readonly serialNumber?: string;
    readonly keyIdentifier?: string;
}

export function sidView(sid: SignerInfo['sid']): SidView {
    return sid.kind === 'issuerAndSerialNumber'
        ? { kind: sid.kind, issuer: dn(sid.issuer), serialNumber: sid.serialNumber.hex }
        : { kind: sid.kind, keyIdentifier: toHex(sid.keyIdentifier) };
}

function attributeView(a: Attribute): { readonly oid: string; readonly name: string | null; readonly valueCount: number } {
    return { ...oidView(a.oid), valueCount: a.values.length };
}

export interface SignerInfoView {
    readonly index: number;
    readonly version: number;
    readonly sid: SidView;
    readonly digestAlgorithm: ReturnType<typeof algorithmView>;
    readonly signatureAlgorithm: ReturnType<typeof algorithmView>;
    readonly signingTime: string | null;
    readonly signingCertificate: Record<string, Wire> | null;
    readonly algorithmProtection: { readonly digestAlgorithm: ReturnType<typeof algorithmView>; readonly signatureAlgorithm: ReturnType<typeof algorithmView> } | null;
    readonly signedAttributes: ReadonlyArray<ReturnType<typeof attributeView>> | null;
    readonly unsignedAttributes: ReadonlyArray<ReturnType<typeof attributeView>> | null;
    readonly timeStampTokens: number;
    readonly signature: string;
}

export function signerInfoView(s: SignerInfo, index: number): SignerInfoView {
    const sc = s.signingCertificate;
    return {
        index,
        version: s.version,
        sid: sidView(s.sid),
        digestAlgorithm: algorithmView(s.digestAlgorithm),
        signatureAlgorithm: algorithmView(s.signatureAlgorithm),
        signingTime: s.signingTime === undefined ? null : formatInstant(s.signingTime.epochMilliseconds),
        signingCertificate: sc === undefined ? null : {
            version: sc.version,
            certIds: sc.certIds.map((c) => ({
                hashAlgorithm: c.hashAlgorithm,
                certHash: toHex(c.certHash),
                issuerSerial: c.issuerSerial === undefined ? null : { issuer: c.issuerSerial.issuer.map(generalNameView), serialNumber: c.issuerSerial.serialNumber.hex },
            })),
        },
        algorithmProtection: s.algorithmProtection === undefined ? null : { digestAlgorithm: algorithmView(s.algorithmProtection.digestAlgorithm), signatureAlgorithm: algorithmView(s.algorithmProtection.signatureAlgorithm) },
        signedAttributes: s.signedAttributes === undefined ? null : s.signedAttributes.map(attributeView),
        unsignedAttributes: s.unsignedAttributes === undefined ? null : s.unsignedAttributes.map(attributeView),
        timeStampTokens: s.timeStampTokens.length,
        signature: toHex(s.signature),
    };
}

export interface SignedDataView {
    readonly version: number;
    readonly contentType: ReturnType<typeof oidView>;
    readonly contentLength: number | null;
    readonly digestAlgorithms: ReadonlyArray<ReturnType<typeof algorithmView>>;
    readonly certificates: ReadonlyArray<ReturnType<typeof certificateRef>>;
    readonly crlCount: number;
    readonly ocspResponseCount: number;
    readonly signerInfos: readonly SignerInfoView[];
    readonly sizeBytes: number;
}

/** Parse every certificate a SignedData embeds (a claim by whoever assembled it). */
export function embeddedCertificates(sd: SignedData, ctx: ParseContext): Certificate[] {
    return sd.certificates.map((der, i) => guard(`Cannot read the embedded certificate certificates[${i}]`, () => parseCertificate(der, ctx.options)));
}

export function signedDataView(sd: SignedData, ctx: ParseContext): SignedDataView {
    return {
        version: sd.version,
        contentType: oidView(sd.contentType),
        contentLength: sd.content === undefined ? null : sd.content.length,
        digestAlgorithms: sd.digestAlgorithms.map(algorithmView),
        certificates: embeddedCertificates(sd, ctx).map(certificateRef),
        crlCount: sd.crls.length,
        ocspResponseCount: sd.ocspResponses.length,
        signerInfos: sd.signerInfos.map(signerInfoView),
        sizeBytes: sd.der.length,
    };
}

/** Load and parse one SignedData input through the call's sink. */
export async function loadSignedData(input: PkiInputFields, what: string, ctx: ParseContext, allowTrailingData = false): Promise<{ der: Uint8Array; source: string; signedData: SignedData }> {
    const obj = await loadPkiObject(input, what, LABELS.cms, ctx);
    const signedData = guard('Cannot read the SignedData', () => parseSignedData(obj.der, { ...ctx.options, allowTrailingData }));
    return { der: obj.der, source: obj.source, signedData };
}

/** The signer at `index`, or NOT_FOUND naming how many there are. */
export function signerAt(sd: SignedData, index: number, path = 'signerIndex'): SignerInfo {
    const signerInfo = sd.signerInfos[index];
    if (signerInfo === undefined) {
        throw new ToolError('NOT_FOUND', `${path} ${index} is out of range: the SignedData has ${sd.signerInfos.length} signer(s).`, { path, signerIndex: index, signerCount: sd.signerInfos.length });
    }
    return signerInfo;
}

export interface InspectCmsResult extends SignedDataView, DiagnosticsReport {
    readonly signerSignature?: { readonly index: number; readonly valid: boolean; readonly signerSubject: string };
}

const ATTRIBUTE_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['oid', 'name', 'valueCount'],
    properties: { oid: { type: 'string' }, name: { type: ['string', 'null'] }, valueCount: { type: 'integer' } },
} as const;

export const SIGNER_INFO_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['index', 'version', 'sid', 'digestAlgorithm', 'signatureAlgorithm', 'signingTime', 'signingCertificate', 'algorithmProtection', 'signedAttributes', 'unsignedAttributes', 'timeStampTokens', 'signature'],
    properties: {
        index: { type: 'integer' },
        version: { type: 'integer', enum: [1, 3] },
        sid: { type: 'object', additionalProperties: false, required: ['kind'], properties: { kind: { type: 'string', enum: ['issuerAndSerialNumber', 'subjectKeyIdentifier'] }, issuer: { type: 'string' }, serialNumber: { type: 'string', description: 'Hex.' }, keyIdentifier: { type: 'string', description: 'Hex.' } } },
        digestAlgorithm: ALGORITHM_VIEW_SCHEMA,
        signatureAlgorithm: ALGORITHM_VIEW_SCHEMA,
        signingTime: { type: ['string', 'null'], description: 'The time the signer CLAIMS (ISO 8601); nothing vouches for it.' },
        signingCertificate: { type: ['object', 'null'], additionalProperties: true, description: 'The ESS signingCertificate (v1) or signingCertificateV2 attribute: version and certIds (hashAlgorithm, certHash hex, issuerSerial).' },
        algorithmProtection: { type: ['object', 'null'], additionalProperties: false, properties: { digestAlgorithm: ALGORITHM_VIEW_SCHEMA, signatureAlgorithm: ALGORITHM_VIEW_SCHEMA }, description: 'CMSAlgorithmProtection (RFC 6211), or null when the signer did not include one.' },
        signedAttributes: { type: ['array', 'null'], items: ATTRIBUTE_VIEW_SCHEMA, description: 'null when the signer has no signed attributes (the signature is then over the content itself).' },
        unsignedAttributes: { type: ['array', 'null'], items: ATTRIBUTE_VIEW_SCHEMA },
        timeStampTokens: { type: 'integer', description: 'Counter time-stamps (id-aa-signatureTimeStampToken) among the unsigned attributes.' },
        signature: { type: 'string', description: 'The signature value as hex — what a counter time-stamp stamps (hash it, then create_timestamp_request digestHex).' },
    },
} as const;

export const SIGNED_DATA_VIEW_PROPERTIES = {
    version: { type: 'integer', enum: [1, 3, 4, 5] },
    contentType: { type: 'object', additionalProperties: false, required: ['oid', 'name'], properties: { oid: { type: 'string' }, name: { type: ['string', 'null'] } } },
    contentLength: { type: ['integer', 'null'], description: 'Bytes of the encapsulated content; null when the signature is detached.' },
    digestAlgorithms: { type: 'array', items: ALGORITHM_VIEW_SCHEMA },
    certificates: { type: 'array', items: CERTIFICATE_REF_SCHEMA, description: 'The embedded certificates (a claim by whoever assembled the message).' },
    crlCount: { type: 'integer' },
    ocspResponseCount: { type: 'integer' },
    signerInfos: { type: 'array', items: SIGNER_INFO_VIEW_SCHEMA },
    sizeBytes: { type: 'integer' },
} as const;

export const INSPECT_CMS_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['version', 'contentType', 'contentLength', 'digestAlgorithms', 'certificates', 'crlCount', 'ocspResponseCount', 'signerInfos', 'sizeBytes', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...SIGNED_DATA_VIEW_PROPERTIES,
        signerSignature: {
            type: 'object',
            additionalProperties: false,
            required: ['index', 'valid', 'signerSubject'],
            description: 'The signature check asked for with signerCertificate: ONE signer against ONE key. A key check, not the verdict (verify_cms).',
            properties: { index: { type: 'integer' }, valid: { type: 'boolean' }, signerSubject: { type: 'string' } },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const INSPECT_CMS_SUMMARY_PROPERTIES = {
    contentTypeOid: { type: 'string' },
    signerCount: { type: 'integer' },
    signers: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { index: { type: 'integer' }, signingTime: { type: ['string', 'null'] }, timeStampTokens: { type: 'integer' } } } },
    signerSignatureValid: { type: 'boolean' },
    diagnosticCount: { type: 'integer' },
} as const;

export async function inspectCms(rawInput: unknown): Promise<InspectCmsResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const { signedData } = await loadSignedData(input.signedData, 'signedData', ctx, input.allowTrailingData);
    const view = signedDataView(signedData, ctx);
    let signerSignature: InspectCmsResult['signerSignature'];
    if (input.signerCertificate !== undefined) {
        const signerInfo = signerAt(signedData, input.signerIndex);
        const certObj = await loadPkiObject(input.signerCertificate, 'signerCertificate', LABELS.certificate, ctx);
        const cert = guard('Cannot read the signer certificate', () => parseCertificate(certObj.der, ctx.options));
        const content = input.content === undefined ? undefined : (await loadContent(input.content, 'content')).bytes;
        const valid = await guardAsync(`Cannot verify signer ${input.signerIndex}`, () => verifySignerInfoSignature(signerInfo, cert, { ...(content !== undefined ? { content } : {}), allowSha1: input.allowSha1 }));
        signerSignature = { index: input.signerIndex, valid, signerSubject: dn(cert.subject) };
    }
    return withDiagnostics({
        ...view,
        ...(signerSignature !== undefined ? { signerSignature } : {}),
    }, ctx.sink.report());
}

export function inspectCmsSummary(r: InspectCmsResult): Record<string, unknown> {
    return {
        version: r.version,
        contentTypeOid: r.contentType.oid,
        contentLength: r.contentLength,
        signerCount: r.signerInfos.length,
        signers: r.signerInfos.map((s) => ({ index: s.index, signingTime: s.signingTime, timeStampTokens: s.timeStampTokens })),
        ...(r.signerSignature !== undefined ? { signerSignatureValid: r.signerSignature.valid } : {}),
        diagnosticCount: diagnosticCount(r),
    };
}

export const INSPECT_CMS_TOOL = defineTool<InspectCmsResult>({
    name: INSPECT_CMS_NAME,
    title: 'Inspect CMS SignedData (RFC 5652 report, signers, attributes, signature values)',
    kind: 'read',
    description:
        "Read-only RFC 5652 report of ONE CMS SignedData (.p7s / .p7m / .p7b, CMS or PKCS7 PEM, or a PDF /Contents): version, content type, attached content length (null = detached), digest algorithms, the embedded certificates (subject / issuer / serial), CRL and OCSP counts, and every signer — identifier (issuer + serial or key id), algorithms, signing time as CLAIMED, ESS signing-certificate, CMSAlgorithmProtection, signed and unsigned attributes (oid, name, value count), counter time-stamp count and the signature value as hex (what a counter time-stamp stamps: fields:['signerInfos.signature'], hash it, create_timestamp_request digestHex). `signerCertificate` (+ `signerIndex`, and `content` for a signer without signed attributes) adds signerSignature.valid — ONE signer against ONE key, a key check and NOT the verdict: verify_cms judges trust, digests, time-stamps and revocation. Trailing bytes are refused unless allowTrailingData:true; BER producers need encodingRules:'ber'. Refuses: NOT_FOUND for a signerIndex past the last signer, PKI_* for an unreadable structure. Token-frugal: verbosity:'summary', fields:[…].",
    inputSchema: INSPECT_CMS_INPUT_SCHEMA,
    rawOutputSchema: INSPECT_CMS_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(INSPECT_CMS_OUTPUT_SCHEMA, INSPECT_CMS_SUMMARY_PROPERTIES, `Structured SignedData report.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'Who signed, when (claimed), with what', input: { signedData: { path: 'fixtures/attached.p7s' }, verbosity: 'summary' } },
        { title: 'The signature value to counter time-stamp, with a key check', input: { signedData: { path: 'fixtures/detached.p7s' }, signerCertificate: { path: 'fixtures/leaf.crt.pem' }, fields: ['signerInfos.signature', 'signerSignature'] } },
    ],
    handler: inspectCms,
    text: (r) => `${INSPECT_CMS_NAME}: SignedData v${r.version}, ${r.contentType.name ?? r.contentType.oid}, ${r.contentLength === null ? 'detached' : `${r.contentLength} bytes of content`}, ${r.signerInfos.length} signer(s), ${r.certificates.length} certificate(s), ${r.crlCount} CRL(s)${r.signerSignature !== undefined ? `; signer ${r.signerSignature.index} signature ${r.signerSignature.valid ? 'valid' : 'INVALID'} under ${r.signerSignature.signerSubject} (key check, not trust)` : ''}; ${r.diagnostics.length} diagnostic(s).`,
    summary: inspectCmsSummary,
});
