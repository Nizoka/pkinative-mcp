/**
 * Tool: sign_cms — an RFC 5652 SignedData (attached or detached, or over a
 * precomputed digest) with ONE signer, signed through a non-extractable Web
 * Crypto key (a PKCS#8 key with its certificate, or a PKCS#12 file that
 * holds both). Signed attributes are always written (contentType,
 * messageDigest, signingTime unless 'none', SigningCertificateV2 and
 * CMSAlgorithmProtection unless turned off, the caller's extras). The new
 * signature is verified against the signer certificate BEFORE it is
 * returned.
 */
import { createSignedData, verifySignerInfoSignature, parseCertificate, parseSignedData, type Certificate } from 'pkinative';
import { z } from 'zod';

import { MAX_ATTRIBUTES_INLINE } from '../caps.js';
import { ContentInputSchema, contentInputSchema, HexSchema, hexSchema, loadContent } from '../content-input.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { ARTEFACT_OUTPUT_PROPERTIES, emitArtefact, outputInputProperties, outputShape, type OutputResult } from '../output.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiBundle, loadPkiObject, pkiBundleSchema, PkiBundleSchema, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { ALLOW_SHA1_INPUT_PROPERTY, loadSigner, SIGNER_INPUT_SCHEMA, SignerSchema } from '../signer.js';
import { keyTypeOfSpki } from '../spki.js';
import { formatInstant, resolveInstant } from '../time.js';
import { ALGORITHM_VIEW_SCHEMA, algorithmView, dn } from '../views.js';
import { fromHex } from '../wire.js';
import { defineTool, PRODUCES } from './_definition.js';
import { AllowSha1Shape, parseInput, ParseShape, withDiagnostics } from './_shared.js';
import { parseCertificates } from './verify-certificate-chain.js';

export const SIGN_CMS_NAME = 'sign_cms';

const OID_PATTERN = '^\\d+(\\.\\d+)+$';
const SID_KINDS = ['issuerAndSerialNumber', 'subjectKeyIdentifier'] as const;

/** The CMS artefact output options shared with amend_cms. */
export const CMS_OUTPUT_INPUT_PROPERTIES = outputInputProperties('der', '.p7s .p7m .p7b .cms .der for der; .pem for pem');
export const CMS_PEM_LABEL = 'CMS';
export const CMS_MIME_TYPE = 'application/pkcs7-signature';
export const CMS_DER_EXTENSIONS: readonly string[] = ['.p7s', '.p7m', '.p7b', '.cms', '.der'];

function attributeListSchema(what: string): Record<string, unknown> {
    return { type: 'array', maxItems: MAX_ATTRIBUTES_INLINE, items: hexSchema('One DER Attribute (SEQUENCE { type, SET OF values }).'), description: what };
}

export const SIGN_CMS_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['signer'],
    properties: {
        content: contentInputSchema('The content to sign (hashed with the signer\'s digest; embedded unless detached)'),
        contentDigest: hexSchema('The content\'s digest, already computed with the signer\'s digest algorithm (the PDF /ByteRange case). Requires detached:true. Exclusive with content.'),
        detached: { type: 'boolean', default: false, description: 'Omit the content from the SignedData (the signature travels without what it signs; most S/MIME and every PDF signature).' },
        contentType: { type: 'string', pattern: OID_PATTERN, description: 'The eContentType (dotted OID). Default id-data (1.2.840.113549.1.7.1); any other makes a version 3 SignedData.' },
        certificate: pkiInputSchema('The signer certificate', ' Required with signer.key; optional with signer.p12 (the bag\'s certificate is used, and this one wins when both are given).'),
        chain: pkiBundleSchema('Further certificates to embed (the chain)', ' The signer certificate is always embedded once; a PKCS#12 bag\'s other certificates are added too.'),
        crls: pkiBundleSchema('CRLs to embed (DER or X509 CRL PEM)'),
        sid: { type: 'string', enum: [...SID_KINDS], default: 'issuerAndSerialNumber', description: "How the SignerInfo names the certificate. Keep issuerAndSerialNumber unless the reader is known: subjectKeyIdentifier (version 3) is refused by some deployed readers and needs the certificate's SKI extension." },
        signingTime: { type: 'string', minLength: 1, description: "The claimed signing time: an ISO 8601 instant, epoch milliseconds, 'now', or 'none' to omit the attribute (PAdES forbids it, S/MIME expects it). Whole seconds. Omitted: PKINATIVE_MCP_AT when pinned, else the wall clock — pin it for reproducible bytes." },
        signingCertificateV2: { type: 'boolean', default: true, description: 'Write the ESS SigningCertificateV2 attribute (RFC 5035), binding the signature to this certificate — CAdES, PAdES and RFC 3161 require it.' },
        algorithmProtection: { type: 'boolean', default: true, description: 'Write CMSAlgorithmProtection (RFC 6211, RFC 8933 §4).' },
        signedAttributes: attributeListSchema('Further signed attributes, each one DER Attribute as hex, written verbatim. A type the builder writes itself, a repeated type or a countersignature is refused (PKI_API_MISUSE).'),
        unsignedAttributes: attributeListSchema('Unsigned attributes, each one DER Attribute as hex (a time-stamp token already in hand: amend_cms add-timestamp checks the imprint first). A signed-only type is refused.'),
        signer: SIGNER_INPUT_SCHEMA,
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...CMS_OUTPUT_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    content: ContentInputSchema.optional(),
    contentDigest: HexSchema.optional(),
    detached: z.boolean().default(false),
    contentType: z.string().regex(new RegExp(OID_PATTERN)).optional(),
    certificate: PkiInputSchema.optional(),
    chain: PkiBundleSchema.optional(),
    crls: PkiBundleSchema.optional(),
    sid: z.enum(SID_KINDS).default('issuerAndSerialNumber'),
    signingTime: z.string().min(1).optional(),
    signingCertificateV2: z.boolean().default(true),
    algorithmProtection: z.boolean().default(true),
    signedAttributes: z.array(HexSchema).max(MAX_ATTRIBUTES_INLINE).optional(),
    unsignedAttributes: z.array(HexSchema).max(MAX_ATTRIBUTES_INLINE).optional(),
    signer: SignerSchema,
    ...AllowSha1Shape,
    ...ParseShape,
    ...outputShape('der'),
}).superRefine((v, ctx) => {
    if ((v.content === undefined) === (v.contentDigest === undefined)) ctx.addIssue({ code: 'custom', message: 'pass exactly one of content / contentDigest', path: ['content'] });
    if (v.contentDigest !== undefined && !v.detached) ctx.addIssue({ code: 'custom', message: 'contentDigest signs a digest only: it needs detached:true', path: ['detached'] });
});

export interface SignCmsResult extends OutputResult, DiagnosticsReport {
    readonly summary: {
        readonly detached: boolean;
        readonly contentType: string;
        readonly signerSubject: string;
        readonly signerSerial: string;
        readonly sid: (typeof SID_KINDS)[number];
        readonly digestAlgorithm: ReturnType<typeof algorithmView>;
        readonly signatureAlgorithm: ReturnType<typeof algorithmView>;
        readonly signingTime: string | null;
        readonly signingTimeSource: 'input' | 'pinned' | 'clock' | 'none';
        readonly certificatesEmbedded: number;
        readonly crlsEmbedded: number;
        readonly signedAttributes: number;
        readonly unsignedAttributes: number;
        readonly signatureVerified: true;
        readonly contentBytes: number | null;
    };
}

export const SIGN_CMS_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode', 'encoding', 'sizeBytes', 'sha256', 'summary', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...ARTEFACT_OUTPUT_PROPERTIES,
        summary: {
            type: 'object',
            additionalProperties: false,
            required: ['detached', 'contentType', 'signerSubject', 'signerSerial', 'sid', 'digestAlgorithm', 'signatureAlgorithm', 'signingTime', 'signingTimeSource', 'certificatesEmbedded', 'crlsEmbedded', 'signedAttributes', 'unsignedAttributes', 'signatureVerified', 'contentBytes'],
            properties: {
                detached: { type: 'boolean' },
                contentType: { type: 'string', description: 'The eContentType OID.' },
                signerSubject: { type: 'string' },
                signerSerial: { type: 'string', description: 'Hex.' },
                sid: { type: 'string', enum: [...SID_KINDS] },
                digestAlgorithm: ALGORITHM_VIEW_SCHEMA,
                signatureAlgorithm: ALGORITHM_VIEW_SCHEMA,
                signingTime: { type: ['string', 'null'], description: 'The signingTime attribute written (ISO 8601, whole seconds), or null when omitted.' },
                signingTimeSource: { type: 'string', enum: ['input', 'pinned', 'clock', 'none'] },
                certificatesEmbedded: { type: 'integer' },
                crlsEmbedded: { type: 'integer' },
                signedAttributes: { type: 'integer', description: 'Signed attributes written in all (the mandatory ones included).' },
                unsignedAttributes: { type: 'integer' },
                signatureVerified: { type: 'boolean', enum: [true], description: 'The new signature was verified against the signer certificate before it was returned (KEY_MISMATCH otherwise).' },
                contentBytes: { type: ['integer', 'null'], description: 'Bytes of content signed; null when a precomputed digest was signed.' },
            },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

/** `signingTime`: 'none' omits the attribute; otherwise the resolved instant, truncated to whole seconds (RFC 5652 §11.3). */
function signingTimeOf(raw: string | undefined): { ms: number | undefined; source: SignCmsResult['summary']['signingTimeSource'] } {
    if (raw === 'none') return { ms: undefined, source: 'none' };
    const at = resolveInstant(raw, 'signingTime');
    return { ms: Math.floor(at.ms / 1000) * 1000, source: at.source };
}

function attributeBytes(list: readonly string[] | undefined, path: string): Uint8Array[] {
    return (list ?? []).map((hex, i) => {
        const bytes = fromHex(hex);
        if (bytes === undefined || bytes.length === 0) throw new ToolError('VALIDATION_ERROR', `${path}[${i}]: expected the DER of one Attribute as hex.`, { path: `${path}[${i}]` });
        return bytes;
    });
}

export async function signCmsTool(rawInput: unknown): Promise<SignCmsResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    let fromInput: Certificate | undefined;
    if (input.certificate !== undefined) {
        const obj = await loadPkiObject(input.certificate, 'certificate', LABELS.certificate, ctx);
        fromInput = guard('Cannot read the signer certificate', () => parseCertificate(obj.der, ctx.options));
    }
    const loaded = await loadSigner(input.signer, input.allowSha1, fromInput === undefined ? undefined : keyTypeOfSpki(fromInput.subjectPublicKeyInfo.der, ctx), ctx);
    const certificate = fromInput ?? loaded.certificate;
    if (certificate === undefined) {
        throw new ToolError('VALIDATION_ERROR', 'The signer certificate is required: pass certificate (or a signer.p12 that holds it).', { path: 'certificate', remedy: 'certificate' });
    }
    const extra = [...parseCertificates(await loadPkiBundle(input.chain, 'chain', LABELS.certificate, ctx), 'chain certificate', ctx), ...loaded.chain];
    const crls = (await loadPkiBundle(input.crls, 'crls', LABELS.crl, ctx)).map((o) => o.der);
    const content = input.content === undefined ? undefined : (await loadContent(input.content, 'content')).bytes;
    const contentDigest = input.contentDigest === undefined ? undefined : fromHex(input.contentDigest);
    if (input.contentDigest !== undefined && (contentDigest === undefined || contentDigest.length === 0)) {
        throw new ToolError('VALIDATION_ERROR', 'contentDigest: expected hexadecimal bytes.', { path: 'contentDigest' });
    }
    const signed = attributeBytes(input.signedAttributes, 'signedAttributes');
    const unsigned = attributeBytes(input.unsignedAttributes, 'unsignedAttributes');
    const time = signingTimeOf(input.signingTime);
    const der = await guardAsync('Cannot sign', () => createSignedData({
        ...(content !== undefined ? { content } : {}),
        ...(contentDigest !== undefined ? { contentDigest } : {}),
        detached: input.detached,
        ...(input.contentType !== undefined ? { contentType: input.contentType } : {}),
        certificate,
        sid: input.sid,
        certificates: [certificate.der, ...extra.map((c) => c.der)],
        crls,
        ...(time.ms !== undefined ? { signingTime: time.ms } : {}),
        signingCertificateV2: input.signingCertificateV2,
        algorithmProtection: input.algorithmProtection,
        signedAttributes: signed,
        unsignedAttributes: unsigned,
    }, loaded.signer, ctx.options.limits !== undefined ? { limits: ctx.options.limits } : {}));

    // A key that does not belong to the certificate would yield a signature nobody verifies. The builder always
    // writes signed attributes, so the signature covers them and the check needs no content.
    const sd = guard('Cannot read the SignedData just created', () => parseSignedData(der, ctx.options));
    const signerInfo = sd.signerInfos[0];
    if (signerInfo === undefined) throw new ToolError('ENGINE_ERROR', 'The SignedData just created has no signer.', { errorClass: 'internal' });
    const ok = await guardAsync('Cannot verify the new signature', () => verifySignerInfoSignature(signerInfo, certificate, { allowSha1: input.allowSha1 }));
    if (!ok) throw new ToolError('KEY_MISMATCH', 'The signing key does not belong to the signer certificate: the new signature does not verify under it.', { remedy: 'signer' });

    const artefact = await emitArtefact(der, {
        mode: input.outputMode,
        encoding: input.encoding,
        outputPath: input.outputPath,
        pemLabel: CMS_PEM_LABEL,
        mimeType: CMS_MIME_TYPE,
        derExtensions: CMS_DER_EXTENSIONS,
    });
    return withDiagnostics({
        ...artefact,
        summary: {
            detached: sd.content === undefined,
            contentType: sd.contentType,
            signerSubject: dn(certificate.subject),
            signerSerial: certificate.serialNumber.hex,
            sid: signerInfo.sid.kind,
            digestAlgorithm: algorithmView(signerInfo.digestAlgorithm),
            signatureAlgorithm: algorithmView(signerInfo.signatureAlgorithm),
            signingTime: time.ms === undefined ? null : formatInstant(time.ms),
            signingTimeSource: time.source,
            certificatesEmbedded: sd.certificates.length,
            crlsEmbedded: sd.crls.length,
            signedAttributes: signerInfo.signedAttributes?.length ?? 0,
            unsignedAttributes: signerInfo.unsignedAttributes?.length ?? 0,
            signatureVerified: true,
            contentBytes: content === undefined ? null : content.length,
        },
    }, ctx.sink.report());
}

export const SIGN_CMS_TOOL = defineTool<SignCmsResult>({
    name: SIGN_CMS_NAME,
    title: 'Sign CMS (RFC 5652 SignedData, attached or detached, Web Crypto signed)',
    kind: 'artefact',
    description:
        "Produce an RFC 5652 SignedData over `content` (attached, or `detached:true`) or over a precomputed `contentDigest` (detached only — the PDF /ByteRange case), with ONE signer: `signer` (a PKCS#8 key or a PKCS#12 file, imported as a NON-EXTRACTABLE Web Crypto key — nothing generates or exports a key here) and `certificate` (required with signer.key; a PKCS#12 bag's certificate serves otherwise), `chain` and `crls` embedded verbatim. Signed attributes are always written: contentType, messageDigest, signingTime (default PKINATIVE_MCP_AT or now, whole seconds; 'none' omits it — pin it for reproducible bytes), SigningCertificateV2 and CMSAlgorithmProtection (on by default; CAdES / PAdES need them), plus your `signedAttributes` / `unsignedAttributes` (DER Attributes as hex). `sid` defaults to issuerAndSerialNumber (keep it unless the reader is known). The new signature is verified against the signer certificate BEFORE it is returned (KEY_MISMATCH otherwise). RSA keys need signer.rsaScheme; SHA-1 needs allowSha1:true. Output DER (default; .p7s), PEM (label CMS) or hex, inline or as a sandbox file (never overwritten). Add a counter time-stamp afterwards with amend_cms.",
    inputSchema: SIGN_CMS_INPUT_SCHEMA,
    outputSchema: SIGN_CMS_OUTPUT_SCHEMA,
    annotations: PRODUCES,
    cacheable: false,
    instantInputs: ['signingTime'],
    examples: [
        { title: 'A detached .p7s over a file, chain embedded, time pinned', input: { content: { path: 'fixtures/content.txt' }, detached: true, certificate: { path: 'fixtures/leaf.crt.pem' }, chain: [{ path: 'fixtures/inter.crt.pem' }], signingTime: '2027-01-01T00:00:00Z', signer: { key: { path: 'fixtures/leaf.key.pem' } } } },
        { title: 'An attached message from a PKCS#12, PAdES-style (no signingTime), written to the sandbox', input: { content: { text: 'hello, world' }, signingTime: 'none', signer: { p12: { path: 'fixtures/leaf.p12' }, password: 'test-only-password' }, outputMode: 'file', outputPath: 'signed/hello.p7m' } },
    ],
    handler: signCmsTool,
    text: (r) => `${SIGN_CMS_NAME}: ${r.summary.detached ? 'detached' : 'attached'} SignedData by ${r.summary.signerSubject} (serial ${r.summary.signerSerial}), ${r.summary.signatureAlgorithm.name ?? r.summary.signatureAlgorithm.oid} / ${r.summary.digestAlgorithm.name ?? r.summary.digestAlgorithm.oid}, signingTime ${r.summary.signingTime ?? 'omitted'}, ${r.summary.certificatesEmbedded} certificate(s) embedded, ${r.sizeBytes} bytes DER, sha256 ${r.sha256.slice(0, 16)}…, signature verified${r.mode === 'file' ? `, written to ${r.filePath ?? ''}` : ` (${r.encoding} delivered as the embedded resource below)`}.`,
});
