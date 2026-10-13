/**
 * Tool: inspect_certificate — the full RFC 5280 report of one certificate
 * (every field, every decoded extension, diagnostics, fingerprints), one
 * extension on demand, raw extensions, and an optional signature check
 * against an issuer or itself. The signature check is ONE signature against
 * ONE key: it is not trust (verify_certificate_chain is).
 */
import {
    computeFingerprint,
    formatFingerprint,
    getExtension,
    parseCertificate,
    verifyCertificateSignature,
    verifySelfSignature,
    type DecodedExtensionKind,
    type FingerprintAlgorithm,
} from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { ALLOW_SHA1_INPUT_PROPERTY } from '../signer.js';
import { CERTIFICATE_VIEW_PROPERTIES, certificateView, dn, EXTENSION_VIEW_SCHEMA, extensionView, type CertificateView } from '../views.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { AllowSha1Shape, diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';
import type { Wire } from '../wire.js';

export const INSPECT_CERTIFICATE_NAME = 'inspect_certificate';

export const EXTENSION_KINDS = [
    'basicConstraints', 'keyUsage', 'extendedKeyUsage', 'subjectAltName', 'issuerAltName', 'subjectKeyIdentifier',
    'authorityKeyIdentifier', 'nameConstraints', 'certificatePolicies', 'policyMappings', 'policyConstraints',
    'inhibitAnyPolicy', 'authorityInfoAccess', 'subjectInfoAccess', 'crlDistributionPoints', 'freshestCRL',
    'signedCertificateTimestampList', 'ocspNoCheck', 'subjectDirectoryAttributes',
] as const satisfies readonly DecodedExtensionKind[];

const FINGERPRINT_ALGORITHMS = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'] as const satisfies readonly FingerprintAlgorithm[];

export const INSPECT_CERTIFICATE_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['certificate'],
    properties: {
        certificate: pkiInputSchema('The certificate (CERTIFICATE PEM or DER)'),
        extension: { type: 'string', enum: [...EXTENSION_KINDS], description: 'Return only this decoded extension (NOT_FOUND when absent). Exclusive with rawExtensions.' },
        rawExtensions: { type: 'boolean', default: false, description: 'Keep every extension undecoded (kind raw, valueDer as hex) — the way past PKI_X509_EXTENSION_MALFORMED.' },
        issuer: pkiInputSchema('The issuer certificate to check the signature against', ' Exclusive with checkSelfSignature. A valid signature is NOT trust: run verify_certificate_chain for that.'),
        checkSelfSignature: { type: 'boolean', default: false, description: 'Check the certificate against its own key (a self-signed root). Exclusive with issuer.' },
        requireAlgorithmMatch: { type: 'boolean', default: true, description: 'Require the outer signatureAlgorithm to equal the TBS signature algorithm (RFC 5280 §4.1.1.2).' },
        fingerprints: { type: 'array', maxItems: 4, uniqueItems: true, items: { type: 'string', enum: [...FINGERPRINT_ALGORITHMS] }, default: ['SHA-256'], description: 'Digests of the DER to report.' },
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    certificate: PkiInputSchema,
    extension: z.enum(EXTENSION_KINDS).optional(),
    rawExtensions: z.boolean().default(false),
    issuer: PkiInputSchema.optional(),
    checkSelfSignature: z.boolean().default(false),
    requireAlgorithmMatch: z.boolean().default(true),
    fingerprints: z.array(z.enum(FINGERPRINT_ALGORITHMS)).max(4).default(['SHA-256']),
    ...AllowSha1Shape,
    ...ParseShape,
    ...ProjectionShape,
}).superRefine((v, ctx) => {
    if (v.extension !== undefined && v.rawExtensions) ctx.addIssue({ code: 'custom', message: 'extension reads a decoded extension; drop rawExtensions', path: ['extension'] });
    if (v.issuer !== undefined && v.checkSelfSignature) ctx.addIssue({ code: 'custom', message: 'pass issuer or checkSelfSignature, not both', path: ['issuer'] });
});

export interface InspectCertificateResult extends CertificateView, DiagnosticsReport {
    readonly subjectString: string;
    readonly issuerString: string;
    readonly fingerprints: Readonly<Record<string, string>>;
    readonly extension?: Record<string, Wire>;
    readonly signature?: { readonly checked: 'issuer' | 'self'; readonly valid: boolean; readonly issuerSubject?: string };
}

export const INSPECT_CERTIFICATE_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['version', 'serialNumber', 'signatureAlgorithm', 'issuer', 'subject', 'validity', 'subjectPublicKeyInfo', 'extensions', 'selfIssued', 'sizeBytes', 'subjectString', 'issuerString', 'fingerprints', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...CERTIFICATE_VIEW_PROPERTIES,
        subjectString: { type: 'string', description: 'RFC 4514 subject.' },
        issuerString: { type: 'string', description: 'RFC 4514 issuer.' },
        fingerprints: { type: 'object', additionalProperties: { type: 'string' }, description: 'Colon-separated uppercase hex digests of the DER, by algorithm.' },
        extension: { ...EXTENSION_VIEW_SCHEMA, description: 'The one extension asked for with `extension`.' },
        signature: {
            type: 'object',
            additionalProperties: false,
            required: ['checked', 'valid'],
            description: 'The signature check asked for (issuer or self). ONE signature against ONE key — not a trust verdict.',
            properties: { checked: { type: 'string', enum: ['issuer', 'self'] }, valid: { type: 'boolean' }, issuerSubject: { type: 'string' } },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const INSPECT_CERTIFICATE_SUMMARY_PROPERTIES = {
    serialNumberHex: { type: 'string' },
    notBefore: { type: 'string' },
    notAfter: { type: 'string' },
    publicKey: { type: 'string' },
    extensionKinds: { type: 'array', items: { type: 'string' } },
    signatureValid: { type: 'boolean' },
    diagnosticCount: { type: 'integer' },
} as const;

export async function inspectCertificate(rawInput: unknown): Promise<InspectCertificateResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const obj = await loadPkiObject(input.certificate, 'certificate', LABELS.certificate, ctx);
    const cert = guard('Cannot read the certificate', () => parseCertificate(obj.der, { ...ctx.options, decodeExtensions: !input.rawExtensions }));
    const view = certificateView(cert, input.rawExtensions);
    const fingerprints: Record<string, string> = {};
    for (const alg of input.fingerprints) fingerprints[alg] = formatFingerprint(computeFingerprint(cert.der, alg));
    let extension: Record<string, Wire> | undefined;
    if (input.extension !== undefined) {
        const ext = guard('Cannot read the extension', () => getExtension(cert, input.extension as DecodedExtensionKind));
        if (ext === undefined) {
            throw new ToolError('NOT_FOUND', `The certificate has no ${input.extension} extension (present: ${cert.extensions.map((e) => e.kind).join(', ') || 'none'}).`, { extension: input.extension, present: cert.extensions.map((e) => e.kind) });
        }
        extension = extensionView(ext);
    }
    let signature: InspectCertificateResult['signature'];
    if (input.issuer !== undefined) {
        const issuerObj = await loadPkiObject(input.issuer, 'issuer', LABELS.certificate, ctx);
        const issuer = guard('Cannot read the issuer certificate', () => parseCertificate(issuerObj.der, ctx.options));
        const valid = await guardAsync('Cannot verify the signature', () => verifyCertificateSignature(cert, issuer, { requireAlgorithmMatch: input.requireAlgorithmMatch, allowSha1: input.allowSha1 }));
        signature = { checked: 'issuer', valid, issuerSubject: dn(issuer.subject) };
    } else if (input.checkSelfSignature) {
        const valid = await guardAsync('Cannot verify the self-signature', () => verifySelfSignature(cert, { requireAlgorithmMatch: input.requireAlgorithmMatch, allowSha1: input.allowSha1 }));
        signature = { checked: 'self', valid };
    }
    return withDiagnostics({
        ...view,
        subjectString: view.subject.string,
        issuerString: view.issuer.string,
        fingerprints,
        ...(extension !== undefined ? { extension } : {}),
        ...(signature !== undefined ? { signature } : {}),
    }, ctx.sink.report());
}

export function inspectCertificateSummary(r: InspectCertificateResult): Record<string, unknown> {
    return {
        serialNumberHex: r.serialNumber.hex,
        subjectString: r.subjectString,
        issuerString: r.issuerString,
        notBefore: r.validity.notBefore.iso,
        notAfter: r.validity.notAfter.iso,
        publicKey: r.subjectPublicKeyInfo['kind'],
        extensionKinds: r.extensions.map((e) => e['kind']),
        selfIssued: r.selfIssued,
        ...(r.signature !== undefined ? { signatureValid: r.signature.valid } : {}),
        diagnosticCount: diagnosticCount(r),
    };
}

export const INSPECT_CERTIFICATE_TOOL = defineTool<InspectCertificateResult>({
    name: INSPECT_CERTIFICATE_NAME,
    title: 'Inspect certificate (RFC 5280 report, extensions, fingerprints, signature check)',
    kind: 'read',
    description:
        "Read-only RFC 5280 report of ONE certificate in one call: version, serial, signature algorithm, issuer and subject (RFC 4514 + RDNs), validity (epoch ms + ISO), public key (kind, bits, curve / modulus / exponent), every extension decoded (the 19 kinds pkinative knows; rawExtensions:true keeps them undecoded), self-issued flag, fingerprints (SHA-256 by default), and every engine diagnostic. `extension:'subjectAltName'` returns that one extension. `issuer` or `checkSelfSignature:true` adds a signature check — ONE signature against ONE key, which is NOT trust: verify_certificate_chain is the RFC 5280 §6 verdict (anchors, validity at an instant, names, policies, revocation). Token-frugal: verbosity:'summary', fields:[…]. Input: pem / derBase64 / path.",
    inputSchema: INSPECT_CERTIFICATE_INPUT_SCHEMA,
    rawOutputSchema: INSPECT_CERTIFICATE_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(INSPECT_CERTIFICATE_OUTPUT_SCHEMA, INSPECT_CERTIFICATE_SUMMARY_PROPERTIES, `Structured certificate report.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'Facts of a certificate in the sandbox', input: { certificate: { path: 'fixtures/leaf.crt.pem' }, verbosity: 'summary' } },
        { title: 'Signature against the issuer, SAN only', input: { certificate: { path: 'fixtures/leaf.crt.pem' }, issuer: { path: 'fixtures/inter.crt.pem' }, fields: ['signature', 'extensions.kind', 'subjectString'] } },
    ],
    handler: inspectCertificate,
    text: (r) => `${INSPECT_CERTIFICATE_NAME}: ${r.subjectString} (serial ${r.serialNumber.hex}) issued by ${r.issuerString}, valid ${r.validity.notBefore.iso} → ${r.validity.notAfter.iso}, ${r.subjectPublicKeyInfo['kind']} key, ${r.extensions.length} extension(s)${r.signature !== undefined ? `, signature ${r.signature.valid ? 'valid' : 'INVALID'} (${r.signature.checked})` : ''}, ${r.diagnostics.length} diagnostic(s).`,
    summary: inspectCertificateSummary,
});
