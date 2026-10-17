/**
 * Tool: create_certificate — issue an X.509 certificate from a JSON spec,
 * signed through a non-extractable Web Crypto key (a PKCS#8 key or a
 * PKCS#12 file the caller brings; nothing generates a key here). The
 * subject public key comes from a certificate, a CSR or a PUBLIC KEY input,
 * or is derived from a plain signing key for a self-signed certificate. The
 * result is verified against the issuer (or itself) before it is returned.
 */
import { computeKeyIdentifier, createCertificate, getExtension, parseCertificate, verifyCertificateSignature, verifySelfSignature, type Certificate } from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { NAME_SPEC_SCHEMA } from '../names.js';
import { ARTEFACT_OUTPUT_PROPERTIES, emitArtefact, outputInputProperties, outputShape, type OutputResult } from '../output.js';
import { createParseContext, PARSE_INPUT_PROPERTIES, type ParseContext } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { ALLOW_SHA1_INPUT_PROPERTY, loadSigner, SIGNER_INPUT_SCHEMA, SignerSchema } from '../signer.js';
import { keyTypeOfSpki, loadPublicKey, readSpki, type KeyType } from '../spki.js';
import { formatInstant } from '../time.js';
import { algorithmView, dn } from '../views.js';
import { buildExtensions, EXTENSIONS_SPEC_SCHEMA, isSpec, nameOf, onlyMembers, serialNumber, validity, type Spec } from '../x509-spec.js';
import { toHex } from '../wire.js';
import { defineTool, PRODUCES } from './_definition.js';
import { AllowSha1Shape, parseInput, ParseShape, withDiagnostics } from './_shared.js';

export const CREATE_CERTIFICATE_NAME = 'create_certificate';

const SPEC_MEMBERS = ['serialNumber', 'subject', 'issuer', 'notBefore', 'notAfter', 'validityDays', 'extensions'];

export const CERTIFICATE_SPEC_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['subject'],
    description: 'What to write into the certificate. Unknown members are refused.',
    properties: {
        serialNumber: { anyOf: [{ type: 'string' }, { type: 'integer', minimum: 1 }], default: 'random', description: "'random' (default: 127 bits from node:crypto — the engine has no RNG; summary.randomSerial reports it), a positive decimal or 0x-hex string, or an integer." },
        subject: NAME_SPEC_SCHEMA,
        issuer: { ...NAME_SPEC_SCHEMA, description: 'The issuer name — only without issuerCertificate (the issuer certificate\'s subject is used then). A certificate whose issuer is named but not given cannot be verified after signing (summary.signatureVerified false).' },
        notBefore: { type: 'string', description: 'ISO 8601 instant or epoch ms (whole seconds). Default: PKINATIVE_MCP_AT, else now — pin it for reproducible bytes.' },
        notAfter: { type: 'string', description: 'ISO 8601 instant or epoch ms. Exclusive with validityDays.' },
        validityDays: { type: 'integer', minimum: 1, default: 365, description: 'Validity in days from notBefore. Exclusive with notAfter.' },
        extensions: { ...EXTENSIONS_SPEC_SCHEMA, description: `${EXTENSIONS_SPEC_SCHEMA.description} Defaults here: subjectKeyIdentifier computed; authorityKeyIdentifier computed from the issuer certificate's subjectKeyIdentifier (or its key) when one is given.` },
    },
} as const;

export const CREATE_CERTIFICATE_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['spec', 'signer'],
    properties: {
        spec: CERTIFICATE_SPEC_SCHEMA,
        issuerCertificate: pkiInputSchema('The issuing CA certificate', ' Omitted: the certificate is self-signed (issuer = subject, the signing key must be the subject\'s).'),
        subjectPublicKey: pkiInputSchema('The subject public key: a certificate, a CSR (CERTIFICATE REQUEST) or a PUBLIC KEY (SPKI)', ' Omitted: derived from a PLAIN signer.key (self-signed only).'),
        signer: SIGNER_INPUT_SCHEMA,
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...outputInputProperties('pem', '.pem for pem; .crt .cer .der for der'),
    },
} as const;

const InputSchema = z.strictObject({
    spec: z.looseObject({ subject: z.unknown() }),
    issuerCertificate: PkiInputSchema.optional(),
    subjectPublicKey: PkiInputSchema.optional(),
    signer: SignerSchema,
    ...AllowSha1Shape,
    ...ParseShape,
    ...outputShape('pem'),
});

export interface CreateCertificateResult extends OutputResult, DiagnosticsReport {
    readonly summary: {
        readonly serialNumber: string;
        readonly randomSerial: boolean;
        readonly subject: string;
        readonly issuer: string;
        readonly selfSigned: boolean;
        readonly signatureAlgorithm: ReturnType<typeof algorithmView>;
        readonly notBefore: string;
        readonly notAfter: string;
        readonly notBeforeSource: 'input' | 'pinned' | 'clock';
        readonly extensions: readonly string[];
        readonly signatureVerified: boolean;
        readonly publicKeyFrom: 'certificate' | 'csr' | 'spki' | 'signer' | 'pkcs12';
    };
}

export const CREATE_CERTIFICATE_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode', 'encoding', 'sizeBytes', 'sha256', 'summary', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...ARTEFACT_OUTPUT_PROPERTIES,
        summary: {
            type: 'object',
            additionalProperties: false,
            required: ['serialNumber', 'randomSerial', 'subject', 'issuer', 'selfSigned', 'signatureAlgorithm', 'notBefore', 'notAfter', 'notBeforeSource', 'extensions', 'signatureVerified', 'publicKeyFrom'],
            properties: {
                serialNumber: { type: 'string', description: 'Hex.' },
                randomSerial: { type: 'boolean', description: 'true when the serial came from the wrapper RNG (node:crypto).' },
                subject: { type: 'string' },
                issuer: { type: 'string' },
                selfSigned: { type: 'boolean' },
                signatureAlgorithm: { type: 'object', additionalProperties: false, properties: { oid: { type: 'string' }, name: { type: ['string', 'null'] }, hasParameters: { type: 'boolean' } } },
                notBefore: { type: 'string' },
                notAfter: { type: 'string' },
                notBeforeSource: { type: 'string', enum: ['input', 'pinned', 'clock'] },
                extensions: { type: 'array', items: { type: 'string' } },
                signatureVerified: { type: 'boolean', description: 'The new certificate was verified against the issuer (or itself) before it was returned. false only when the issuer is named in the spec but not given.' },
                publicKeyFrom: { type: 'string', enum: ['certificate', 'csr', 'spki', 'signer', 'pkcs12'] },
            },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

function issuerKeyId(issuer: Certificate, ctx: ParseContext): Uint8Array {
    const ski = guard('Cannot read the issuer key identifier', () => getExtension(issuer, 'subjectKeyIdentifier'));
    if (ski !== undefined) return ski.keyIdentifier;
    return computeKeyIdentifier(readSpki(issuer.subjectPublicKeyInfo.der, ctx).bits);
}

export async function createCertificateTool(rawInput: unknown): Promise<CreateCertificateResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const spec = input.spec as Spec;
    if (!isSpec(spec)) throw new ToolError('VALIDATION_ERROR', 'spec: expected an object', { path: 'spec' });
    onlyMembers(spec, SPEC_MEMBERS, '');
    const subject = nameOf(spec, 'subject');
    if (subject === undefined) throw new ToolError('VALIDATION_ERROR', 'spec.subject is required', { path: 'spec.subject' });
    const issuerName = nameOf(spec, 'issuer');

    let issuer: Certificate | undefined;
    if (input.issuerCertificate !== undefined) {
        if (issuerName !== undefined) throw new ToolError('VALIDATION_ERROR', 'spec.issuer and issuerCertificate are exclusive: the issuer certificate names the issuer.', { path: 'spec.issuer' });
        const obj = await loadPkiObject(input.issuerCertificate, 'issuerCertificate', LABELS.certificate, ctx);
        issuer = guard('Cannot read the issuer certificate', () => parseCertificate(obj.der, ctx.options));
    }

    // The signing key's type: the issuer's key, else the subject's own key for a self-signed certificate.
    let hint: KeyType | undefined = issuer !== undefined ? keyTypeOfSpki(issuer.subjectPublicKeyInfo.der, ctx) : undefined;
    let publicKey: { spki: Uint8Array; bits: Uint8Array; from: CreateCertificateResult['summary']['publicKeyFrom'] } | undefined;
    if (input.subjectPublicKey !== undefined) {
        const pk = await loadPublicKey(input.subjectPublicKey, 'subjectPublicKey', ctx);
        publicKey = { spki: pk.spki, bits: pk.bits, from: pk.from };
        if (issuer === undefined && issuerName === undefined && hint === undefined) hint = pk.type;
    }
    const loaded = await loadSigner(input.signer, input.allowSha1, hint, ctx);
    if (publicKey === undefined) {
        if (issuer !== undefined || issuerName !== undefined) {
            throw new ToolError('VALIDATION_ERROR', 'subjectPublicKey is required when the certificate is not self-signed (a certificate, a CSR or a PUBLIC KEY).', { path: 'subjectPublicKey', remedy: 'subjectPublicKey' });
        }
        if (loaded.publicKey === undefined) {
            throw new ToolError('VALIDATION_ERROR', 'The subject public key cannot be derived from an encrypted key: pass subjectPublicKey (a certificate, a CSR or a PUBLIC KEY).', { path: 'subjectPublicKey', remedy: 'subjectPublicKey' });
        }
        publicKey = { spki: loaded.publicKey, bits: readSpki(loaded.publicKey, ctx).bits, from: loaded.certificate !== undefined ? 'pkcs12' : 'signer' };
    }

    const { serial, random } = serialNumber(spec['serialNumber']);
    const window = validity(spec);
    const selfSigned = issuer === undefined && issuerName === undefined;
    const extensions = buildExtensions(spec['extensions'], {
        subjectKeyBits: publicKey.bits,
        issuerKeyId: issuer !== undefined ? issuerKeyId(issuer, ctx) : selfSigned ? computeKeyIdentifier(publicKey.bits) : undefined,
        defaults: { ski: true, aki: issuer !== undefined },
    });
    const der = await guardAsync('Cannot create the certificate', () => createCertificate({
        serialNumber: serial,
        subject,
        ...(issuer !== undefined ? { issuerDer: issuer.subject.der } : issuerName !== undefined ? { issuer: issuerName } : {}),
        notBefore: window.notBefore,
        notAfter: window.notAfter,
        subjectPublicKey: publicKey.spki,
        extensions,
    }, loaded.signer, ctx.options.limits !== undefined ? { limits: ctx.options.limits } : {}));

    const cert = guard('Cannot read the certificate just created', () => parseCertificate(der, ctx.options));
    let signatureVerified = false;
    if (issuer !== undefined) {
        signatureVerified = await guardAsync('Cannot verify the new certificate', () => verifyCertificateSignature(cert, issuer, { allowSha1: input.allowSha1 }));
        if (!signatureVerified) throw new ToolError('KEY_MISMATCH', 'The signing key does not belong to issuerCertificate: the new certificate does not verify against it.', { remedy: 'signer' });
    } else if (selfSigned) {
        signatureVerified = await guardAsync('Cannot verify the new certificate', () => verifySelfSignature(cert, { allowSha1: input.allowSha1 }));
        if (!signatureVerified) throw new ToolError('KEY_MISMATCH', 'The signing key does not belong to the subject public key: the self-signed certificate does not verify.', { remedy: 'signer' });
    }

    const artefact = await emitArtefact(der, {
        mode: input.outputMode,
        encoding: input.encoding,
        outputPath: input.outputPath,
        pemLabel: 'CERTIFICATE',
        mimeType: 'application/pkix-cert',
        derExtensions: ['.crt', '.cer', '.der'],
    });
    return withDiagnostics({
        ...artefact,
        summary: {
            serialNumber: toHex(cert.serialNumber.bytes),
            randomSerial: random,
            subject: dn(cert.subject),
            issuer: dn(cert.issuer),
            selfSigned,
            signatureAlgorithm: algorithmView(cert.signatureAlgorithm),
            notBefore: formatInstant(window.notBefore),
            notAfter: formatInstant(window.notAfter),
            notBeforeSource: window.notBeforeSource,
            extensions: cert.extensions.map((e) => e.kind),
            signatureVerified,
            publicKeyFrom: publicKey.from,
        },
    }, ctx.sink.report());
}

export const CREATE_CERTIFICATE_TOOL = defineTool<CreateCertificateResult>({
    name: CREATE_CERTIFICATE_NAME,
    title: 'Create certificate (CA or leaf, from a JSON spec, Web Crypto signed)',
    kind: 'artefact',
    description:
        "Issue an X.509 v3 certificate from `spec` (subject, validity, extensions — basicConstraints, keyUsage, extendedKeyUsage, subjectAltName, issuerAltName, SKI / AKI, raw), signed through `signer` (a PKCS#8 key or a PKCS#12 file, imported as a NON-EXTRACTABLE Web Crypto key — nothing generates or exports a key here). Self-signed when no `issuerCertificate` is given (the subject key is derived from a plain signer.key, or taken from `subjectPublicKey`); issued when `issuerCertificate` is given (`subjectPublicKey` = a certificate, a CSR or a PUBLIC KEY is then required; the AKI is computed from the issuer). Serial 'random' by default (node:crypto, reported as summary.randomSerial), notBefore defaults to PKINATIVE_MCP_AT or now (whole seconds) — pin both for reproducible bytes. The new certificate is verified against the issuer (or itself) BEFORE it is returned (KEY_MISMATCH otherwise). RSA keys need signer.rsaScheme; SHA-1 needs allowSha1:true. Output PEM (default), DER or hex, inline or as a sandbox file (never overwritten).",
    inputSchema: CREATE_CERTIFICATE_INPUT_SCHEMA,
    outputSchema: CREATE_CERTIFICATE_OUTPUT_SCHEMA,
    annotations: PRODUCES,
    cacheable: false,
    instantInputs: ['spec.notBefore'],
    examples: [
        { title: 'A self-signed CA (serial pinned, dates pinned)', input: { spec: { serialNumber: 1, subject: { C: 'FR', O: 'Acme', CN: 'Acme Test CA' }, notBefore: '2027-01-01T00:00:00Z', validityDays: 3650, extensions: { basicConstraints: { ca: true, pathLen: 0 }, keyUsage: ['keyCertSign', 'cRLSign'] } }, signer: { key: { path: 'fixtures/ed25519.key.pem' } } } },
        { title: 'A leaf issued from a CSR by the test intermediate (PKCS#12 signer)', input: { spec: { subject: { CN: 'svc.example.test' }, notBefore: '2027-01-01T00:00:00Z', validityDays: 90, extensions: { subjectAltName: { dns: ['svc.example.test'] }, extendedKeyUsage: ['serverAuth'], keyUsage: ['digitalSignature'] } }, issuerCertificate: { path: 'fixtures/leaf.crt.pem' }, subjectPublicKey: { path: 'fixtures/leaf.csr.pem' }, signer: { p12: { path: 'fixtures/leaf.p12' }, password: 'test-only-password' }, outputMode: 'file', outputPath: 'issued/svc.crt.pem' } },
    ],
    handler: createCertificateTool,
    text: (r) => `${CREATE_CERTIFICATE_NAME}: ${r.summary.selfSigned ? 'self-signed' : 'issued'} ${r.summary.subject} (serial ${r.summary.serialNumber}${r.summary.randomSerial ? ', random' : ''}) by ${r.summary.issuer}, ${r.summary.notBefore} → ${r.summary.notAfter}, ${r.sizeBytes} bytes DER, sha256 ${r.sha256.slice(0, 16)}…, signature ${r.summary.signatureVerified ? 'verified' : 'NOT verified'}${r.mode === 'file' ? `, written to ${r.filePath ?? ''}` : ` (${r.encoding} delivered as the embedded resource below)`}.`,
});
