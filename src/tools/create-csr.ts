/**
 * Tool: create_csr — a PKCS#10 certification request from a JSON spec
 * (subject + the extensions to request), signed through a non-extractable
 * Web Crypto key. The public key is the signing key's own (derived from a
 * plain PKCS#8 key or taken from the PKCS#12 certificate), or the
 * `subjectPublicKey` input for an encrypted key; the proof of possession is
 * verified before the request is returned (KEY_MISMATCH otherwise).
 */
import { createCertificationRequest, parseCertificationRequest, verifyCertificationRequest } from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { NAME_SPEC_SCHEMA, specError } from '../names.js';
import { ARTEFACT_OUTPUT_PROPERTIES, emitArtefact, outputInputProperties, outputShape, type OutputResult } from '../output.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { ALLOW_SHA1_INPUT_PROPERTY, loadSigner, SIGNER_INPUT_SCHEMA, SignerSchema } from '../signer.js';
import { loadPublicKey, readSpki, type KeyType } from '../spki.js';
import { ALGORITHM_VIEW_SCHEMA, algorithmView, dn } from '../views.js';
import { buildExtensions, EXTENSIONS_SPEC_SCHEMA, isSpec, nameOf, onlyMembers, type Spec } from '../x509-spec.js';
import { defineTool, PRODUCES } from './_definition.js';
import { AllowSha1Shape, parseInput, ParseShape, withDiagnostics } from './_shared.js';

export const CREATE_CSR_NAME = 'create_csr';

/** The extensions a requester may ask for; the issuer-side ones are refused by name. */
const CSR_EXTENSION_KEYS = ['basicConstraints', 'keyUsage', 'extendedKeyUsage', 'subjectAltName', 'subjectKeyIdentifier', 'raw'] as const;
const ISSUER_EXTENSION_KEYS = ['issuerAltName', 'authorityKeyIdentifier'] as const;

const { issuerAltName: _ian, authorityKeyIdentifier: _aki, ...REQUESTABLE } = EXTENSIONS_SPEC_SCHEMA.properties;
void _ian;
void _aki;

export const CSR_SPEC_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['subject'],
    description: 'What to write into the request: the subject and the extensions to ask for. Unknown members are refused.',
    properties: {
        subject: NAME_SPEC_SCHEMA,
        extensions: {
            type: 'object',
            additionalProperties: false,
            description: 'The extensions to request through extensionRequest (RFC 2985 §5.4.2; a CA may ignore them): subjectAltName, keyUsage, extendedKeyUsage, basicConstraints, subjectKeyIdentifier (true = computed from the key, or hex; default omitted) and raw[]. issuerAltName / authorityKeyIdentifier are the issuer\'s to write and are refused.',
            properties: REQUESTABLE,
        },
    },
} as const;

export const CREATE_CSR_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['spec', 'signer'],
    properties: {
        spec: CSR_SPEC_SCHEMA,
        subjectPublicKey: pkiInputSchema('The public key to certify: a certificate, a CSR (CERTIFICATE REQUEST) or a PUBLIC KEY (SPKI)', ' Omitted: derived from a PLAIN signer.key or taken from the PKCS#12 certificate; required for an encrypted PKCS#8 key. It must be the signing key\'s public half (a CSR is a proof of possession).'),
        signer: SIGNER_INPUT_SCHEMA,
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...outputInputProperties('pem', '.pem for pem; .csr .p10 .der for der'),
    },
} as const;

const InputSchema = z.strictObject({
    spec: z.looseObject({ subject: z.unknown() }),
    subjectPublicKey: PkiInputSchema.optional(),
    signer: SignerSchema,
    ...AllowSha1Shape,
    ...ParseShape,
    ...outputShape('pem'),
});

export interface CreateCsrResult extends OutputResult, DiagnosticsReport {
    readonly summary: {
        readonly subject: string;
        readonly signatureAlgorithm: ReturnType<typeof algorithmView>;
        readonly extensions: readonly string[];
        readonly signatureVerified: true;
        readonly publicKeyFrom: 'certificate' | 'csr' | 'spki' | 'signer' | 'pkcs12';
    };
}

export const CREATE_CSR_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode', 'encoding', 'sizeBytes', 'sha256', 'summary', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...ARTEFACT_OUTPUT_PROPERTIES,
        summary: {
            type: 'object',
            additionalProperties: false,
            required: ['subject', 'signatureAlgorithm', 'extensions', 'signatureVerified', 'publicKeyFrom'],
            properties: {
                subject: { type: 'string', description: 'RFC 4514 subject.' },
                signatureAlgorithm: ALGORITHM_VIEW_SCHEMA,
                extensions: { type: 'array', items: { type: 'string' }, description: 'The kinds requested.' },
                signatureVerified: { type: 'boolean', enum: [true], description: 'The proof of possession was verified before the request was returned (always true: a mismatch is KEY_MISMATCH).' },
                publicKeyFrom: { type: 'string', enum: ['certificate', 'csr', 'spki', 'signer', 'pkcs12'] },
            },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export async function createCsr(rawInput: unknown): Promise<CreateCsrResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const spec = input.spec as Spec;
    if (!isSpec(spec)) throw new ToolError('VALIDATION_ERROR', 'spec: expected an object', { path: 'spec' });
    onlyMembers(spec, ['subject', 'extensions'], '');
    const subject = nameOf(spec, 'subject');
    if (subject === undefined) throw new ToolError('VALIDATION_ERROR', 'spec.subject is required', { path: 'spec.subject' });
    const ext = spec['extensions'];
    if (ext !== undefined) {
        if (!isSpec(ext)) throw specError('extensions', 'expected an object');
        for (const key of Object.keys(ext)) {
            if ((ISSUER_EXTENSION_KEYS as readonly string[]).includes(key)) throw specError(`extensions.${key}`, 'is written by the issuer, not requested (create_certificate adds it)');
            if (!(CSR_EXTENSION_KEYS as readonly string[]).includes(key)) throw specError(`extensions.${key}`, `unknown extension (${CSR_EXTENSION_KEYS.join(', ')})`);
        }
    }

    let hint: KeyType | undefined;
    let publicKey: { spki: Uint8Array; bits: Uint8Array; from: CreateCsrResult['summary']['publicKeyFrom'] } | undefined;
    if (input.subjectPublicKey !== undefined) {
        const pk = await loadPublicKey(input.subjectPublicKey, 'subjectPublicKey', ctx);
        publicKey = { spki: pk.spki, bits: pk.bits, from: pk.from };
        hint = pk.type;
    }
    const loaded = await loadSigner(input.signer, input.allowSha1, hint, ctx);
    if (publicKey === undefined) {
        if (loaded.publicKey === undefined) {
            throw new ToolError('VALIDATION_ERROR', 'The public key cannot be derived from an encrypted key: pass subjectPublicKey (a certificate, a CSR or a PUBLIC KEY).', { path: 'subjectPublicKey', remedy: 'subjectPublicKey' });
        }
        publicKey = { spki: loaded.publicKey, bits: readSpki(loaded.publicKey, ctx).bits, from: loaded.certificate !== undefined ? 'pkcs12' : 'signer' };
    }

    const extensions = buildExtensions(ext, { subjectKeyBits: publicKey.bits, issuerKeyId: undefined, defaults: { ski: false, aki: false } });
    const spki = publicKey.spki;
    const der = await guardAsync('Cannot create the request', () => createCertificationRequest(
        { subject, subjectPublicKey: spki, extensions },
        loaded.signer,
        ctx.options.limits !== undefined ? { limits: ctx.options.limits } : {},
    ));

    // A request signed by a key that is not the one it names verifies nowhere: refuse it before it is written.
    const check = await guardAsync('Cannot verify the new request', () => verifyCertificationRequest(der, { ...ctx.options, allowSha1: input.allowSha1 }));
    if (!check.valid) {
        throw new ToolError('KEY_MISMATCH', 'The signing key does not belong to the subject public key: the request does not verify (a CSR is a proof of possession).', { remedy: 'signer', reasons: check.reasons.map((r) => r.code) });
    }
    const csr = check.request ?? guard('Cannot read the request just created', () => parseCertificationRequest(der, ctx.options));

    const artefact = await emitArtefact(der, {
        mode: input.outputMode,
        encoding: input.encoding,
        outputPath: input.outputPath,
        pemLabel: 'CERTIFICATE REQUEST',
        mimeType: 'application/pkcs10',
        derExtensions: ['.csr', '.p10', '.der'],
    });
    return withDiagnostics({
        ...artefact,
        summary: {
            subject: dn(csr.subject),
            signatureAlgorithm: algorithmView(csr.signatureAlgorithm),
            extensions: (csr.extensions ?? []).map((e) => e.kind),
            signatureVerified: true,
            publicKeyFrom: publicKey.from,
        },
    }, ctx.sink.report());
}

export const CREATE_CSR_TOOL = defineTool<CreateCsrResult>({
    name: CREATE_CSR_NAME,
    title: 'Create CSR (PKCS#10 request from a JSON spec, Web Crypto signed)',
    kind: 'artefact',
    description:
        "Build a PKCS#10 certification request (RFC 2986) from `spec` (subject; the extensions to request — subjectAltName, keyUsage, extendedKeyUsage, basicConstraints, subjectKeyIdentifier, raw — carried in extensionRequest; issuerAltName / authorityKeyIdentifier are refused as the issuer's), signed through `signer` (a PKCS#8 key or a PKCS#12 file imported as a NON-EXTRACTABLE Web Crypto key; nothing generates or exports a key here). The public key certified is the signing key's own: derived from a plain signer.key, taken from the PKCS#12 certificate, or given as `subjectPublicKey` (a certificate, a CSR or a PUBLIC KEY — required for an encrypted PKCS#8 key, whose type then comes from it). The proof of possession is verified BEFORE the request is returned: KEY_MISMATCH when the key and the public key differ. RSA keys need signer.rsaScheme; an encrypted key needs signer.password (or PKINATIVE_MCP_PASSWORD); SHA-1 needs allowSha1:true. ECDSA / RSA-PSS signatures are randomised (PRODUCES). Output PEM (default), DER or hex, inline or as a sandbox file (never overwritten). inspect_csr reads it back; create_certificate issues from it (subjectPublicKey = the request).",
    inputSchema: CREATE_CSR_INPUT_SCHEMA,
    outputSchema: CREATE_CSR_OUTPUT_SCHEMA,
    annotations: PRODUCES,
    cacheable: false,
    examples: [
        { title: 'A TLS server request from a plain EC key', input: { spec: { subject: { C: 'FR', O: 'Acme', CN: 'svc.example.test' }, extensions: { subjectAltName: { dns: ['svc.example.test', 'www.svc.example.test'] }, keyUsage: ['digitalSignature'], extendedKeyUsage: ['serverAuth'] } }, signer: { key: { path: 'fixtures/leaf.key.pem' } } } },
        { title: 'From an encrypted key, public key given, written as DER', input: { spec: { subject: { CN: 'svc.example.test' } }, subjectPublicKey: { path: 'fixtures/leaf.pub.pem' }, signer: { key: { path: 'fixtures/leaf.key.enc.pem' }, password: 'test-only-password' }, encoding: 'der', outputMode: 'file', outputPath: 'requests/svc.csr' } },
    ],
    handler: createCsr,
    text: (r) => `${CREATE_CSR_NAME}: request for ${r.summary.subject} (${r.summary.signatureAlgorithm.name ?? r.summary.signatureAlgorithm.oid}, ${r.summary.extensions.length} extension(s) requested, key from ${r.summary.publicKeyFrom}), ${r.sizeBytes} bytes DER, sha256 ${r.sha256.slice(0, 16)}…, proof of possession verified${r.mode === 'file' ? `, written to ${r.filePath ?? ''}` : ` (${r.encoding} delivered as the embedded resource below)`}.`,
});
