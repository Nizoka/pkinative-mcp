/**
 * Tool: create_ocsp_request — the DER OCSPRequest (RFC 6960 §4.1) for one
 * certificate, with the CertID hashed by SHA-1 (the engine default, the
 * one every responder answers) or SHA-256, and an optional nonce (RFC
 * 8954: 1–32 octets, 'random' draws 16 from node:crypto). `certIdOnly`
 * returns the bare CertID instead. The server never sends the request:
 * POST it to the responder named by the certificate's authorityInfoAccess.
 */
import { createOcspRequest, encodeOcspCertId, parseCertificate, type OcspHashAlgorithm } from 'pkinative';
import { z } from 'zod';

import { HexSchema, hexSchema } from '../content-input.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { ARTEFACT_OUTPUT_PROPERTIES, emitArtefact, outputInputProperties, outputShape, type OutputResult } from '../output.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { randomNonceBytes } from '../random.js';
import { dn } from '../views.js';
import { toHex } from '../wire.js';
import { defineTool, PRODUCES } from './_definition.js';
import { MAX_PEM_LABEL_LENGTH, PEM_LABEL_PATTERN, assertProducibleLabel } from './convert-pem.js';
import { parseInput, ParseShape, withDiagnostics } from './_shared.js';
import { nonceBytes } from './verify-certificate-chain.js';

export const CREATE_OCSP_REQUEST_NAME = 'create_ocsp_request';

export const OCSP_HASH_ALGORITHMS = ['SHA-1', 'SHA-256'] as const satisfies readonly OcspHashAlgorithm[];

export const CREATE_OCSP_REQUEST_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['certificate', 'issuer'],
    properties: {
        certificate: pkiInputSchema('The certificate whose status to ask for'),
        issuer: pkiInputSchema('The CA certificate that issued it (its name and key are hashed into the CertID)'),
        hashAlgorithm: { type: 'string', enum: [...OCSP_HASH_ALGORITHMS], default: 'SHA-1', description: "The CertID hash. 'SHA-1' (default — the engine default and what every responder answers; RFC 6960 §4.3) or 'SHA-256' (recommended, RFC 6960 §4.3 / RFC 5019 note: some responders still answer SHA-1 only)." },
        nonce: {
            anyOf: [
                { type: 'string', enum: ['random'], description: '16 random bytes from node:crypto (summary.randomNonce:true).' },
                hexSchema('The nonce bytes (1–32 octets, RFC 8954 §2.1).'),
            ],
            description: "The RFC 8954 nonce extension: 'random', or hex of 1–32 bytes. Omitted: no nonce. Keep summary.nonceHex to match the response (check_ocsp_status nonce).",
        },
        certIdOnly: { type: 'boolean', default: false, description: 'Return the bare DER CertID (RFC 6960 §4.1.1) instead of the request (der or hex only — a CertID has no PEM label).' },
        label: { type: 'string', minLength: 1, maxLength: MAX_PEM_LABEL_LENGTH, pattern: PEM_LABEL_PATTERN, description: "The PEM label for encoding:'pem' (default OCSP REQUEST; upper-case words and digits). A private-key label is refused." },
        ...PARSE_INPUT_PROPERTIES,
        ...outputInputProperties('der', '.orq .der .bin for der'),
    },
} as const;

const InputSchema = z.strictObject({
    certificate: PkiInputSchema,
    issuer: PkiInputSchema,
    hashAlgorithm: z.enum(OCSP_HASH_ALGORITHMS).default('SHA-1'),
    nonce: z.union([z.literal('random'), HexSchema]).optional(),
    certIdOnly: z.boolean().default(false),
    label: z.string().min(1).max(MAX_PEM_LABEL_LENGTH).regex(new RegExp(PEM_LABEL_PATTERN)).optional(),
    ...ParseShape,
    ...outputShape('der'),
});

export interface CreateOcspRequestResult extends OutputResult, DiagnosticsReport {
    readonly summary: {
        readonly certIdHex: string;
        readonly hashAlgorithm: OcspHashAlgorithm;
        readonly nonceHex?: string;
        readonly randomNonce: boolean;
        readonly certIdOnly: boolean;
        readonly serialNumber: string;
        readonly subject: string;
        readonly issuer: string;
        readonly sizeBytes: number;
    };
}

export const CREATE_OCSP_REQUEST_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode', 'encoding', 'sizeBytes', 'sha256', 'summary', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...ARTEFACT_OUTPUT_PROPERTIES,
        summary: {
            type: 'object',
            additionalProperties: false,
            required: ['certIdHex', 'hashAlgorithm', 'randomNonce', 'certIdOnly', 'serialNumber', 'subject', 'issuer', 'sizeBytes'],
            properties: {
                certIdHex: { type: 'string', description: 'The DER CertID (hex) the request carries — match it against the response (inspect_ocsp_response responses[].certId).' },
                hashAlgorithm: { type: 'string', enum: [...OCSP_HASH_ALGORITHMS] },
                nonceHex: { type: 'string', description: 'The nonce bytes used (hex) — pass them as check_ocsp_status nonce.' },
                randomNonce: { type: 'boolean', description: 'true when the nonce came from the wrapper RNG (node:crypto).' },
                certIdOnly: { type: 'boolean' },
                serialNumber: { type: 'string', description: 'Hex.' },
                subject: { type: 'string' },
                issuer: { type: 'string' },
                sizeBytes: { type: 'integer', description: 'Size of the DER artefact.' },
            },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export async function createOcspRequestTool(rawInput: unknown): Promise<CreateOcspRequestResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    if (input.certIdOnly && input.encoding === 'pem') {
        throw new ToolError('VALIDATION_ERROR', "certIdOnly: a bare CertID has no PEM label — use encoding:'der' or 'hex'.", { path: 'encoding', remedy: "encoding:'der'" });
    }
    const certObj = await loadPkiObject(input.certificate, 'certificate', LABELS.certificate, ctx);
    const certificate = guard('Cannot read the certificate', () => parseCertificate(certObj.der, ctx.options));
    const issuerObj = await loadPkiObject(input.issuer, 'issuer', LABELS.certificate, ctx);
    const issuer = guard('Cannot read the issuer certificate', () => parseCertificate(issuerObj.der, ctx.options));
    const random = input.nonce === 'random';
    const nonce = random ? randomNonceBytes(16) : nonceBytes(input.nonce, 'nonce');
    const certId = guard('Cannot encode the CertID', () => encodeOcspCertId(certificate, issuer, input.hashAlgorithm));
    const der = input.certIdOnly
        ? certId
        : guard('Cannot create the OCSP request', () => createOcspRequest(certificate, issuer, { hashAlgorithm: input.hashAlgorithm, ...(nonce !== undefined ? { nonce } : {}) }));
    if (input.label !== undefined) assertProducibleLabel(input.label, 'label');
    const artefact = await emitArtefact(der, {
        mode: input.outputMode,
        encoding: input.encoding,
        outputPath: input.outputPath,
        pemLabel: input.label ?? 'OCSP REQUEST',
        mimeType: 'application/ocsp-request',
        derExtensions: ['.orq', '.der', '.bin'],
    });
    return withDiagnostics({
        ...artefact,
        summary: {
            certIdHex: toHex(certId),
            hashAlgorithm: input.hashAlgorithm,
            ...(nonce !== undefined ? { nonceHex: toHex(nonce) } : {}),
            randomNonce: random,
            certIdOnly: input.certIdOnly,
            serialNumber: certificate.serialNumber.hex,
            subject: dn(certificate.subject),
            issuer: dn(issuer.subject),
            sizeBytes: der.byteLength,
        },
    }, ctx.sink.report());
}

export const CREATE_OCSP_REQUEST_TOOL = defineTool<CreateOcspRequestResult>({
    name: CREATE_OCSP_REQUEST_NAME,
    title: 'Create OCSP request (RFC 6960 DER, SHA-1 or SHA-256 CertID, nonce)',
    kind: 'artefact',
    description:
        "Build the DER OCSPRequest (RFC 6960 §4.1) asking a responder for the status of `certificate`, identified by the CertID computed from `issuer` (the CA that issued it — its name and key hashes) and the serial. `hashAlgorithm` 'SHA-1' (default, the engine default and what every responder answers) or 'SHA-256' (recommended where the responder supports it). `nonce` adds the RFC 8954 nonce extension: 'random' (16 bytes from node:crypto, summary.randomNonce:true) or your own hex (1–32 bytes); keep summary.nonceHex to demand it back with check_ocsp_status. `certIdOnly:true` returns the bare CertID (der / hex). This server never sends anything: POST the bytes yourself (Content-Type application/ocsp-request) to the URL in the certificate's authorityInfoAccess (inspect_certificate), then judge the answer with check_ocsp_status { response, certificate, issuer, nonce }. summary.certIdHex is the CertID to match in the response. Output DER (default, .orq), PEM or hex, inline or as a sandbox file (never overwritten).",
    inputSchema: CREATE_OCSP_REQUEST_INPUT_SCHEMA,
    outputSchema: CREATE_OCSP_REQUEST_OUTPUT_SCHEMA,
    annotations: PRODUCES,
    cacheable: true,
    examples: [
        { title: 'A SHA-256 request with a random nonce (hex inline)', input: { certificate: { path: 'fixtures/leaf.crt.pem' }, issuer: { path: 'fixtures/inter.crt.pem' }, hashAlgorithm: 'SHA-256', nonce: 'random', encoding: 'hex' } },
        { title: 'The default SHA-1 request, written to the sandbox', input: { certificate: { path: 'fixtures/leaf.crt.pem' }, issuer: { path: 'fixtures/inter.crt.pem' }, outputMode: 'file', outputPath: 'ocsp/leaf.orq' } },
    ],
    handler: createOcspRequestTool,
    text: (r) => `${CREATE_OCSP_REQUEST_NAME}: ${r.summary.certIdOnly ? 'CertID' : 'OCSP request'} for serial ${r.summary.serialNumber} (${r.summary.subject}) issued by ${r.summary.issuer}, ${r.summary.hashAlgorithm} CertID${r.summary.nonceHex !== undefined ? `, nonce ${r.summary.nonceHex}${r.summary.randomNonce ? ' (random)' : ''}` : ', no nonce'}, ${r.sizeBytes} bytes DER, sha256 ${r.sha256.slice(0, 16)}…${r.mode === 'file' ? `, written to ${r.filePath ?? ''}` : ` (${r.encoding} delivered as the embedded resource below)`}.`,
});
