/**
 * Tool: open_pkcs12 — the one-call PKCS#12 verdict: MAC checked where it
 * can be (RFC 9579 PBMAC1), every SafeContents decrypted, every key
 * unwrapped by the host straight into a NON-EXTRACTABLE Web Crypto key
 * (described, never exported), every certificate and CRL read. A negative
 * verdict (wrong password, legacy cipher, no MAC, RSA without a scheme) is
 * `valid:false` + `reasons[]`, never isError. `exportCertificates:true`
 * attaches a PEM bundle of the certificates and CRLs — only from a file
 * that opened: nothing unauthenticated is ever exported.
 */
import { encodePem, openPkcs12, type Certificate, type OpenPkcs12Options, type OpenPkcs12Report } from 'pkinative';
import { z } from 'zod';

import { MAX_BASE64_OUTPUT_BYTES } from '../caps.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { SIGNING_KEY_VIEW_SCHEMA, signingKeyView, type SigningKeyView } from '../key-views.js';
import { ARTEFACT_OUTPUT_PROPERTIES, outputInputProperties, outputShape, writeSandboxedText, type OutputResult } from '../output.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { PASSWORD_INPUT_PROPERTY, PasswordSchema, resolvePassword, secretRequired } from '../secrets.js';
import { REASONS_OUTPUT_PROPERTY } from '../trust.js';
import { CERTIFICATE_REF_SCHEMA, certificateRef, reasonsView } from '../views.js';
import { toHex } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, WRITES } from './_definition.js';
import { diagnosticCount, parseInput, ParseShape, ProjectionShape, sha256Hex, withDiagnostics } from './_shared.js';

export const OPEN_PKCS12_NAME = 'open_pkcs12';

const RSA_HASHES = ['SHA-256', 'SHA-384', 'SHA-512'] as const;

export const OPEN_PKCS12_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['pkcs12'],
    properties: {
        pkcs12: pkiInputSchema('The PKCS#12 file (.p12 / .pfx; DER, or BER with encodingRules:\'ber\' for a Windows-written PFX)'),
        ...PASSWORD_INPUT_PROPERTY,
        allowUnverifiedIntegrity: { type: 'boolean', default: false, description: 'Accept a file whose integrity cannot be checked (no MAC, or the legacy RFC 7292 Appendix B MAC) and report it valid — only for a file whose origin you trust: without a MAC any unencrypted bag can be swapped, and a file with nothing encrypted then opens under any password. The report says integrity:\'unverified\' either way.' },
        rsaScheme: { type: 'string', enum: ['pkcs1', 'pss'], description: "What an RSA key will sign with: 'pkcs1' (RSASSA-PKCS1-v1_5) or 'pss' (RSA-PSS). No default: without it an RSA key is not imported and the verdict says PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED. Ignored by keys of every other kind." },
        hash: { type: 'string', enum: [...RSA_HASHES], description: "The hash of the RSA signature algorithm (with rsaScheme only). Default 'SHA-256'." },
        exportCertificates: { type: 'boolean', default: false, description: 'Attach a PEM bundle of the certificates (CERTIFICATE blocks) then the CRLs (X509 CRL blocks) as the `artefact` — only from a file that opened (valid:true); never a key.' },
        ...outputInputProperties('pem', '.pem only — a bundle has no DER form'),
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    pkcs12: PkiInputSchema,
    password: PasswordSchema.optional(),
    allowUnverifiedIntegrity: z.boolean().default(false),
    rsaScheme: z.enum(['pkcs1', 'pss']).optional(),
    hash: z.enum(RSA_HASHES).optional(),
    exportCertificates: z.boolean().default(false),
    ...outputShape('pem'),
    ...ParseShape,
    ...ProjectionShape,
}).superRefine((v, ctx) => {
    if (v.hash !== undefined && v.rsaScheme === undefined) ctx.addIssue({ code: 'custom', message: "hash applies with rsaScheme ('pkcs1' | 'pss') only", path: ['hash'] });
    if (v.encoding !== 'pem') ctx.addIssue({ code: 'custom', message: "the certificate bundle is PEM text: encoding 'der' / 'hex' has no meaning for several blocks", path: ['encoding'] });
    if (!v.exportCertificates && (v.outputMode === 'file' || v.outputPath !== undefined)) ctx.addIssue({ code: 'custom', message: 'outputMode / outputPath apply with exportCertificates:true only', path: ['outputMode'] });
});

export interface Pkcs12KeyView {
    readonly path: string;
    readonly friendlyName: string | null;
    readonly localKeyId: string | null;
    readonly certificate: ReturnType<typeof certificateRef> | null;
    /** The non-extractable handle described; null when the key could not be opened (the reasons say why). */
    readonly signingKey: SigningKeyView | null;
}

export interface OpenPkcs12Result extends DiagnosticsReport {
    readonly valid: boolean;
    readonly integrity: OpenPkcs12Report['integrity'];
    readonly reasons: ReadonlyArray<Record<string, string>>;
    readonly keys: readonly Pkcs12KeyView[];
    readonly certificates: ReadonlyArray<ReturnType<typeof certificateRef>>;
    readonly keyCount: number;
    readonly certificateCount: number;
    readonly crlCount: number;
    /** Present (true) when exportCertificates was asked on a file that did not open: nothing was exported. */
    readonly exportSkipped?: true;
    readonly artefact?: OutputResult;
}

export const OPEN_PKCS12_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['valid', 'integrity', 'reasons', 'keys', 'certificates', 'keyCount', 'certificateCount', 'crlCount', 'diagnostics', 'diagnosticCounts'],
    properties: {
        valid: { type: 'boolean', description: 'Everything opened and the integrity verified (or explicitly waived). false is a negative verdict (reasons[]), never an error.' },
        integrity: { type: 'string', enum: ['verified', 'unverified', 'mismatch'], description: "'verified' for a matching PBMAC1 MAC; 'unverified' when it could not be checked (no MAC, legacy MAC); 'mismatch' for a wrong password or an altered file — nothing was decrypted then." },
        ...REASONS_OUTPUT_PROPERTY,
        keys: {
            type: 'array',
            description: 'Every private key bag, in encoded order: where it was, its names, the certificate sharing its localKeyId, and the non-extractable Web Crypto handle described (never exported).',
            items: {
                type: 'object',
                additionalProperties: false,
                required: ['path', 'friendlyName', 'localKeyId', 'certificate', 'signingKey'],
                properties: {
                    path: { type: 'string' },
                    friendlyName: { type: ['string', 'null'] },
                    localKeyId: { type: ['string', 'null'], description: 'Hex.' },
                    certificate: { ...CERTIFICATE_REF_SCHEMA, type: ['object', 'null'] },
                    signingKey: { ...SIGNING_KEY_VIEW_SCHEMA, type: ['object', 'null'], description: 'The signing key described (algorithm; handle type, algorithm, extractable:false, usages); null when it could not be opened — the reasons say why.' },
                },
            },
        },
        certificates: { type: 'array', items: CERTIFICATE_REF_SCHEMA, description: "Every certificate that parsed, in encoded order — the keys' own and any chain the file carries." },
        keyCount: { type: 'integer' },
        certificateCount: { type: 'integer' },
        crlCount: { type: 'integer' },
        exportSkipped: { type: 'boolean', enum: [true], description: 'exportCertificates was asked but the file did not open (valid:false): nothing was exported.' },
        artefact: {
            type: 'object',
            additionalProperties: false,
            description: 'With exportCertificates:true on a file that opened: the PEM bundle (certificates then CRLs), delivered once as the embedded resource (text) or the resource_link; summary counts the blocks.',
            properties: {
                ...ARTEFACT_OUTPUT_PROPERTIES,
                summary: { type: 'object', additionalProperties: false, required: ['certificates', 'crls'], properties: { certificates: { type: 'integer' }, crls: { type: 'integer' } } },
            },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const OPEN_PKCS12_SUMMARY_PROPERTIES = {
    reasonCodes: { type: 'array', items: { type: 'string' } },
    diagnosticCount: { type: 'integer' },
} as const;

/** Certificates then CRLs, as one RFC 7468 text (the pkinative-cli `pemBundle`). */
export function pemBundle(certificates: readonly Uint8Array[], crls: readonly Uint8Array[]): string {
    return guard('Cannot encode the PEM bundle', () => [...certificates.map((c) => encodePem('CERTIFICATE', c)), ...crls.map((c) => encodePem('X509 CRL', c))].join(''));
}

/**
 * Deliver a multi-block PEM text as an artefact. `emitArtefact` wraps ONE DER
 * value in one PEM block; a bundle is several blocks, so the text is
 * delivered as it stands: base64 of its UTF-8 inline (the server renders a
 * PEM resource as text), or an exclusive `.pem` write in the sandbox.
 */
async function emitPemBundle(text: string, mode: 'base64' | 'file', outputPath: string | undefined, summary: Readonly<Record<string, unknown>>): Promise<OutputResult> {
    const bytes = new TextEncoder().encode(text);
    const base = { encoding: 'pem' as const, sizeBytes: bytes.byteLength, sha256: await sha256Hex(bytes), mimeType: 'application/x-pem-file', summary };
    if (mode === 'file') {
        if (outputPath === undefined) throw new ToolError('MISSING_OUTPUT_PATH', "outputPath is required when outputMode='file'.", { remedy: 'outputPath' });
        const written = await writeSandboxedText(text, outputPath, ['.pem']);
        return { ...base, mode: 'file', filePath: written.filePath };
    }
    if (bytes.byteLength > MAX_BASE64_OUTPUT_BYTES) {
        throw new ToolError('OUTPUT_TOO_LARGE', `The bundle (${bytes.byteLength} bytes) exceeds the ${MAX_BASE64_OUTPUT_BYTES}-byte inline cap — use outputMode:'file' with PKINATIVE_MCP_OUTPUT_DIR set.`, { sizeBytes: bytes.byteLength, cap: MAX_BASE64_OUTPUT_BYTES, remedy: "outputMode:'file'" });
    }
    return { ...base, mode: 'base64', base64: Buffer.from(bytes).toString('base64') };
}

function keyView(k: OpenPkcs12Report['keys'][number]): Pkcs12KeyView {
    return {
        path: k.path,
        friendlyName: k.friendlyName ?? null,
        localKeyId: k.localKeyId !== undefined ? toHex(k.localKeyId) : null,
        certificate: k.certificate !== undefined ? certificateRef(k.certificate) : null,
        signingKey: k.signingKey !== undefined ? signingKeyView(k.signingKey) : null,
    };
}

export async function openPkcs12Tool(rawInput: unknown): Promise<OpenPkcs12Result> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    // The password lives in this frame only: never in a message, in data, in the result or in a log.
    const password = resolvePassword(input.password);
    if (password === undefined) throw secretRequired('A PKCS#12 file');
    const obj = await loadPkiObject(input.pkcs12, 'pkcs12', LABELS.any, ctx);
    const hash = input.hash ?? 'SHA-256';
    const rsaAlgorithm: OpenPkcs12Options['rsaAlgorithm'] = input.rsaScheme === undefined ? undefined
        : input.rsaScheme === 'pkcs1' ? { name: 'RSASSA-PKCS1-v1_5', hash } : { name: 'RSA-PSS', hash };
    // openPkcs12 reports and never throws for the file's sake: parse failures, legacy ciphers, a wrong password are reasons.
    const report = await guardAsync('Cannot open the PKCS#12 file', () => openPkcs12(obj.der, {
        ...ctx.options,
        password,
        allowUnverifiedIntegrity: input.allowUnverifiedIntegrity,
        ...(rsaAlgorithm !== undefined ? { rsaAlgorithm } : {}),
    }));

    let artefact: OutputResult | undefined;
    // Nothing is exported from a file that did not open: neither an unauthenticated certificate nor an empty bundle.
    if (input.exportCertificates && report.valid) {
        const text = pemBundle(report.certificates.map((c: Certificate) => c.der), report.crls);
        artefact = await emitPemBundle(text, input.outputMode, input.outputPath, { certificates: report.certificates.length, crls: report.crls.length });
    }

    return withDiagnostics({
        valid: report.valid,
        integrity: report.integrity,
        reasons: reasonsView(report.reasons),
        keys: report.keys.map(keyView),
        certificates: report.certificates.map(certificateRef),
        keyCount: report.keys.length,
        certificateCount: report.certificates.length,
        crlCount: report.crls.length,
        ...(input.exportCertificates && !report.valid ? { exportSkipped: true as const } : {}),
        ...(artefact !== undefined ? { artefact } : {}),
    }, ctx.sink.report());
}

export function openPkcs12Summary(r: OpenPkcs12Result): Record<string, unknown> {
    return {
        valid: r.valid,
        integrity: r.integrity,
        reasonCodes: r.reasons.map((x) => x['code']),
        keyCount: r.keyCount,
        certificateCount: r.certificateCount,
        crlCount: r.crlCount,
        diagnosticCount: diagnosticCount(r),
    };
}

export function openPkcs12Text(r: OpenPkcs12Result): string {
    if (!r.valid) {
        const codes = [...new Set(r.reasons.map((x) => x['code']))].join(', ');
        return `${OPEN_PKCS12_NAME}: NOT OK — ${codes} (integrity ${r.integrity}; ${r.keys.filter((k) => k.signingKey !== null).length}/${r.keyCount} key(s) imported, ${r.certificateCount} certificate(s))${r.exportSkipped === true ? '; certificates NOT exported: the file did not open' : ''}.`;
    }
    const imported = r.keys.filter((k) => k.signingKey !== null).length;
    const artefact = r.artefact !== undefined ? `; ${r.artefact.summary?.['certificates'] as number} certificate(s) + ${r.artefact.summary?.['crls'] as number} CRL(s) exported as a PEM bundle${r.artefact.mode === 'file' ? ` written to ${r.artefact.filePath ?? ''}` : ' (embedded resource below)'}` : '';
    return `${OPEN_PKCS12_NAME}: OK — integrity ${r.integrity}, ${imported} key(s) imported (non-extractable), ${r.certificateCount} certificate(s), ${r.crlCount} CRL(s)${artefact}; ${r.diagnostics.length} diagnostic(s).`;
}

export const OPEN_PKCS12_TOOL = defineTool<OpenPkcs12Result>({
    name: OPEN_PKCS12_NAME,
    title: 'Open PKCS#12 (MAC, decryption, non-extractable key import, certificates; optional PEM bundle)',
    kind: 'verdict',
    description:
        "Open a PKCS#12 (.p12 / .pfx) in one call with `password` (or PKINATIVE_MCP_PASSWORD; SECRET_REQUIRED without one): the RFC 9579 PBMAC1 MAC is verified, every PBES2 SafeContents decrypted, every key unwrapped by the host straight into a NON-EXTRACTABLE Web Crypto key — described (algorithm, handle type, usages) and never exported — every certificate parsed (compact refs) and every CRL counted. The verdict is valid + integrity ('verified' | 'unverified' | 'mismatch') + reasons[]; a negative verdict is a REPORT, never isError: a wrong password or altered file → integrity 'mismatch' + PKI_REASON_PKCS12_MAC_MISMATCH (nothing decrypted); a legacy RC2 / 3DES file → PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED (convert it once with openssl pkcs12 -legacy then -export -pbmac1_pbkdf2); no MAC or a legacy MAC → PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED unless allowUnverifiedIntegrity:true (trusted origin only); an RSA key without `rsaScheme` ('pkcs1' | 'pss', hash default SHA-256; no default scheme) → PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED with that key's signingKey null. `exportCertificates:true` attaches a PEM bundle of the certificates then the CRLs (PEM only; inline embedded resource or a sandbox .pem file, never overwritten) — only from a file that opened; nothing is exported otherwise, and never a key. No result carries a key byte, a bag value or the password; a call with a password is never cached. Token-frugal: verbosity:'summary' (valid, integrity, reasonCodes, counts).",
    inputSchema: OPEN_PKCS12_INPUT_SCHEMA,
    rawOutputSchema: OPEN_PKCS12_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(OPEN_PKCS12_OUTPUT_SCHEMA, OPEN_PKCS12_SUMMARY_PROPERTIES, `PKCS#12 opening verdict (keys described, never exported).${PROJECTION_NOTE}`),
    annotations: WRITES,
    cacheable: false,
    examples: [
        { title: 'Open a .p12 and export its certificate chain as PEM', input: { pkcs12: { path: 'fixtures/leaf.p12' }, password: 'test-only-password', exportCertificates: true } },
        { title: 'An RSA key signs PKCS#1 v1.5 — summary verdict only', input: { pkcs12: { path: 'fixtures/rsa.p12' }, password: 'test-only-password', rsaScheme: 'pkcs1', verbosity: 'summary' } },
    ],
    handler: openPkcs12Tool,
    text: openPkcs12Text,
    summary: openPkcs12Summary,
});
