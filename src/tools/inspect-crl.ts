/**
 * Tool: inspect_crl — the RFC 5280 §5 report of one certificate revocation
 * list (issuer, this / next update, CRL number, delta indicator, issuing
 * distribution point, entry count, extensions), one entry on demand (by
 * serial or by certificate — the entries are walked, never all decoded)
 * and an optional signature check against the issuer. A valid signature
 * is one key, not trust; check_crl_revocation is the revocation verdict.
 */
import { findRevocation, parseCertificate, parseCertificateList, verifyCrlSignature, type CertificateList, type RevokedCertificate } from 'pkinative';
import { z } from 'zod';

import { HexSchema, hexSchema } from '../content-input.js';
import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { createParseContext, PARSE_INPUT_PROPERTIES, type ParseContext } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema, type PkiObject } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { ALLOW_SHA1_INPUT_PROPERTY } from '../signer.js';
import { formatInstant } from '../time.js';
import { ALGORITHM_VIEW_SCHEMA, algorithmView, dn, EXTENSION_VIEW_SCHEMA, extensionView, NAME_VIEW_SCHEMA, nameView, stripRaw, TIME_VIEW_SCHEMA, timeView } from '../views.js';
import { fromHex, toHex, type Wire } from '../wire.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { AllowSha1Shape, diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';

export const INSPECT_CRL_NAME = 'inspect_crl';

export const INSPECT_CRL_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['crl'],
    properties: {
        crl: pkiInputSchema('The CRL (X509 CRL PEM or DER)'),
        find: {
            type: 'object',
            additionalProperties: false,
            description: 'Look one serial up in the list (the entries are walked, never all decoded): exactly one of serialHex / certificate.',
            properties: {
                serialHex: hexSchema('The serial number to look up.'),
                certificate: pkiInputSchema('The certificate whose serial (and issuer) to look up'),
            },
        },
        issuer: pkiInputSchema('The CRL issuer certificate to check the signature against', ' A valid signature is NOT trust: check_crl_revocation / verify_certificate_chain judge revocation.'),
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    crl: PkiInputSchema,
    find: z.strictObject({
        serialHex: HexSchema.optional(),
        certificate: PkiInputSchema.optional(),
    }).superRefine((v, ctx) => {
        if ((v.serialHex === undefined) === (v.certificate === undefined)) ctx.addIssue({ code: 'custom', message: 'pass exactly one of serialHex / certificate', path: ['serialHex'] });
    }).optional(),
    issuer: PkiInputSchema.optional(),
    ...AllowSha1Shape,
    ...ParseShape,
    ...ProjectionShape,
});

export interface CrlView {
    readonly version: number;
    readonly issuer: ReturnType<typeof nameView>;
    readonly issuerString: string;
    readonly signatureAlgorithm: ReturnType<typeof algorithmView>;
    readonly thisUpdate: ReturnType<typeof timeView>;
    readonly nextUpdate: ReturnType<typeof timeView> | null;
    readonly crlNumber: string | null;
    readonly isDelta: boolean;
    readonly baseCrlNumber: string | null;
    readonly issuingDistributionPoint: Wire | null;
    readonly entryCount: number;
    readonly extensions: ReadonlyArray<Record<string, Wire>>;
    readonly sizeBytes: number;
}

export interface CrlEntryView {
    readonly revoked: boolean;
    readonly serialNumber: string;
    readonly revocationDate?: ReturnType<typeof timeView>;
    readonly reason?: string | null;
    readonly invalidityDate?: string | null;
    readonly extensions?: ReadonlyArray<Record<string, Wire>>;
}

export interface InspectCrlResult extends CrlView, DiagnosticsReport {
    readonly entry?: CrlEntryView;
    readonly signature?: { readonly valid: boolean; readonly issuerSubject: string };
}

export const CRL_VIEW_PROPERTIES = {
    version: { type: 'integer', enum: [1, 2] },
    issuer: NAME_VIEW_SCHEMA,
    issuerString: { type: 'string', description: 'RFC 4514 issuer.' },
    signatureAlgorithm: ALGORITHM_VIEW_SCHEMA,
    thisUpdate: TIME_VIEW_SCHEMA,
    nextUpdate: { ...TIME_VIEW_SCHEMA, type: ['object', 'null'] },
    crlNumber: { type: ['string', 'null'], description: 'Decimal (RFC 5280 §5.2.3); null when absent.' },
    isDelta: { type: 'boolean', description: 'Carries a deltaCRLIndicator (RFC 5280 §5.2.4).' },
    baseCrlNumber: { type: ['string', 'null'], description: 'The base CRL number a delta applies to (decimal); null otherwise.' },
    issuingDistributionPoint: { type: ['object', 'null'], additionalProperties: true, description: 'RFC 5280 §5.2.5, decoded (fullName, onlyContainsUserCerts, onlyContainsCACerts, onlySomeReasons, indirectCRL, onlyContainsAttributeCerts); null when absent = the list covers everything its CA issued.' },
    entryCount: { type: 'integer', description: 'Entries in revokedCertificates (counted by walking, bounded by limits.maxRevokedCertificates).' },
    extensions: { type: 'array', items: EXTENSION_VIEW_SCHEMA },
    sizeBytes: { type: 'integer' },
} as const;

export const INSPECT_CRL_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['version', 'issuer', 'issuerString', 'signatureAlgorithm', 'thisUpdate', 'nextUpdate', 'crlNumber', 'isDelta', 'baseCrlNumber', 'issuingDistributionPoint', 'entryCount', 'extensions', 'sizeBytes', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...CRL_VIEW_PROPERTIES,
        entry: {
            type: 'object',
            additionalProperties: false,
            required: ['revoked', 'serialNumber'],
            description: 'The lookup asked for with `find`: whether the serial is listed, and the entry when it is.',
            properties: {
                revoked: { type: 'boolean' },
                serialNumber: { type: 'string', description: 'Hex.' },
                revocationDate: TIME_VIEW_SCHEMA,
                reason: { type: ['string', 'null'], description: 'CRLReason (RFC 5280 §5.3.1); null when the entry has none.' },
                invalidityDate: { type: ['string', 'null'], description: 'ISO instant (RFC 5280 §5.3.2); null when absent.' },
                extensions: { type: 'array', items: EXTENSION_VIEW_SCHEMA },
            },
        },
        signature: {
            type: 'object',
            additionalProperties: false,
            required: ['valid', 'issuerSubject'],
            description: 'The signature check asked for with `issuer`. ONE signature against ONE key — not a trust verdict.',
            properties: { valid: { type: 'boolean' }, issuerSubject: { type: 'string' } },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const INSPECT_CRL_SUMMARY_PROPERTIES = {
    thisUpdateIso: { type: 'string' },
    nextUpdateIso: { type: ['string', 'null'] },
    revoked: { type: 'boolean' },
    signatureValid: { type: 'boolean' },
    diagnosticCount: { type: 'integer' },
} as const;

export function crlView(list: CertificateList): CrlView {
    return {
        version: list.version,
        issuer: nameView(list.issuer),
        issuerString: dn(list.issuer),
        signatureAlgorithm: algorithmView(list.signatureAlgorithm),
        thisUpdate: timeView(list.thisUpdate),
        nextUpdate: list.nextUpdate === undefined ? null : timeView(list.nextUpdate),
        crlNumber: list.crlNumber === undefined ? null : list.crlNumber.toString(10),
        isDelta: list.isDelta,
        baseCrlNumber: list.baseCrlNumber === undefined ? null : list.baseCrlNumber.toString(10),
        issuingDistributionPoint: list.issuingDistributionPoint === undefined ? null : stripRaw(list.issuingDistributionPoint),
        entryCount: list.entryCount,
        extensions: list.extensions.map((e) => extensionView(e)),
        sizeBytes: list.der.length,
    };
}

export function crlEntryView(serial: Uint8Array, entry: RevokedCertificate | undefined): CrlEntryView {
    if (entry === undefined) return { revoked: false, serialNumber: toHex(serial) };
    return {
        revoked: true,
        serialNumber: entry.serialNumber.hex,
        revocationDate: timeView(entry.revocationDate),
        reason: entry.reason ?? null,
        invalidityDate: entry.invalidityDate === undefined ? null : formatInstant(entry.invalidityDate),
        extensions: entry.extensions.map((e) => extensionView(e)),
    };
}

/** Load and parse one CRL input through the sink. */
export async function loadCrl(input: z.infer<typeof PkiInputSchema>, what: string, label: string, ctx: ParseContext): Promise<{ obj: PkiObject; crl: CertificateList }> {
    const obj = await loadPkiObject(input, what, LABELS.crl, ctx);
    return { obj, crl: guard(`Cannot read the ${label}`, () => parseCertificateList(obj.der, ctx.options)) };
}

export async function inspectCrl(rawInput: unknown): Promise<InspectCrlResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const { obj, crl } = await loadCrl(input.crl, 'crl', 'CRL', ctx);
    let entry: CrlEntryView | undefined;
    if (input.find !== undefined) {
        let serial: Uint8Array;
        let issuerDer: Uint8Array | undefined;
        if (input.find.certificate !== undefined) {
            const certObj = await loadPkiObject(input.find.certificate, 'find.certificate', LABELS.certificate, ctx);
            const cert = guard('Cannot read the certificate to look up', () => parseCertificate(certObj.der, ctx.options));
            serial = cert.serialNumber.bytes;
            issuerDer = cert.issuer.der;
        } else {
            const bytes = fromHex(input.find.serialHex as string);
            if (bytes === undefined || bytes.length === 0) throw new ToolError('VALIDATION_ERROR', 'find.serialHex: expected at least one byte of hex.', { path: 'find.serialHex' });
            serial = bytes;
        }
        const found = guard('Cannot search the CRL', () => findRevocation(obj.der, serial, { ...ctx.options, ...(issuerDer !== undefined ? { issuerDer } : {}) }));
        entry = crlEntryView(serial, found);
    }
    let signature: InspectCrlResult['signature'];
    if (input.issuer !== undefined) {
        const issuerObj = await loadPkiObject(input.issuer, 'issuer', LABELS.certificate, ctx);
        const issuer = guard('Cannot read the issuer certificate', () => parseCertificate(issuerObj.der, ctx.options));
        const valid = await guardAsync('Cannot verify the CRL signature', () => verifyCrlSignature(crl, issuer, { allowSha1: input.allowSha1 }));
        signature = { valid, issuerSubject: dn(issuer.subject) };
    }
    return withDiagnostics({
        ...crlView(crl),
        ...(entry !== undefined ? { entry } : {}),
        ...(signature !== undefined ? { signature } : {}),
    }, ctx.sink.report());
}

export function inspectCrlSummary(r: InspectCrlResult): Record<string, unknown> {
    return {
        issuerString: r.issuerString,
        thisUpdateIso: r.thisUpdate.iso,
        nextUpdateIso: r.nextUpdate === null ? null : r.nextUpdate.iso,
        crlNumber: r.crlNumber,
        entryCount: r.entryCount,
        isDelta: r.isDelta,
        ...(r.entry !== undefined ? { revoked: r.entry.revoked } : {}),
        ...(r.signature !== undefined ? { signatureValid: r.signature.valid } : {}),
        diagnosticCount: diagnosticCount(r),
    };
}

export const INSPECT_CRL_TOOL = defineTool<InspectCrlResult>({
    name: INSPECT_CRL_NAME,
    title: 'Inspect CRL (RFC 5280 §5 report, one entry lookup, signature check)',
    kind: 'read',
    description:
        "Read-only RFC 5280 §5 report of ONE certificate revocation list: version, issuer (RFC 4514 + RDNs), signature algorithm, thisUpdate / nextUpdate, CRL number, delta indicator and base CRL number, issuing distribution point, entry count (the entries are counted by walking, never all decoded — bounded by limits.maxRevokedCertificates), every extension decoded, size, diagnostics. `find` looks ONE serial up (serialHex, or a certificate whose serial and issuer are used) and returns `entry` (revoked, revocationDate, reason, invalidityDate, entry extensions). `issuer` adds a signature check — ONE signature against ONE key, not a verdict: check_crl_revocation judges a certificate against the list (freshness, scope, delta), verify_certificate_chain judges the whole chain. Token-frugal: verbosity:'summary' (issuerString, thisUpdateIso, nextUpdateIso, crlNumber, entryCount, isDelta, revoked, signatureValid). Input: pem / derBase64 / path.",
    inputSchema: INSPECT_CRL_INPUT_SCHEMA,
    rawOutputSchema: INSPECT_CRL_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(INSPECT_CRL_OUTPUT_SCHEMA, INSPECT_CRL_SUMMARY_PROPERTIES, `Structured CRL report.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'Facts of a CRL, signature against its issuer', input: { crl: { path: 'fixtures/inter.crl.pem' }, issuer: { path: 'fixtures/inter.crt.pem' }, verbosity: 'summary' } },
        { title: 'Is this certificate listed?', input: { crl: { path: 'fixtures/inter.crl.pem' }, find: { certificate: { path: 'fixtures/revoked.crt.pem' } }, fields: ['entry', 'issuerString', 'nextUpdate.iso'] } },
    ],
    handler: inspectCrl,
    text: (r) => `${INSPECT_CRL_NAME}: CRL v${r.version}${r.isDelta ? ' (delta)' : ''} by ${r.issuerString}, number ${r.crlNumber ?? '(none)'}, ${r.entryCount} entr${r.entryCount === 1 ? 'y' : 'ies'}, this ${r.thisUpdate.iso} → next ${r.nextUpdate?.iso ?? '(none)'}${r.entry !== undefined ? `, serial ${r.entry.serialNumber} ${r.entry.revoked ? `REVOKED${r.entry.reason !== null && r.entry.reason !== undefined ? ` (${r.entry.reason})` : ''}` : 'not listed'}` : ''}${r.signature !== undefined ? `, signature ${r.signature.valid ? 'valid' : 'INVALID'}` : ''}, ${r.diagnostics.length} diagnostic(s).`,
    summary: inspectCrlSummary,
});
