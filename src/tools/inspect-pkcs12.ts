/**
 * Tool: inspect_pkcs12 — describe a PKCS#12 container (RFC 7292) without
 * its password: the MAC construction (PBMAC1 or the legacy RFC 7292
 * Appendix B KDF), every SafeContents with its encryption scheme, and the
 * bags of the unencrypted ones. With `password`: the MAC is verified and
 * every SafeContents opened, each bag listed as an allow-list view
 * (certificates by subject, keys by algorithm — never a key byte, not even
 * from an unencrypted keyBag). Opening is `openSafeContents`, not
 * `openPkcs12`: nothing is imported here (open_pkcs12 is the verdict).
 */
import { openSafeContents, parsePkcs12, verifyPkcs12Mac, type Pkcs12, type SafeContentsInfo } from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { bagView, ENCRYPTION_VIEW_SCHEMA, encryptionView, KEY_VIEW_SCHEMA, macView, type BagView, type EncryptionView, type MacView } from '../key-views.js';
import { createParseContext, PARSE_INPUT_PROPERTIES, type ParseContext } from '../parse-context.js';
import { guard, guardAsync } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { PASSWORD_INPUT_PROPERTY, PasswordSchema, resolvePassword } from '../secrets.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';

export const INSPECT_PKCS12_NAME = 'inspect_pkcs12';

export const INSPECT_PKCS12_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['pkcs12'],
    properties: {
        pkcs12: pkiInputSchema('The PKCS#12 file (.p12 / .pfx; DER, or BER with encodingRules:\'ber\' for a Windows-written PFX)'),
        ...PASSWORD_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    pkcs12: PkiInputSchema,
    password: PasswordSchema.optional(),
    ...ParseShape,
    ...ProjectionShape,
});

export interface SafeContentsView {
    readonly path: string;
    readonly encrypted: boolean;
    readonly encryption: EncryptionView | null;
    readonly bags: readonly BagView[];
}

export interface OpenedContentsView {
    readonly path: string;
    readonly encrypted: boolean;
    readonly bags: readonly BagView[];
}

export interface InspectPkcs12Result extends DiagnosticsReport {
    readonly version: Pkcs12['version'];
    readonly mac: MacView | null;
    readonly contents: readonly SafeContentsView[];
    readonly bagCount: number;
    readonly sizeBytes: number;
    readonly macVerified?: boolean | null;
    readonly opened?: readonly OpenedContentsView[];
}

/** JSON Schema of `macView` (the MAC construction; PBMAC1 parameters when RFC 9579). */
export const MAC_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['kind', 'algorithm', 'iterations'],
    properties: {
        kind: { type: 'string', description: "'pbmac1' (RFC 9579, verifiable) or 'pkcs12-kdf' (RFC 7292 Appendix B, never verified by pkinative)." },
        algorithm: { type: 'string', description: 'The digestAlgorithm OID.' },
        iterations: { type: 'integer' },
        pbmac1: {
            type: 'object',
            additionalProperties: false,
            required: ['iterations', 'prf', 'hmac', 'keyLength'],
            properties: { iterations: { type: 'integer' }, prf: { type: 'string' }, hmac: { type: 'string' }, keyLength: { type: 'integer' } },
        },
    },
} as const;

/** JSON Schema of `bagView` (a SafeBag without its value: a certificate by identity, a key by its description only). */
export const BAG_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['path', 'kind', 'oid'],
    properties: {
        path: { type: 'string', description: 'authSafe[i].bags[j] (nested safeContentsBags flattened).' },
        kind: { type: 'string', description: 'keyBag, pkcs8ShroudedKeyBag, certBag, crlBag, secretBag, safeContentsBag or unknown.' },
        oid: { type: 'string' },
        friendlyName: { type: 'string' },
        localKeyId: { type: 'string', description: 'Hex; what ties a key to its certificate.' },
        certificate: {
            type: 'object',
            additionalProperties: false,
            description: 'A certBag: subject, issuer, serial — or { unreadable: true, bytes } when it does not parse.',
            properties: { subject: { type: 'string' }, issuer: { type: 'string' }, serialNumber: { type: 'string' }, unreadable: { type: 'boolean' }, bytes: { type: 'integer' } },
        },
        crlBytes: { type: 'integer', description: 'A crlBag: the CRL size.' },
        key: KEY_VIEW_SCHEMA,
    },
} as const;

const CONTENTS_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['path', 'encrypted', 'encryption', 'bags'],
    properties: {
        path: { type: 'string' },
        encrypted: { type: 'boolean' },
        encryption: { ...ENCRYPTION_VIEW_SCHEMA, type: ['object', 'null'], description: 'The password scheme of an encrypted SafeContents (pbes2 present when PBES2); null for a plain one.' },
        bags: { type: 'array', items: BAG_VIEW_SCHEMA, description: 'The bags of a plain SafeContents; empty for an encrypted one until opened.' },
    },
} as const;

export const INSPECT_PKCS12_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['version', 'mac', 'contents', 'bagCount', 'sizeBytes', 'diagnostics', 'diagnosticCounts'],
    properties: {
        version: { type: 'integer', enum: [3] },
        mac: { ...MAC_VIEW_SCHEMA, type: ['object', 'null'], description: 'The MacData, or null when the file carries none (its integrity cannot be verified).' },
        contents: { type: 'array', items: CONTENTS_SCHEMA, description: 'The AuthenticatedSafe entries, in encoded order.' },
        bagCount: { type: 'integer', description: 'Bags listed: those of `opened` when a password was given, else those of the plain SafeContents.' },
        sizeBytes: { type: 'integer' },
        macVerified: { type: ['boolean', 'null'], description: 'With password: true when the PBMAC1 MAC matches, false for a wrong password or an altered file (a report, not an error); null when the file has no MAC.' },
        opened: {
            type: 'array',
            description: 'With password: every SafeContents opened (the encrypted ones decrypted), its bags as allow-list views.',
            items: { type: 'object', additionalProperties: false, required: ['path', 'encrypted', 'bags'], properties: { path: { type: 'string' }, encrypted: { type: 'boolean' }, bags: { type: 'array', items: BAG_VIEW_SCHEMA } } },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const INSPECT_PKCS12_SUMMARY_PROPERTIES = {
    macKind: { type: ['string', 'null'] },
    contentCount: { type: 'integer' },
    bagKinds: { type: 'array', items: { type: 'string' } },
    diagnosticCount: { type: 'integer' },
} as const;

function contentsView(c: SafeContentsInfo, ctx: ParseContext): SafeContentsView {
    return {
        path: c.path,
        encrypted: c.encrypted,
        encryption: c.encryption !== undefined ? encryptionView(c.encryption) : null,
        bags: c.bags.map((b) => bagView(b, ctx.options)),
    };
}

export async function inspectPkcs12(rawInput: unknown): Promise<InspectPkcs12Result> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    // The password lives in this frame only: never in a message, in data, in the result or in a log.
    const password = resolvePassword(input.password);
    const obj = await loadPkiObject(input.pkcs12, 'pkcs12', LABELS.any, ctx);
    const pkcs12 = guard('Cannot read the PKCS#12 file', () => parsePkcs12(obj.der, ctx.options));
    const contents = pkcs12.contents.map((c) => contentsView(c, ctx));

    let macVerified: boolean | null | undefined;
    let opened: OpenedContentsView[] | undefined;
    if (password !== undefined) {
        // A legacy (RFC 7292 Appendix B) MAC is refused here with PKI_KEY_MAC_UNSUPPORTED, as pkinative's doctrine says.
        macVerified = pkcs12.mac === undefined ? null : await guardAsync('Cannot verify the MAC', () => verifyPkcs12Mac(pkcs12, password));
        opened = [];
        for (const c of pkcs12.contents) {
            // A wrong password on an encrypted SafeContents is PKI_CRYPTO_DECRYPTION_FAILED (AES-CBC cannot tell it from altered data).
            const bags = await guardAsync(`Cannot open ${c.path}`, () => openSafeContents(c, password, ctx.options));
            opened.push({ path: c.path, encrypted: c.encrypted, bags: bags.map((b) => bagView(b, ctx.options)) });
        }
    }

    const listed = opened ?? contents;
    return withDiagnostics({
        version: pkcs12.version,
        mac: macView(pkcs12.mac),
        contents,
        bagCount: listed.reduce((n, c) => n + c.bags.length, 0),
        sizeBytes: obj.der.length,
        ...(macVerified !== undefined ? { macVerified } : {}),
        ...(opened !== undefined ? { opened } : {}),
    }, ctx.sink.report());
}

function bagKinds(r: InspectPkcs12Result): string[] {
    return [...new Set((r.opened ?? r.contents).flatMap((c) => c.bags.map((b) => b.kind)))];
}

export function inspectPkcs12Summary(r: InspectPkcs12Result): Record<string, unknown> {
    return {
        version: r.version,
        macKind: r.mac?.kind ?? null,
        ...(r.macVerified !== undefined ? { macVerified: r.macVerified } : {}),
        contentCount: r.contents.length,
        bagCount: r.bagCount,
        bagKinds: bagKinds(r),
        diagnosticCount: diagnosticCount(r),
    };
}

export const INSPECT_PKCS12_TOOL = defineTool<InspectPkcs12Result>({
    name: INSPECT_PKCS12_NAME,
    title: 'Inspect PKCS#12 (MAC kind, SafeContents, bags; optional MAC check and opening, no key byte)',
    kind: 'read',
    description:
        "Describe a PKCS#12 (.p12 / .pfx) WITHOUT its password: version, the MAC construction (kind 'pbmac1' RFC 9579 with its PBKDF2 / HMAC parameters, or 'pkcs12-kdf' — the RFC 7292 Appendix B MAC pkinative never verifies; null when the file has none), every SafeContents with its encryption scheme (PBES2 parameters, or the name of a legacy RC2 / 3DES scheme pkinative refuses), and the bags of the unencrypted SafeContents. With `password` (or PKINATIVE_MCP_PASSWORD): `macVerified` (true / false — a wrong password or an altered file is a REPORT, not an error; null without a MAC) and `opened`: every SafeContents opened, each bag as an allow-list view — a certBag by subject / issuer / serial, a keyBag or pkcs8ShroudedKeyBag by its algorithm, curve and encryption parameters, a crlBag by size. No result ever carries a key byte, a bag value or the password, not even from an unencrypted keyBag. Refusals: a wrong password on an ENCRYPTED SafeContents is PKI_CRYPTO_DECRYPTION_FAILED; a legacy MAC PKI_KEY_MAC_UNSUPPORTED and a legacy cipher PKI_KEY_ENCRYPTION_UNSUPPORTED (only when a password asks for them), each with the OpenSSL 3.4 conversion remedy; a public-key integrity-mode file PKI_KEY_MAC_UNSUPPORTED at parse. Nothing is imported here: open_pkcs12 is the one-call verdict with non-extractable key import. limits.maxPkcs12Bags and maxPkcs12KdfIterations bound the file's declared cost. Token-frugal: verbosity:'summary' (macKind, macVerified, contentCount, bagCount, bagKinds).",
    inputSchema: INSPECT_PKCS12_INPUT_SCHEMA,
    rawOutputSchema: INSPECT_PKCS12_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(INSPECT_PKCS12_OUTPUT_SCHEMA, INSPECT_PKCS12_SUMMARY_PROPERTIES, `PKCS#12 description (allow-list views, never a key byte).${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'What is in this .p12 and how is it protected? (no password)', input: { pkcs12: { path: 'fixtures/leaf.p12' } } },
        { title: 'Verify the MAC and list every bag', input: { pkcs12: { path: 'fixtures/leaf.p12' }, password: 'test-only-password', fields: ['macVerified', 'opened.path', 'opened.bags.kind', 'opened.bags.certificate.subject'] } },
    ],
    handler: inspectPkcs12,
    text: (r) => `${INSPECT_PKCS12_NAME}: PKCS#12 v${r.version}, MAC ${r.mac === null ? 'none' : `${r.mac.kind} (${r.mac.iterations} iteration(s))`}${r.macVerified !== undefined ? `, MAC ${r.macVerified === null ? 'absent' : r.macVerified ? 'verified' : 'MISMATCH (wrong password or altered file)'}` : ''}; ${r.contents.length} SafeContents (${r.contents.map((c) => `${c.path}: ${c.encrypted ? `encrypted, ${c.encryption?.scheme ?? 'unknown scheme'}` : `${c.bags.length} bag(s)`}`).join('; ')})${r.opened !== undefined ? `; opened: ${r.bagCount} bag(s) — ${bagKinds(r).join(', ') || 'none'}` : ''}, ${r.sizeBytes} bytes, ${r.diagnostics.length} diagnostic(s).`,
    summary: inspectPkcs12Summary,
});
