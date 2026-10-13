/**
 * Tool: inspect_private_key — describe a PKCS#8 private key (RFC 5958),
 * plain or PBES2-encrypted (RFC 8018), without its password: the format,
 * the algorithm and curve, the attributes, the PBES2 parameters. With
 * `tryImport:true` the key is imported (and, for an encrypted key,
 * decrypted by the host straight) into a NON-EXTRACTABLE Web Crypto key
 * that is described and never exported. No result ever carries a key byte:
 * the report is built from the `key-views.ts` allow-list only.
 */
import { getOidName, parseEncryptedPrivateKeyInfo, parsePrivateKeyInfo } from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { encryptedKeyView, KEY_VIEW_SCHEMA, privateKeyView, SIGNING_KEY_VIEW_SCHEMA, signingKeyView, type EncryptedKeyView, type PrivateKeyView, type SigningKeyView } from '../key-views.js';
import { createParseContext, PARSE_INPUT_PROPERTIES } from '../parse-context.js';
import { guard } from '../pki-errors.js';
import { LABELS, loadPkiObject, pkiInputSchema, PkiInputSchema } from '../pki-input.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { PASSWORD_INPUT_PROPERTY, PasswordSchema, resolvePassword } from '../secrets.js';
import { ALLOW_SHA1_INPUT_PROPERTY, HASHES, importKeyInput, isEncryptedPkcs8, KEY_TYPES, type SignerInput } from '../signer.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { AllowSha1Shape, diagnosticCount, parseInput, ParseShape, ProjectionShape, withDiagnostics } from './_shared.js';

export const INSPECT_PRIVATE_KEY_NAME = 'inspect_private_key';

export const INSPECT_PRIVATE_KEY_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['key'],
    properties: {
        key: pkiInputSchema('The PKCS#8 private key (PRIVATE KEY or ENCRYPTED PRIVATE KEY PEM, or DER)', ' A SEC1 / PKCS#1 key must be converted first (openssl pkcs8 -topk8).'),
        tryImport: { type: 'boolean', default: false, description: 'Also import the key into a NON-EXTRACTABLE Web Crypto key and describe the handle (never exported). An encrypted key then needs password and keyType; an RSA key needs rsaScheme.' },
        ...PASSWORD_INPUT_PROPERTY,
        keyType: { type: 'string', enum: [...KEY_TYPES], description: 'The type of an ENCRYPTED key (it reveals its type only once decrypted). With tryImport:true only; KEY_TYPE_REQUIRED when missing for an encrypted key.' },
        hash: { type: 'string', enum: [...HASHES], description: "Signature hash of the imported key. Default: the curve's hash for ECDSA (SHA-256/384/512), SHA-256 for RSA; refused for Ed25519 / Ed448. 'SHA-1' needs allowSha1:true. With tryImport:true only." },
        rsaScheme: { type: 'string', enum: ['pkcs1', 'pss'], description: "REQUIRED to import an RSA key: 'pkcs1' (RSASSA-PKCS1-v1_5) or 'pss' (RSA-PSS); pkinative has no default (RSA_SCHEME_REQUIRED). With tryImport:true only." },
        saltLength: { type: 'integer', minimum: 0, maximum: 512, description: "RSA-PSS salt length in bytes (rsaScheme:'pss' only; default: the hash length). With tryImport:true only." },
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    key: PkiInputSchema,
    tryImport: z.boolean().default(false),
    password: PasswordSchema.optional(),
    keyType: z.enum(KEY_TYPES).optional(),
    hash: z.enum(HASHES).optional(),
    rsaScheme: z.enum(['pkcs1', 'pss']).optional(),
    saltLength: z.number().int().min(0).max(512).optional(),
    ...AllowSha1Shape,
    ...ParseShape,
    ...ProjectionShape,
}).superRefine((v, ctx) => {
    if (!v.tryImport) {
        for (const member of ['password', 'keyType', 'hash', 'rsaScheme', 'saltLength'] as const) {
            if (v[member] !== undefined) ctx.addIssue({ code: 'custom', message: `${member} applies to tryImport:true only (a description needs no password)`, path: [member] });
        }
    }
    if (v.saltLength !== undefined && v.rsaScheme !== 'pss') ctx.addIssue({ code: 'custom', message: "saltLength applies to rsaScheme:'pss' only", path: ['saltLength'] });
});

export interface ImportedKeyView {
    readonly ok: true;
    readonly encrypted: boolean;
    readonly algorithm: SigningKeyView['algorithm'];
    readonly key: SigningKeyView['key'];
}

/** The allow-list view of a key (plain or encrypted) plus the import proof. No member ever holds a key byte. */
export interface InspectPrivateKeyResult extends Omit<Partial<PrivateKeyView>, 'format'>, Omit<Partial<EncryptedKeyView>, 'format'>, DiagnosticsReport {
    readonly format: 'pkcs8' | 'encrypted-pkcs8';
    /** The name of the key algorithm OID (plain key), or null when unknown. */
    readonly algorithmName?: string | null;
    readonly encrypted: boolean;
    readonly sizeBytes: number;
    readonly imported?: ImportedKeyView;
}

const IMPORTED_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['ok', 'encrypted', 'algorithm', 'key'],
    description: 'With tryImport:true: the key was imported (decrypted for an encrypted key) into a non-extractable Web Crypto key, described here and never exported.',
    properties: {
        ok: { type: 'boolean', enum: [true] },
        encrypted: { type: 'boolean', description: 'true when the password was used to decrypt the key.' },
        algorithm: SIGNING_KEY_VIEW_SCHEMA.properties.algorithm,
        key: SIGNING_KEY_VIEW_SCHEMA.properties.key,
    },
} as const;

export const INSPECT_PRIVATE_KEY_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['format', 'encrypted', 'sizeBytes', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...KEY_VIEW_SCHEMA.properties,
        algorithmName: { type: ['string', 'null'], description: 'The name of the key algorithm OID (ecPublicKey, rsaEncryption, Ed25519 …), plain keys only.' },
        encrypted: { type: 'boolean', description: 'true for an ENCRYPTED PRIVATE KEY (format encrypted-pkcs8).' },
        sizeBytes: { type: 'integer', description: 'Size of the DER structure (ciphertext included for an encrypted key).' },
        imported: IMPORTED_VIEW_SCHEMA,
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

export const INSPECT_PRIVATE_KEY_SUMMARY_PROPERTIES = {
    kind: { type: ['string', 'null'] },
    curve: { type: ['string', 'null'] },
    scheme: { type: ['string', 'null'], description: 'The password-based encryption scheme of an encrypted key.' },
    // The full shape carries the import description; the summary collapses it to its `ok` boolean.
    imported: { anyOf: [{ type: 'boolean' }, IMPORTED_VIEW_SCHEMA], description: 'The import proof (full), or its ok flag (summary).' },
    diagnosticCount: { type: 'integer' },
} as const;

/**
 * `importKeyInput` is the signer fragment's importer and names its inputs
 * `signer.*`; here the same inputs are top-level, so the message, the path
 * and the remedy of a refusal are re-addressed before they leave.
 */
function withoutSignerPrefix(err: unknown): unknown {
    if (!(err instanceof ToolError)) return err;
    const fix = (s: string): string => s.replaceAll('signer.', '');
    const data = err.data === undefined ? undefined : Object.fromEntries(Object.entries(err.data).map(([k, v]) => [k, typeof v === 'string' ? fix(v) : v]));
    return new ToolError(err.code, fix(err.message), data);
}

export async function inspectPrivateKey(rawInput: unknown): Promise<InspectPrivateKeyResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    const obj = await loadPkiObject(input.key, 'key', [...LABELS.privateKey, ...LABELS.encryptedPrivateKey], ctx);
    const encrypted = obj.label === undefined ? isEncryptedPkcs8(obj.der, ctx) : (LABELS.encryptedPrivateKey as readonly string[]).includes(obj.label);
    const view: PrivateKeyView | EncryptedKeyView = encrypted
        ? encryptedKeyView(guard('Cannot read the encrypted key', () => parseEncryptedPrivateKeyInfo(obj.der, ctx.options)))
        : privateKeyView(guard('Cannot read the private key', () => parsePrivateKeyInfo(obj.der, ctx.options)));

    let imported: ImportedKeyView | undefined;
    if (input.tryImport) {
        // The password lives in this frame only: never in a message, in data, in the result or in a log.
        const password = resolvePassword(input.password);
        const signer: SignerInput = {
            key: input.key,
            ...(input.keyType !== undefined ? { keyType: input.keyType } : {}),
            ...(input.hash !== undefined ? { hash: input.hash } : {}),
            ...(input.rsaScheme !== undefined ? { rsaScheme: input.rsaScheme } : {}),
            ...(input.saltLength !== undefined ? { saltLength: input.saltLength } : {}),
        };
        try {
            const key = await importKeyInput(signer, input.allowSha1, password, undefined, ctx);
            const described = signingKeyView(key.signer);
            imported = { ok: true, encrypted: key.encrypted, algorithm: described.algorithm, key: described.key };
        } catch (err) {
            throw withoutSignerPrefix(err);
        }
    }

    return withDiagnostics({
        ...view,
        ...(view.format === 'pkcs8' ? { algorithmName: getOidName(view.algorithm) ?? null } : {}),
        encrypted,
        sizeBytes: obj.der.length,
        ...(imported !== undefined ? { imported } : {}),
    }, ctx.sink.report());
}

export function inspectPrivateKeySummary(r: InspectPrivateKeyResult): Record<string, unknown> {
    return {
        format: r.format,
        kind: r.kind ?? null,
        curve: r.curve ?? null,
        encrypted: r.encrypted,
        scheme: r.encryption?.scheme ?? null,
        ...(r.imported !== undefined ? { imported: r.imported.ok } : {}),
        diagnosticCount: diagnosticCount(r),
    };
}

function describe(r: InspectPrivateKeyResult): string {
    if (r.format === 'encrypted-pkcs8') {
        const e = r.encryption;
        return `encrypted PKCS#8, ${e?.scheme ?? 'unknown scheme'}${e?.pbes2 !== undefined ? `, ${e.pbes2.iterations} PBKDF2 iterations` : ' (a scheme pkinative refuses)'}, ${r.encryptedBytes ?? 0} encrypted bytes`;
    }
    return `plain PKCS#8 v${r.version ?? 0} ${r.kind ?? 'unknown'}${r.curve !== undefined ? ` ${r.curve}` : ''} key (${r.algorithmName ?? r.algorithm ?? '?'}), ${r.attributes?.length ?? 0} attribute(s), public key ${r.publicKey === true ? 'present' : 'absent'}`;
}

export const INSPECT_PRIVATE_KEY_TOOL = defineTool<InspectPrivateKeyResult>({
    name: INSPECT_PRIVATE_KEY_NAME,
    title: 'Inspect private key (PKCS#8 description, optional import proof, no key byte)',
    kind: 'read',
    description:
        "Describe a PKCS#8 private key WITHOUT its password: format ('pkcs8' or 'encrypted-pkcs8'), version, kind (ec / rsa / rsa-pss / ed25519 / ed448 / x25519 / x448 / ml-dsa / unknown), curve, algorithm OID and name, attributes, whether a public key is embedded; for an encrypted key the PBES2 parameters (PBKDF2 iterations, PRF, AES key size, salt length, ciphertext size) or the name of a scheme pkinative refuses (PKCS#12 / PKCS#5 v1.5 ciphers). `tryImport:true` additionally imports the key into a NON-EXTRACTABLE Web Crypto key and reports the handle (type, algorithm, usages) — an encrypted key then needs `password` (or PKINATIVE_MCP_PASSWORD; SECRET_REQUIRED) and `keyType` (KEY_TYPE_REQUIRED), an RSA key needs `rsaScheme` (RSA_SCHEME_REQUIRED, no default); a wrong password is PKI_CRYPTO_DECRYPTION_FAILED and a legacy cipher PKI_KEY_ENCRYPTION_UNSUPPORTED with the openssl pkcs8 remedy. No result ever carries a key byte, a scalar or the password: the report is an allow-list view and the key never leaves the engine (nothing exports or writes a key here). A PUBLIC KEY or a non-PKCS#8 DER is refused with the PKI_* cause. A call carrying a password is never cached. Token-frugal: verbosity:'summary' (format, kind, curve, encrypted, scheme, imported). Input: pem / derBase64 / path.",
    inputSchema: INSPECT_PRIVATE_KEY_INPUT_SCHEMA,
    rawOutputSchema: INSPECT_PRIVATE_KEY_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(INSPECT_PRIVATE_KEY_OUTPUT_SCHEMA, INSPECT_PRIVATE_KEY_SUMMARY_PROPERTIES, `Private key description (allow-list view, never a key byte).${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'What is this key protected with? (no password)', input: { key: { path: 'fixtures/leaf.key.enc.pem' }, verbosity: 'summary' } },
        { title: 'Prove an encrypted EC key is usable (non-extractable import)', input: { key: { path: 'fixtures/leaf.key.enc.pem' }, tryImport: true, password: 'test-only-password', keyType: 'ec-p256', fields: ['imported', 'encryption.scheme'] } },
    ],
    handler: inspectPrivateKey,
    text: (r) => `${INSPECT_PRIVATE_KEY_NAME}: ${describe(r)}, ${r.sizeBytes} bytes${r.imported !== undefined ? `; imported${r.imported.encrypted ? ' (decrypted)' : ''} as ${r.imported.algorithm.name} (${r.imported.key.type}, non-extractable)` : ''}, ${r.diagnostics.length} diagnostic(s).`,
    summary: inspectPrivateKeySummary,
});
