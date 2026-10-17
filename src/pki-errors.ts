/**
 * pkinative error → ToolError mapping: the ONLY module that reads `err.code`.
 *
 * Every engine call in a tool runs through `guard()` / `guardAsync()`, so an
 * autonomous caller always gets the exact CAUSE (`code`: pkinative's frozen
 * `PKI_*` code verbatim), the coarse CLASS (`data.errorClass`), the
 * structured detail the engine knows (`path`, `offset`, `algorithm`, the
 * limit that fired) and a remedy phrased as MCP inputs (`data.remedy`).
 *
 * The class table is typed `satisfies Record<PkiErrorCode, …>`: an engine
 * minor that adds a code fails `tsc` here instead of leaking as ENGINE_ERROR.
 */
import {
    PkiCertificateError,
    PkiCmsError,
    PkiCryptoError,
    PkiEncodingError,
    PkiError,
    PkiKeyError,
    PkiLimitError,
    type PkiErrorCode,
} from 'pkinative';

import { PKI_DIAGNOSTIC_SEVERITY, PKI_ERROR_CLASSES, PKI_REASON_TABLE } from './data/pkinative/code-tables.js';
import { ToolError } from './errors.js';
import { MAX_INPUT_BYTES_ENV, MAX_KDF_ITERATIONS_ENV, MAX_PATHS_EXPLORED_ENV } from './caps.js';

/** The coarse class of an engine refusal (what an agent branches on second, after the code). */
export type PkiErrorClass = 'usage' | 'input' | 'parse' | 'security' | 'limit' | 'unsupported' | 'crypto' | 'password' | 'check' | 'internal';

/** The 57 frozen pkinative codes → coarse class (the pkinative-cli table, exit codes dropped). */
export const PKI_ERROR_CLASS = {
    // base (5)
    PKI_INVALID_INPUT: 'input',
    PKI_INVALID_OPTION: 'usage',
    PKI_API_MISUSE: 'usage',
    PKI_STRICT_DIAGNOSTIC: 'check',
    PKI_INTERNAL: 'internal',
    // asn1 + oid (19)
    PKI_ASN1_TRUNCATED: 'parse',
    PKI_ASN1_TAG_INVALID: 'parse',
    PKI_ASN1_LENGTH_INVALID: 'parse',
    PKI_ASN1_LENGTH_NON_MINIMAL: 'parse',
    PKI_ASN1_LENGTH_OVERFLOW: 'parse',
    PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN: 'parse',
    PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN: 'parse',
    PKI_ASN1_CONSTRUCTED_FORM_INVALID: 'parse',
    PKI_ASN1_EOC_UNEXPECTED: 'parse',
    PKI_ASN1_TRAILING_DATA: 'parse',
    PKI_ASN1_UNEXPECTED_TAG: 'parse',
    PKI_ASN1_BOOLEAN_INVALID: 'parse',
    PKI_ASN1_INTEGER_INVALID: 'parse',
    PKI_ASN1_INTEGER_UNREPRESENTABLE: 'parse',
    PKI_ASN1_BIT_STRING_INVALID: 'parse',
    PKI_ASN1_NULL_INVALID: 'parse',
    PKI_ASN1_STRING_INVALID: 'parse',
    PKI_ASN1_TIME_INVALID: 'parse',
    PKI_ASN1_VALUE_OUT_OF_RANGE: 'input',
    PKI_OID_INVALID: 'parse',
    // pem (7)
    PKI_PEM_NO_BLOCK: 'parse',
    PKI_PEM_LABEL_INVALID: 'input',
    PKI_PEM_LABEL_MISMATCH: 'parse',
    PKI_PEM_UNEXPECTED_LABEL: 'input',
    PKI_PEM_UNTERMINATED: 'parse',
    PKI_PEM_BASE64_INVALID: 'parse',
    PKI_PEM_HEADERS_FORBIDDEN: 'unsupported',
    // x509 (10)
    PKI_X509_STRUCTURE_INVALID: 'parse',
    PKI_X509_VERSION_INVALID: 'parse',
    PKI_X509_NAME_INVALID: 'parse',
    PKI_X509_VALIDITY_INVALID: 'parse',
    PKI_X509_SPKI_INVALID: 'parse',
    PKI_X509_UNIQUE_ID_INVALID: 'parse',
    PKI_X509_EXTENSIONS_EMPTY: 'parse',
    PKI_X509_EXTENSION_DUPLICATE: 'parse',
    PKI_X509_EXTENSION_MALFORMED: 'parse',
    PKI_X509_GENERAL_NAME_INVALID: 'parse',
    // limits (2)
    PKI_LIMIT_EXCEEDED: 'limit',
    PKI_LIMIT_INVALID: 'usage',
    // crypto (5)
    PKI_CRYPTO_UNAVAILABLE: 'crypto',
    PKI_CRYPTO_ALGORITHM_UNSUPPORTED: 'unsupported',
    PKI_CRYPTO_KEY_UNSUPPORTED: 'unsupported',
    PKI_CRYPTO_ALGORITHM_REFUSED: 'security',
    PKI_CRYPTO_DECRYPTION_FAILED: 'password',
    // cms (4)
    PKI_CMS_STRUCTURE_INVALID: 'parse',
    PKI_CMS_CONTENT_TYPE_UNEXPECTED: 'input',
    PKI_CMS_VERSION_UNSUPPORTED: 'unsupported',
    PKI_CMS_CONTENT_NOT_OCTET_STRING: 'unsupported',
    // keys (4)
    PKI_KEY_STRUCTURE_INVALID: 'parse',
    PKI_KEY_VERSION_UNSUPPORTED: 'unsupported',
    PKI_KEY_ENCRYPTION_UNSUPPORTED: 'security',
    PKI_KEY_MAC_UNSUPPORTED: 'security',
} as const satisfies Record<PkiErrorCode, PkiErrorClass>;

/** Every frozen PKI_* error code (57), in table order. */
export const PKI_ERROR_CODES: readonly PkiErrorCode[] = Object.keys(PKI_ERROR_CLASS) as PkiErrorCode[];
/** Every PKI_REASON_* code (43). */
export const PKI_REASON_CODES: readonly string[] = Object.keys(PKI_REASON_TABLE);
/** Every PKI_DIAG_* code (97). */
export const PKI_DIAGNOSTIC_CODES: readonly string[] = Object.keys(PKI_DIAGNOSTIC_SEVERITY);
/** The engine class name raising each code (from the vendored registry). */
export const PKI_ERROR_ENGINE_CLASS: Readonly<Record<PkiErrorCode, string>> = PKI_ERROR_CLASSES;

/** The one-time conversion of a legacy PKCS#12 file, as pkinative 1.0.0 gives it. */
export const LEGACY_PKCS12_REMEDY = 'convert it once with OpenSSL 3.4 or later: openssl pkcs12 -in legacy.p12 -legacy -aes256 -out bundle.pem, '
    + 'then openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12 (delete bundle.pem afterwards)';

/** The two ways past an integrity check that cannot run. */
export const UNVERIFIED_INTEGRITY_REMEDY = 'allowUnverifiedIntegrity:true (open_pkcs12; only for a file whose origin you trust), or re-export it with openssl pkcs12 -export -pbmac1_pbkdf2';

/** A legacy-encrypted PKCS#8 key (PBES1, 3DES): re-encrypt it with PBES2, which pkinative reads. */
export const LEGACY_PKCS8_REMEDY = 're-encrypt the key with PBES2 and AES: openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -in legacy.key -out modern.key';

/** The remedy for a password that decrypts or authenticates nothing. */
export const WRONG_PASSWORD_REMEDY = 'check the password (the password input or PKINATIVE_MCP_PASSWORD)';

/**
 * The MCP input(s) that lift an engine refusal: the tool-input counterpart of
 * pkinative's own remedy, which names library options. Absent = no input
 * lifts it (the input itself must change); `explain_code` carries the
 * engine's full remedy.
 */
export const PKI_REMEDY = {
    PKI_ASN1_LENGTH_NON_MINIMAL: "encodingRules:'ber' (the producer wrote BER, not DER)",
    PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN: "encodingRules:'ber' (indefinite lengths are BER; common in CMS)",
    PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN: "encodingRules:'ber' (constructed strings are BER)",
    PKI_ASN1_BOOLEAN_INVALID: "encodingRules:'ber' (a non-0xFF TRUE is BER)",
    PKI_ASN1_TRAILING_DATA: 'pass exactly one object; decode_asn1 sequence:true for concatenated objects; allowTrailingData:true (decode_asn1, inspect_cms, verify_cms) when the container defines what follows',
    PKI_PEM_BASE64_INVALID: "pemMode:'lax' (whitespace, line length, headers); a missing \"=\" padding must be restored first",
    PKI_PEM_UNEXPECTED_LABEL: "convert_pem mode:'decode' (lists the labels present)",
    PKI_STRICT_DIAGNOSTIC: 'strict:false, or fix the producer the diagnostic names',
    PKI_CRYPTO_ALGORITHM_REFUSED: 'allowSha1:true (only for legacy material you already trust)',
    PKI_CRYPTO_DECRYPTION_FAILED: WRONG_PASSWORD_REMEDY,
    PKI_X509_EXTENSION_MALFORMED: 'inspect_certificate rawExtensions:true (keeps every extension undecoded), or decode_asn1 on the value',
    // From a PKCS#12 file; a PKCS#8 key gets LEGACY_PKCS8_REMEDY at its call site.
    PKI_KEY_ENCRYPTION_UNSUPPORTED: LEGACY_PKCS12_REMEDY,
    PKI_KEY_MAC_UNSUPPORTED: UNVERIFIED_INTEGRITY_REMEDY,
    PKI_API_MISUSE: 'the tool description (the inputs given are incomplete or inconsistent for this input)',
    PKI_LIMIT_EXCEEDED: 'limits.<limit> (data.limit names it; describe_engine lists them); raise a bound for trusted input only, never above the operator ceiling',
} as const satisfies Partial<Record<PkiErrorCode, string>>;

const CEILING_ENV_BY_LIMIT: Readonly<Record<string, string>> = {
    maxInputBytes: MAX_INPUT_BYTES_ENV,
    maxKdfIterations: MAX_KDF_ITERATIONS_ENV,
    maxPkcs12KdfIterations: MAX_KDF_ITERATIONS_ENV,
    maxPathsExplored: MAX_PATHS_EXPLORED_ENV,
};

function detailOf(err: PkiError): Record<string, string | number> {
    const detail: Record<string, string | number> = {};
    if (err instanceof PkiLimitError) {
        detail['limit'] = err.limit;
        detail['configured'] = err.configured;
        detail['observed'] = err.observed;
        const env = CEILING_ENV_BY_LIMIT[err.limit];
        if (env !== undefined) detail['env'] = env;
    }
    if (err instanceof PkiCryptoError && err.algorithm !== undefined) detail['algorithm'] = err.algorithm;
    if (err instanceof PkiCertificateError || err instanceof PkiCmsError || err instanceof PkiKeyError) {
        if (err.path !== undefined) detail['path'] = err.path;
    }
    if (err instanceof PkiEncodingError || err instanceof PkiCertificateError || err instanceof PkiCmsError || err instanceof PkiKeyError) {
        if (err.offset !== undefined) detail['offset'] = err.offset;
    }
    return detail;
}

const FS_ERROR_CODES: ReadonlySet<string> = new Set([
    'ENOENT', 'EACCES', 'EPERM', 'EISDIR', 'ENOTDIR', 'ENOSPC', 'EEXIST',
    'EMFILE', 'ENFILE', 'EBUSY', 'EROFS', 'ELOOP', 'ENAMETOOLONG', 'EIO',
]);

/** True for a Node filesystem error with a known errno code. */
export function isFsError(err: unknown): err is NodeJS.ErrnoException {
    return err instanceof Error && typeof (err as NodeJS.ErrnoException).code === 'string'
        && FS_ERROR_CODES.has((err as NodeJS.ErrnoException).code as string);
}

/**
 * Translate an engine failure into a `ToolError` carrying the frozen code,
 * the class, the detail and a remedy. `remedies` overrides the PKI_REMEDY
 * table for this call site, where the right advice depends on what was being
 * read. ToolErrors pass through unchanged; a filesystem error becomes
 * `IO_ERROR` without the OS message; anything else is `ENGINE_ERROR`.
 */
export function mapPkiError(err: unknown, context: string, remedies: Readonly<Record<string, string>> = {}): ToolError {
    if (err instanceof ToolError) return err;
    if (err instanceof PkiError) {
        const code = err.code as string;
        const errorClass: PkiErrorClass = Object.hasOwn(PKI_ERROR_CLASS, code) ? PKI_ERROR_CLASS[code as PkiErrorCode] : 'internal';
        const detail = detailOf(err);
        const remedy = Object.hasOwn(remedies, code) ? remedies[code] : Object.hasOwn(PKI_REMEDY, code) ? PKI_REMEDY[code as keyof typeof PKI_REMEDY] : undefined;
        return new ToolError(code, `${context}: ${err.message}`, {
            errorClass,
            engineError: err.name,
            ...detail,
            ...(remedy !== undefined ? { remedy } : {}),
        });
    }
    if (isFsError(err)) {
        return new ToolError('IO_ERROR', `${context}: ${String(err.code)}`, { errno: String(err.code) });
    }
    const message = err instanceof Error ? err.message : String(err);
    return new ToolError('ENGINE_ERROR', `${context}: ${message}`, { errorClass: 'internal', engineError: err instanceof Error ? err.name : typeof err });
}

/** True when `err` is the engine's error carrying `code`. */
export function isPkiCode(err: unknown, code: string): boolean {
    return err instanceof PkiError && err.code === code;
}

/** Run a synchronous engine call, translating any failure. */
export function guard<T>(context: string, fn: () => T, remedies?: Readonly<Record<string, string>>): T {
    try {
        return fn();
    } catch (e) {
        throw mapPkiError(e, context, remedies);
    }
}

/** Run an asynchronous engine call, translating any failure. */
export async function guardAsync<T>(context: string, fn: () => Promise<T>, remedies?: Readonly<Record<string, string>>): Promise<T> {
    try {
        return await fn();
    } catch (e) {
        throw mapPkiError(e, context, remedies);
    }
}

/**
 * The ToolError for a PKCS#12 file that did not open, shared by `open_pkcs12`
 * and the `signer.p12` path so both say the same thing:
 *   an RSA key without a scheme   RSA_SCHEME_REQUIRED
 *   a legacy cipher               PKI_KEY_ENCRYPTION_UNSUPPORTED (security), with the two-step conversion
 *   a MAC the password misses     PKI_CRYPTO_DECRYPTION_FAILED (password)
 *   no checkable MAC              ENGINE_VERDICT with the allowUnverifiedIntegrity remedy
 *   anything else                 ENGINE_VERDICT, with the reasons
 */
export function pkcs12Failure(report: { readonly integrity: string; readonly reasons: readonly { readonly code: string }[] }): ToolError {
    const has = (code: string): boolean => report.reasons.some((r) => r.code === code);
    const codes = [...new Set(report.reasons.map((r) => r.code))].join(', ');
    const options = { reasons: report.reasons };
    if (has('PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED')) {
        return new ToolError('RSA_SCHEME_REQUIRED', "The PKCS#12 key is RSA: pass rsaScheme:'pkcs1'|'pss' to import it (pkinative has no default RSA signature scheme).", { ...options, remedy: "rsaScheme:'pkcs1'|'pss'" });
    }
    if (has('PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED')) {
        return new ToolError('PKI_KEY_ENCRYPTION_UNSUPPORTED', `The PKCS#12 file uses a legacy cipher pkinative refuses by policy (PBES2 and PBMAC1 only): ${codes}.`, { ...options, errorClass: 'security', remedy: LEGACY_PKCS12_REMEDY });
    }
    if (report.integrity === 'mismatch') {
        return new ToolError('PKI_CRYPTO_DECRYPTION_FAILED', 'The PKCS#12 MAC does not match: the password is wrong, or the file was altered.', { ...options, errorClass: 'password', remedy: WRONG_PASSWORD_REMEDY });
    }
    if (has('PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED')) {
        return new ToolError('ENGINE_VERDICT', `The PKCS#12 integrity cannot be verified: ${codes}.`, { ...options, remedy: UNVERIFIED_INTEGRITY_REMEDY });
    }
    return new ToolError('ENGINE_VERDICT', `The PKCS#12 file did not open: ${codes}.`, options);
}
