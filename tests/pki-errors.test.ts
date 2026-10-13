/**
 * Tests for `src/pki-errors.ts` — the only module that reads an engine
 * `err.code`: the frozen code tables against the vendored registries, the
 * mapping of real engine errors to ToolError (code verbatim, class, detail,
 * remedy), filesystem and unknown errors, and the PKCS#12 verdict mapping.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parseCertificate, PkiCertificateError, PkiCryptoError, PkiError, PkiLimitError, type PkiErrorCode } from 'pkinative';

import { MAX_INPUT_BYTES_ENV, MAX_KDF_ITERATIONS_ENV, MAX_PATHS_EXPLORED_ENV } from '../src/caps.js';
import { SecurityError, ToolError } from '../src/errors.js';
import {
    guard,
    guardAsync,
    isFsError,
    isPkiCode,
    LEGACY_PKCS12_REMEDY,
    LEGACY_PKCS8_REMEDY,
    mapPkiError,
    PKI_DIAGNOSTIC_CODES,
    PKI_ERROR_CLASS,
    PKI_ERROR_CODES,
    PKI_ERROR_ENGINE_CLASS,
    PKI_REASON_CODES,
    PKI_REMEDY,
    pkcs12Failure,
    UNVERIFIED_INTEGRITY_REMEDY,
    WRONG_PASSWORD_REMEDY,
} from '../src/pki-errors.js';
import { fixtureBytes } from './_pki-fixtures.js';

const DATA = path.resolve(import.meta.dirname, '..', 'src', 'data', 'pkinative');

function registry<T>(file: string, member: string): T[] {
    const json = JSON.parse(readFileSync(path.join(DATA, file), 'utf8')) as Record<string, unknown>;
    return json[member] as T[];
}

const SILENT = { onDiagnostic: () => undefined };
const GARBAGE = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]);

describe('the code tables', () => {
    it('PKI_ERROR_CLASS covers exactly the 57 codes of errors.json, in registry order, each with its engine class', () => {
        const errors = registry<{ code: PkiErrorCode; class: string }>('errors.json', 'errors');
        expect(errors).toHaveLength(57);
        expect(PKI_ERROR_CODES).toHaveLength(57);
        expect([...PKI_ERROR_CODES]).toEqual(errors.map((e) => e.code));
        expect(Object.keys(PKI_ERROR_CLASS)).toEqual(errors.map((e) => e.code));
        for (const e of errors) expect(PKI_ERROR_ENGINE_CLASS[e.code], e.code).toBe(e.class);
        const classes = new Set(Object.values(PKI_ERROR_CLASS));
        for (const c of classes) expect(['usage', 'input', 'parse', 'security', 'limit', 'unsupported', 'crypto', 'password', 'check', 'internal']).toContain(c);
        expect(PKI_ERROR_CLASS.PKI_LIMIT_EXCEEDED).toBe('limit');
        expect(PKI_ERROR_CLASS.PKI_CRYPTO_DECRYPTION_FAILED).toBe('password');
        expect(PKI_ERROR_CLASS.PKI_KEY_ENCRYPTION_UNSUPPORTED).toBe('security');
    });

    it('PKI_REASON_CODES (43) and PKI_DIAGNOSTIC_CODES (97) match the vendored registries', () => {
        const reasons = registry<{ code: string }>('reasons.json', 'reasons');
        const diagnostics = registry<{ code: string }>('diagnostics.json', 'diagnostics');
        expect(reasons).toHaveLength(43);
        expect(diagnostics).toHaveLength(97);
        expect([...PKI_REASON_CODES]).toEqual(reasons.map((r) => r.code));
        expect([...PKI_DIAGNOSTIC_CODES]).toEqual(diagnostics.map((d) => d.code));
        expect(PKI_REASON_CODES.every((c) => c.startsWith('PKI_REASON_'))).toBe(true);
        expect(PKI_DIAGNOSTIC_CODES.every((c) => c.startsWith('PKI_DIAG_'))).toBe(true);
    });

    it('every remedy names a known code and reads as MCP inputs', () => {
        for (const [code, remedy] of Object.entries(PKI_REMEDY)) {
            expect(PKI_ERROR_CODES, code).toContain(code);
            expect(remedy.length, code).toBeGreaterThan(10);
        }
        expect(PKI_REMEDY.PKI_KEY_ENCRYPTION_UNSUPPORTED).toBe(LEGACY_PKCS12_REMEDY);
        expect(PKI_REMEDY.PKI_KEY_MAC_UNSUPPORTED).toBe(UNVERIFIED_INTEGRITY_REMEDY);
        expect(PKI_REMEDY.PKI_CRYPTO_DECRYPTION_FAILED).toBe(WRONG_PASSWORD_REMEDY);
        expect(LEGACY_PKCS12_REMEDY).toContain('openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2');
        expect(LEGACY_PKCS8_REMEDY).toContain('openssl pkcs8 -topk8 -v2 aes-256-cbc');
        expect(UNVERIFIED_INTEGRITY_REMEDY).toContain('allowUnverifiedIntegrity:true');
        expect(WRONG_PASSWORD_REMEDY).toContain('PKINATIVE_MCP_PASSWORD');
    });
});

describe('mapPkiError', () => {
    it('a real parse failure: the PKI_* code verbatim, errorClass parse, the engine class name, path / offset when known', () => {
        let caught: unknown;
        try {
            parseCertificate(GARBAGE, SILENT);
        } catch (err) {
            caught = err;
        }
        expect(caught).toBeInstanceOf(PkiCertificateError);
        const mapped = mapPkiError(caught, 'Cannot read the certificate');
        expect(mapped).toBeInstanceOf(ToolError);
        expect(mapped.code).toBe('PKI_X509_STRUCTURE_INVALID');
        expect(mapped.message.startsWith('Cannot read the certificate: pkinative: ')).toBe(true);
        expect(mapped.data).toMatchObject({ errorClass: 'parse', engineError: 'PkiCertificateError', offset: 0 });
        expect(mapped.data).not.toHaveProperty('remedy');
        expect(Object.keys(mapped.data ?? {}).sort()).toEqual(expect.arrayContaining(['errorClass', 'engineError', 'offset']));
        // A truncated DER: an encoding error with its offset.
        let enc: unknown;
        try {
            parseCertificate(new Uint8Array([0x30, 0x82, 0x01]), SILENT);
        } catch (err) {
            enc = err;
        }
        const encoding = mapPkiError(enc, 'ctx');
        expect(encoding.code).toMatch(/^PKI_ASN1_/);
        expect(encoding.data).toMatchObject({ errorClass: 'parse', engineError: 'PkiEncodingError' });
    });

    it('a PkiLimitError carries limit / configured / observed, and env for a ceiling-backed limit', () => {
        let depth: unknown;
        try {
            parseCertificate(fixtureBytes('leaf.crt.der'), { ...SILENT, limits: { maxDepth: 1 } });
        } catch (err) {
            depth = err;
        }
        expect(depth).toBeInstanceOf(PkiLimitError);
        const mapped = mapPkiError(depth, 'ctx');
        expect(mapped.code).toBe('PKI_LIMIT_EXCEEDED');
        expect(mapped.data).toEqual({ errorClass: 'limit', engineError: 'PkiLimitError', limit: 'maxDepth', configured: 1, observed: 2, remedy: PKI_REMEDY.PKI_LIMIT_EXCEEDED });
        expect(mapped.data).not.toHaveProperty('env');
        let input: unknown;
        try {
            parseCertificate(fixtureBytes('leaf.crt.der'), { ...SILENT, limits: { maxInputBytes: 10 } });
        } catch (err) {
            input = err;
        }
        expect(mapPkiError(input, 'ctx').data).toMatchObject({ limit: 'maxInputBytes', configured: 10, observed: 701, env: MAX_INPUT_BYTES_ENV });
        for (const [limit, env] of [['maxKdfIterations', MAX_KDF_ITERATIONS_ENV], ['maxPkcs12KdfIterations', MAX_KDF_ITERATIONS_ENV], ['maxPathsExplored', MAX_PATHS_EXPLORED_ENV]]) {
            expect(mapPkiError(new PkiLimitError('PKI_LIMIT_EXCEEDED', 'x', limit as string, 1, 2), 'c').data?.['env'], limit).toBe(env);
        }
        expect(mapPkiError(new PkiLimitError('PKI_LIMIT_INVALID', 'x', 'limits', Number.NaN, Number.NaN), 'c').data).toMatchObject({ errorClass: 'usage', limit: 'limits' });
    });

    it('a PkiCryptoError carries the algorithm; the remedy table applies and a per-call override wins', () => {
        const refused = new PkiCryptoError('PKI_CRYPTO_ALGORITHM_REFUSED', 'pkinative: SHA-1 refused', '1.2.840.113549.1.1.5');
        const mapped = mapPkiError(refused, 'Cannot verify');
        expect(mapped.code).toBe('PKI_CRYPTO_ALGORITHM_REFUSED');
        expect(mapped.data).toEqual({ errorClass: 'security', engineError: 'PkiCryptoError', algorithm: '1.2.840.113549.1.1.5', remedy: PKI_REMEDY.PKI_CRYPTO_ALGORITHM_REFUSED });
        expect(mapped.data?.['remedy']).toContain('allowSha1:true');
        expect(mapPkiError(refused, 'c', { PKI_CRYPTO_ALGORITHM_REFUSED: 'custom advice' }).data?.['remedy']).toBe('custom advice');
        expect(mapPkiError(refused, 'c', { PKI_OID_INVALID: 'unrelated' }).data?.['remedy']).toBe(PKI_REMEDY.PKI_CRYPTO_ALGORITHM_REFUSED);
        const noAlgorithm = mapPkiError(new PkiCryptoError('PKI_CRYPTO_UNAVAILABLE', 'x'), 'c');
        expect(noAlgorithm.data).toEqual({ errorClass: 'crypto', engineError: 'PkiCryptoError' });
        // A code the table does not know (an engine minor) is classed internal rather than dropped.
        const future = new PkiError('PKI_FUTURE_CODE' as PkiErrorCode, 'pkinative: new');
        expect(mapPkiError(future, 'c')).toMatchObject({ code: 'PKI_FUTURE_CODE', data: { errorClass: 'internal', engineError: 'PkiError' } });
    });

    it('a filesystem error is IO_ERROR with the errno only (no OS message, no path)', () => {
        const enoent = Object.assign(new Error("ENOENT: no such file or directory, open '/secret/place/x.crt'"), { code: 'ENOENT' });
        const mapped = mapPkiError(enoent, 'Cannot read the input');
        expect(mapped.code).toBe('IO_ERROR');
        expect(mapped.message).toBe('Cannot read the input: ENOENT');
        expect(mapped.data).toEqual({ errno: 'ENOENT' });
        expect(isFsError(enoent)).toBe(true);
        expect(isFsError(Object.assign(new Error('x'), { code: 'EACCES' }))).toBe(true);
        expect(isFsError(Object.assign(new Error('x'), { code: 'ERR_INVALID_ARG_TYPE' }))).toBe(false);
        expect(isFsError(Object.assign(new Error('x'), { code: 42 }))).toBe(false);
        expect(isFsError(new Error('x'))).toBe(false);
        expect(isFsError('ENOENT')).toBe(false);
        expect(isFsError(null)).toBe(false);
    });

    it('a ToolError passes through unchanged; anything else is ENGINE_ERROR classed internal', () => {
        const tool = new ToolError('VALIDATION_ERROR', 'x', { a: 1 });
        expect(mapPkiError(tool, 'c')).toBe(tool);
        const security = new SecurityError('nope');
        expect(mapPkiError(security, 'c')).toBe(security);
        const type = mapPkiError(new TypeError('boom'), 'Cannot import');
        expect(type.code).toBe('ENGINE_ERROR');
        expect(type.message).toBe('Cannot import: boom');
        expect(type.data).toEqual({ errorClass: 'internal', engineError: 'TypeError' });
        expect(mapPkiError('a string', 'c')).toMatchObject({ code: 'ENGINE_ERROR', message: 'c: a string', data: { errorClass: 'internal', engineError: 'string' } });
        expect(mapPkiError(undefined, 'c')).toMatchObject({ code: 'ENGINE_ERROR', data: { engineError: 'undefined' } });
    });
});

describe('guard / guardAsync / isPkiCode', () => {
    it('guard returns the value or translates the throw; the remedies reach the mapping', () => {
        expect(guard('c', () => 42)).toBe(42);
        let err: ToolError | undefined;
        try {
            guard('Cannot read', () => parseCertificate(GARBAGE, SILENT), { PKI_X509_STRUCTURE_INVALID: 'pass a certificate' });
        } catch (e) {
            err = e as ToolError;
        }
        expect(err?.code).toBe('PKI_X509_STRUCTURE_INVALID');
        expect(err?.data?.['remedy']).toBe('pass a certificate');
        expect(() => guard('c', () => { throw new ToolError('NOT_FOUND', 'x'); })).toThrow(expect.objectContaining({ code: 'NOT_FOUND' }));
        expect(() => guard('c', () => { throw new RangeError('r'); })).toThrow(expect.objectContaining({ code: 'ENGINE_ERROR' }));
    });

    it('guardAsync does the same for promises and for a synchronous throw inside the thunk', async () => {
        await expect(guardAsync('c', () => Promise.resolve('ok'))).resolves.toBe('ok');
        await expect(guardAsync('Cannot open', () => Promise.reject(new PkiCryptoError('PKI_CRYPTO_DECRYPTION_FAILED', 'pkinative: bad')))).rejects.toMatchObject({ code: 'PKI_CRYPTO_DECRYPTION_FAILED', data: { errorClass: 'password', remedy: WRONG_PASSWORD_REMEDY } });
        await expect(guardAsync('c', () => { throw new Error('sync'); })).rejects.toMatchObject({ code: 'ENGINE_ERROR', message: 'c: sync' });
        await expect(guardAsync('c', () => Promise.reject(Object.assign(new Error('x'), { code: 'EISDIR' })))).rejects.toMatchObject({ code: 'IO_ERROR', data: { errno: 'EISDIR' } });
    });

    it('isPkiCode is true for the engine error carrying that code only', () => {
        const limit = new PkiLimitError('PKI_LIMIT_EXCEEDED', 'x', 'maxDepth', 1, 2);
        expect(isPkiCode(limit, 'PKI_LIMIT_EXCEEDED')).toBe(true);
        expect(isPkiCode(limit, 'PKI_LIMIT_INVALID')).toBe(false);
        expect(isPkiCode(new ToolError('PKI_LIMIT_EXCEEDED', 'x'), 'PKI_LIMIT_EXCEEDED')).toBe(false);
        expect(isPkiCode(Object.assign(new Error('x'), { code: 'PKI_LIMIT_EXCEEDED' }), 'PKI_LIMIT_EXCEEDED')).toBe(false);
        expect(isPkiCode(null, 'PKI_LIMIT_EXCEEDED')).toBe(false);
    });
});

describe('pkcs12Failure', () => {
    const reason = (code: string): { code: string } => ({ code });

    it('an RSA key without a scheme is RSA_SCHEME_REQUIRED (checked first)', () => {
        const err = pkcs12Failure({ integrity: 'verified', reasons: [reason('PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED'), reason('PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED')] });
        expect(err.code).toBe('RSA_SCHEME_REQUIRED');
        expect(err.data).toEqual({ reasons: [reason('PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED'), reason('PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED')], remedy: "rsaScheme:'pkcs1'|'pss'" });
    });

    it('a legacy cipher is PKI_KEY_ENCRYPTION_UNSUPPORTED (security) with the conversion, even when the integrity is also unverified', () => {
        const reasons = [reason('PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED'), reason('PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED'), reason('PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED')];
        const err = pkcs12Failure({ integrity: 'unverified', reasons });
        expect(err.code).toBe('PKI_KEY_ENCRYPTION_UNSUPPORTED');
        expect(err.message).toContain('PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED, PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED');
        expect(err.message).not.toContain('UNSUPPORTED, PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED');
        expect(err.data).toEqual({ reasons, errorClass: 'security', remedy: LEGACY_PKCS12_REMEDY });
    });

    it('a MAC mismatch is PKI_CRYPTO_DECRYPTION_FAILED (password)', () => {
        const err = pkcs12Failure({ integrity: 'mismatch', reasons: [reason('PKI_REASON_PKCS12_MAC_MISMATCH')] });
        expect(err.code).toBe('PKI_CRYPTO_DECRYPTION_FAILED');
        expect(err.message).toContain('the password is wrong');
        expect(err.data).toEqual({ reasons: [reason('PKI_REASON_PKCS12_MAC_MISMATCH')], errorClass: 'password', remedy: WRONG_PASSWORD_REMEDY });
    });

    it('an unverifiable integrity is ENGINE_VERDICT with the allowUnverifiedIntegrity remedy; anything else is ENGINE_VERDICT with the reasons', () => {
        const unverified = pkcs12Failure({ integrity: 'unverified', reasons: [reason('PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED')] });
        expect(unverified.code).toBe('ENGINE_VERDICT');
        expect(unverified.message).toBe('The PKCS#12 integrity cannot be verified: PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED.');
        expect(unverified.data).toEqual({ reasons: [reason('PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED')], remedy: UNVERIFIED_INTEGRITY_REMEDY });
        const other = pkcs12Failure({ integrity: 'verified', reasons: [reason('PKI_REASON_INPUT_MALFORMED'), reason('PKI_REASON_INPUT_MALFORMED')] });
        expect(other.code).toBe('ENGINE_VERDICT');
        expect(other.message).toBe('The PKCS#12 file did not open: PKI_REASON_INPUT_MALFORMED.');
        expect(other.data).toEqual({ reasons: [reason('PKI_REASON_INPUT_MALFORMED'), reason('PKI_REASON_INPUT_MALFORMED')] });
        expect(other.data).not.toHaveProperty('remedy');
        expect(pkcs12Failure({ integrity: 'verified', reasons: [] }).message).toBe('The PKCS#12 file did not open: .');
    });
});
