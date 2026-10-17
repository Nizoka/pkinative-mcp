/**
 * Error-code inventory: every `ToolError('CODE', …)` literal in `src/` must be
 * (a) a wrapper code of src/wrapper-codes.ts or a frozen `PKI_*` code,
 * (b) documented in the error reference of docs/AGENT_CONTRACT.md §6 and
 * (c) exercised by at least one test under `tests/`; and every one of the
 * engine's 57 frozen `PKI_*` codes (passed through verbatim by
 * `src/pki-errors.ts`) must either be named by a test that reaches it or be
 * listed in `UNREACHABLE_THROUGH_WRAPPER` with the reason. The second half
 * of this file adds the targeted tests for the codes no tool suite reached
 * before: hand-built DER, PEM, X.509, CMS and PKCS#8 bytes through the tools.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

import { contractErrorRows } from '../scripts/lib/mcp-surface.js';
import { PKI_ERROR_CLASS, PKI_ERROR_CODES, PKI_REMEDY } from '../src/pki-errors.js';
import { callToolDirect, ensureEngineReady } from '../src/server.js';
import { WRAPPER_CODE_NAMES } from '../src/wrapper-codes.js';
import { fixtureBytes, fixtureInput, fixtureText } from './_pki-fixtures.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT = path.join(ROOT, 'docs', 'AGENT_CONTRACT.md');

function walk(dir: string, out: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const full = path.join(dir, entry);
        if (statSync(full).isDirectory()) walk(full, out);
        else if (entry.endsWith('.ts')) out.push(full);
    }
    return out;
}

/** Every `ToolError('CODE'` / `ToolError(\n 'CODE'` literal under src/, de-duplicated, plus the fixed codes of the error subclasses. */
function collectSourceCodes(): string[] {
    const codes = new Set<string>();
    for (const file of walk(path.join(ROOT, 'src'))) {
        const text = readFileSync(file, 'utf8');
        for (const m of text.matchAll(/ToolError\(\s*'([A-Z][A-Z0-9_]+)'/g)) codes.add(m[1]!);
    }
    const errors = readFileSync(path.join(ROOT, 'src', 'errors.ts'), 'utf8');
    for (const m of errors.matchAll(/super\(\s*'([A-Z][A-Z0-9_]+)'/g)) codes.add(m[1]!);
    return [...codes].sort();
}

/**
 * Frozen engine codes no test reaches through this wrapper, with the reason.
 * "pre-empted" = no input can make the wrapper emit it (the boundary refuses
 * earlier with its own code); "not crafted" = a hand-built object would
 * reach it and the suite does not build one. Every other PKI_* code is named
 * by a test that reaches it.
 */
const UNREACHABLE_THROUGH_WRAPPER: Readonly<Record<string, string>> = {
    PKI_INVALID_INPUT: 'pre-empted: the engine raises it for a non-Uint8Array / non-string input; Zod and the PKI input fragment hand it bytes or text only',
    PKI_INVALID_OPTION: 'pre-empted: every engine option is bounded by the Zod schema (VALIDATION_ERROR) or fixed by the wrapper (encodingRules, pemMode, limits ≥ 1)',
    PKI_ASN1_LENGTH_OVERFLOW: 'observed: a 9-octet length field is reported as PKI_ASN1_TRUNCATED against the input size, so no inline DER under the 128 MiB cap reaches the overflow branch',
    PKI_PEM_LABEL_INVALID: 'pre-empted: on write the convert_pem / encode_asn1 label pattern refuses first (VALIDATION_ERROR); on read the engine accepts any label text and the reader reports PKI_PEM_UNEXPECTED_LABEL instead',
    PKI_X509_NAME_INVALID: 'not crafted: needs a certificate whose Name is not a SEQUENCE OF SET OF AttributeTypeAndValue; every fixture name is well-formed',
    PKI_X509_VALIDITY_INVALID: 'not crafted: needs a Validity that is not two Time values; every fixture validity is UTCTime pairs',
    PKI_X509_UNIQUE_ID_INVALID: 'not crafted: needs a malformed issuerUniqueID / subjectUniqueID BIT STRING; no fixture carries one',
    PKI_X509_EXTENSIONS_EMPTY: 'not crafted: needs an extensions [3] SEQUENCE with no element; OpenSSL never writes one',
    PKI_X509_EXTENSION_DUPLICATE: 'not crafted: needs a certificate carrying the same extension OID twice; OpenSSL refuses to write one',
    PKI_X509_GENERAL_NAME_INVALID: 'not crafted: needs a GeneralName with an unknown CHOICE tag or a malformed IP address octet string inside a certificate; the check_certificate_name ip input is validated by the wrapper first',
    PKI_CRYPTO_ALGORITHM_UNSUPPORTED: 'not crafted: needs a signature or digest OID the engine does not know (a GOST or SM2 certificate); every fixture is ECDSA P-256, RSA or Ed25519',
    PKI_CRYPTO_KEY_UNSUPPORTED: 'not crafted: needs a key the host Web Crypto cannot import (a brainpool curve, Ed448 on a host without it); the wrapper reports UNSUPPORTED_KEY for the kinds it recognises first',
    PKI_CMS_VERSION_UNSUPPORTED: 'not crafted: needs a SignedData / SignerInfo with a version above those RFC 5652 defines; OpenSSL writes v1 / v3 only',
    PKI_CMS_CONTENT_NOT_OCTET_STRING: 'not crafted: needs an encapContentInfo whose eContent is not an OCTET STRING; OpenSSL writes OCTET STRING (BER constructed under -stream)',
    PKI_KEY_VERSION_UNSUPPORTED: 'reached below (a PKCS#8 version 7); listed for the inventory of the key family',
};
delete (UNREACHABLE_THROUGH_WRAPPER as Record<string, string>)['PKI_KEY_VERSION_UNSUPPORTED'];

describe('ToolError code inventory', () => {
    const codes = collectSourceCodes();
    const tests = walk(path.join(ROOT, 'tests'))
        .filter((f) => !f.endsWith('error-codes.test.ts'))
        .map((f) => ({ file: path.basename(f), text: readFileSync(f, 'utf8') }));
    const thisFile = readFileSync(fileURLToPath(import.meta.url), 'utf8');
    const targeted = thisFile.slice(thisFile.indexOf("describe('previously uncovered codes"));

    it('finds the wrapper vocabulary plus the PKI_* literals the tools raise themselves', () => {
        expect(codes.length).toBeGreaterThanOrEqual(WRAPPER_CODE_NAMES.length);
        for (const c of WRAPPER_CODE_NAMES) expect(codes, c).toContain(c);
        // Every non-wrapper literal is one of the engine's frozen codes (never an invented one).
        for (const c of codes) {
            if (!WRAPPER_CODE_NAMES.includes(c)) expect(PKI_ERROR_CODES as readonly string[], `${c} is neither a wrapper code nor a frozen PKI_* code`).toContain(c);
        }
        expect(WRAPPER_CODE_NAMES).toHaveLength(21);
    });

    it.skipIf(!existsSync(CONTRACT))('documents every wrapper code and every source literal in docs/AGENT_CONTRACT.md §6 (the error-table rows)', () => {
        const rows = contractErrorRows(readFileSync(CONTRACT, 'utf8'));
        expect(rows.length, 'docs/AGENT_CONTRACT.md has a "## 6." error reference with `CODE` rows').toBeGreaterThan(0);
        const missing = [...new Set([...codes, ...WRAPPER_CODE_NAMES])].filter((c) => !rows.includes(c));
        expect(missing, `codes missing from docs/AGENT_CONTRACT.md §6: ${missing.join(', ')}`).toEqual([]);
    });

    it('exercises every wrapper code in at least one test under tests/', () => {
        // The targeted tests below count too, but only their describe/it bodies — not this inventory list.
        const missing = WRAPPER_CODE_NAMES.filter((c) => !tests.some((t) => t.text.includes(c)) && !targeted.includes(c));
        expect(missing, `wrapper codes without a test that names them: ${missing.join(', ')}`).toEqual([]);
    });

    it('every frozen PKI_* code is either reached by a test or declared unreachable with a reason', () => {
        expect(PKI_ERROR_CODES).toHaveLength(57);
        expect(Object.keys(PKI_ERROR_CLASS)).toEqual([...PKI_ERROR_CODES]);
        const named = (c: string): boolean => tests.some((t) => t.text.includes(c)) || targeted.includes(c);
        const missing = PKI_ERROR_CODES.filter((c) => !named(c) && !(c in UNREACHABLE_THROUGH_WRAPPER));
        expect(missing, `PKI_* codes neither named by a test nor declared unreachable: ${missing.join(', ')}`).toEqual([]);
        // The unreachable list must not hide a code a targeted test actually reaches.
        const contradicted = Object.keys(UNREACHABLE_THROUGH_WRAPPER).filter((c) => targeted.includes(`'${c}'],`) || targeted.includes(`toBe('${c}')`));
        expect(contradicted).toEqual([]);
        for (const [code, reason] of Object.entries(UNREACHABLE_THROUGH_WRAPPER)) {
            expect(PKI_ERROR_CODES as readonly string[], code).toContain(code);
            expect(reason.length, code).toBeGreaterThan(40);
            expect(reason).toMatch(/^(?:pre-empted|not crafted|observed):/);
        }
    });
});

/* -------------------------------------------------------------------------- */
/* Targeted tests for codes no tool suite reached before                      */
/* -------------------------------------------------------------------------- */

interface Refusal {
    readonly code: string;
    readonly message: string;
    readonly data: Record<string, unknown> | undefined;
}

async function refusal(tool: string, args: Record<string, unknown>): Promise<Refusal> {
    const r = await callToolDirect(tool, args);
    expect(r.isError, `${tool} should refuse: ${String(JSON.stringify(r.structuredContent)).slice(0, 200)}`).toBe(true);
    const err = (r._meta as { error: { code: string; message: string; data?: Record<string, unknown> } }).error;
    expect((r.content[0] as { text: string }).text).toBe(`${tool} failed [${err.code}]: ${err.message}`);
    return { code: err.code, message: err.message, data: err.data };
}

const b64 = (bytes: readonly number[] | Uint8Array): string => Buffer.from(bytes).toString('base64');
const der = (bytes: readonly number[]): { derBase64: string } => ({ derBase64: b64(bytes) });

describe('previously uncovered codes', () => {
    beforeAll(async () => {
        await ensureEngineReady();
    });

    it('ASN.1 family: every structural refusal of decode_asn1 is the frozen code with errorClass parse, and the BER ones name the remedy', async () => {
        const cases: Array<[string, Record<string, unknown>]> = [
            ['PKI_ASN1_TAG_INVALID', { input: der([0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]) }],
            ['PKI_ASN1_LENGTH_INVALID', { input: der([0x30, 0xff]) }],
            ['PKI_ASN1_LENGTH_NON_MINIMAL', { input: der([0x04, 0x81, 0x05, 1, 2, 3, 4, 5]) }],
            ['PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN', { input: der([0x30, 0x80, 0x05, 0x00, 0x00, 0x00]) }],
            ['PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN', { input: der([0x24, 0x04, 0x04, 0x02, 0xaa, 0xbb]) }],
            ['PKI_ASN1_CONSTRUCTED_FORM_INVALID', { input: der([0x10, 0x00]) }],
            ['PKI_ASN1_CONSTRUCTED_FORM_INVALID', { input: der([0x22, 0x03, 0x02, 0x01, 0x05]) }],
            ['PKI_ASN1_EOC_UNEXPECTED', { input: der([0x30, 0x02, 0x00, 0x00]) }],
            ['PKI_ASN1_EOC_UNEXPECTED', { input: der([0x00, 0x00]) }],
            ['PKI_ASN1_TRUNCATED', { input: der([0x30, 0x05, 0x02, 0x01]) }],
            ['PKI_ASN1_TRAILING_DATA', { input: der([0x05, 0x00, 0x05, 0x00]) }],
            ['PKI_ASN1_UNEXPECTED_TAG', { input: der([0x02, 0x01, 0x05]), read: 'boolean' }],
            ['PKI_ASN1_BOOLEAN_INVALID', { input: der([0x01, 0x01, 0x01]), read: 'boolean' }],
            ['PKI_ASN1_BOOLEAN_INVALID', { input: der([0x01, 0x02, 0xff, 0xff]), read: 'boolean' }],
            ['PKI_ASN1_INTEGER_INVALID', { input: der([0x02, 0x00]), read: 'integer' }],
            ['PKI_ASN1_INTEGER_INVALID', { input: der([0x02, 0x02, 0x00, 0x7f]), read: 'integer' }],
            ['PKI_ASN1_INTEGER_UNREPRESENTABLE', { input: der([0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]), read: 'small-integer' }],
            ['PKI_ASN1_BIT_STRING_INVALID', { input: der([0x03, 0x00]), read: 'bit-string' }],
            ['PKI_ASN1_BIT_STRING_INVALID', { input: der([0x03, 0x02, 0x08, 0xff]), read: 'bit-string' }],
            ['PKI_ASN1_NULL_INVALID', { input: der([0x05, 0x01, 0x00]), read: 'null' }],
            ['PKI_ASN1_STRING_INVALID', { input: der([0x0c, 0x02, 0xc3, 0x28]), read: 'string' }],
            ['PKI_ASN1_TIME_INVALID', { input: der([0x17, 0x03, 0x31, 0x32, 0x5a]), read: 'time' }],
            ['PKI_OID_INVALID', { input: der([0x06, 0x02, 0x80, 0x01]), read: 'oid' }],
            ['PKI_OID_INVALID', { input: der([0x06, 0x00]), read: 'oid' }],
        ];
        for (const [expected, args] of cases) {
            const err = await refusal('decode_asn1', args);
            expect(err.code, JSON.stringify(args)).toBe(expected);
            expect(err.data?.['errorClass'], expected).toBe(PKI_ERROR_CLASS[expected as keyof typeof PKI_ERROR_CLASS]);
            expect(err.data?.['engineError'], expected).toBe('PkiEncodingError');
            expect(err.message).toContain('pkinative:');
            if (expected in PKI_REMEDY) expect(err.data?.['remedy'], expected).toBe(PKI_REMEDY[expected as keyof typeof PKI_REMEDY]);
        }
        // The same BER constructs are accepted under encodingRules:'ber' (with PKI_DIAG_BER_CONSTRUCT_ACCEPTED, tests/diagnostics-inventory).
        const ber = await callToolDirect('decode_asn1', { input: der([0x24, 0x04, 0x04, 0x02, 0xaa, 0xbb]), encodingRules: 'ber' });
        expect(ber.isError).not.toBe(true);
        // A 9-octet length is reported as PKI_ASN1_TRUNCATED, never PKI_ASN1_LENGTH_OVERFLOW (the inventory above says so).
        expect((await refusal('decode_asn1', { input: der([0x30, 0x89, 1, 1, 1, 1, 1, 1, 1, 1, 1]) })).code).toBe('PKI_ASN1_TRUNCATED');
    });

    it('PEM family: no block, unterminated, label mismatch, bad base64 (with the lax remedy), RFC 1421 headers, the wrong label for the reader', async () => {
        const pem = (text: string): { pem: string } => ({ pem: text });
        expect((await refusal('decode_asn1', { input: pem('-----BEGIN CERTIFICATE') })).code).toBe('PKI_PEM_NO_BLOCK');
        expect((await refusal('decode_asn1', { input: pem('-----BEGIN CERTIFICATE-----\nMIIB\n') })).code).toBe('PKI_PEM_UNTERMINATED');
        expect((await refusal('decode_asn1', { input: pem('-----BEGIN CERTIFICATE-----\nMIIB\n-----END KEY-----\n') })).code).toBe('PKI_PEM_LABEL_MISMATCH');
        const base64 = await refusal('decode_asn1', { input: pem('-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n') });
        expect(base64.code).toBe('PKI_PEM_BASE64_INVALID');
        expect(base64.data?.['remedy']).toBe(PKI_REMEDY.PKI_PEM_BASE64_INVALID);
        const headers = await refusal('decode_asn1', { input: pem('-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nBQA=\n-----END CERTIFICATE-----\n') });
        expect(headers.code).toBe('PKI_PEM_HEADERS_FORBIDDEN');
        expect(headers.data?.['errorClass']).toBe('unsupported');
        // A certificate handed to a reader of another kind: the wrapper names the labels present.
        for (const [tool, args] of [
            ['inspect_csr', { request: fixtureInput('leaf.crt.pem') }],
            ['inspect_crl', { crl: fixtureInput('leaf.crt.pem') }],
            ['inspect_private_key', { key: fixtureInput('leaf.crt.pem') }],
        ] as const) {
            const err = await refusal(tool, args);
            expect(err.code, tool).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(err.data?.['errorClass'], tool).toBe('input');
            expect(err.message, tool).toContain('labels present: CERTIFICATE');
        }
        // A pem that does not start with -----BEGIN is refused by the input fragment before the engine sees it.
        expect((await refusal('decode_asn1', { input: pem('hello world this is not pem at all') })).code).toBe('VALIDATION_ERROR');
    });

    it('X.509 family: structure, version and extension refusals, in every reader that parses a certificate-shaped object', async () => {
        const leaf = fixtureBytes('leaf.crt.der');
        expect((await refusal('inspect_certificate', { certificate: der([0x05, 0x00]) })).code).toBe('PKI_X509_STRUCTURE_INVALID');
        expect((await refusal('inspect_certificate', { certificate: der([0x30, 0x00]) })).code).toBe('PKI_X509_STRUCTURE_INVALID');
        // The version is the [0] EXPLICIT INTEGER at the head of tbsCertificate: a0 03 02 01 02.
        let at = -1;
        for (let i = 0; i < 40; i++) {
            if (leaf[i] === 0xa0 && leaf[i + 1] === 0x03 && leaf[i + 2] === 0x02 && leaf[i + 3] === 0x01 && leaf[i + 4] === 0x02) { at = i + 4; break; }
        }
        expect(at).toBeGreaterThan(0);
        const v6 = new Uint8Array(leaf);
        v6[at] = 0x05;
        const version = await refusal('inspect_certificate', { certificate: { derBase64: b64(v6) } });
        expect(version.code).toBe('PKI_X509_VERSION_INVALID');
        expect(version.data).toMatchObject({ errorClass: 'parse', engineError: 'PkiCertificateError' });
        expect(typeof version.data?.['offset']).toBe('number');
        // The same bytes handed to the other certificate-shaped readers.
        expect((await refusal('inspect_crl', { crl: { derBase64: b64(leaf) } })).code).toBe('PKI_X509_STRUCTURE_INVALID');
        expect((await refusal('inspect_ocsp_response', { response: { derBase64: b64(leaf) } })).code).toBe('PKI_X509_STRUCTURE_INVALID');
        expect((await refusal('inspect_csr', { request: { derBase64: b64(leaf) } })).code).toBe('PKI_X509_STRUCTURE_INVALID');
        const malformed = await refusal('decode_extension', { oid: '2.5.29.19', valueHex: '3003' });
        expect(malformed.code).toBe('PKI_X509_EXTENSION_MALFORMED');
        // decode_extension overrides the table remedy at its call site (there is no certificate to re-read with rawExtensions).
        expect(malformed.data?.['remedy']).toContain('decode_asn1');
        expect(PKI_REMEDY.PKI_X509_EXTENSION_MALFORMED).toContain('decode_asn1');
    });

    it('CMS family: a non-ContentInfo and a ContentInfo that is not id-signedData', async () => {
        const leaf = fixtureBytes('leaf.crt.der');
        const structure = await refusal('inspect_cms', { signedData: { derBase64: b64(leaf) } });
        expect(structure.code).toBe('PKI_CMS_STRUCTURE_INVALID');
        expect(structure.data).toMatchObject({ errorClass: 'parse', engineError: 'PkiCmsError' });
        expect((await refusal('inspect_timestamp', { input: { derBase64: b64(leaf) }, as: 'token' })).code).toBe('PKI_CMS_STRUCTURE_INVALID');
        // ContentInfo { id-data, [0] NULL }: the right shape, the wrong content type.
        const idData = der([0x30, 0x0f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x02, 0x05, 0x00]);
        const contentType = await refusal('inspect_cms', { signedData: idData });
        expect(contentType.code).toBe('PKI_CMS_CONTENT_TYPE_UNEXPECTED');
        expect(contentType.data?.['errorClass']).toBe('input');
        expect(contentType.message).toContain('1.2.840.113549.1.7.1');
        // ContentInfo { id-signedData, [0] NULL }: the content is not a SignedData SEQUENCE.
        const garbage = der([0x30, 0x0f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0, 0x02, 0x05, 0x00]);
        expect((await refusal('inspect_cms', { signedData: garbage })).code).toBe('PKI_CMS_STRUCTURE_INVALID');
    });

    it('key family: a PKCS#8 that is not one, an unsupported PKCS#8 version, a PKCS#12 that is not one', async () => {
        const structure = await refusal('inspect_private_key', { key: der([0x30, 0x03, 0x02, 0x01, 0x00]) });
        expect(structure.code).toBe('PKI_KEY_STRUCTURE_INVALID');
        expect(structure.data).toMatchObject({ errorClass: 'parse', engineError: 'PkiKeyError' });
        expect(structure.message).toContain('openssl pkcs8 -topk8');
        const version = await refusal('inspect_private_key', { key: der([0x30, 0x05, 0x02, 0x01, 0x07, 0x30, 0x00]) });
        expect(version.code).toBe('PKI_KEY_VERSION_UNSUPPORTED');
        expect(version.data?.['errorClass']).toBe('unsupported');
        const p12 = await refusal('inspect_pkcs12', { pkcs12: der([0x30, 0x03, 0x02, 0x01, 0x03]) });
        expect(p12.code).toBe('PKI_KEY_STRUCTURE_INVALID');
        expect(p12.message).toContain('PKCS#12');
    });

    it('every targeted refusal carries the frozen code verbatim and a class the table knows', async () => {
        const err = await refusal('decode_asn1', { input: { pem: fixtureText('leaf.crt.pem').replace(/\n-----END/, 'x\n-----END') } });
        expect(PKI_ERROR_CODES as readonly string[]).toContain(err.code);
        expect(Object.values(PKI_ERROR_CLASS)).toContain(err.data?.['errorClass']);
    });
});
