/**
 * Tests for `inspect_timestamp` — the response, token and TSTInfo views,
 * auto-detection and `as`, the strict escalation, projection, path inputs,
 * every error code.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { parseTimeStampToken } from 'pkinative';

import { callToolDirect } from '../src/server.js';
import { inspectTimestamp, inspectTimestampSummary, INSPECT_TIMESTAMP_TOOL } from '../src/tools/inspect-timestamp.js';
import { codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBytes, fixtureInput } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const CONTENT_SHA256 = 'b1a1c762480b580288e0737422f01130e824c8014422371ae571880dfc642533';
/** TimeStampResp { status { rejection (2) } } */
const REJECTION = { derBase64: Buffer.from('30053003020102', 'hex').toString('base64') };
const TST_INFO = { derBase64: Buffer.from(parseTimeStampToken(fixtureBytes('content.tst'), { onDiagnostic: () => undefined }).tstInfo.der).toString('base64') };

const EXPECTED_TST_INFO = {
    version: 1,
    policy: { oid: '1.3.6.1.4.1.99999.1', name: null },
    messageImprint: { hashAlgorithm: { oid: '2.16.840.1.101.3.4.2.1', name: 'sha256', hasParameters: true }, hashedMessage: CONTENT_SHA256 },
    serialNumber: { hex: '02', decimal: '2' },
    genTime: { type: 'GeneralizedTime', epochMilliseconds: 1791140735000, iso: '2026-10-04T19:05:35.000Z', text: '20261004190535Z' },
    accuracy: { seconds: 1, millis: 0, micros: 0 },
    ordering: false,
    nonce: '672214778591974456',
    tsa: { kind: 'directoryName', name: expect.stringContaining('CN=Test TSA') },
    extensions: [],
};

describe('inspect_timestamp', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('views', () => {
        it('reads a granted response: status, the token, its envelope, the OpenSSL SET diagnostic', async () => {
            const r = await inspectTimestamp({ input: fixtureInput('content.tsr') });
            expect(r.as).toBe('response');
            expect(r.status).toEqual({ status: 'granted', statusStrings: [], failInfo: [] });
            expect(r.token?.tstInfo).toEqual(EXPECTED_TST_INFO);
            expect(r.token?.signerInfos).toBe(1);
            expect(r.token?.certificates.map((c) => c.serialNumber)).toEqual(['1005', '02']);
            expect(r.tstInfo).toBeUndefined();
            expect(r.sizeBytes).toBe(fixtureBytes('content.tsr').length);
            expect(r.diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_CMS_SET_NOT_SORTED']);
        });

        it('reads a bare token and a bare TSTInfo, auto-detected and forced', async () => {
            const token = await inspectTimestamp({ input: fixtureInput('content.tst') });
            expect(token.as).toBe('token');
            expect(token.status).toBeUndefined();
            expect(token.token?.tstInfo).toEqual(EXPECTED_TST_INFO);
            expect((await inspectTimestamp({ input: fixtureInput('content.tst'), as: 'token' })).as).toBe('token');
            const info = await inspectTimestamp({ input: TST_INFO });
            expect(info.as).toBe('tstinfo');
            expect(info.tstInfo).toEqual(EXPECTED_TST_INFO);
            expect(info.token).toBeUndefined();
            expect((await inspectTimestamp({ input: TST_INFO, as: 'tstinfo' })).as).toBe('tstinfo');
        });

        it('reads a declined response (no token)', async () => {
            const r = await inspectTimestamp({ input: REJECTION });
            expect(r).toMatchObject({ as: 'response', status: { status: 'rejection', statusStrings: [], failInfo: [] }, sizeBytes: 7 });
            expect(r.token).toBeUndefined();
        });
    });

    describe('strict', () => {
        it('surfaces the strict refusal through the auto-detection and through as', async () => {
            expect(await codeOf(inspectTimestamp({ input: fixtureInput('content.tst'), strict: true }))).toBe('PKI_STRICT_DIAGNOSTIC');
            expect(await codeOf(inspectTimestamp({ input: fixtureInput('content.tst'), as: 'token', strict: true }))).toBe('PKI_STRICT_DIAGNOSTIC');
            expect(await codeOf(inspectTimestamp({ input: REJECTION, strict: true }))).toBe('OK');
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars', async () => {
            const r = await inspectTimestamp({ input: fixtureInput('content.tsr') });
            expect(inspectTimestampSummary(r)).toEqual({ as: 'response', statusCode: 'granted', genTime: '2026-10-04T19:05:35.000Z', serialNumber: '02', imprintHex: CONTENT_SHA256, hashAlgorithm: 'sha256', diagnosticCount: 1 });
            expect(inspectTimestampSummary(await inspectTimestamp({ input: REJECTION }))).toEqual({ as: 'response', statusCode: 'rejection', diagnosticCount: 0 });
        });

        it('fields project over the wire', async () => {
            const result = await callToolDirect('inspect_timestamp', { input: fixtureInput('content.tst'), fields: ['as', 'token.tstInfo.genTime.iso', 'token.certificates.subject'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ as: 'token', token: { tstInfo: { genTime: { iso: '2026-10-04T19:05:35.000Z' } }, certificates: [{ subject: expect.stringContaining('CN=Test TSA') }, { subject: expect.stringContaining('CN=Test Intermediate CA') }] } });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('inspect_timestamp: TimeStampToken: sha256 b1a1c762480b5802… stamped at 2026-10-04T19:05:35.000Z') });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads a .tsr from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('content.tsr'), path.join(sandbox, 'content.tsr'));
            expect((await inspectTimestamp({ input: { path: 'content.tsr' } })).as).toBe('response');
            expect(await codeOf(inspectTimestamp({ input: { path: '../content.tsr' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(inspectTimestamp({ input: { path: 'content.exe' } }))).toBe('INVALID_EXTENSION');
        });
    });

    describe('refusals', () => {
        it.each([
            ['no input', {}],
            ['unknown as', { input: fixtureInput('content.tsr'), as: 'request' }],
            ['two input forms', { input: { derBase64: 'AAAA', path: 'x.tsr' } }],
            ['unknown key', { input: fixtureInput('content.tsr'), bogus: 1 }],
        ])('VALIDATION_ERROR: %s', async (_label, input) => {
            expect(await codeOf(inspectTimestamp(input))).toBe('VALIDATION_ERROR');
        });

        it('names the cause when the bytes are none of the three, and the exact refusal under as', async () => {
            const result = await callToolDirect('inspect_timestamp', { input: { derBase64: Buffer.from('0500', 'hex').toString('base64') } });
            expect(errorCodeOf(result)).toBe('PKI_CMS_STRUCTURE_INVALID');
            expect(result._meta?.['error']).toMatchObject({ message: expect.stringMatching(/not a TimeStampResp, a TimeStampToken or a TSTInfo/), data: { remedy: expect.stringMatching(/^as:/) } });
            expect(await codeOf(inspectTimestamp({ input: fixtureInput('content.tsq') }))).toBe('PKI_CMS_STRUCTURE_INVALID');
            expect(await codeOf(inspectTimestamp({ input: fixtureInput('content.tsq'), as: 'tstinfo' }))).toBe('PKI_ASN1_UNEXPECTED_TAG');
            expect(await codeOf(inspectTimestamp({ input: fixtureInput('content.tsr'), as: 'token' }))).toMatch(/^PKI_/);
        });

        it('a private key is refused and never echoed', async () => {
            const result = await callToolDirect('inspect_timestamp', { input: fixtureInput('leaf.key.pem') });
            expect(errorCodeOf(result)).toMatch(/^PKI_/);
            expect(JSON.stringify(result)).not.toContain('PRIVATE KEY-----\\n');
        });
    });

    describe('definition', () => {
        it('is read-only, cacheable, with two examples', () => {
            expect(INSPECT_TIMESTAMP_TOOL.kind).toBe('read');
            expect(INSPECT_TIMESTAMP_TOOL.annotations.readOnlyHint).toBe(true);
            expect(INSPECT_TIMESTAMP_TOOL.cacheable).toBe(true);
            expect(INSPECT_TIMESTAMP_TOOL.examples?.length).toBe(2);
        });
    });
});
