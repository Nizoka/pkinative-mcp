/**
 * A2-008 — Reproducible output, proven on the BUILT server across time zones.
 *
 * Every instant the server writes is UTC (the engine encodes UTCTime /
 * GeneralizedTime from the pinned instant, never from a local rendering), so
 * a pinned artefact must be the same bytes on every host. Unit tests cannot
 * show that: vitest pins TZ=UTC for the whole run. This suite spawns
 * `dist/cli.js` under two real zones, 23 hours apart and on opposite sides
 * of the date line — Pacific/Kiritimati (UTC+14) and America/Anchorage
 * (UTC-9 in January) — drives the same deterministic `create_certificate`
 * (Ed25519 signer, pinned notBefore, explicit serial) and
 * `create_timestamp_request` (fixed nonce) through each, and compares the
 * bytes with each other and with the in-process UTC call.
 *
 * Requires `npm run build`; skipped locally when dist/ is absent, like
 * tests/cli-stdio.test.ts, and a hard failure under CI.
 */
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { callToolDirect } from '../src/server.js';
import { expectCleanStdioExit, hasDist, inCi, openAgent, type AgentCallToolResult } from './_agent-client.js';
import { assertNoSecret, assertResultClean, assertValidDer } from './_pki-assert.js';
import { AT, fixtureText } from './_pki-fixtures.js';

/** UTC+14 and UTC-9: the pinned instant falls on 1 January in UTC, 1 January 14:00 in Kiritimati, 31 December 15:00 in Anchorage. */
const ZONES = ['Pacific/Kiritimati', 'America/Anchorage'] as const;
/** `getTimezoneOffset()` of the pinned instant under each zone (minutes behind UTC): proves the child really ran under it. */
const OFFSETS: Readonly<Record<(typeof ZONES)[number], number>> = { 'Pacific/Kiritimati': -840, 'America/Anchorage': 540 };
/** The summary renders instants as UTC ISO 8601 (`toISOString()`, milliseconds included) — never with a local offset. */
const UTC_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

/** The self-signed CA of examples/create-certificate-self-signed-ca.json, the key inline (no sandbox in this session). */
const CERTIFICATE = {
    spec: {
        serialNumber: 1,
        subject: { C: 'FR', O: 'Acme', CN: 'Acme Test CA' },
        notBefore: AT,
        validityDays: 3650,
        extensions: { basicConstraints: { ca: true, pathLen: 0 }, keyUsage: ['keyCertSign', 'cRLSign'] },
    },
    signer: { key: { pem: fixtureText('ed25519.key.pem') } },
    encoding: 'der',
};

/** The request of examples/create-timestamp-request-digest-hex.json, as DER. */
const TIMESTAMP_REQUEST = {
    digestHex: '00'.repeat(48),
    hashAlgorithm: 'SHA-384',
    nonce: '42',
    policy: '1.3.6.1.4.1.99999.1',
    certReq: false,
    encoding: 'der',
};

interface Artefacts {
    readonly certificate: Buffer;
    readonly request: Buffer;
    readonly summary: { notBefore: string; notAfter: string; notBeforeSource: string; serialNumber: string; randomSerial: boolean };
}

/** The embedded-resource bytes (blob for DER) of an artefact result. */
function blobOf(result: AgentCallToolResult): Buffer {
    expect(result.isError, (result.content[0] as { text?: string } | undefined)?.text).not.toBe(true);
    const block = result.content.find((c) => c.type === 'resource') as { resource?: { blob?: string; mimeType?: string } } | undefined;
    expect(block?.resource?.blob, 'an embedded resource blob').toBeTypeOf('string');
    return Buffer.from(block!.resource!.blob!, 'base64');
}

/** Drive the built server under `TZ=zone` and bring back the two artefacts. */
async function produceUnder(zone: (typeof ZONES)[number]): Promise<Artefacts> {
    const client = await openAgent('stdio-legacy', { env: { TZ: zone } });
    try {
        const certificate = await client.callTool('create_certificate', CERTIFICATE);
        assertResultClean(certificate, `create_certificate under ${zone}`);
        const request = await client.callTool('create_timestamp_request', TIMESTAMP_REQUEST);
        const summary = (certificate.structuredContent as { summary: Artefacts['summary'] }).summary;
        return { certificate: blobOf(certificate), request: blobOf(request), summary };
    } finally {
        const report = await client.close();
        expectCleanStdioExit(report);
        assertNoSecret(report.stderr, `stderr under ${zone}`);
        // stdout carried nothing but JSON-RPC frames.
        for (const line of report.stdoutLines) expect(() => JSON.parse(line), `stdout line under ${zone}: ${line.slice(0, 80)}`).not.toThrow();
    }
}

describe('dist/cli.js presence (reproducible-build)', () => {
    it.runIf(inCi)('is built before the test run in CI (build must precede test in every workflow)', () => {
        expect(hasDist, 'dist/cli.js is missing under CI — run `npm run build` before `npm test`').toBe(true);
    });
});

describe('the host honours TZ for a child process', () => {
    it.each(ZONES)('A2-008: a Node child under TZ=%s renders the pinned instant with that zone\'s offset', (zone) => {
        const probe = spawnSync(process.execPath, ['-p', `new Date(${JSON.stringify(AT)}).getTimezoneOffset()`], { encoding: 'utf8', env: { ...process.env, TZ: zone } });
        expect(probe.status).toBe(0);
        expect(Number(probe.stdout.trim())).toBe(OFFSETS[zone]);
    });
});

describe.skipIf(!hasDist)('the built server writes the same bytes under every time zone', () => {
    it('A2-008: a pinned create_certificate and create_timestamp_request are byte-identical under Pacific/Kiritimati and America/Anchorage, and equal the in-process UTC call', async () => {
        const [kiritimati, anchorage] = await Promise.all(ZONES.map(produceUnder));

        assertValidDer(new Uint8Array(kiritimati!.certificate));
        assertValidDer(new Uint8Array(kiritimati!.request));
        expect(kiritimati!.certificate.equals(anchorage!.certificate), 'certificate bytes differ between the two zones').toBe(true);
        expect(kiritimati!.request.equals(anchorage!.request), 'time-stamp request bytes differ between the two zones').toBe(true);

        // The instant is reported as UTC in both — not 14:00 in Kiritimati, not 31 December in Anchorage.
        for (const produced of [kiritimati!, anchorage!]) {
            expect(produced.summary.notBefore).toMatch(UTC_ISO);
            expect(produced.summary.notAfter).toMatch(UTC_ISO);
            expect(Date.parse(produced.summary.notBefore)).toBe(Date.parse(AT));
            expect(Date.parse(produced.summary.notAfter)).toBe(Date.parse('2036-12-29T00:00:00Z'));
            expect(produced.summary.notBeforeSource).toBe('input');
            expect(produced.summary.randomSerial).toBe(false);
            expect(produced.summary.serialNumber).toBe('01');
        }

        // The third witness: this process (TZ=UTC under vitest) through callToolDirect, what the sample generator uses.
        const inProcess = await callToolDirect('create_certificate', CERTIFICATE);
        assertResultClean(inProcess, 'create_certificate in-process');
        expect(blobOf(inProcess as AgentCallToolResult).equals(kiritimati!.certificate)).toBe(true);
        const inProcessRequest = await callToolDirect('create_timestamp_request', TIMESTAMP_REQUEST);
        expect(blobOf(inProcessRequest as AgentCallToolResult).equals(kiritimati!.request)).toBe(true);
    }, 90_000);

    it('A2-008: the pin is what does the work — without notBefore the certificate carries the clock, and the summary says so', async () => {
        const { spec, ...rest } = CERTIFICATE;
        const { notBefore: _pinned, ...unpinned } = spec;
        const client = await openAgent('stdio-legacy', { env: { TZ: ZONES[0], PKINATIVE_MCP_AT: '' } });
        try {
            const result = await client.callTool('create_certificate', { ...rest, spec: unpinned });
            assertResultClean(result, 'unpinned create_certificate');
            const summary = (result.structuredContent as { summary: Artefacts['summary'] }).summary;
            expect(summary.notBeforeSource).toBe('clock');
            // A UTC instant, on the UTC calendar year of the wall clock — never a Kiritimati rendering.
            expect(summary.notBefore).toMatch(UTC_ISO);
            expect(summary.notBefore.slice(0, 4)).toBe(String(new Date().getUTCFullYear()));
            expect(blobOf(result).equals(blobOf(await client.callTool('create_certificate', CERTIFICATE)))).toBe(false);
        } finally {
            expectCleanStdioExit(await client.close());
        }
    }, 60_000);
});
