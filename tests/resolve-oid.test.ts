/**
 * Tests for `resolve_oid` — names, validity, the registry listing, the
 * X.690 encoding both ways, projection, every refusal.
 */
import { beforeAll, describe, expect, it } from 'vitest';

import { callToolDirect } from '../src/server.js';
import { resolveOid, resolveOidSummary, RESOLVE_OID_TOOL } from '../src/tools/resolve-oid.js';
import { DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, MAX_OIDS_PER_CALL } from '../src/caps.js';
import { codeOf, errorCodeOf } from './_pki-assert.js';

describe('resolve_oid', () => {
    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    describe('name', () => {
        it('names registered OIDs and reports null for the rest', async () => {
            const r = await resolveOid({ mode: 'name', oids: ['2.5.4.3', '1.2.3.4', '1.2.840.10045.4.3.2'] });
            expect(r.mode).toBe('name');
            expect(r.oids).toEqual([{ oid: '2.5.4.3', name: 'commonName' }, { oid: '1.2.3.4', name: null }, { oid: '1.2.840.10045.4.3.2', name: 'ecdsa-with-SHA256' }]);
            expect(r.diagnostics).toEqual([]);
        });

        it('never throws for a malformed string', async () => {
            const r = await resolveOid({ mode: 'name', oids: ['x.y'] });
            expect(r.oids).toEqual([{ oid: 'x.y', name: null }]);
        });
    });

    describe('validate', () => {
        it('reports validity per OID (never an error) and allValid', async () => {
            const r = await resolveOid({ mode: 'validate', oids: ['1.2.3', 'x.y', '2.999', '1.40', '1.02'] });
            expect(r.oids).toEqual([{ oid: '1.2.3', valid: true }, { oid: 'x.y', valid: false }, { oid: '2.999', valid: true }, { oid: '1.40', valid: false }, { oid: '1.02', valid: false }]);
            expect(r.allValid).toBe(false);
            expect((await resolveOid({ mode: 'validate', oids: ['1.2'] })).allValid).toBe(true);
        });
    });

    describe('list', () => {
        it('pages the registry with the defaults', async () => {
            const r = await resolveOid({ mode: 'list' });
            expect(r.entries?.length).toBe(DEFAULT_LIST_LIMIT);
            expect(r.total).toBeGreaterThan(300);
            expect(r).toMatchObject({ offset: 0, limit: DEFAULT_LIST_LIMIT, hasMore: true });
            expect(r.entries?.[0]).toEqual({ oid: expect.any(String), name: expect.any(String), standard: expect.any(String) });
        });

        it('filters case-insensitively on the name or the OID, and walks to the last page', async () => {
            const some = await resolveOid({ mode: 'list', filter: 'OCSPSIGNING' });
            expect(some.entries).toEqual([{ oid: '1.3.6.1.5.5.7.3.9', name: 'OCSPSigning', standard: 'RFC 5280' }]);
            expect(some).toMatchObject({ total: 1, hasMore: false });
            const byOid = await resolveOid({ mode: 'list', filter: '2.5.29.1', limit: 3 });
            expect(byOid.entries?.every((e) => e.oid.includes('2.5.29.1'))).toBe(true);
            expect(byOid.hasMore).toBe((byOid.total ?? 0) > 3);
            const all = await resolveOid({ mode: 'list', limit: MAX_LIST_LIMIT });
            expect(all.hasMore).toBe(false);
            const past = await resolveOid({ mode: 'list', offset: 100_000 });
            expect(past).toMatchObject({ entries: [], hasMore: false });
        });
    });

    describe('encode', () => {
        it('encodes content octets, TLVs and relative OIDs', async () => {
            expect((await resolveOid({ mode: 'encode', oids: ['1.2.840.113549'] })).oids).toEqual([{ oid: '1.2.840.113549', hex: '2a864886f70d' }]);
            expect((await resolveOid({ mode: 'encode', oids: ['1.2.840.113549', '2.5.4.3'], form: 'tlv' })).oids).toEqual([{ oid: '1.2.840.113549', hex: '06062a864886f70d' }, { oid: '2.5.4.3', hex: '0603550403' }]);
            expect((await resolveOid({ mode: 'encode', oids: ['8571.3.2'], form: 'tlv', relative: true })).oids).toEqual([{ oid: '8571.3.2', hex: '0d04c27b0302' }]);
        });

        it('PKI_OID_INVALID for an invalid OID', async () => {
            const result = await callToolDirect('resolve_oid', { mode: 'encode', oids: ['1.2', 'x.y'] });
            expect(errorCodeOf(result)).toBe('PKI_OID_INVALID');
            expect((result._meta?.['error'] as { data: { errorClass: string } }).data.errorClass).toBe('parse');
        });
    });

    describe('decode', () => {
        it.each([
            ['2a864886f70d', {}, { oid: '1.2.840.113549', name: null }],
            ['55:04:03', {}, { oid: '2.5.4.3', name: 'commonName' }],
            ['0x550403', {}, { oid: '2.5.4.3', name: 'commonName' }],
            ['0603550403', { form: 'tlv' }, { oid: '2.5.4.3', name: 'commonName' }],
            ['0d04c27b0302', { form: 'tlv', relative: true }, { oid: '8571.3.2', name: null }],
        ])('decodes %s', async (hex, extra, expected) => {
            const r = await resolveOid({ mode: 'decode', hex, ...extra });
            expect(r).toMatchObject({ mode: 'decode', ...expected });
        });

        it('PKI_OID_INVALID / PKI_ASN1_* for malformed octets', async () => {
            expect(await codeOf(resolveOid({ mode: 'decode', hex: '80' }))).toBe('PKI_OID_INVALID');
            expect(await codeOf(resolveOid({ mode: 'decode', hex: '0603550403ff', form: 'tlv' }))).toBe('PKI_ASN1_TRAILING_DATA');
            expect(await codeOf(resolveOid({ mode: 'decode', hex: '0500', form: 'tlv' }))).toBe('PKI_ASN1_UNEXPECTED_TAG');
            expect(await codeOf(resolveOid({ mode: 'decode', hex: '06', form: 'tlv' }))).toMatch(/^PKI_ASN1_/);
        });

        it('PKI_LIMIT_EXCEEDED past limits.maxOidBytes', async () => {
            const result = await callToolDirect('resolve_oid', { mode: 'decode', hex: '2a864886f70d', limits: { maxOidBytes: 2 } });
            expect(errorCodeOf(result)).toBe('PKI_LIMIT_EXCEEDED');
            expect((result._meta?.['error'] as { data: { limit: string } }).data.limit).toBe('maxOidBytes');
        });
    });

    describe('projection', () => {
        it('summary keeps mode, count and the scalars of the mode', async () => {
            expect(resolveOidSummary(await resolveOid({ mode: 'name', oids: ['2.5.4.3', '2.5.4.6'] }))).toEqual({ mode: 'name', count: 2, diagnosticCount: 0 });
            expect(resolveOidSummary(await resolveOid({ mode: 'validate', oids: ['1.2'] }))).toEqual({ mode: 'validate', count: 1, allValid: true, diagnosticCount: 0 });
            expect(resolveOidSummary(await resolveOid({ mode: 'list', filter: 'ocspsigning' }))).toEqual({ mode: 'list', count: 1, total: 1, hasMore: false, diagnosticCount: 0 });
            expect(resolveOidSummary(await resolveOid({ mode: 'decode', hex: '550403' }))).toEqual({ mode: 'decode', count: 1, oid: '2.5.4.3', name: 'commonName', diagnosticCount: 0 });
        });

        it('fields project over the wire and the text line names the OIDs', async () => {
            const result = await callToolDirect('resolve_oid', { mode: 'name', oids: ['2.5.4.3'], fields: ['oids.name'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ oids: [{ name: 'commonName' }] });
            expect(result.content[0]).toEqual({ type: 'text', text: 'resolve_oid: 2.5.4.3 = commonName.' });
            const summary = await callToolDirect('resolve_oid', { mode: 'validate', oids: ['1.2', 'x'], verbosity: 'summary' });
            expect(summary.structuredContent).toEqual({ mode: 'validate', count: 2, allValid: false, diagnosticCount: 0 });
            expect(summary.content[0]).toEqual({ type: 'text', text: 'resolve_oid: invalid: x (2 checked).' });
        });
    });

    describe('refusals', () => {
        it.each([
            ['no mode', {}],
            ['unknown mode', { mode: 'frob' }],
            ['unknown key', { mode: 'list', bogus: 1 }],
            ['name without oids', { mode: 'name' }],
            ['validate without oids', { mode: 'validate' }],
            ['encode without oids', { mode: 'encode' }],
            ['empty oids', { mode: 'name', oids: [] }],
            ['too many oids', { mode: 'name', oids: Array.from({ length: MAX_OIDS_PER_CALL + 1 }, () => '1.2') }],
            ['decode without hex', { mode: 'decode' }],
            ['decode with a non-hex string', { mode: 'decode', hex: 'zz' }],
            ['list with oids', { mode: 'list', oids: ['1.2'] }],
            ['list with hex', { mode: 'list', hex: '0500' }],
            ['name with filter', { mode: 'name', oids: ['1.2'], filter: 'x' }],
            ['name with relative', { mode: 'name', oids: ['1.2'], relative: true }],
            ['relative without tlv (encode)', { mode: 'encode', oids: ['8571.3.2'], relative: true }],
            ['relative without tlv (decode)', { mode: 'decode', hex: 'c27b0302', relative: true }],
            ['limit above the cap', { mode: 'list', limit: MAX_LIST_LIMIT + 1 }],
            ['limit zero', { mode: 'list', limit: 0 }],
            ['negative offset', { mode: 'list', offset: -1 }],
        ])('VALIDATION_ERROR: %s', async (_name, input) => {
            expect(await codeOf(resolveOid(input))).toBe('VALIDATION_ERROR');
        });

        it('LIMIT_CEILING_EXCEEDED for a limit above its operator ceiling', async () => {
            expect(await codeOf(resolveOid({ mode: 'decode', hex: '550403', limits: { maxInputBytes: 1024 * 1024 * 1024 } }))).toBe('LIMIT_CEILING_EXCEEDED');
        });
    });

    describe('definition', () => {
        it('is read-only, cacheable, with two validating examples', () => {
            expect(RESOLVE_OID_TOOL.kind).toBe('read');
            expect(RESOLVE_OID_TOOL.annotations.readOnlyHint).toBe(true);
            expect(RESOLVE_OID_TOOL.cacheable).toBe(true);
            expect(RESOLVE_OID_TOOL.examples?.length).toBe(2);
        });
    });
});
