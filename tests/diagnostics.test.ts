/**
 * Tests for `src/diagnostics.ts` — the de-duplicating, capped diagnostic
 * sink, and the proof that a real engine diagnostic reaches it instead of
 * `console.warn`.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { decodePem, parseCertificate, parseCertificateList, parseSignedData, type PkiDiagnostic } from 'pkinative';

import { MAX_DIAGNOSTICS } from '../src/caps.js';
import { createDiagnosticSink, DIAGNOSTICS_OUTPUT_PROPERTIES } from '../src/diagnostics.js';
import { PKI_DIAGNOSTIC_CODES } from '../src/pki-errors.js';
import { looksLikePem } from '../src/pki-input.js';
import { FIXTURE_FILES, fixtureBytes, fixtureText } from './_pki-fixtures.js';

function emit(sink: ReturnType<typeof createDiagnosticSink>, d: Partial<PkiDiagnostic> & { code: PkiDiagnostic['code']; path: string }): void {
    (sink.options.onDiagnostic as (x: PkiDiagnostic) => void)({ severity: 'warning', message: `m:${d.code}`, standard: 'RFC 5280', offset: undefined, ...d });
}

describe('createDiagnosticSink', () => {
    it('starts empty and reports an empty block', () => {
        const sink = createDiagnosticSink();
        expect(sink.diagnostics).toEqual([]);
        expect(sink.counts).toEqual({});
        expect(sink.truncated).toBe(false);
        expect(sink.has('PKI_DIAG_SERIAL_TOO_LONG')).toBe(false);
        expect(sink.report()).toEqual({ diagnostics: [], diagnosticCounts: {} });
        expect(sink.options).not.toHaveProperty('strict');
        expect(typeof sink.options.onDiagnostic).toBe('function');
    });

    it('strict:true is passed to the engine options', () => {
        expect(createDiagnosticSink(true).options.strict).toBe(true);
        expect(createDiagnosticSink(false).options).not.toHaveProperty('strict');
        expect(createDiagnosticSink().options).not.toHaveProperty('strict');
    });

    it('de-duplicates by code + path while counting every occurrence; offset is present only when known', () => {
        const sink = createDiagnosticSink();
        emit(sink, { code: 'PKI_DIAG_SKI_MISSING', path: 'tbsCertificate.extensions', offset: 12 });
        emit(sink, { code: 'PKI_DIAG_SKI_MISSING', path: 'tbsCertificate.extensions', message: 'again' });
        emit(sink, { code: 'PKI_DIAG_SKI_MISSING', path: 'certificates[1].tbsCertificate.extensions' });
        emit(sink, { code: 'PKI_DIAG_PEM_LAX_ACCEPTED', path: '', severity: 'info' });
        emit(sink, { code: 'PKI_DIAG_PEM_LAX_ACCEPTED', path: '', severity: 'info' });
        expect(sink.diagnostics).toEqual([
            { code: 'PKI_DIAG_SKI_MISSING', severity: 'warning', message: 'm:PKI_DIAG_SKI_MISSING', standard: 'RFC 5280', path: 'tbsCertificate.extensions', offset: 12 },
            { code: 'PKI_DIAG_SKI_MISSING', severity: 'warning', message: 'm:PKI_DIAG_SKI_MISSING', standard: 'RFC 5280', path: 'certificates[1].tbsCertificate.extensions' },
            { code: 'PKI_DIAG_PEM_LAX_ACCEPTED', severity: 'info', message: 'm:PKI_DIAG_PEM_LAX_ACCEPTED', standard: 'RFC 5280', path: '' },
        ]);
        expect(sink.counts).toEqual({ PKI_DIAG_SKI_MISSING: 3, PKI_DIAG_PEM_LAX_ACCEPTED: 2 });
        expect(sink.has('PKI_DIAG_SKI_MISSING')).toBe(true);
        expect(sink.has('PKI_DIAG_AKI_MISSING')).toBe(false);
        expect(sink.truncated).toBe(false);
        const report = sink.report();
        expect(report.diagnosticCounts).toEqual(sink.counts);
        expect(report.diagnosticsTruncated).toBeUndefined();
        expect(report).not.toHaveProperty('diagnosticsTruncated');
        // The report is a snapshot: later diagnostics do not mutate it.
        expect(report.diagnostics).not.toBe(sink.diagnostics);
        expect(report.diagnosticCounts).not.toBe(sink.counts);
        emit(sink, { code: 'PKI_DIAG_AKI_MISSING', path: 'x' });
        expect(report.diagnostics).toHaveLength(3);
        expect(report.diagnosticCounts).not.toHaveProperty('PKI_DIAG_AKI_MISSING');
        expect(sink.report().diagnostics).toHaveLength(4);
    });

    it('caps the rows at MAX_DIAGNOSTICS (200) and flags the truncation; counts stay exact', () => {
        const sink = createDiagnosticSink();
        for (let i = 0; i < MAX_DIAGNOSTICS + 50; i++) {
            emit(sink, { code: 'PKI_DIAG_RDN_SET_NOT_SORTED', path: `tbsCertificate.subject.rdns[${i}]` });
        }
        expect(MAX_DIAGNOSTICS).toBe(200);
        expect(sink.diagnostics).toHaveLength(200);
        expect(sink.diagnostics[199]?.path).toBe('tbsCertificate.subject.rdns[199]');
        expect(sink.truncated).toBe(true);
        expect(sink.counts['PKI_DIAG_RDN_SET_NOT_SORTED']).toBe(250);
        expect(sink.report()).toMatchObject({ diagnosticsTruncated: true, diagnosticCounts: { PKI_DIAG_RDN_SET_NOT_SORTED: 250 } });
        // A repeat of a kept row after the cap is neither added again nor lost from the counts.
        emit(sink, { code: 'PKI_DIAG_RDN_SET_NOT_SORTED', path: 'tbsCertificate.subject.rdns[0]' });
        expect(sink.diagnostics).toHaveLength(200);
        expect(sink.counts['PKI_DIAG_RDN_SET_NOT_SORTED']).toBe(251);
        // A new code past the cap is counted and `has()` sees it, but it gets no row.
        emit(sink, { code: 'PKI_DIAG_SKI_MISSING', path: 'x' });
        expect(sink.has('PKI_DIAG_SKI_MISSING')).toBe(true);
        expect(sink.diagnostics).toHaveLength(200);
    });

    it('the shared output schema names the required row members, the cap and the code count', () => {
        expect(Object.keys(DIAGNOSTICS_OUTPUT_PROPERTIES)).toEqual(['diagnostics', 'diagnosticCounts', 'diagnosticsTruncated']);
        expect(DIAGNOSTICS_OUTPUT_PROPERTIES.diagnostics.items.required).toEqual(['code', 'severity', 'message', 'standard', 'path']);
        expect(Object.keys(DIAGNOSTICS_OUTPUT_PROPERTIES.diagnostics.items.properties)).toEqual(['code', 'severity', 'message', 'standard', 'path', 'offset']);
        expect(DIAGNOSTICS_OUTPUT_PROPERTIES.diagnostics.items.additionalProperties).toBe(false);
        expect(DIAGNOSTICS_OUTPUT_PROPERTIES.diagnostics.items.properties.severity.enum).toEqual(['warning', 'info']);
        expect(DIAGNOSTICS_OUTPUT_PROPERTIES.diagnostics.description).toContain(`${PKI_DIAGNOSTIC_CODES.length} PKI_DIAG_* codes`);
        expect(DIAGNOSTICS_OUTPUT_PROPERTIES.diagnostics.description).toContain(`at most ${MAX_DIAGNOSTICS}`);
        expect(DIAGNOSTICS_OUTPUT_PROPERTIES.diagnosticCounts.additionalProperties).toEqual({ type: 'integer', minimum: 0 });
        expect(DIAGNOSTICS_OUTPUT_PROPERTIES.diagnosticsTruncated.description).toContain(String(MAX_DIAGNOSTICS));
    });
});

describe('real engine diagnostics', () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    /** Every DER object of a fixture (the blocks of a PEM text, or the bytes themselves). */
    function dersOf(name: string): Uint8Array[] {
        const bytes = fixtureBytes(name);
        if (!looksLikePem(bytes)) return [bytes];
        try {
            return decodePem(fixtureText(name), { onDiagnostic: () => undefined }).map((b) => b.bytes);
        } catch {
            return [];
        }
    }

    it('a sink installed on the engine options collects PKI_DIAG_* codes across the fixtures, and console.warn / stderr stay silent', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
        const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
        const sink = createDiagnosticSink();
        let parsed = 0;
        for (const name of FIXTURE_FILES) {
            for (const der of dersOf(name)) {
                for (const read of [parseCertificate, parseCertificateList, parseSignedData]) {
                    try {
                        read(der, sink.options);
                        parsed++;
                    } catch {
                        /* not that kind of object: the parser throws, the sink is untouched */
                    }
                }
            }
        }
        expect(parsed).toBeGreaterThan(10);
        const codes = Object.keys(sink.counts);
        expect(codes.length).toBeGreaterThan(0);
        for (const code of codes) {
            expect(code, code).toMatch(/^PKI_DIAG_/);
            expect(PKI_DIAGNOSTIC_CODES, code).toContain(code);
        }
        expect(sink.diagnostics.every((d) => (d.severity === 'warning' || d.severity === 'info') && typeof d.standard === 'string' && typeof d.path === 'string')).toBe(true);
        expect(warn).not.toHaveBeenCalled();
        expect(stderr).not.toHaveBeenCalled();
    });

    it('revoked.crt.pem raises PKI_DIAG_COMMON_NAME_NOT_IN_SAN at tbsCertificate.subject; a second read through the same sink counts without a new row', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
        const sink = createDiagnosticSink();
        const der = dersOf('revoked.crt.pem')[0] as Uint8Array;
        parseCertificate(der, sink.options);
        expect(sink.has('PKI_DIAG_COMMON_NAME_NOT_IN_SAN')).toBe(true);
        expect(sink.diagnostics.find((d) => d.code === 'PKI_DIAG_COMMON_NAME_NOT_IN_SAN')).toMatchObject({ severity: 'warning', path: 'tbsCertificate.subject', standard: expect.any(String) });
        const rows = sink.diagnostics.length;
        parseCertificate(der, sink.options);
        expect(sink.diagnostics).toHaveLength(rows);
        expect(sink.counts['PKI_DIAG_COMMON_NAME_NOT_IN_SAN']).toBe(2);
        expect(warn).not.toHaveBeenCalled();
        // A clean certificate through the same engine call reports nothing.
        const clean = createDiagnosticSink();
        parseCertificate(dersOf('leaf.crt.pem')[0] as Uint8Array, clean.options);
        expect(clean.report()).toEqual({ diagnostics: [], diagnosticCounts: {} });
    });

    it('strict:true makes the engine escalate the first diagnostic to PKI_STRICT_DIAGNOSTIC instead of reporting it', () => {
        const sink = createDiagnosticSink(true);
        const der = dersOf('revoked.crt.pem')[0] as Uint8Array;
        expect(() => parseCertificate(der, sink.options)).toThrow(expect.objectContaining({ code: 'PKI_STRICT_DIAGNOSTIC' }));
    });
});
