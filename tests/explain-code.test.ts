/**
 * Tests for `explain_code` — the registries vendored at the pkinative v1.0.0 tag.
 */
import { describe, it, expect } from 'vitest';

import { CODE_REGISTRY, explainCode, EXPLAIN_CODE_TOOL } from '../src/tools/explain-code.js';
import { PKI_DIAGNOSTIC_CODES, PKI_ERROR_CODES, PKI_REASON_CODES } from '../src/pki-errors.js';
import { WRAPPER_CODES } from '../src/wrapper-codes.js';
import { callToolDirect } from '../src/server.js';
import { codeOf } from './_pki-assert.js';

describe('explain_code', () => {
    it('holds every engine code and every wrapper code exactly once', () => {
        expect(CODE_REGISTRY.size).toBe(57 + 43 + 97 + WRAPPER_CODES.length);
        for (const code of PKI_ERROR_CODES) expect(CODE_REGISTRY.get(code)?.kind, code).toBe('error');
        for (const code of PKI_REASON_CODES) expect(CODE_REGISTRY.get(code)?.kind, code).toBe('reason');
        for (const code of PKI_DIAGNOSTIC_CODES) expect(CODE_REGISTRY.get(code)?.kind, code).toBe('diagnostic');
        for (const w of WRAPPER_CODES) expect(CODE_REGISTRY.get(w.code)?.kind, w.code).toBe('wrapper');
    });

    it('explains an engine error with its class, CWE and both remedies', async () => {
        const r = await explainCode({ code: 'PKI_CRYPTO_ALGORITHM_REFUSED' });
        expect(r).toMatchObject({ code: 'PKI_CRYPTO_ALGORITHM_REFUSED', kind: 'error', errorClass: 'security', engineClass: 'PkiCryptoError', since: expect.any(String) });
        expect(r.summary).toMatch(/SHA-1|refus/i);
        expect(r.remedy?.engine).toBeTruthy();
        expect(r.remedy?.mcp).toContain('allowSha1');
    });

    it('explains a reason, a diagnostic (with severity) and a wrapper code', async () => {
        const reason = await explainCode({ code: 'PKI_REASON_REVOKED' });
        expect(reason).toMatchObject({ kind: 'reason', standard: expect.any(String) });
        expect(reason.severity).toBeUndefined();
        const diag = await explainCode({ code: 'PKI_DIAG_SERIAL_TOO_LONG' });
        expect(diag).toMatchObject({ kind: 'diagnostic', severity: 'warning', standard: expect.stringContaining('RFC 5280') });
        const wrapper = await explainCode({ code: 'SECRET_REQUIRED' });
        expect(wrapper).toMatchObject({ kind: 'wrapper', remedy: { mcp: expect.stringContaining('PKINATIVE_MCP_PASSWORD') } });
    });

    it('lists codes, optionally of one kind, with a count', async () => {
        const all = await explainCode({ list: true });
        expect(all.count).toBe(CODE_REGISTRY.size);
        expect(all.codes?.length).toBe(CODE_REGISTRY.size);
        const reasons = await explainCode({ list: true, kind: 'reason' });
        expect(reasons.count).toBe(43);
        expect(reasons.codes?.every((c) => c.kind === 'reason' && c.code.startsWith('PKI_REASON_'))).toBe(true);
    });

    it('refuses an unknown code, a kind mismatch, a malformed code and a call without code or list', async () => {
        expect(await codeOf(explainCode({ code: 'NOPE' }))).toBe('NOT_FOUND');
        expect(await codeOf(explainCode({ code: 'PKI_REASON_REVOKED', kind: 'error' }))).toBe('NOT_FOUND');
        expect(await codeOf(explainCode({ code: 'lower_case' }))).toBe('VALIDATION_ERROR');
        expect(await codeOf(explainCode({ code: '__proto__' }))).toBe('VALIDATION_ERROR');
        expect(await codeOf(explainCode({}))).toBe('VALIDATION_ERROR');
        expect(await codeOf(explainCode({ code: 'X', extra: 1 }))).toBe('VALIDATION_ERROR');
    });

    it('projects over the wire and is cacheable', async () => {
        const r = await callToolDirect('explain_code', { list: true, kind: 'wrapper', fields: ['codes.code', 'count'] });
        expect(r.isError).toBeUndefined();
        expect(r.structuredContent).toEqual({ codes: WRAPPER_CODES.map((w) => ({ code: w.code })), count: WRAPPER_CODES.length });
        expect((r.content[0] as { text: string }).text).toContain(`${WRAPPER_CODES.length} code(s)`);
        expect(EXPLAIN_CODE_TOOL.cacheable).toBe(true);
        expect(EXPLAIN_CODE_TOOL.annotations.readOnlyHint).toBe(true);
    });
});
