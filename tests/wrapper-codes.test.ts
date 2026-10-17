/**
 * Tests for `src/wrapper-codes.ts` — the wrapper's own error codes: every
 * entry documented, codes unique, and every code literal thrown anywhere in
 * `src/` either listed here or a PKI_* engine code carried verbatim.
 */
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

import { PKI_ERROR_CODES } from '../src/pki-errors.js';
import { WRAPPER_CODE_NAMES, WRAPPER_CODES } from '../src/wrapper-codes.js';

const SRC = path.resolve(import.meta.dirname, '..', 'src');

function walk(dir: string, out: string[] = []): string[] {
    for (const name of readdirSync(dir)) {
        const full = path.join(dir, name);
        if (statSync(full).isDirectory()) walk(full, out);
        else if (name.endsWith('.ts')) out.push(full);
    }
    return out;
}

describe('WRAPPER_CODES', () => {
    it('every entry has a code, a meaning and a remedy; codes are SCREAMING_SNAKE and unique; WRAPPER_CODE_NAMES mirrors them', () => {
        expect(WRAPPER_CODES.length).toBeGreaterThanOrEqual(20);
        for (const entry of WRAPPER_CODES) {
            expect(Object.keys(entry), entry.code).toEqual(['code', 'meaning', 'remedy']);
            expect(entry.code, entry.code).toMatch(/^[A-Z][A-Z0-9_]+$/);
            expect(entry.code.startsWith('PKI_'), entry.code).toBe(false);
            expect(entry.meaning.length, entry.code).toBeGreaterThan(20);
            expect(entry.remedy.length, entry.code).toBeGreaterThan(10);
        }
        expect(new Set(WRAPPER_CODE_NAMES).size).toBe(WRAPPER_CODES.length);
        expect(WRAPPER_CODE_NAMES).toEqual(WRAPPER_CODES.map((c) => c.code));
        for (const required of ['VALIDATION_ERROR', 'SECURITY_VIOLATION', 'GOVERNANCE_VIOLATION', 'INPUT_TOO_LARGE', 'OUTPUT_EXISTS', 'LIMIT_CEILING_EXCEEDED', 'SECRET_REQUIRED', 'ENGINE_ERROR', 'ENGINE_VERDICT', 'UNKNOWN_RESOURCE']) {
            expect(WRAPPER_CODE_NAMES, required).toContain(required);
        }
        // No wrapper code collides with an engine code.
        for (const code of WRAPPER_CODE_NAMES) expect(PKI_ERROR_CODES as readonly string[], code).not.toContain(code);
    });

    it('every code literal thrown in src/ is a wrapper code or a PKI_* engine code', () => {
        const files = walk(SRC);
        expect(files.length).toBeGreaterThan(30);
        const literal = /new ToolError\(\s*'([A-Z][A-Z0-9_]*)'/g;
        const seen = new Map<string, string[]>();
        for (const file of files) {
            const text = readFileSync(file, 'utf8');
            for (const m of text.matchAll(literal)) {
                const code = m[1] as string;
                const where = seen.get(code) ?? [];
                where.push(path.relative(SRC, file));
                seen.set(code, where);
            }
            if (/new SecurityError\(/.test(text)) seen.set('SECURITY_VIOLATION', [...(seen.get('SECURITY_VIOLATION') ?? []), path.relative(SRC, file)]);
            if (/new GovernanceError\(/.test(text)) seen.set('GOVERNANCE_VIOLATION', [...(seen.get('GOVERNANCE_VIOLATION') ?? []), path.relative(SRC, file)]);
        }
        expect(seen.size).toBeGreaterThan(10);
        const unlisted = [...seen.keys()].filter((code) => !WRAPPER_CODE_NAMES.includes(code) && !(code.startsWith('PKI_') && (PKI_ERROR_CODES as readonly string[]).includes(code)));
        expect(unlisted, `codes thrown in src/ but unknown to WRAPPER_CODES / PKI_ERROR_CODES: ${unlisted.map((c) => `${c} (${seen.get(c)?.join(', ')})`).join('; ')}`).toEqual([]);
        // The sandbox and the governance tool are where the two subclass codes come from.
        expect(seen.get('SECURITY_VIOLATION')).toContain('sandbox.ts');
        expect(seen.get('GOVERNANCE_VIOLATION')?.some((f) => f.includes('governance'))).toBe(true);
    });
});
