/**
 * Tests for `src/parse-context.ts` — the per-call parse context: engine
 * options with the sink installed, the effective maxInputBytes, and the
 * running inline-byte budget of one call.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { DEFAULT_PKI_LIMITS, type PkiDiagnostic } from 'pkinative';

import { __resetCeilingsForTests, MAX_INLINE_INPUT_BYTES_PER_CALL, MAX_INPUT_BYTES_ENV } from '../src/caps.js';
import { ToolError } from '../src/errors.js';
import { createParseContext, PARSE_INPUT_PROPERTIES, ParseShape } from '../src/parse-context.js';

function thrown(fn: () => unknown): ToolError {
    try {
        fn();
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to throw');
}

const DIAGNOSTIC: PkiDiagnostic = {
    code: 'PKI_DIAG_SERIAL_TOO_LONG',
    severity: 'warning',
    message: 'serial number is 21 octets',
    standard: 'RFC 5280 §4.1.2.2',
    path: 'tbsCertificate.serialNumber',
    offset: 7,
};

describe('createParseContext', () => {
    afterEach(() => {
        delete process.env[MAX_INPUT_BYTES_ENV];
        __resetCeilingsForTests();
    });

    it('defaults: der, strict PEM, non-strict, no limits key, the engine maxInputBytes, a sink installed', () => {
        const ctx = createParseContext({});
        expect(ctx.options.encodingRules).toBe('der');
        expect(ctx.options).not.toHaveProperty('limits');
        expect(ctx.options).not.toHaveProperty('strict');
        expect(typeof ctx.options.onDiagnostic).toBe('function');
        expect(ctx.options.onDiagnostic).toBe(ctx.sink.options.onDiagnostic);
        expect(ctx.pemMode).toBe('strict');
        expect(ctx.strict).toBe(false);
        expect(ctx.maxInputBytes).toBe(DEFAULT_PKI_LIMITS.maxInputBytes);
        expect(ctx.sink.report()).toEqual({ diagnostics: [], diagnosticCounts: {} });
    });

    it('strict:true installs the engine strict flag; encodingRules and pemMode pass through', () => {
        const strict = createParseContext({ strict: true });
        expect(strict.strict).toBe(true);
        expect(strict.options.strict).toBe(true);
        expect(createParseContext({ strict: false }).options).not.toHaveProperty('strict');
        const ber = createParseContext({ encodingRules: 'ber', pemMode: 'lax' });
        expect(ber.options.encodingRules).toBe('ber');
        expect(ber.pemMode).toBe('lax');
        expect(ber.strict).toBe(false);
    });

    it('limits are resolved under the ceilings and drive maxInputBytes', () => {
        const ctx = createParseContext({ limits: { maxDepth: 3, maxInputBytes: 4096 } });
        expect(ctx.options.limits).toEqual({ maxDepth: 3, maxInputBytes: 4096 });
        expect(ctx.maxInputBytes).toBe(4096);
        expect(createParseContext({ limits: {} }).options).not.toHaveProperty('limits');
        const over = thrown(() => createParseContext({ limits: { maxInputBytes: DEFAULT_PKI_LIMITS.maxInputBytes + 1 } }));
        expect(over.code).toBe('LIMIT_CEILING_EXCEEDED');
        expect(over.data).toMatchObject({ limit: 'maxInputBytes', env: MAX_INPUT_BYTES_ENV });
        // An operator ceiling below the engine default tightens the context.
        process.env[MAX_INPUT_BYTES_ENV] = '2048';
        __resetCeilingsForTests();
        const tight = createParseContext({});
        expect(tight.maxInputBytes).toBe(2048);
        expect(tight.options.limits).toEqual({ maxInputBytes: 2048 });
    });

    it('charge() accumulates across calls and throws INPUT_TOO_LARGE past the per-call inline envelope', () => {
        const ctx = createParseContext({});
        expect(() => ctx.charge(MAX_INLINE_INPUT_BYTES_PER_CALL - 1, 'trustAnchors[0]')).not.toThrow();
        expect(() => ctx.charge(1, 'trustAnchors[1]')).not.toThrow();
        const err = thrown(() => ctx.charge(1, 'certificate'));
        expect(err.code).toBe('INPUT_TOO_LARGE');
        expect(err.data).toEqual({ what: 'certificate (inline inputs of this call)', observed: MAX_INLINE_INPUT_BYTES_PER_CALL + 1, cap: MAX_INLINE_INPUT_BYTES_PER_CALL, remedy: 'path' });
        expect(err.message).toContain('inline inputs of this call');
        expect(err.message).toContain('PKINATIVE_MCP_OUTPUT_DIR');
        // A fresh context starts from zero.
        expect(() => createParseContext({}).charge(MAX_INLINE_INPUT_BYTES_PER_CALL, 'x')).not.toThrow();
    });

    it('the sink collects what the engine reports through options.onDiagnostic', () => {
        const ctx = createParseContext({});
        const onDiagnostic = ctx.options.onDiagnostic as (d: PkiDiagnostic) => void;
        onDiagnostic(DIAGNOSTIC);
        onDiagnostic(DIAGNOSTIC);
        onDiagnostic({ ...DIAGNOSTIC, path: 'tbsCertificate.extensions[0]', offset: undefined });
        expect(ctx.sink.has('PKI_DIAG_SERIAL_TOO_LONG')).toBe(true);
        expect(ctx.sink.report()).toEqual({
            diagnostics: [
                { code: 'PKI_DIAG_SERIAL_TOO_LONG', severity: 'warning', message: DIAGNOSTIC.message, standard: DIAGNOSTIC.standard, path: 'tbsCertificate.serialNumber', offset: 7 },
                { code: 'PKI_DIAG_SERIAL_TOO_LONG', severity: 'warning', message: DIAGNOSTIC.message, standard: DIAGNOSTIC.standard, path: 'tbsCertificate.extensions[0]' },
            ],
            diagnosticCounts: { PKI_DIAG_SERIAL_TOO_LONG: 3 },
        });
    });
});

describe('PARSE_INPUT_PROPERTIES / ParseShape', () => {
    it('are in lock-step: the same keys, enums and defaults', () => {
        expect(Object.keys(PARSE_INPUT_PROPERTIES)).toEqual(Object.keys(ParseShape));
        expect(Object.keys(PARSE_INPUT_PROPERTIES)).toEqual(['encodingRules', 'pemMode', 'strict', 'limits']);
        expect(PARSE_INPUT_PROPERTIES.encodingRules).toMatchObject({ type: 'string', enum: ['der', 'ber'], default: 'der' });
        expect(PARSE_INPUT_PROPERTIES.pemMode).toMatchObject({ type: 'string', enum: ['strict', 'lax'], default: 'strict' });
        expect(PARSE_INPUT_PROPERTIES.strict).toMatchObject({ type: 'boolean', default: false });
        expect(PARSE_INPUT_PROPERTIES.strict.description).toContain('PKI_STRICT_DIAGNOSTIC');
        expect(PARSE_INPUT_PROPERTIES.limits.type).toBe('object');
        expect(ParseShape.encodingRules.parse(undefined)).toBe('der');
        expect(ParseShape.pemMode.parse(undefined)).toBe('strict');
        expect(ParseShape.strict.parse(undefined)).toBe(false);
        expect(ParseShape.encodingRules.safeParse('cer').success).toBe(false);
        expect(ParseShape.limits.safeParse({ maxDepth: 0 }).success).toBe(false);
        expect(ParseShape.limits.safeParse(undefined).success).toBe(true);
    });
});
