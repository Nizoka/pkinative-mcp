/**
 * The per-call parse context every engine-touching tool builds from the
 * shared `PARSE` fragment (`encodingRules`, `pemMode`, `strict`, `limits`):
 * the engine options with the diagnostic sink installed, the effective
 * `maxInputBytes`, and the running budget of inline bytes decoded for this
 * call (so a bundle of many inline objects stays inside one envelope).
 */
import type { PkiParseOptions } from 'pkinative';
import { z } from 'zod';

import { assertInputWithin, MAX_INLINE_INPUT_BYTES_PER_CALL } from './caps.js';
import { createDiagnosticSink, type DiagnosticSink } from './diagnostics.js';
import { effectiveMaxInputBytes, LIMITS_INPUT_SCHEMA, LimitsSchema, resolveCallLimits, type LimitsInput } from './limits.js';

export interface ParseInputFields {
    readonly encodingRules?: 'der' | 'ber' | undefined;
    readonly pemMode?: 'strict' | 'lax' | undefined;
    readonly strict?: boolean | undefined;
    readonly limits?: LimitsInput | undefined;
}

export interface ParseContext {
    /** Engine options: encoding rules, limits (ceiling-checked), strictness, the diagnostic sink. */
    readonly options: PkiParseOptions;
    readonly pemMode: 'strict' | 'lax';
    readonly strict: boolean;
    /** The effective `maxInputBytes`: the cap every PKI object read is held to. */
    readonly maxInputBytes: number;
    readonly sink: DiagnosticSink;
    /** Account for decoded inline bytes; throws INPUT_TOO_LARGE past the per-call envelope. */
    charge(bytes: number, what: string): void;
}

/** Build the context for one call. Throws LIMIT_CEILING_EXCEEDED for a limit above its ceiling. */
export function createParseContext(input: ParseInputFields): ParseContext {
    const sink = createDiagnosticSink(input.strict === true);
    const limits = resolveCallLimits(input.limits);
    let charged = 0;
    return {
        options: { ...sink.options, encodingRules: input.encodingRules ?? 'der', ...(limits !== undefined ? { limits } : {}) },
        pemMode: input.pemMode ?? 'strict',
        strict: input.strict === true,
        maxInputBytes: effectiveMaxInputBytes(input.limits),
        sink,
        charge(bytes: number, what: string): void {
            charged += bytes;
            assertInputWithin(charged, MAX_INLINE_INPUT_BYTES_PER_CALL, `${what} (inline inputs of this call)`);
        },
    };
}

/** JSON Schema properties of the `PARSE` fragment (spread into every engine-touching tool). */
export const PARSE_INPUT_PROPERTIES = {
    encodingRules: {
        type: 'string',
        enum: ['der', 'ber'],
        default: 'der',
        description: "ASN.1 encoding rules accepted: 'der' (default, strict X.690 DER) or 'ber' (also indefinite lengths, non-minimal lengths, constructed strings — common in CMS from legacy producers).",
    },
    pemMode: {
        type: 'string',
        enum: ['strict', 'lax'],
        default: 'strict',
        description: "PEM reading discipline: 'strict' (RFC 7468 exactly) or 'lax' (tolerates whitespace, line length and RFC 1421 headers; a missing base64 padding is refused in both modes).",
    },
    strict: {
        type: 'boolean',
        default: false,
        description: 'Escalate the first engine warning diagnostic (a long serial, an explicit DEFAULT, a missing key identifier, …) to a PKI_STRICT_DIAGNOSTIC error instead of reporting it in diagnostics[].',
    },
    limits: LIMITS_INPUT_SCHEMA,
} as const;

/** Zod twin of {@link PARSE_INPUT_PROPERTIES}. */
export const ParseShape = {
    encodingRules: z.enum(['der', 'ber']).default('der'),
    pemMode: z.enum(['strict', 'lax']).default('strict'),
    strict: z.boolean().default(false),
    limits: LimitsSchema.optional(),
};
