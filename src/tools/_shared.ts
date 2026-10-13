/**
 * Zod fragments shared by every tool (kept in lock-step with the JSON Schema
 * fragments exported by the modules they mirror), the boundary parser and
 * the small helpers every handler uses.
 */
import { z } from 'zod';

import { MAX_FIELDS_PATHS } from '../caps.js';
import { ToolError } from '../errors.js';
import { ParseShape } from '../parse-context.js';
import type { DiagnosticsReport } from '../diagnostics.js';
import { redact } from '../secrets.js';

export { ParseShape };

/** `verbosity` / `fields` (see `PROJECTION_INPUT_PROPERTIES`). */
export const ProjectionShape = {
    verbosity: z.enum(['full', 'summary']).default('full'),
    fields: z.array(z.string().min(1)).max(MAX_FIELDS_PATHS).optional(),
};

/** `allowSha1` (see `ALLOW_SHA1_INPUT_PROPERTY`). */
export const AllowSha1Shape = {
    allowSha1: z.boolean().default(false),
};

/** Parse with a schema and convert a failure into `VALIDATION_ERROR` (the message names the path). */
export function parseInput<T>(schema: z.ZodType<T>, rawInput: unknown): T {
    const parsed = schema.safeParse(rawInput ?? {});
    if (!parsed.success) {
        const issues = parsed.error.issues.map((i) => `${i.path.length > 0 ? i.path.map(String).join('.') : '$'}: ${i.message}`);
        // A rejected `password` value must never be echoed: the issue text names the path only.
        const raw = rawInput as Record<string, unknown> | null | undefined;
        const secrets = [raw?.['password'], (raw?.['signer'] as Record<string, unknown> | undefined)?.['password']].filter((s): s is string => typeof s === 'string');
        throw new ToolError('VALIDATION_ERROR', redact(`Invalid arguments: ${issues.join('; ')}`, secrets), { issues: issues.map((i) => redact(i, secrets)) });
    }
    return parsed.data;
}

/** SHA-256 of bytes as lowercase hex (determinism proofs). */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
    const { createHash } = await import('node:crypto');
    return createHash('sha256').update(bytes).digest('hex');
}

/** Attach the diagnostics report to a result object. */
export function withDiagnostics<T extends object>(result: T, report: DiagnosticsReport): T & DiagnosticsReport {
    return { ...result, ...report };
}

/** The `diagnosticCount` scalar of every summary projection. */
export function diagnosticCount(report: DiagnosticsReport): number {
    return report.diagnostics.length;
}
