/**
 * Diagnostic collection. pkinative reports non-fatal profile concerns (a
 * serial longer than 20 octets, an explicit DEFAULT, a missing key
 * identifier, …) through an `onDiagnostic` callback; when no callback is
 * installed it falls back to `console.warn`, which a stdio MCP server must
 * never risk. Every engine call therefore goes through a sink from this
 * module, and every tool result carries `diagnostics[]`.
 *
 * The three engine entry points without an `onDiagnostic` option in 1.0.0
 * (`verifySignedData`, `buildCertificatePath`, `validateCertificatePath`)
 * are pre-parsed through a sink by their tools, so their diagnostics are
 * collected the same way.
 */
import type { PkiDiagnostic, PkiParseOptions } from 'pkinative';

import { MAX_DIAGNOSTICS } from './caps.js';

/** Wire shape of one diagnostic (the engine's `PkiDiagnostic` verbatim). */
export interface DiagnosticRow {
    readonly code: string;
    readonly severity: 'warning' | 'info';
    readonly message: string;
    readonly standard: string;
    readonly path: string;
    readonly offset?: number;
}

export interface DiagnosticSink {
    /** Pass as `onDiagnostic` (and `strict`) to the engine. */
    readonly options: Pick<PkiParseOptions, 'onDiagnostic' | 'strict'>;
    /** De-duplicated rows (by code + path), capped at {@link MAX_DIAGNOSTICS}. */
    readonly diagnostics: DiagnosticRow[];
    /** Count per code over EVERY diagnostic received (not capped). */
    readonly counts: Record<string, number>;
    /** True when rows were dropped by the cap. */
    readonly truncated: boolean;
    /** True when a diagnostic with `code` was received. */
    has(code: string): boolean;
    /** The serialisable summary attached to tool results. */
    report(): DiagnosticsReport;
}

export interface DiagnosticsReport {
    readonly diagnostics: readonly DiagnosticRow[];
    readonly diagnosticCounts: Readonly<Record<string, number>>;
    readonly diagnosticsTruncated?: true;
}

/** Create a sink. `strict: true` asks the engine to escalate the first warning (`PKI_STRICT_DIAGNOSTIC`). */
export function createDiagnosticSink(strict = false): DiagnosticSink {
    const diagnostics: DiagnosticRow[] = [];
    const counts: Record<string, number> = {};
    const seen = new Set<string>();
    let truncated = false;
    const onDiagnostic = (d: PkiDiagnostic): void => {
        counts[d.code] = (counts[d.code] ?? 0) + 1;
        const key = `${d.code}\0${d.path}`;
        if (seen.has(key)) return;
        seen.add(key);
        if (diagnostics.length >= MAX_DIAGNOSTICS) {
            truncated = true;
            return;
        }
        diagnostics.push({
            code: d.code,
            severity: d.severity,
            message: d.message,
            standard: d.standard,
            path: d.path,
            ...(d.offset !== undefined ? { offset: d.offset } : {}),
        });
    };
    return {
        options: { onDiagnostic, ...(strict ? { strict: true } : {}) },
        diagnostics,
        counts,
        get truncated() {
            return truncated;
        },
        has: (code) => counts[code] !== undefined,
        report: () => ({
            diagnostics: [...diagnostics],
            diagnosticCounts: { ...counts },
            ...(truncated ? { diagnosticsTruncated: true as const } : {}),
        }),
    };
}

/** JSON Schema of the `diagnostics` output block shared by every engine-touching tool. */
export const DIAGNOSTICS_OUTPUT_PROPERTIES = {
    diagnostics: {
        type: 'array',
        description:
            'Non-fatal profile concerns the engine raised while parsing or building (de-duplicated by code + path, at most 200). Empty for a clean object. The 97 PKI_DIAG_* codes are listed by describe_engine and explained by explain_code.',
        items: {
            type: 'object',
            additionalProperties: false,
            required: ['code', 'severity', 'message', 'standard', 'path'],
            properties: {
                code: { type: 'string' },
                severity: { type: 'string', enum: ['warning', 'info'] },
                message: { type: 'string' },
                standard: { type: 'string' },
                path: { type: 'string' },
                offset: { type: 'integer', minimum: 0 },
            },
        },
    },
    diagnosticCounts: {
        type: 'object',
        description: 'Number of diagnostics received per code (counts every occurrence, including de-duplicated ones).',
        additionalProperties: { type: 'integer', minimum: 0 },
    },
    diagnosticsTruncated: { type: 'boolean', description: 'Present (true) when more than 200 distinct diagnostics were dropped from `diagnostics`.' },
} as const;
