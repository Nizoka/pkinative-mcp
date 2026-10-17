/**
 * Tool: explain_code — explain any code this server can emit: the 57 PKI_*
 * engine errors (class, when raised, the engine remedy and the MCP-input
 * remedy), the 43 PKI_REASON_* report reasons, the 97 PKI_DIAG_* diagnostics
 * and the wrapper's own codes. Backed by the registries vendored from the
 * pkinative v1.0.0 tag (src/data/pkinative/*.json).
 */
import { z } from 'zod';

import diagnosticsJson from '../data/pkinative/diagnostics.json' with { type: 'json' };
import errorsJson from '../data/pkinative/errors.json' with { type: 'json' };
import reasonsJson from '../data/pkinative/reasons.json' with { type: 'json' };
import { ToolError } from '../errors.js';
import { PKI_ERROR_CLASS, PKI_REMEDY } from '../pki-errors.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { WRAPPER_CODES } from '../wrapper-codes.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { parseInput, ProjectionShape } from './_shared.js';

export const EXPLAIN_CODE_NAME = 'explain_code';

const KINDS = ['error', 'reason', 'diagnostic', 'wrapper'] as const;
type Kind = (typeof KINDS)[number];

export interface CodeEntry {
    readonly code: string;
    readonly kind: Kind;
    readonly summary: string;
    readonly standard?: string;
    readonly severity?: string;
    readonly errorClass?: string;
    readonly engineClass?: string;
    readonly cwe?: string;
    readonly since?: string;
    readonly remedy: { readonly engine?: string; readonly mcp?: string };
}

interface ErrorRow { readonly code: string; readonly class: string; readonly since: string; readonly raisedWhen: string; readonly remedy: string; readonly standard: string; readonly cwe?: string }
interface ReasonRow { readonly code: string; readonly since: string; readonly returnedWhen: string; readonly remedy: string; readonly standard: string }
interface DiagnosticRow { readonly code: string; readonly severity: string; readonly since: string; readonly raisedWhen: string; readonly remedy: string; readonly standard: string }

function build(): ReadonlyMap<string, CodeEntry> {
    const map = new Map<string, CodeEntry>();
    for (const e of (errorsJson as { errors: readonly ErrorRow[] }).errors) {
        map.set(e.code, {
            code: e.code,
            kind: 'error',
            summary: e.raisedWhen,
            standard: e.standard,
            errorClass: PKI_ERROR_CLASS[e.code as keyof typeof PKI_ERROR_CLASS],
            engineClass: e.class,
            ...(e.cwe !== undefined ? { cwe: e.cwe } : {}),
            since: e.since,
            remedy: { engine: e.remedy, ...(Object.hasOwn(PKI_REMEDY, e.code) ? { mcp: PKI_REMEDY[e.code as keyof typeof PKI_REMEDY] } : {}) },
        });
    }
    for (const r of (reasonsJson as { reasons: readonly ReasonRow[] }).reasons) {
        map.set(r.code, { code: r.code, kind: 'reason', summary: r.returnedWhen, standard: r.standard, since: r.since, remedy: { engine: r.remedy } });
    }
    for (const d of (diagnosticsJson as { diagnostics: readonly DiagnosticRow[] }).diagnostics) {
        map.set(d.code, { code: d.code, kind: 'diagnostic', summary: d.raisedWhen, standard: d.standard, severity: d.severity, since: d.since, remedy: { engine: d.remedy } });
    }
    for (const w of WRAPPER_CODES) {
        map.set(w.code, { code: w.code, kind: 'wrapper', summary: w.meaning, remedy: { mcp: w.remedy } });
    }
    return map;
}

/** Every code this server can emit, keyed by code. */
export const CODE_REGISTRY: ReadonlyMap<string, CodeEntry> = build();

export const EXPLAIN_CODE_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    properties: {
        code: { type: 'string', minLength: 1, maxLength: 80, pattern: '^[A-Z][A-Z0-9_]*$', description: 'The code to explain (PKI_*, PKI_REASON_*, PKI_DIAG_* or a wrapper code such as SECURITY_VIOLATION). Omit with list:true to enumerate.' },
        kind: { type: 'string', enum: [...KINDS], description: 'Restrict a listing to one vocabulary.' },
        list: { type: 'boolean', default: false, description: 'List the codes (optionally of one kind) instead of explaining one.' },
        ...PROJECTION_INPUT_PROPERTIES,
    },
} as const;

const InputSchema = z.strictObject({
    code: z.string().min(1).max(80).regex(/^[A-Z][A-Z0-9_]*$/).optional(),
    kind: z.enum(KINDS).optional(),
    list: z.boolean().default(false),
    ...ProjectionShape,
}).superRefine((v, ctx) => {
    if (v.code === undefined && !v.list) ctx.addIssue({ code: 'custom', message: 'pass code, or list:true', path: ['code'] });
});

export interface ExplainCodeResult {
    readonly code?: string;
    readonly kind?: Kind;
    readonly summary?: string;
    readonly standard?: string;
    readonly severity?: string;
    readonly errorClass?: string;
    readonly engineClass?: string;
    readonly cwe?: string;
    readonly since?: string;
    readonly remedy?: { readonly engine?: string; readonly mcp?: string };
    readonly codes?: ReadonlyArray<{ readonly code: string; readonly kind: Kind; readonly summary: string }>;
    readonly count?: number;
}

export const EXPLAIN_CODE_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    properties: {
        code: { type: 'string' },
        kind: { type: 'string', enum: [...KINDS] },
        summary: { type: 'string', description: 'When the code is raised / returned.' },
        standard: { type: 'string' },
        severity: { type: 'string', enum: ['warning', 'info'] },
        errorClass: { type: 'string', description: 'The coarse class (usage, input, parse, security, limit, unsupported, crypto, password, check, internal).' },
        engineClass: { type: 'string', description: 'The PkiError subclass.' },
        cwe: { type: 'string' },
        since: { type: 'string' },
        remedy: { type: 'object', additionalProperties: false, properties: { engine: { type: 'string', description: "The engine's own remedy (library options)." }, mcp: { type: 'string', description: 'The MCP input that lifts it.' } } },
        codes: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { code: { type: 'string' }, kind: { type: 'string' }, summary: { type: 'string' } } } },
        count: { type: 'integer' },
    },
} as const;

export async function explainCode(rawInput: unknown): Promise<ExplainCodeResult> {
    const input = parseInput(InputSchema, rawInput);
    if (input.code !== undefined) {
        const entry = CODE_REGISTRY.get(input.code);
        if (entry === undefined) {
            throw new ToolError('NOT_FOUND', `Unknown code ${input.code}: not one of the ${CODE_REGISTRY.size} codes this server emits (list them with list:true).`, { code: input.code, remedy: 'list:true' });
        }
        if (input.kind !== undefined && entry.kind !== input.kind) {
            throw new ToolError('NOT_FOUND', `${input.code} is a ${entry.kind} code, not a ${input.kind} code.`, { code: input.code, kind: entry.kind });
        }
        return { ...entry };
    }
    const codes = [...CODE_REGISTRY.values()].filter((e) => input.kind === undefined || e.kind === input.kind).map((e) => ({ code: e.code, kind: e.kind, summary: e.summary }));
    return { codes, count: codes.length };
}

export const EXPLAIN_CODE_TOOL = defineTool<ExplainCodeResult>({
    name: EXPLAIN_CODE_NAME,
    title: 'Explain a code (errors, reasons, diagnostics, wrapper codes)',
    kind: 'explain',
    description:
        "Explain any code this server can emit, from the registries vendored at the pkinative v1.0.0 tag: the 57 PKI_* engine error codes (coarse class, PkiError subclass, when raised, CWE, the engine's remedy and the MCP input that lifts it), the 43 PKI_REASON_* codes a verdict returns, the 97 PKI_DIAG_* diagnostics (with severity) and the wrapper's own codes (VALIDATION_ERROR, SECURITY_VIOLATION, LIMIT_CEILING_EXCEEDED, SECRET_REQUIRED, …). list:true enumerates (kind filters one vocabulary). Branch on codes, never on message text.",
    inputSchema: EXPLAIN_CODE_INPUT_SCHEMA,
    rawOutputSchema: EXPLAIN_CODE_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(EXPLAIN_CODE_OUTPUT_SCHEMA, {}, `A code explanation, or a listing.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: true,
    examples: [
        { title: 'Why was my RSA PKCS#12 key not imported?', input: { code: 'PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED' } },
        { title: 'Every reason code a verdict can return', input: { list: true, kind: 'reason', fields: ['codes.code', 'count'] } },
    ],
    handler: explainCode,
    text: (r) => r.code !== undefined ? `${EXPLAIN_CODE_NAME}: ${r.code} (${r.kind}${r.errorClass !== undefined ? `, ${r.errorClass}` : ''}${r.severity !== undefined ? `, ${r.severity}` : ''}) — ${r.summary ?? ''}` : `${EXPLAIN_CODE_NAME}: ${r.count ?? 0} code(s).`,
});
