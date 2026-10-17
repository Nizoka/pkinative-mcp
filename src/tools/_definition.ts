/**
 * The registry entry every tool module contributes (`src/tools/_registry.ts`
 * assembles them in registration order; `src/server.ts` dispatches on
 * `kind`). Kept out of server.ts so the tool modules never import the
 * server (no cycle), and so the registry can be built without a transport.
 */
import type { OutputResult } from '../output.js';

/** How `server.ts` shapes a tool's result. */
export type ToolKind =
    /** A report (`structuredContent` = the wire form, projectable with verbosity / fields). */
    | 'read'
    /** A verdict (`valid` + `reasons[]`; never isError for a negative verdict). */
    | 'verdict'
    /** A produced DER artefact (embedded resource block once, or a resource_link). */
    | 'artefact'
    /** The capability manifest (never cached). */
    | 'engine'
    /** A code lookup. */
    | 'explain'
    /** The HITL issue draft. */
    | 'governance';

export const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;
/** Writes a deterministic artefact (file mode never overwrites). */
export const WRITES = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;
/** Produces a non-idempotent artefact (random serial / nonce, wall-clock time, randomised ECDSA). */
export const PRODUCES = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false } as const;

export type ToolAnnotations = typeof READ_ONLY | typeof WRITES | typeof PRODUCES;

/** A read / verdict result may carry one artefact attachment (an extracted block, a re-encoded node, a PEM bundle). */
export interface ArtefactAttachment {
    readonly artefact?: OutputResult | undefined;
}

export interface ToolDefinition {
    readonly name: string;
    readonly title: string;
    readonly description: string;
    readonly kind: ToolKind;
    readonly inputSchema: Readonly<Record<string, unknown>>;
    readonly outputSchema?: Readonly<Record<string, unknown>>;
    /** The full output schema before projection (read / verdict tools) — kept for the lock-step tests. */
    readonly rawOutputSchema?: Readonly<Record<string, unknown>>;
    readonly annotations: ToolAnnotations;
    /** Minimal MCP `_meta.examples` payload — each entry is a self-contained input (≤ 2). */
    readonly examples?: ReadonlyArray<{ readonly title: string; readonly input: Record<string, unknown> }>;
    /** False for tools whose output depends on the environment or a secret, whatever the input. */
    readonly cacheable: boolean;
    /** The instant inputs of the tool (`at`, `signingTime`, `spec.notBefore` …): absent ⇒ clock-dependent ⇒ never cached. */
    readonly instantInputs?: readonly string[];
    readonly handler: (args: unknown) => Promise<Record<string, unknown>>;
    /** The one-line `content[0].text`. */
    readonly text: (result: Record<string, unknown>) => string;
    /** The `verbosity:'summary'` projection (read / verdict / engine tools). */
    readonly summary?: (result: Record<string, unknown>) => Record<string, unknown>;
}

/** Type-safe helper: a tool module declares its definition with its own result type, erased for the registry. */
export function defineTool<R extends object>(def: Omit<ToolDefinition, 'handler' | 'text' | 'summary'> & {
    readonly handler: (args: unknown) => Promise<R>;
    readonly text: (result: R) => string;
    readonly summary?: (result: R) => Record<string, unknown>;
}): ToolDefinition {
    const { handler, text, summary, ...rest } = def;
    return {
        ...rest,
        handler: handler as (args: unknown) => Promise<Record<string, unknown>>,
        text: text as (result: Record<string, unknown>) => string,
        ...(summary !== undefined ? { summary: summary as (result: Record<string, unknown>) => Record<string, unknown> } : {}),
    };
}

/**
 * MCP 2026-07-28 (server/tools, Output Schema): "Servers MUST provide
 * structured results that conform to [the output] schema". The read tools can
 * project their result (`verbosity: 'summary'` collapses to scalars, `fields`
 * keeps a dot-path subset), so their advertised schema describes the *full*
 * shape with every property optional at every level — `additionalProperties:
 * false` stays, `required` is removed recursively — and declares the
 * summary-only scalars. A validating host then accepts the full result, the
 * summary and any projection alike.
 */
export function projectableOutputSchema(schema: Readonly<Record<string, unknown>>, summaryProperties: Readonly<Record<string, unknown>>, description: string): Record<string, unknown> {
    const strip = (node: unknown): unknown => {
        if (Array.isArray(node)) return node.map(strip);
        if (node === null || typeof node !== 'object') return node;
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
            // The schema keyword is an array; a *property* named "required" is an object.
            if (k === 'required' && Array.isArray(v)) continue;
            out[k] = strip(v);
        }
        return out;
    };
    const stripped = strip(schema) as Record<string, unknown>;
    return {
        ...stripped,
        description,
        properties: { ...(stripped['properties'] as Record<string, unknown>), ...summaryProperties },
    };
}

export const PROJECTION_NOTE =
    " Every property is optional because the result can be projected: verbosity:'summary' returns only the scalar summary fields, fields:[...] keeps a dot-path subset. Defaults return the full shape.";
