/**
 * Structural fingerprint of the tool catalogue (`tools/list`) with every
 * `description` doc string removed (a schema *property* named description is
 * kept): names, titles, annotations, input/output schema shapes (types,
 * enums, defaults, constraints, required, additionalProperties) and the
 * number of `_meta.examples`.
 *
 * Pure: shared by scripts/tool-shape.ts (print / --write / --check) and the
 * gate's `verify:tool-shape` step, which holds the BUILT catalogue to the
 * committed fixture the way tests/catalogue-parity.test.ts holds the source
 * one. Ported from pdfnative-mcp.
 */

export interface ListedTool {
    readonly name: string;
    readonly title?: string;
    readonly annotations?: unknown;
    readonly inputSchema?: unknown;
    readonly outputSchema?: unknown;
    readonly _meta?: { readonly examples?: readonly unknown[] };
}

export interface ToolShape {
    readonly name: string;
    readonly title?: string;
    readonly annotations?: unknown;
    readonly inputSchema: unknown;
    readonly outputSchema: unknown;
    readonly exampleCount: number;
}

export function strip(node: unknown): unknown {
    if (Array.isArray(node)) return node.map(strip);
    if (node === null || typeof node !== 'object') return node;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (!(k === 'description' && typeof v === 'string')) out[k] = strip(v);
    }
    return out;
}

export function toolShape(tools: readonly ListedTool[]): ToolShape[] {
    return tools.map((t) => ({
        name: t.name,
        title: t.title,
        annotations: t.annotations,
        inputSchema: strip(t.inputSchema),
        outputSchema: strip(t.outputSchema),
        exampleCount: (t._meta?.examples ?? []).length,
    }));
}

/** The exact text of tests/_fixtures/tool-shape.json for a catalogue. */
export function serializeShape(tools: readonly ListedTool[]): string {
    return `${JSON.stringify(toolShape(tools), null, 1)}\n`;
}

// ── Size budget ──────────────────────────────────────────────────────

/**
 * Every shared fragment (the PKI input, the signer, the trust fragment, the
 * projection inputs, the diagnostics report) is inlined in every tool that
 * carries it (no `$ref`, for host compatibility), so the catalogue grows
 * with each fragment. A host forwards it to the model on every session, so
 * the growth is budgeted here and the measured figure is held to the
 * manifest (`declared.toolsListBytes`) so the documents quote a number
 * `--check` has seen. 448 KiB for this 34-tool catalogue (pdfnative-mcp
 * budgets 320 KiB for 20 tools): the 22 named limits and the parse fragment
 * ride on 31 tools, the PKI input on 70 properties — their descriptions are
 * kept terse on purpose, the long form living in describe_engine and the
 * agent contract.
 */
export const TOOLS_LIST_BUDGET_BYTES = 448 * 1024;
export const INSTRUCTIONS_BUDGET_BYTES = 8 * 1024;
/** `declared.toolsListBytes` may drift this far from the measurement before the manifest must move. */
export const TOOLS_LIST_TOLERANCE = 0.02;

export interface CatalogueSize {
    /** UTF-8 bytes of the `tools/list` result as a host receives it. */
    readonly toolsBytes: number;
    /** UTF-8 bytes of `serverInfo.instructions`. */
    readonly instructionsBytes: number;
    /** `declared.toolsListBytes` of docs/assets/ecosystem.json, or null when the manifest is absent. */
    readonly declaredToolsBytes: number | null;
}

/** Failure lines, empty when every budget holds. Pure, so tests feed it figures directly. */
export function judgeCatalogueBudget(size: CatalogueSize): string[] {
    const failures: string[] = [];
    if (size.toolsBytes > TOOLS_LIST_BUDGET_BYTES) {
        failures.push(`tools/list is ${size.toolsBytes} bytes — the budget is ${TOOLS_LIST_BUDGET_BYTES} (docs/API_STABILITY.md §5: trim a shared fragment or raise the budget deliberately)`);
    }
    if (size.instructionsBytes > INSTRUCTIONS_BUDGET_BYTES) {
        failures.push(`serverInfo.instructions is ${size.instructionsBytes} bytes — the budget is ${INSTRUCTIONS_BUDGET_BYTES}; move detail to a prompt or a guide`);
    }
    if (size.declaredToolsBytes !== null) {
        const drift = Math.abs(size.toolsBytes - size.declaredToolsBytes) / size.declaredToolsBytes;
        if (drift > TOOLS_LIST_TOLERANCE) {
            failures.push(`declared.toolsListBytes says ${size.declaredToolsBytes} but tools/list measures ${size.toolsBytes} — update docs/assets/ecosystem.json (and the documents quoting it), not the code`);
        }
    }
    return failures;
}
