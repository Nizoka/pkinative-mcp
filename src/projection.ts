/**
 * Token-frugal response projection layer.
 *
 * A thin, dependency-free abstraction that lets autonomous AI agents (and CI)
 * shrink the `structuredContent` the read-only tools emit — typically by ~90 %
 * for large results — without losing the fields they actually branch on. It
 * mirrors the `--summary` / `--fields` design of the sibling `zipnative-cli`.
 *
 * Two composable levers, surfaced as opt-in tool inputs on the read-only tools:
 *
 *   1. `verbosity: 'summary'` — collapses a full result to a canonical subset
 *      (handled per-tool in `src/server.ts`; this module supplies `selectFields`).
 *   2. `fields: ['a', 'b.c']` — projects a result down to a set of dot-paths; an
 *      array segment maps over every element.
 *
 * Everything here is pure data manipulation: no I/O, no globals, no deps.
 */

/** True for a non-null, non-array object literal. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Normalise a caller-supplied `fields` value (array of dot-paths, or a single
 * comma-separated string) into trimmed, non-empty dot-path strings.
 */
export function parseFieldList(fields: unknown): string[] {
    const raw: string[] = [];
    if (typeof fields === 'string') {
        raw.push(...fields.split(','));
    } else if (Array.isArray(fields)) {
        for (const entry of fields) {
            if (typeof entry === 'string') raw.push(...entry.split(','));
        }
    }
    return raw.map((s) => s.trim()).filter((s) => s.length > 0);
}

/**
 * Project a value down to a single dot-path, preserving its nesting.
 * - An empty path returns the whole subtree (leaf).
 * - On an array, the remaining path is mapped over every element.
 * - A missing/typed-out path yields `undefined` (the caller omits it).
 */
function pick(value: unknown, segments: readonly string[]): unknown {
    if (segments.length === 0) return value;
    if (Array.isArray(value)) {
        return value.map((el) => pick(el, segments));
    }
    if (isPlainObject(value)) {
        const [head, ...rest] = segments;
        if (head === undefined || !(head in value)) return undefined;
        const picked = pick(value[head], rest);
        if (picked === undefined) return undefined;
        return { [head]: picked };
    }
    // A primitive with path left to walk → the path does not exist.
    return undefined;
}

/** Deep-merge two projections so multiple `fields` paths combine into one. */
function deepMerge(a: unknown, b: unknown): unknown {
    if (b === undefined) return a;
    if (a === undefined) return b;
    if (Array.isArray(a) && Array.isArray(b)) {
        const len = Math.max(a.length, b.length);
        const out: unknown[] = [];
        for (let i = 0; i < len; i++) out.push(deepMerge(a[i], b[i]));
        return out;
    }
    if (isPlainObject(a) && isPlainObject(b)) {
        const out: Record<string, unknown> = { ...a };
        for (const [k, v] of Object.entries(b)) {
            out[k] = k in out ? deepMerge(out[k], v) : v;
        }
        return out;
    }
    return b; // scalar conflict: last path wins
}

/**
 * Build a pruned projection of `value` containing only the requested dot-paths.
 *
 * - Paths are dot-separated; a segment landing on an array maps over its items
 *   (e.g. `signatures.valid` → `{ signatures: [{ valid }, …] }`).
 * - Unknown or non-existent paths are silently omitted (lenient by design, so an
 *   agent never errors a tool call by asking for a field that is conditionally
 *   absent).
 * - Multiple paths are deep-merged into a single object.
 */
export function selectFields(value: unknown, paths: readonly string[]): unknown {
    let result: unknown;
    for (const path of paths) {
        const segments = path
            .split('.')
            .map((s) => s.trim())
            .filter((s) => s.length > 0);
        if (segments.length === 0) continue;
        result = deepMerge(result, pick(value, segments));
    }
    return result === undefined ? {} : result;
}

/** Verbosity levels accepted by the read-only tools. */
export type Verbosity = 'summary' | 'full';

/** Read the opt-in `verbosity` input (defaults to `'full'`). */
export function readVerbosity(input: unknown): Verbosity {
    if (isPlainObject(input) && input['verbosity'] === 'summary') return 'summary';
    return 'full';
}

/** Read the opt-in `fields` input as a normalised dot-path list (empty when absent). */
export function readFields(input: unknown): string[] {
    if (!isPlainObject(input)) return [];
    return parseFieldList(input['fields']);
}

/** JSON Schema properties for the two projection inputs (spread into read tools). */
export const PROJECTION_INPUT_PROPERTIES = {
    verbosity: {
        type: 'string',
        enum: ['full', 'summary'],
        default: 'full',
        description: "'summary' returns only the scalar verdict fields (drops arrays and payloads) — the token-frugal form.",
    },
    fields: {
        type: 'array',
        maxItems: 16,
        items: { type: 'string', minLength: 1 },
        description: "Dot-path projection applied after verbosity (e.g. ['entryCount', 'entries.name']); array segments map over elements; unmatched paths are reported in _meta.unmatchedFields.",
    },
} as const;
