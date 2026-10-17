/**
 * pkinative-mcp — hermetic example runner (pure planning + a driver)
 * ===================================================================
 * `examples/*.json` are the published MCP call payloads:
 *
 *   { "description": "…", "tool": "<name>", "arguments": { … } }
 *   { "description": "…", "steps": [ { "tool": "<name>", "arguments": { … } }, … ] }
 *
 * plus two optional members: `expectError: "<CODE>"` (the call must fail with
 * that wrapper / engine code — a documented refusal) and
 * `documentationOnly: true` (the payload is validated against the tool's
 * input schema but never executed: it names a file the reader must bring).
 *
 * Placeholders are whole string values:
 *   <fixture:NAME>          the PKI input fragment of tests/fixtures/pki/NAME
 *                           ({ pem } for a .pem file, { derBase64 } otherwise)
 *   <content:NAME>          the CONTENT input fragment ({ base64 }) of a fixture
 *   <base64 from step N>    the base64 of the artefact step N produced
 *   <password:test-only>    the fixture password (public test material)
 * `path: 'fixtures/NAME'` inputs resolve through the sandbox the generator
 * prepares (scripts/helpers/io.ts); every example is therefore hermetic —
 * the fixture set is the only material, and it is in the repository.
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { EXAMPLES_DIR, FIXTURE_PASSWORD, contentInput, fixtureExists, fixtureInput } from '../helpers/io.js';
import { validate, type Json } from './json-schema-lite.js';

export { EXAMPLES_DIR };

export interface ExampleStep {
    readonly tool: string;
    readonly arguments: Readonly<Record<string, unknown>>;
}

export interface Example {
    /** File name without `.json`. */
    readonly name: string;
    readonly description: string;
    readonly steps: readonly ExampleStep[];
    /** The call must fail with this code. */
    readonly expectError?: string;
    /** Validate against the input schema only; never execute. */
    readonly documentationOnly: boolean;
}

interface ExampleFile {
    readonly description?: string;
    readonly tool?: string;
    readonly arguments?: Record<string, unknown>;
    readonly steps?: readonly ExampleStep[];
    readonly expectError?: string;
    readonly documentationOnly?: boolean;
}

export function parseExample(name: string, text: string): Example {
    const parsed = JSON.parse(text) as ExampleFile;
    const steps = Array.isArray(parsed.steps)
        ? parsed.steps.map((s) => ({ tool: s.tool, arguments: s.arguments ?? {} }))
        : typeof parsed.tool === 'string' ? [{ tool: parsed.tool, arguments: parsed.arguments ?? {} }] : [];
    if (steps.length === 0) throw new Error(`examples/${name}.json: no tool / steps`);
    for (const [i, s] of steps.entries()) {
        if (typeof s.tool !== 'string' || s.tool.length === 0) throw new Error(`examples/${name}.json: step ${i + 1} has no tool`);
    }
    return {
        name,
        description: typeof parsed.description === 'string' ? parsed.description : '',
        steps,
        ...(typeof parsed.expectError === 'string' ? { expectError: parsed.expectError } : {}),
        documentationOnly: parsed.documentationOnly === true,
    };
}

export function loadExamples(dir: string = EXAMPLES_DIR): Example[] {
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
        .filter((f) => f.endsWith('.json'))
        .sort()
        .map((f) => parseExample(f.replace(/\.json$/, ''), readFileSync(join(dir, f), 'utf8')));
}

/** Every `<…>` token that is a whole string value somewhere in `value`. */
export function placeholdersOf(value: unknown, into: Set<string> = new Set()): Set<string> {
    if (typeof value === 'string') {
        const m = /^<(.+)>$/.exec(value);
        if (m?.[1] !== undefined) into.add(m[1]);
    } else if (Array.isArray(value)) {
        for (const v of value) placeholdersOf(v, into);
    } else if (value !== null && typeof value === 'object') {
        for (const v of Object.values(value)) placeholdersOf(v, into);
    }
    return into;
}

const STEP_REF = /^base64 from step (\d+)$/;
const FIXTURE_REF = /^fixture:([A-Za-z0-9._-]+)$/;
const CONTENT_REF = /^content:([A-Za-z0-9._-]+)$/;
const PASSWORD_REF = 'password:test-only';

/** True for a placeholder the generator can resolve from the repository alone. */
export function isHermeticPlaceholder(token: string): boolean {
    if (STEP_REF.test(token) || token === PASSWORD_REF) return true;
    const fixture = FIXTURE_REF.exec(token)?.[1] ?? CONTENT_REF.exec(token)?.[1];
    return fixture !== undefined && fixtureExists(fixture);
}

/** The placeholders that keep an example out of the hermetic run (empty = it runs). */
export function blockingPlaceholders(example: Example): string[] {
    const tokens = new Set<string>();
    for (const step of example.steps) placeholdersOf(step.arguments, tokens);
    return [...tokens].filter((t) => !isHermeticPlaceholder(t)).sort();
}

export function substitute(value: unknown, resolve: (token: string) => unknown): unknown {
    if (typeof value === 'string') {
        const m = /^<(.+)>$/.exec(value);
        return m?.[1] === undefined ? value : resolve(m[1]);
    }
    if (Array.isArray(value)) return value.map((v) => substitute(v, resolve));
    if (value !== null && typeof value === 'object') {
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value)) out[k] = substitute(v, resolve);
        return out;
    }
    return value;
}

/** Resolve the arguments of step `index` (0-based) given the artefacts (base64) of the earlier steps. */
export function resolveArguments(example: Example, index: number, earlier: ReadonlyArray<string | null>): Record<string, unknown> {
    const step = example.steps[index];
    if (step === undefined) throw new Error(`${example.name}: no step ${index + 1}`);
    return substitute(step.arguments, (token) => {
        const ref = STEP_REF.exec(token);
        if (ref !== null) {
            const n = Number(ref[1]);
            const artefact = earlier[n - 1];
            if (n < 1 || n > index) throw new Error(`${example.name}: step ${index + 1} refers to step ${n}, which is not an earlier step`);
            if (artefact === null || artefact === undefined) throw new Error(`${example.name}: step ${n} produced no artefact to chain into step ${index + 1}`);
            return artefact;
        }
        const fixture = FIXTURE_REF.exec(token)?.[1];
        if (fixture !== undefined) return fixtureInput(fixture);
        const content = CONTENT_REF.exec(token)?.[1];
        if (content !== undefined) return contentInput(content);
        if (token === PASSWORD_REF) return FIXTURE_PASSWORD;
        throw new Error(`${example.name}: <${token}> is not a hermetic placeholder`);
    }) as Record<string, unknown>;
}

export interface StepOutput {
    /** 1-based step number. */
    readonly step: number;
    readonly tool: string;
    readonly arguments: Readonly<Record<string, unknown>>;
    readonly result: unknown;
    /** Base64 of the artefact the step produced, or null. */
    readonly artefactBase64: string | null;
}

export interface RunnerDeps {
    /** Call a tool; returns the raw result and the base64 of its artefact (null for a JSON-only result). */
    readonly call: (tool: string, args: Readonly<Record<string, unknown>>) => Promise<{ readonly result: unknown; readonly artefactBase64: string | null; readonly isError: boolean; readonly code: string | null }>;
}

/** Run every step of a hermetic example in order, chaining artefacts; an `expectError` example must fail with its code on its LAST step. */
export async function runExample(example: Example, deps: RunnerDeps): Promise<StepOutput[]> {
    const outputs: StepOutput[] = [];
    const artefacts: Array<string | null> = [];
    for (const [i, step] of example.steps.entries()) {
        const args = resolveArguments(example, i, artefacts);
        const r = await deps.call(step.tool, args);
        const last = i === example.steps.length - 1;
        if (example.expectError !== undefined && last) {
            if (!r.isError) throw new Error(`${example.name}: expected ${step.tool} to fail with ${example.expectError}, it succeeded`);
            if (r.code !== example.expectError) throw new Error(`${example.name}: expected ${step.tool} to fail with ${example.expectError}, got ${r.code ?? 'no code'}`);
        } else if (r.isError) {
            throw new Error(`${example.name}: step ${i + 1} (${step.tool}) failed: ${describeError(r.result)}`);
        }
        artefacts.push(r.artefactBase64);
        outputs.push({ step: i + 1, tool: step.tool, arguments: args, result: r.result, artefactBase64: r.artefactBase64 });
    }
    return outputs;
}

function describeError(result: unknown): string {
    const content = (result as { content?: Array<{ text?: string }> } | undefined)?.content;
    return content?.[0]?.text ?? 'unknown error';
}

/**
 * Hold a documentation-only example to the input schema of its tool (every
 * placeholder resolved to a fixture value first, so the shape is what a host
 * would send). Returns the failure lines; empty when it conforms.
 */
export function validateAgainstSchema(example: Example, schemaOf: (tool: string) => Readonly<Record<string, unknown>> | undefined): string[] {
    const failures: string[] = [];
    const stand: Array<string | null> = [];
    for (const [i, step] of example.steps.entries()) {
        const schema = schemaOf(step.tool);
        if (schema === undefined) {
            failures.push(`${example.name}: step ${i + 1} names an unknown tool "${step.tool}"`);
            continue;
        }
        let args: Record<string, unknown>;
        try {
            args = resolveArguments(example, i, stand);
        } catch (err) {
            failures.push(err instanceof Error ? err.message : String(err));
            continue;
        }
        stand.push('AAAA');
        for (const f of validate(args as Json, schema as { readonly [key: string]: Json })) failures.push(`${example.name}: step ${i + 1} (${step.tool}) ${f}`);
    }
    return failures;
}
