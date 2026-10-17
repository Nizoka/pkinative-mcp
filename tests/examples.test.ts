/**
 * Examples-as-tests: every file under `examples/` is loaded through the same
 * planner the sample generator uses (scripts/lib/example-runner.ts), its tool
 * names are checked against the live registry and its resolved arguments
 * against the advertised input schema, and every hermetic example is executed
 * end to end through `callToolDirect` inside a sandbox holding the fixtures
 * under `fixtures/` with the instant pinned. An `expectError` example must
 * fail with its code on its last step; a `documentationOnly` example is
 * schema-checked and never executed. Every result is swept for secret
 * needles and every DER artefact must parse as one DER value.
 *
 * This guarantees the published examples never drift from the real schemas
 * or runtime behaviour: a stale field name or renamed tool fails CI.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { AT_ENV, prepareSandbox, removeSandbox, SAMPLE_AT } from '../scripts/helpers/io.js';
import { blockingPlaceholders, loadExamples, runExample, validateAgainstSchema, type Example } from '../scripts/lib/example-runner.js';
import { callToolDirect, ensureEngineReady, listToolsPayload, toolNames } from '../src/server.js';
import { artefactBytes, assertResultClean, assertValidDer, errorCodeOf } from './_pki-assert.js';
import { AT } from './_pki-fixtures.js';

const EXAMPLES: readonly Example[] = loadExamples();
const SCHEMAS = new Map(listToolsPayload().tools.map((t) => [t.name, t.inputSchema as Readonly<Record<string, unknown>>]));

type Result = Awaited<ReturnType<typeof callToolDirect>>;

/** The artefact of a successful artefact result, as base64 of its DER (a PEM text is decoded first); null for a JSON-only result. */
function artefactOf(result: Result): string | null {
    const block = result.content.find((c) => c.type === 'resource');
    if (block === undefined) return null;
    const bytes = artefactBytes(result as { content: ReadonlyArray<Record<string, unknown>> });
    assertValidDer(bytes);
    return Buffer.from(bytes).toString('base64');
}

let sandbox: string | null = null;

beforeAll(async () => {
    await ensureEngineReady();
    sandbox = prepareSandbox('pkinative-mcp-examples-');
    expect(process.env[AT_ENV]).toBe(SAMPLE_AT);
    expect(SAMPLE_AT).toBe(AT);
});

afterAll(() => {
    removeSandbox(sandbox);
    sandbox = null;
});

describe('examples/ catalogue', () => {
    it('holds at least one example per tool, and names only registered tools', () => {
        expect(EXAMPLES.length).toBeGreaterThan(0);
        const covered = new Set(EXAMPLES.flatMap((e) => e.steps.map((s) => s.tool)));
        const names = toolNames();
        for (const tool of names) {
            if (tool === 'draft_governance_issue' || tool === 'describe_engine' || tool === 'explain_code') continue;
            expect(covered.has(tool), `no example exercises ${tool}`).toBe(true);
        }
        for (const tool of covered) expect(names, `${tool} is not a registered tool`).toContain(tool);
    });

    it('uses only the documented placeholder vocabulary', () => {
        for (const e of EXAMPLES) {
            const blocking = blockingPlaceholders(e);
            expect(blocking, `${e.name} uses an unresolvable placeholder`).toEqual([]);
        }
    });

    it('every example carries a description and, when chained, resolvable step references', () => {
        for (const e of EXAMPLES) {
            expect(e.description.length, e.name).toBeGreaterThan(20);
            for (const [i, step] of e.steps.entries()) {
                for (const m of JSON.stringify(step.arguments).matchAll(/<base64 from step (\d+)>/g)) {
                    const n = Number(m[1]);
                    expect(n, `${e.name} step ${i + 1} references a later or same step`).toBeLessThan(i + 1);
                }
            }
        }
    });
});

describe.each(EXAMPLES.map((e) => [e.name, e] as const))('%s', (_name, example) => {
    it('conforms to the input schema of every tool it calls', () => {
        expect(validateAgainstSchema(example, (tool) => SCHEMAS.get(tool))).toEqual([]);
    });

    it.skipIf(example.documentationOnly)(example.expectError === undefined ? 'runs end to end' : `fails with ${example.expectError}`, async () => {
        const outputs = await runExample(example, {
            call: async (tool, args) => {
                const result = await callToolDirect(tool, args);
                assertResultClean(result, `${example.name} ${tool}`);
                const isError = result.isError === true;
                return { result, artefactBase64: isError ? null : artefactOf(result), isError, code: errorCodeOf(result) };
            },
        });
        expect(outputs).toHaveLength(example.steps.length);
        for (const o of outputs) {
            const r = o.result as Result;
            if (example.expectError !== undefined && o.step === example.steps.length) {
                expect(r.isError).toBe(true);
                expect(errorCodeOf(r)).toBe(example.expectError);
                const text = (r.content[0] as { text?: string }).text ?? '';
                expect(text).toContain(`[${example.expectError}]`);
            } else {
                expect(r.isError, `${o.tool} step ${o.step}`).not.toBe(true);
                expect(r.structuredContent, `${o.tool} returns structuredContent`).toBeDefined();
            }
        }
    });
});
