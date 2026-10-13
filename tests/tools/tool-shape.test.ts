// scripts/lib/tool-shape.ts — the structural projection of tools/list the
// gate's verify:tool-shape step and tests/catalogue-parity.test.ts share, and
// the catalogue size budget.

import { describe, it, expect } from 'vitest';

import { listToolsPayload } from '../../src/server.js';
import { INSTRUCTIONS_BUDGET_BYTES, TOOLS_LIST_BUDGET_BYTES, judgeCatalogueBudget, serializeShape, strip, toolShape } from '../../scripts/lib/tool-shape.js';

describe('tool-shape: strip', () => {
    it('removes every string `description` at every depth and keeps a property NAMED description', () => {
        const schema = {
            type: 'object', description: 'doc',
            properties: { description: { type: 'string', description: 'the field' }, n: { type: 'integer', description: 'x', minimum: 1 } },
            items: [{ description: 'a' }],
        };
        expect(strip(schema)).toEqual({ type: 'object', properties: { description: { type: 'string' }, n: { type: 'integer', minimum: 1 } }, items: [{}] });
        expect(strip(null)).toBeNull();
        expect(strip('description')).toBe('description');
    });
});

describe('tool-shape: projection', () => {
    it('keeps names, titles, annotations, stripped schemas and the example count', () => {
        const shapes = toolShape([{ name: 'a', title: 'A', annotations: { readOnlyHint: true }, inputSchema: { type: 'object', description: 'd' }, outputSchema: { type: 'object' }, _meta: { examples: [{}, {}] } }, { name: 'b' }]);
        expect(shapes).toEqual([
            { name: 'a', title: 'A', annotations: { readOnlyHint: true }, inputSchema: { type: 'object' }, outputSchema: { type: 'object' }, exampleCount: 2 },
            { name: 'b', title: undefined, annotations: undefined, inputSchema: undefined, outputSchema: undefined, exampleCount: 0 },
        ]);
    });

    it('serialises deterministically with a trailing newline, and the live catalogue projects without a description left', () => {
        const live = listToolsPayload().tools;
        const text = serializeShape(live);
        expect(text.endsWith('\n')).toBe(true);
        expect(text).toBe(serializeShape(live));
        const parsed = JSON.parse(text) as Array<{ name: string; inputSchema: unknown }>;
        expect(parsed.map((t) => t.name)).toEqual(live.map((t) => t.name));
        const walk = (n: unknown, at: string, out: string[]): void => {
            if (Array.isArray(n)) { n.forEach((x, i) => walk(x, `${at}[${i}]`, out)); return; }
            if (n === null || typeof n !== 'object') return;
            for (const [k, v] of Object.entries(n as Record<string, unknown>)) {
                if (k === 'description' && typeof v === 'string') out.push(at);
                else walk(v, `${at}.${k}`, out);
            }
        };
        const left: string[] = [];
        for (const t of parsed) walk(t.inputSchema, `${t.name}.in`, left);
        expect(left).toEqual([]);
    });
});

describe('tool-shape: budget', () => {
    it('passes within the budgets and within the manifest tolerance', () => {
        expect(judgeCatalogueBudget({ toolsBytes: 100_000, instructionsBytes: 4_000, declaredToolsBytes: 101_000 })).toEqual([]);
        expect(judgeCatalogueBudget({ toolsBytes: 100_000, instructionsBytes: 4_000, declaredToolsBytes: null })).toEqual([]);
    });

    it('fails an oversized catalogue, oversized instructions and a stale declaration', () => {
        expect(judgeCatalogueBudget({ toolsBytes: TOOLS_LIST_BUDGET_BYTES + 1, instructionsBytes: 1, declaredToolsBytes: null })).toEqual([expect.stringMatching(/tools\/list is .* bytes — the budget/)]);
        expect(judgeCatalogueBudget({ toolsBytes: 1, instructionsBytes: INSTRUCTIONS_BUDGET_BYTES + 1, declaredToolsBytes: null })).toEqual([expect.stringMatching(/serverInfo\.instructions is/)]);
        expect(judgeCatalogueBudget({ toolsBytes: 110_000, instructionsBytes: 1, declaredToolsBytes: 100_000 })).toEqual([expect.stringMatching(/declared\.toolsListBytes says 100000/)]);
    });

    it('the live instructions fit their budget (the tools/list budget is judged by verify:tool-shape --check in the gate)', async () => {
        const { __serverInstructions } = await import('../../src/server.js');
        const size = { toolsBytes: 1, instructionsBytes: Buffer.byteLength(__serverInstructions, 'utf8'), declaredToolsBytes: null };
        expect(judgeCatalogueBudget(size)).toEqual([]);
    });
});
