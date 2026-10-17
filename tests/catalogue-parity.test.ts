/**
 * Catalogue parity gate: the *shape* of `tools/list` —
 * names, titles, annotations, input/output schemas with every `description`
 * removed, and the presence of examples — must match the committed fixture.
 *
 * Wording (descriptions, `_meta.examples` content, server instructions) is
 * free to evolve for token economy; a structural change must come with a
 * deliberate fixture refresh (`node scripts/tool-shape.mjs --write` after
 * `npm run build`) reviewed under docs/API_STABILITY.md §5.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { listToolsPayload } from '../src/server.js';

function strip(node: unknown): unknown {
    if (Array.isArray(node)) return node.map(strip);
    if (node === null || typeof node !== 'object') return node;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) if (!(k === 'description' && typeof v === 'string')) out[k] = strip(v);
    return out;
}

interface ToolShape {
    name: string;
    title?: string;
    annotations?: unknown;
    inputSchema: unknown;
    outputSchema: unknown;
    exampleCount: number;
}

const fixture = JSON.parse(readFileSync(new URL('./_fixtures/tool-shape.json', import.meta.url), 'utf8')) as ToolShape[];

describe('tools/list structural parity with tests/_fixtures/tool-shape.json', () => {
    const live = listToolsPayload().tools;

    it('lists exactly the fixture tools, in the same (registration) order', () => {
        expect(live.map((t) => t.name)).toEqual(fixture.map((t) => t.name));
    });

    for (const expected of fixture) {
        it(`${expected.name}: title, annotations and schema shapes are unchanged`, () => {
            const t = live.find((x) => x.name === expected.name)!;
            expect(t.title).toBe(expected.title);
            expect(t.annotations).toEqual(expected.annotations);
            expect(strip(t.inputSchema)).toEqual(expected.inputSchema);
            expect(strip(t.outputSchema)).toEqual(expected.outputSchema);
            const examples = ((t._meta as { examples?: unknown[] } | undefined)?.examples ?? []).length;
            expect(examples, 'at least one example; at most the fixture count (token budget)').toBeGreaterThanOrEqual(1);
            expect(examples).toBeLessThanOrEqual(expected.exampleCount);
        });
    }

    it('every description in the catalogue is non-empty and ends cleanly', () => {
        const issues: string[] = [];
        const walk = (n: unknown, at: string): void => {
            if (Array.isArray(n)) { n.forEach((x, i) => walk(x, `${at}[${i}]`)); return; }
            if (n === null || typeof n !== 'object') return;
            for (const [k, v] of Object.entries(n as Record<string, unknown>)) {
                if (k === 'description' && typeof v === 'string') {
                    if (v.trim().length === 0) issues.push(`${at}: empty description`);
                    else if (/\s$/.test(v)) issues.push(`${at}: trailing whitespace`);
                } else walk(v, `${at}.${k}`);
            }
        };
        for (const t of live) {
            if (typeof t.description !== 'string' || t.description.length === 0) issues.push(`${t.name}: empty tool description`);
            walk(t.inputSchema, `${t.name}.in`);
            walk(t.outputSchema, `${t.name}.out`);
        }
        expect(issues).toEqual([]);
    });
});
