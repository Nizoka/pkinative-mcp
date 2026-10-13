/**
 * MCP 2026-07-28 normative conformance of the tool catalogue:
 *
 *   - server/tools, Output Schema: "Servers MUST provide structured results
 *     that conform to this schema" — every `structuredContent` this server
 *     can emit (full result, `verbosity:'summary'`, `fields` projections,
 *     file mode, diagnostics / summary extras) is validated against the
 *     advertised `outputSchema` with the SDK's own JSON Schema 2020-12 engine.
 *     The cases are the catalogue's own `_meta.examples` (every tool ships
 *     one or two), run in a sandbox holding the 42 fixtures under
 *     `fixtures/`, plus their summary / fields variants and a few extras.
 *   - `_meta.examples[].input` ("a self-contained input") must validate
 *     against the tool's `inputSchema`, and must execute without
 *     VALIDATION_ERROR (an `expectError` example may refuse with that code).
 *   - Every object schema keeps `additionalProperties: false`, no `$ref`.
 *   - server.json satisfies the registry limits that the publisher enforces.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, readFileSync, promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/server/validators/ajv';

import { callToolDirect, ensureEngineReady, listToolsPayload, toolDefinition } from '../src/server.js';
import { assertResultClean } from './_pki-assert.js';
import { FIXTURE_FILES, FIXTURES } from './_pki-fixtures.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SERVER_JSON = path.join(ROOT, 'server.json');

const validator = new AjvJsonSchemaValidator();
const tools = listToolsPayload().tools;
const byName = new Map(tools.map((t) => [t.name, t]));

function validateAgainst(schema: unknown, value: unknown): string | null {
    const v = validator.getValidator(schema as Parameters<typeof validator.getValidator>[0]);
    const r = v(value);
    return r.valid ? null : r.errorMessage;
}

interface Example { readonly title: string; readonly input: Record<string, unknown> }

function examplesOf(name: string): readonly Example[] {
    return ((byName.get(name)?._meta as { examples?: Example[] } | undefined)?.examples) ?? [];
}

/** The first top-level key of an example input that is a plain scalar/object field a projection can name. */
function firstField(schema: Record<string, unknown>): string {
    const props = Object.keys((schema['properties'] as Record<string, unknown>) ?? {});
    return props.find((p) => !['diagnostics', 'diagnosticCounts', 'diagnosticsTruncated'].includes(p)) ?? props[0] ?? 'x';
}

describe('MCP 2026-07-28 — structuredContent conforms to outputSchema (SDK 2020-12 validator)', () => {
    let sandbox: string;

    beforeAll(async () => {
        await ensureEngineReady();
        sandbox = await fs.mkdtemp(path.join(os.tmpdir(), 'pkinative-schema-'));
        await fs.mkdir(path.join(sandbox, 'fixtures'));
        for (const name of FIXTURE_FILES) await fs.copyFile(path.join(FIXTURES, name), path.join(sandbox, 'fixtures', name));
        process.env['PKINATIVE_MCP_OUTPUT_DIR'] = sandbox;
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_AT'];
    });

    afterAll(async () => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        await fs.rm(sandbox, { recursive: true, force: true });
    });

    for (const t of tools) {
        const def = toolDefinition(t.name);
        const projectable = def !== undefined && ['read', 'verdict', 'engine', 'explain'].includes(def.kind);
        for (const [i, ex] of examplesOf(t.name).entries()) {
            it(`${t.name} example ${i + 1} (${ex.title.slice(0, 50)}) validates`, async () => {
                // File-mode examples write once: give each run a unique path.
                const input = JSON.parse(JSON.stringify(ex.input).replace(/"outputPath":"([^"]+)"/, `"outputPath":"schema-${i}-$1"`)) as Record<string, unknown>;
                const r = await callToolDirect(t.name, input);
                const text = (r.content[0] as { text?: string } | undefined)?.text ?? '';
                if (r.isError === true) {
                    // Only a documented engine refusal (a PKI_* code, e.g. a legacy PKCS#12 example) is acceptable; never VALIDATION_ERROR.
                    expect(text, `${t.name}: ${text.slice(0, 200)}`).not.toContain('VALIDATION_ERROR');
                    expect(text).toMatch(/\[PKI_[A-Z0-9_]+\]|\[NOT_FOUND\]/);
                    return;
                }
                assertResultClean(r);
                expect(validateAgainst(t.outputSchema, r.structuredContent), `${t.name} example ${i + 1}`).toBeNull();
                if (projectable) {
                    const summary = await callToolDirect(t.name, { ...input, verbosity: 'summary' });
                    expect(summary.isError).not.toBe(true);
                    expect(validateAgainst(t.outputSchema, summary.structuredContent), `${t.name} summary`).toBeNull();
                    const field = firstField(t.outputSchema as Record<string, unknown>);
                    const projected = await callToolDirect(t.name, { ...input, fields: [field, 'diagnostics'] });
                    expect(projected.isError).not.toBe(true);
                    expect(validateAgainst(t.outputSchema, projected.structuredContent), `${t.name} fields`).toBeNull();
                }
            }, 60_000);
        }
    }
});

describe('tool catalogue hygiene', () => {
    it('every object schema keeps additionalProperties:false (or an explicit additionalProperties schema) and no schema uses $ref', () => {
        const walk = (node: unknown, at: string, issues: string[]): void => {
            if (Array.isArray(node)) {
                node.forEach((n, i) => walk(n, `${at}[${i}]`, issues));
                return;
            }
            if (node === null || typeof node !== 'object') return;
            const o = node as Record<string, unknown>;
            const isObjectType = o['type'] === 'object' || (Array.isArray(o['type']) && (o['type'] as unknown[]).includes('object'));
            if (isObjectType && o['properties'] !== undefined && o['additionalProperties'] === undefined) issues.push(`${at}: object without additionalProperties`);
            if ('$ref' in o) issues.push(`${at}: $ref`);
            for (const [k, v] of Object.entries(o)) walk(v, `${at}.${k}`, issues);
        };
        const issues: string[] = [];
        for (const t of tools) {
            walk(t.inputSchema, `${t.name}.inputSchema`, issues);
            if (t.outputSchema !== undefined) walk(t.outputSchema, `${t.name}.outputSchema`, issues);
            expect((t.inputSchema as Record<string, unknown>)['additionalProperties'], `${t.name}.inputSchema`).toBe(false);
        }
        expect(issues).toEqual([]);
    });

    it('every input-schema property (recursively, union arms and array items included) has a non-empty description', () => {
        const missing: string[] = [];
        const walk = (node: unknown, at: string): void => {
            if (node === null || typeof node !== 'object') return;
            const o = node as Record<string, unknown>;
            if (o['properties'] !== undefined) {
                for (const [k, v] of Object.entries(o['properties'] as Record<string, Record<string, unknown>>)) {
                    const d = v['description'];
                    if (typeof d !== 'string' || d.trim().length === 0) missing.push(`${at}.${k}`);
                    walk(v, `${at}.${k}`);
                }
            }
            if (o['items'] !== undefined) walk(o['items'], `${at}[]`);
            for (const [i, arm] of ((o['oneOf'] ?? o['anyOf'] ?? []) as unknown[]).entries()) walk(arm, `${at}|${i}`);
        };
        let total = 0;
        const count = (node: unknown): void => {
            if (node === null || typeof node !== 'object') return;
            const o = node as Record<string, unknown>;
            if (o['properties'] !== undefined) {
                for (const v of Object.values(o['properties'] as Record<string, unknown>)) {
                    total++;
                    count(v);
                }
            }
            if (o['items'] !== undefined) count(o['items']);
            for (const arm of (o['oneOf'] ?? o['anyOf'] ?? []) as unknown[]) count(arm);
        };
        for (const t of tools) {
            walk(t.inputSchema, t.name);
            count(t.inputSchema);
        }
        expect(total).toBeGreaterThan(200);
        expect(missing, `undescribed input properties: ${missing.join(', ')}`).toEqual([]);
    });

    it('every _meta.examples[].input validates against its inputSchema', () => {
        const failures: string[] = [];
        for (const t of tools) {
            const examples = examplesOf(t.name);
            expect(examples.length, `${t.name} has examples`).toBeGreaterThan(0);
            for (const ex of examples) {
                const err = validateAgainst(t.inputSchema, ex.input);
                if (err !== null) failures.push(`${t.name} :: ${ex.title} :: ${err}`);
            }
        }
        expect(failures).toEqual([]);
    });

    it('every artefact tool declares a typed summary and a sha256', () => {
        for (const t of tools) {
            const def = toolDefinition(t.name);
            if (def?.kind !== 'artefact') continue;
            const schema = t.outputSchema as { properties: Record<string, { additionalProperties?: boolean; properties?: Record<string, unknown> }>; required?: string[] };
            expect(schema.properties['sha256'], `${t.name}.sha256`).toBeDefined();
            expect(schema.properties['summary'], `${t.name}.summary`).toBeDefined();
            expect(schema.properties['summary']?.additionalProperties, `${t.name}.summary strict`).toBe(false);
            expect(schema.required, t.name).toEqual(expect.arrayContaining(['mode', 'encoding', 'sizeBytes', 'sha256', 'summary']));
        }
    });

    it.skipIf(!existsSync(SERVER_JSON))('server.json respects the registry limits the publisher enforces', () => {
        const manifest = JSON.parse(readFileSync(SERVER_JSON, 'utf8')) as { description: string; name: string; version: string };
        expect(manifest.description.length).toBeLessThanOrEqual(100);
        expect(manifest.name).toMatch(/^io\.github\.[A-Za-z0-9-]+\/[a-z0-9-]+$/);
    });
});
