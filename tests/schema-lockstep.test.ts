/**
 * A-005 / A-017 — mechanical Zod ↔ JSON Schema lock-step.
 *
 * The Zod `InputSchema` consts are module-private by design (the advertised
 * `<NAME>_INPUT_SCHEMA` is the contract, the Zod twin is the gate), so this
 * suite transpiles every tool module with the TypeScript compiler API
 * (no bundler, no heuristics), rewrites its relative imports to `dist/`,
 * exposes the module-private `InputSchema` and runs the result as an ESM program and converts the Zod schema with
 * `z.toJSONSchema({ io: 'input', unrepresentable: 'any' })`. The output is
 * compared structurally with the hand-written schema `tools/list` advertises:
 * property sets, `required`, `type`, `enum`, `default`, numeric and length
 * bounds, `pattern`, `additionalProperties`, union arms. Every asymmetry
 * outside the justified allow-list below fails.
 *
 * Requires `npm run build` (dist/); skipped locally without it, a hard failure
 * under CI like the stdio smoke suite.
 */
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';
import { describe, expect, it } from 'vitest';

import { listToolsPayload } from '../src/server.js';
import { hasDist, inCi } from './_agent-client.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TOOLS_DIR = path.join(ROOT, 'src', 'tools');

const SPEC_PARSER = 'The spec object is documented in JSON Schema for the agent, but validated by the hand-written spec parser (JSON-path VALIDATION_ERROR per member, recursion the schema cannot express without $ref): the Zod twin is a loose object that only pins the discriminating member.';

/**
 * Justified asymmetries, keyed `<tool>` → `<path> [<kind>]` → reason. Anything
 * not listed here is a lock-step defect.
 */
const ALLOW_LIST: Readonly<Record<string, Readonly<Record<string, string>>>> = {
    create_certificate: {
        'create_certificate.spec [additionalProperties]': SPEC_PARSER,
        'create_certificate.spec.serialNumber [property]': SPEC_PARSER,
        'create_certificate.spec.issuer [property]': SPEC_PARSER,
        'create_certificate.spec.notBefore [property]': SPEC_PARSER,
        'create_certificate.spec.notAfter [property]': SPEC_PARSER,
        'create_certificate.spec.validityDays [property]': SPEC_PARSER,
        'create_certificate.spec.extensions [property]': SPEC_PARSER,
        'create_certificate.spec.subject [union]': SPEC_PARSER,
    },
    create_csr: {
        'create_csr.spec [additionalProperties]': SPEC_PARSER,
        'create_csr.spec.extensions [property]': SPEC_PARSER,
        'create_csr.spec.subject [union]': SPEC_PARSER,
    },
    encode_asn1: {
        'encode_asn1.spec [additionalProperties]': SPEC_PARSER,
        'encode_asn1.spec.value [property]': SPEC_PARSER,
        'encode_asn1.spec.hex [property]': SPEC_PARSER,
        'encode_asn1.spec.unusedBits [property]': SPEC_PARSER,
        'encode_asn1.spec.bits [property]': SPEC_PARSER,
        'encode_asn1.spec.stringType [property]': SPEC_PARSER,
        'encode_asn1.spec.timeType [property]': SPEC_PARSER,
        'encode_asn1.spec.children [property]': SPEC_PARSER,
        'encode_asn1.spec.tag [property]': SPEC_PARSER,
        'encode_asn1.spec.class [property]': SPEC_PARSER,
        'encode_asn1.spec.constructed [property]': SPEC_PARSER,
        'encode_asn1.spec.inner [property]': SPEC_PARSER,
        'encode_asn1.spec.type [enum]': SPEC_PARSER,
    },
};

/**
 * Representation differences that are NOT drift and are normalised before
 * comparing (documented here so the allow-list stays short):
 *   - `z.number().int()` without an explicit `.max()` serialises with
 *     `maximum: Number.MAX_SAFE_INTEGER`; the hand-written side omits it.
 *   - `z.literal('x')` serialises as `const: 'x'`; the hand-written side uses
 *     the equivalent single-value `enum: ['x']`.
 */
function normalise(node: Node): void {
    if (node['type'] === 'integer' && node['maximum'] === Number.MAX_SAFE_INTEGER) delete node['maximum'];
    if (node['type'] === 'integer' && node['minimum'] === -Number.MAX_SAFE_INTEGER) delete node['minimum'];
    if (node['const'] !== undefined && node['enum'] === undefined) {
        node['enum'] = [node['const']];
        delete node['const'];
    }
    for (const child of Object.values(node.properties ?? {})) normalise(child);
    if (node.items !== undefined) normalise(node.items);
    for (const arm of node.oneOf ?? node.anyOf ?? []) normalise(arm);
}

interface Diff { at: string; kind: string; hand: unknown; zod: unknown }

/**
 * The tool module as an ESM program that prints `z.toJSONSchema(InputSchema)`:
 * transpiled by the TypeScript compiler (types erased, nothing else changed),
 * relative imports pointed at `dist/`, the private `InputSchema` appended.
 */
function programOf(text: string): string {
    const js = ts.transpileModule(text, {
        compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022, verbatimModuleSyntax: true },
        reportDiagnostics: false,
    }).outputText;
    const rewritten = js.replace(/from\s+'(\.\.?\/[^']+)'/g, (_m, from: string) => {
        if (from.startsWith('../')) return `from './dist/${from.slice(3)}'`;
        return `from './dist/tools/${from.slice(2)}'`;
    });
    return [
        rewritten,
        /from 'zod'/.test(rewritten) ? '' : "import { z } from 'zod';",
        "process.stdout.write(JSON.stringify(z.toJSONSchema(InputSchema, { io: 'input', unrepresentable: 'any' })));",
    ].join('\n');
}

const KEYS = ['type', 'enum', 'const', 'default', 'minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'pattern', 'additionalProperties', 'format'] as const;

type Node = Record<string, unknown> & { properties?: Record<string, Node>; items?: Node; oneOf?: Node[]; anyOf?: Node[]; required?: string[] };

function compare(h: Node | undefined, z: Node | undefined, at: string, diffs: Diff[]): void {
    if (h === undefined || z === undefined) {
        diffs.push({ at, kind: 'node-missing', hand: h === undefined ? 'MISSING' : 'present', zod: z === undefined ? 'MISSING' : 'present' });
        return;
    }
    const hArms = h.oneOf ?? h.anyOf;
    const zArms = z.anyOf ?? z.oneOf;
    if (hArms !== undefined || zArms !== undefined) {
        if (hArms === undefined || zArms === undefined) {
            diffs.push({ at, kind: 'union', hand: hArms === undefined ? 'no union' : `${h.oneOf ? 'oneOf' : 'anyOf'}[${hArms.length}]`, zod: zArms === undefined ? 'no union' : `${z.anyOf ? 'anyOf' : 'oneOf'}[${zArms.length}]` });
        } else {
            if ((h.oneOf ? 'oneOf' : 'anyOf') !== (z.anyOf ? 'anyOf' : 'oneOf')) diffs.push({ at, kind: 'union-keyword', hand: h.oneOf ? 'oneOf' : 'anyOf', zod: z.anyOf ? 'anyOf' : 'oneOf' });
            if (hArms.length !== zArms.length) diffs.push({ at, kind: 'union-arity', hand: hArms.length, zod: zArms.length });
            for (let i = 0; i < Math.min(hArms.length, zArms.length); i++) compare(hArms[i], zArms[i], `${at}[arm ${i}]`, diffs);
        }
        return;
    }
    for (const k of KEYS) {
        const hv = h[k];
        const zv = z[k];
        if (JSON.stringify(hv) !== JSON.stringify(zv)) diffs.push({ at, kind: k, hand: hv === undefined ? 'absent' : hv, zod: zv === undefined ? 'absent' : zv });
    }
    const hp = h.properties;
    const zp = z.properties;
    if (hp !== undefined || zp !== undefined) {
        const hk = Object.keys(hp ?? {});
        const zk = Object.keys(zp ?? {});
        for (const k of hk) if (!zk.includes(k)) diffs.push({ at: `${at}.${k}`, kind: 'property', hand: 'present', zod: 'MISSING' });
        for (const k of zk) if (!hk.includes(k)) diffs.push({ at: `${at}.${k}`, kind: 'property', hand: 'MISSING', zod: 'present' });
        const hr = [...(h.required ?? [])].sort();
        const zr = [...(z.required ?? [])].sort();
        if (JSON.stringify(hr) !== JSON.stringify(zr)) diffs.push({ at, kind: 'required', hand: hr, zod: zr });
        for (const k of hk) if (zk.includes(k)) compare(hp![k], zp![k], `${at}.${k}`, diffs);
    }
    if (h.items !== undefined || z.items !== undefined) compare(h.items, z.items, `${at}[]`, diffs);
}

/** Run the extracted Zod schema of one tool module through z.toJSONSchema in a child process. */
function zodSchemaOf(file: string): { tool: string; schema?: Node; error?: string } {
    const text = readFileSync(path.join(TOOLS_DIR, file), 'utf8');
    const toolName = /export const [A-Z0-9_]+_NAME = '([a-z0-9_]+)';/.exec(text)?.[1] ?? file;
    const program = programOf(text);
    const run = spawnSync(process.execPath, ['--input-type=module'], { cwd: ROOT, input: program, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    if (run.status !== 0) return { tool: toolName, error: run.stderr.slice(0, 2000) };
    const schema = JSON.parse(run.stdout) as Node;
    delete schema['$schema'];
    normalise(schema);
    return { tool: toolName, schema };
}

const files = readdirSync(TOOLS_DIR).filter((f) => f.endsWith('.ts') && !f.startsWith('_'));
const byName = new Map(listToolsPayload().tools.map((t) => [t.name, t.inputSchema as Node]));

describe('dist/ presence', () => {
    it.runIf(inCi)('is built before the lock-step suite runs in CI', () => {
        expect(hasDist).toBe(true);
    });
});

describe.skipIf(!hasDist)('A-005: z.toJSONSchema(InputSchema) equals the advertised inputSchema for every tool (modulo the justified allow-list)', () => {
    it('covers every registered tool', () => {
        expect(files).toHaveLength(byName.size);
    });

    for (const file of files) {
        it(`${file}`, () => {
            const { tool, schema, error } = zodSchemaOf(file);
            expect(error, `generation failed for ${tool}:\n${error ?? ''}`).toBeUndefined();
            const hand = byName.get(tool);
            expect(hand, `${tool} is registered`).toBeDefined();
            const diffs: Diff[] = [];
            compare(hand!, schema!, tool, diffs);
            const allowed = ALLOW_LIST[tool] ?? {};
            const unexplained = diffs.filter((d) => allowed[`${d.at} [${d.kind}]`] === undefined);
            expect(unexplained.map((d) => `${d.at} [${d.kind}] hand=${JSON.stringify(d.hand)} zod=${JSON.stringify(d.zod)}`)).toEqual([]);
            // Every allow-list entry must still correspond to a live asymmetry (no stale excuses).
            const stale = Object.keys(allowed).filter((key) => !diffs.some((d) => `${d.at} [${d.kind}]` === key));
            expect(stale, `stale allow-list entries for ${tool}`).toEqual([]);
        });
    }
});

describe('A-017: the artefact producers share one Zod output fragment and every tool parses through parseInput', () => {
    it('every artefact tool spreads outputShape(...) (no duplicated outputMode / outputPath / encoding Zod shape)', () => {
        const artefactFiles = files.filter((file) => readFileSync(path.join(TOOLS_DIR, file), 'utf8').includes('emitArtefact('));
        expect(artefactFiles.length).toBeGreaterThan(0);
        for (const file of artefactFiles) {
            const text = readFileSync(path.join(TOOLS_DIR, file), 'utf8');
            expect(text, file).toMatch(/\.\.\.outputShape\(/);
            expect(text, file).not.toMatch(/outputMode:\s*z\.enum/);
            expect(text, file).not.toMatch(/outputPath:\s*z\.string/);
        }
        const output = readFileSync(path.join(ROOT, 'src', 'output.ts'), 'utf8');
        expect(output).toContain('export function outputShape');
    });

    it('every tool module calls parseInput (VALIDATION_ERROR wording is uniform)', () => {
        for (const file of files) {
            const text = readFileSync(path.join(TOOLS_DIR, file), 'utf8');
            expect(text, file).toMatch(/parseInput\(InputSchema, rawInput\)/);
            expect(text, file).not.toMatch(/\bInputSchema\.safeParse\(/);
        }
    });

    it('no input schema uses $ref / $defs / $schema', () => {
        for (const [name, schema] of byName) expect(JSON.stringify(schema), name).not.toMatch(/"\$(?:ref|defs|schema)"/);
    });
});
