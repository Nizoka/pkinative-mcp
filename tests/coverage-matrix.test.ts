/**
 * Coverage matrix: the whole pkinative 1.0.0 runtime surface is reached by a
 * named tool. The vendored registry `src/data/pkinative/core-exports.json`
 * (from the engine's frozen API at the v1.0.0 tag) lists 294 exports, 117 of
 * them runtime (`reach: "capability"`). Every one of those 117 must be
 * imported, by name and not as a type, by a module under `src/`, and every
 * tool module must reach the engine (directly or through a shared module).
 * The engine surface deliberately left out of the inputs is enumerated by
 * `describe_engine.unexposed` with its rationale — members, never exports.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';
import * as engine from 'pkinative';

import registry from '../src/data/pkinative/core-exports.json' with { type: 'json' };
import { UNEXPOSED_EXPORTS } from '../src/tools/describe-engine.js';
import { TOOLS } from '../src/tools/_registry.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'src');

interface ExportEntry { readonly name: string; readonly kind: string; readonly reach: string; readonly via: readonly string[] }
const EXPORTS = (registry as { exports: readonly ExportEntry[]; counts: { exports: number; capability: number; typeOnly: number }; pkinative: string });
const CAPABILITY = EXPORTS.exports.filter((e) => e.reach === 'capability').map((e) => e.name);

function walk(dir: string, out: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const full = path.join(dir, entry);
        if (statSync(full).isDirectory()) walk(full, out);
        else if (entry.endsWith('.ts')) out.push(full);
    }
    return out;
}

/** `file → the runtime names it imports from 'pkinative'` (type-only names and `import type` statements excluded). */
function engineImports(): Map<string, Set<string>> {
    const out = new Map<string, Set<string>>();
    for (const file of walk(SRC)) {
        const text = readFileSync(file, 'utf8');
        const names = new Set<string>();
        for (const m of text.matchAll(/import\s*\{([^}]*)\}\s*from\s*'pkinative'/g)) {
            for (const raw of m[1]!.split(',')) {
                const n = raw.trim();
                if (n.length === 0 || n.startsWith('type ')) continue;
                names.add(n.split(/\s+as\s+/)[0]!.trim());
            }
        }
        out.set(path.relative(ROOT, file).split(path.sep).join('/'), names);
    }
    return out;
}

/** Which src modules a tool module reaches (its own relative imports, transitively). */
function reachableModules(file: string, seen = new Set<string>()): Set<string> {
    if (seen.has(file)) return seen;
    seen.add(file);
    const text = readFileSync(path.join(ROOT, file), 'utf8');
    for (const m of text.matchAll(/from\s+'(\.\.?\/[^']+)\.js'/g)) {
        const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), `${m[1]!}.ts`));
        if (existsSync(path.join(ROOT, target))) reachableModules(target, seen);
    }
    return seen;
}

describe('engine surface registry', () => {
    it('is the frozen pkinative 1.0.0 surface: 294 exports, 117 runtime, 177 type-only', () => {
        expect(EXPORTS.pkinative).toBe('1.0.0');
        expect(EXPORTS.counts).toEqual({ exports: 294, capability: 117, typeOnly: 177 });
        expect(EXPORTS.exports).toHaveLength(294);
        expect(CAPABILITY).toHaveLength(117);
        expect(EXPORTS.exports.filter((e) => e.reach === 'type-only')).toHaveLength(177);
    });

    it('every runtime export of the registry exists on the installed engine with the declared kind', () => {
        for (const e of EXPORTS.exports.filter((x) => x.reach === 'capability')) {
            const value = (engine as Record<string, unknown>)[e.name];
            expect(value, `${e.name} is exported by pkinative`).toBeDefined();
            if (e.kind === 'function' || e.kind === 'class') expect(typeof value, e.name).toBe('function');
            else expect(typeof value, `${e.name} (${e.kind})`).not.toBe('function');
        }
    });

    it('the engine exports nothing at runtime that the registry does not list', () => {
        const listed = new Set(CAPABILITY);
        const extra = Object.keys(engine).filter((k) => !listed.has(k));
        expect(extra).toEqual([]);
    });
});

describe('117 / 117 runtime exports are reached by a tool', () => {
    const imports = engineImports();
    const all = new Set<string>();
    for (const names of imports.values()) for (const n of names) all.add(n);

    it('every runtime export is imported by name under src/ (never only as a type)', () => {
        const missing = CAPABILITY.filter((n) => !all.has(n));
        expect(missing).toEqual([]);
    });

    it('nothing is imported from the engine that the registry does not know', () => {
        const known = new Set(EXPORTS.exports.map((e) => e.name));
        const unknown = [...all].filter((n) => !known.has(n));
        expect(unknown).toEqual([]);
    });

    it('every tool module reaches the engine, directly or through a shared module', () => {
        for (const tool of TOOLS) {
            const file = `src/tools/${tool.name.replace(/_/g, '-')}.ts`;
            expect(existsSync(path.join(ROOT, file)), `${tool.name} lives in ${file}`).toBe(true);
            const reached = reachableModules(file);
            const engineNames = new Set<string>();
            for (const m of reached) for (const n of imports.get(m) ?? []) engineNames.add(n);
            expect(engineNames.size, `${tool.name} reaches no engine export`).toBeGreaterThan(0);
        }
    });

    it('the registry attributes every runtime export to at least one CLI invocation, and the tool catalogue covers every CLI group', () => {
        const groups = new Set<string>();
        for (const e of EXPORTS.exports.filter((x) => x.reach === 'capability')) {
            expect(e.via.length, `${e.name} has a CLI attribution`).toBeGreaterThan(0);
            for (const v of e.via) groups.add(v.split(' ')[0]!);
        }
        groups.delete('*');
        // Each CLI group has a tool whose name carries the group's noun.
        const names = TOOLS.map((t) => t.name).join(' ');
        const NOUN: Readonly<Record<string, RegExp>> = {
            pem: /convert_pem/, oid: /resolve_oid/, fingerprint: /compute_fingerprint/, asn1: /decode_asn1|encode_asn1/,
            cert: /inspect_certificate|create_certificate/, csr: /inspect_csr|create_csr/, chain: /verify_certificate_chain|build_certificate_path/,
            crl: /inspect_crl|check_crl_revocation/, ocsp: /inspect_ocsp_response|check_ocsp_status/, cms: /sign_cms|verify_cms/, tsp: /create_timestamp_request|verify_timestamp/,
            key: /inspect_private_key/, p12: /inspect_pkcs12|open_pkcs12/, doctor: /describe_engine/, limits: /describe_engine/, schema: /describe_engine|explain_code/, explain: /explain_code/,
        };
        for (const g of groups) {
            expect(NOUN[g], `CLI group "${g}" is mapped to a tool`).toBeDefined();
            expect(names, `CLI group "${g}"`).toMatch(NOUN[g]!);
        }
    });
});

describe('the unexposed surface is explained, never silently dropped', () => {
    it('every unexposed entry is a member or a type family, not a runtime export, and carries a rationale', () => {
        const runtime = new Set(CAPABILITY);
        for (const u of UNEXPOSED_EXPORTS) {
            expect(runtime.has(u.export), `${u.export} is a runtime export and must be reached by a tool`).toBe(false);
            expect(u.rationale.length).toBeGreaterThan(20);
        }
        expect(UNEXPOSED_EXPORTS.map((u) => u.export)).toContain('ExternalSigner.produceSignature');
        expect(UNEXPOSED_EXPORTS.map((u) => u.export)).toContain('PkiParseOptions.onDiagnostic');
    });

    it.skipIf(!existsSync(path.join(ROOT, 'docs', 'data', 'core-exports.json')))('docs/data/core-exports.json mirrors the vendored registry', () => {
        const mirror = JSON.parse(readFileSync(path.join(ROOT, 'docs', 'data', 'core-exports.json'), 'utf8')) as { counts: unknown; exports: readonly ExportEntry[] };
        expect(mirror.counts).toEqual(EXPORTS.counts);
        expect(mirror.exports.map((e) => e.name)).toEqual(EXPORTS.exports.map((e) => e.name));
    });
});
