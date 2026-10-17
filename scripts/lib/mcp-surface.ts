/**
 * pkinative-mcp — the server surface, derived from the source tree
 * ================================================================
 * `docs/assets/ecosystem.json` quotes counts the docs repeat in prose: how
 * many tools, prompts, error codes, operator variables, examples, samples,
 * corpus entries. None of those figures is hand-maintained here: they are
 * read from the files the server is built from — the `<NAME>_NAME` constants
 * under `src/tools/`, the `<NAME>_TOOL` lists of the `src/tools/_group-*.ts`
 * files in the order `src/tools/_registry.ts` spreads them, the `PROMPTS`
 * table of `src/server.ts`, every `ToolError('CODE'` literal under `src/`,
 * the `environmentVariables` of `server.json`, the corpus table — and from
 * directory walks for the examples, the tests and the sample baseline.
 *
 * Scripts never import `src/` (scripts/helpers/server.ts), and `verify:docs`
 * runs in the gate's fast profile, before any build: every parser below is a
 * pure function over text, unit-tested in tests/tools/mcp-surface.test.ts.
 * `computeDerived()` is the one function that touches the filesystem.
 * Ported from pdfnative-mcp 1.7.0 with the registry split into group files.
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { CONFORMANT, CORPUS, REFUSED } from './pki-corpus.js';

/** The operator-variable prefix (every variable the server reads). */
export const ENV_PREFIX = 'PKINATIVE_MCP_';

// ── Pure parsers ─────────────────────────────────────────────────────

/** `export const CREATE_CSR_NAME = 'create_csr';` → `['CREATE_CSR_NAME', 'create_csr']`, or null. */
export function toolNameConstant(toolModuleText: string): readonly [string, string] | null {
    const m = /^export const ([A-Z][A-Z0-9_]*_NAME)\s*=\s*'([a-z][a-z0-9_]*)'\s*;/m.exec(toolModuleText);
    return m ? [m[1] as string, m[2] as string] : null;
}

/** `export const CREATE_CSR_TOOL = defineTool…` → `CREATE_CSR_TOOL`, or null. */
export function toolDefinitionConstant(toolModuleText: string): string | null {
    const m = /^export const ([A-Z][A-Z0-9_]*_TOOL)\s*(?::\s*ToolDefinition\s*)?=\s*defineTool\b/m.exec(toolModuleText);
    return m?.[1] ?? null;
}

/** The `<NAME>_TOOL` identifiers of every `export const X_TOOLS: readonly ToolDefinition[] = [ … ]` list, keyed by list name, in list order. */
export function toolLists(groupText: string): Map<string, string[]> {
    const out = new Map<string, string[]>();
    for (const m of groupText.matchAll(/^export const ([A-Z][A-Z0-9_]*_TOOLS)\s*:[^=]*=\s*\[([\s\S]*?)\];/gm)) {
        out.set(m[1] as string, [...(m[2] as string).matchAll(/\b([A-Z][A-Z0-9_]*_TOOL)\b/g)].map((x) => x[1] as string));
    }
    return out;
}

/** The lists `TOOLS` spreads, in order: `...ENCODING_TOOLS, ...CERTIFICATE_TOOLS, …`. */
export function registrySpreadOrder(registryText: string): string[] {
    const m = /^export const TOOLS\s*:[^=]*=\s*\[([\s\S]*?)\];/m.exec(registryText);
    if (m === null) return [];
    return [...(m[1] as string).matchAll(/\.\.\.([A-Z][A-Z0-9_]*_TOOLS)\b/g)].map((x) => x[1] as string);
}

/** The `name: '<prompt>'` entries of the `PROMPTS` table. */
export function promptNames(serverText: string): string[] {
    const start = serverText.search(/^(?:export )?const PROMPTS\b/m);
    if (start === -1) return [];
    const rest = serverText.slice(start);
    const end = rest.search(/^\];/m);
    const table = end === -1 ? rest : rest.slice(0, end);
    return [...table.matchAll(/^\s{8}name:\s*'([a-z][a-z0-9_]*)'\s*,/gm)].map((m) => m[1] as string);
}

/** Every `ToolError('CODE'` literal of one source text (a line break after the parenthesis is allowed). */
export function toolErrorCodes(sourceText: string): string[] {
    return [...sourceText.matchAll(/ToolError\(\s*'([A-Z][A-Z0-9_]+)'/g)].map((m) => m[1] as string);
}

/** The fixed codes `src/errors.ts` subclasses pass through `super('CODE'`. */
export function subclassErrorCodes(errorsText: string): string[] {
    return [...errorsText.matchAll(/super\(\s*'([A-Z][A-Z0-9_]+)'/g)].map((m) => m[1] as string);
}

/** The `code: 'CODE'` rows of the wrapper-code table (`src/wrapper-codes.ts`). */
export function wrapperCodes(wrapperText: string): string[] {
    return [...new Set([...wrapperText.matchAll(/\bcode:\s*'([A-Z][A-Z0-9_]+)'/g)].map((m) => m[1] as string))];
}

/** The first-column codes of the `## 6. Error reference` table of the agent contract. */
export function contractErrorRows(contractText: string): string[] {
    const start = contractText.search(/^## 6\. /m);
    if (start === -1) return [];
    const rest = contractText.slice(start + 1);
    const end = rest.search(/^## /m);
    const section = end === -1 ? rest : rest.slice(0, end);
    const out: string[] = [];
    for (const line of section.split(/\r?\n/)) {
        const cell = /^\|\s*([^|]+?)\s*\|/.exec(line)?.[1];
        if (cell === undefined) continue;
        for (const m of cell.matchAll(/`([A-Z][A-Z0-9_]+)`/g)) out.push(m[1] as string);
    }
    return [...new Set(out)];
}

/** Every backticked lower_snake token with an underscore — the shape of a tool name — in a text. */
export function snakeTokens(text: string): string[] {
    return [...new Set([...text.matchAll(/`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`/g)].map((m) => m[1] as string))];
}

/** Every operator-variable token (`PKINATIVE_MCP_*`) in a text. */
export function envVarTokens(text: string): string[] {
    return [...new Set([...text.matchAll(/\bPKINATIVE_MCP_[A-Z][A-Z0-9_]*[A-Z0-9]\b/g)].map((m) => m[0]))];
}

/** The `environmentVariables[].name` list of the packages of `server.json`. */
export function serverJsonEnvVars(serverJsonText: string): string[] {
    const parsed = JSON.parse(serverJsonText) as { packages?: Array<{ environmentVariables?: Array<{ name?: unknown }> }> };
    const out: string[] = [];
    for (const pkg of parsed.packages ?? []) {
        for (const v of pkg.environmentVariables ?? []) if (typeof v.name === 'string' && !out.includes(v.name)) out.push(v.name);
    }
    return out;
}

/** The numbered rows of the `## 1. Tool catalogue` table: backticked name in the second column. */
export function contractCatalogueTools(contractText: string): string[] {
    const start = contractText.search(/^## 1\. /m);
    if (start === -1) return [];
    const rest = contractText.slice(start + 1);
    const end = rest.search(/^## /m);
    const section = end === -1 ? rest : rest.slice(0, end);
    const out: string[] = [];
    for (const line of section.split(/\r?\n/)) {
        const m = /^\|\s*\d+\s*\|\s*`([a-z][a-z0-9_]*)`/.exec(line);
        if (m) out.push(m[1] as string);
    }
    return out;
}

/** `[1.1.0]: https://…/compare/v1.0.0...v1.1.0` → `{ label, from, to }` per link definition, in file order. */
export interface CompareLink {
    readonly label: string;
    readonly from: string | null;
    readonly to: string;
    readonly line: number;
}

export function changelogCompareLinks(changelogText: string): CompareLink[] {
    const out: CompareLink[] = [];
    changelogText.split(/\r?\n/).forEach((text, i) => {
        const compare = /^\[([^\]]+)\]:\s*\S+\/compare\/(\S+?)\.\.\.(\S+)\s*$/.exec(text);
        if (compare) {
            out.push({ label: compare[1] as string, from: compare[2] as string, to: compare[3] as string, line: i + 1 });
            return;
        }
        const tag = /^\[([^\]]+)\]:\s*\S+\/releases\/tag\/(\S+)\s*$/.exec(text);
        if (tag) out.push({ label: tag[1] as string, from: null, to: tag[2] as string, line: i + 1 });
    });
    return out;
}

/** `## [1.1.0] - 2026-11-01` / `## [Unreleased]` headings, in file order. */
export function changelogHeadings(changelogText: string): Array<{ label: string; line: number }> {
    const out: Array<{ label: string; line: number }> = [];
    changelogText.split(/\r?\n/).forEach((text, i) => {
        const m = /^## \[([^\]]+)\]/.exec(text);
        if (m) out.push({ label: m[1] as string, line: i + 1 });
    });
    return out;
}

export interface LadderFinding {
    readonly line: number;
    readonly message: string;
}

/**
 * The compare-link ladder: every heading has a link definition, every link
 * compares the previous heading's tag with its own, and `[Unreleased]`
 * starts at the newest released tag. The first release has a tag link.
 */
export function checkChangelogLadder(changelogText: string): LadderFinding[] {
    const headings = changelogHeadings(changelogText);
    const links = new Map(changelogCompareLinks(changelogText).map((l) => [l.label, l] as const));
    const out: LadderFinding[] = [];
    const released = headings.filter((h) => h.label !== 'Unreleased');
    headings.forEach((h) => {
        const link = links.get(h.label);
        if (!link) {
            out.push({ line: h.line, message: `heading [${h.label}] has no link definition at the foot of the file` });
            return;
        }
        if (h.label === 'Unreleased') {
            const newest = released[0]?.label;
            if (newest !== undefined && (link.from !== `v${newest}` || link.to !== 'HEAD')) {
                out.push({ line: link.line, message: `[Unreleased] must compare v${newest}...HEAD — found ${link.from ?? '(tag link)'}...${link.to}` });
            }
            return;
        }
        const index = released.findIndex((r) => r.label === h.label);
        const previous = released[index + 1]?.label;
        if (link.to !== `v${h.label}`) out.push({ line: link.line, message: `[${h.label}] must end at v${h.label} — found ${link.to}` });
        if (previous !== undefined && link.from !== `v${previous}`) {
            out.push({ line: link.line, message: `[${h.label}] must compare v${previous}...v${h.label} — found ${link.from ?? '(tag link)'}...${link.to}` });
        }
    });
    for (const [label, link] of links) {
        if (!headings.some((h) => h.label === label)) out.push({ line: link.line, message: `link definition [${label}] has no heading` });
    }
    return out;
}

// ── Filesystem ───────────────────────────────────────────────────────

function walk(dir: string, filter: (p: string) => boolean, out: string[] = []): string[] {
    if (!existsSync(dir)) return out;
    for (const entry of readdirSync(dir).sort()) {
        if (entry === 'node_modules' || entry.startsWith('.')) continue;
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) walk(full, filter, out);
        else if (filter(full)) out.push(full);
    }
    return out;
}

/** Tool names declared under `src/tools/`, keyed by their `<NAME>_NAME` constant. */
export function declaredTools(root: string): Map<string, string> {
    const out = new Map<string, string>();
    for (const file of walk(join(root, 'src', 'tools'), (p) => p.endsWith('.ts'))) {
        const pair = toolNameConstant(readFileSync(file, 'utf8'));
        if (pair) out.set(pair[0], pair[1]);
    }
    return out;
}

/** `<NAME>_TOOL` definition constants under `src/tools/`, mapped to the tool name their module declares. */
export function definedTools(root: string): Map<string, string> {
    const out = new Map<string, string>();
    for (const file of walk(join(root, 'src', 'tools'), (p) => p.endsWith('.ts'))) {
        const text = readFileSync(file, 'utf8');
        const def = toolDefinitionConstant(text);
        const pair = toolNameConstant(text);
        if (def !== null && pair !== null) out.set(def, pair[1]);
    }
    return out;
}

/** The registered tool names, in `TOOLS` order (the registry's spread order, then each group list, resolved through `src/tools/`). */
export function toolNames(root: string): string[] {
    const toolsDir = join(root, 'src', 'tools');
    const registryPath = join(toolsDir, '_registry.ts');
    if (!existsSync(registryPath)) return [];
    const registryText = readFileSync(registryPath, 'utf8');
    const lists = toolLists(registryText);
    for (const file of walk(toolsDir, (p) => /[\\/]_group-[^\\/]+\.ts$/.test(p))) {
        for (const [name, ids] of toolLists(readFileSync(file, 'utf8'))) lists.set(name, ids);
    }
    const defined = definedTools(root);
    const out: string[] = [];
    for (const list of registrySpreadOrder(registryText)) {
        for (const id of lists.get(list) ?? []) {
            const name = defined.get(id);
            if (name !== undefined && !out.includes(name)) out.push(name);
        }
    }
    return out;
}

/** Every `ToolError` code emitted under `src/`, sorted. */
export function errorCodes(root: string): string[] {
    const codes = new Set<string>();
    for (const file of walk(join(root, 'src'), (p) => p.endsWith('.ts'))) {
        for (const c of toolErrorCodes(readFileSync(file, 'utf8'))) codes.add(c);
    }
    const errorsPath = join(root, 'src', 'errors.ts');
    if (existsSync(errorsPath)) for (const c of subclassErrorCodes(readFileSync(errorsPath, 'utf8'))) codes.add(c);
    return [...codes].sort();
}

function baselineEntryCount(root: string): number {
    const path = join(root, 'tests', '_fixtures', 'samples.sha256.json');
    if (!existsSync(path)) return 0;
    try {
        const parsed = JSON.parse(readFileSync(path, 'utf8')) as { entries?: Record<string, unknown> };
        return Object.keys(parsed.entries ?? {}).length;
    } catch {
        return 0;
    }
}

export interface DerivedCounts {
    readonly tools: number;
    readonly prompts: number;
    readonly errorCodes: number;
    readonly envVars: number;
    readonly examples: number;
    readonly testFiles: number;
    readonly samples: number;
    readonly corpusEntries: number;
    readonly corpusConformant: number;
    readonly corpusRefused: number;
}

export function computeDerived(root: string): DerivedCounts {
    const serverPath = join(root, 'src', 'server.ts');
    const serverJsonPath = join(root, 'server.json');
    return {
        tools: toolNames(root).length,
        prompts: existsSync(serverPath) ? promptNames(readFileSync(serverPath, 'utf8')).length : 0,
        errorCodes: errorCodes(root).length,
        envVars: existsSync(serverJsonPath) ? serverJsonEnvVars(readFileSync(serverJsonPath, 'utf8')).length : 0,
        examples: walk(join(root, 'examples'), (p) => p.endsWith('.json')).length,
        testFiles: walk(join(root, 'tests'), (p) => p.endsWith('.test.ts')).length,
        samples: baselineEntryCount(root),
        corpusEntries: CORPUS.length,
        corpusConformant: CONFORMANT.length,
        corpusRefused: REFUSED.length,
    };
}
