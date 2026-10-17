// A2-006 — scripts/lib/mcp-surface.ts reads the server surface from text:
// scripts never import src/, and verify:docs runs before any build. Each
// parser is exercised with inline fixtures in both directions, then the real
// tree is compared with the live registry: a parser that silently stops
// matching (a reformatted group list, a renamed PROMPTS table) must fail
// here, not pass with a zero. Ported from pdfnative-mcp 1.7.0
// (tests/tools/mcp-surface.test.ts), with the registry split into group files.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
    ENV_PREFIX,
    changelogCompareLinks,
    changelogHeadings,
    checkChangelogLadder,
    computeDerived,
    contractCatalogueTools,
    contractErrorRows,
    declaredTools,
    definedTools,
    envVarTokens,
    errorCodes,
    promptNames,
    registrySpreadOrder,
    serverJsonEnvVars,
    snakeTokens,
    subclassErrorCodes,
    toolDefinitionConstant,
    toolErrorCodes,
    toolLists,
    toolNameConstant,
    toolNames,
    wrapperCodes,
} from '../../scripts/lib/mcp-surface.js';
import { WRAPPER_CODES } from '../../src/wrapper-codes.js';
import { __prompts, listToolsPayload } from '../../src/server.js';
import { connectLegacy } from '../_mcp-harness.js';

const ROOT = resolve(import.meta.dirname, '..', '..');
const read = (...parts: string[]): string => readFileSync(resolve(ROOT, ...parts), 'utf8');

interface Ecosystem {
    readonly declared: { readonly wrapperCodes: number };
    readonly derived: {
        readonly tools: number;
        readonly toolGroups: Record<string, string[]>;
        readonly prompts: number;
        readonly errorCodes: number;
        readonly envVars: number;
        readonly examples: number;
        readonly testFiles: number;
        readonly samples: number;
        readonly corpusEntries: number;
        readonly corpusConformant: number;
        readonly corpusRefused: number;
    };
}

describe('mcp-surface: pure parsers', () => {
    it('A2-006: reads the <NAME>_NAME constant and the <NAME>_TOOL definition of a tool module', () => {
        expect(toolNameConstant("import x from 'y';\nexport const CREATE_CSR_NAME = 'create_csr';\n")).toEqual(['CREATE_CSR_NAME', 'create_csr']);
        expect(toolNameConstant("const CREATE_CSR_NAME = 'create_csr';")).toBeNull();
        expect(toolNameConstant("export const SCHEMA_NAME = 'Not A Tool';")).toBeNull();
        expect(toolDefinitionConstant('export const CREATE_CSR_TOOL = defineTool({')).toBe('CREATE_CSR_TOOL');
        expect(toolDefinitionConstant('export const CREATE_CSR_TOOL: ToolDefinition = defineTool<Input>({')).toBe('CREATE_CSR_TOOL');
        expect(toolDefinitionConstant('const CREATE_CSR_TOOL = defineTool({')).toBeNull();
        expect(toolDefinitionConstant("export const CREATE_CSR_TOOLS = ['x'];")).toBeNull();
    });

    it('A2-006: reads every <X>_TOOLS list of a group file in order, and the spread order of the registry', () => {
        const group = [
            "import { A_TOOL } from './a.js';",
            'export const META_TOOLS: readonly ToolDefinition[] = [DESCRIBE_ENGINE_TOOL, EXPLAIN_CODE_TOOL];',
            '',
            'export const CERTIFICATE_TOOLS: readonly ToolDefinition[] = [',
            '    INSPECT_CERTIFICATE_TOOL,',
            '    CREATE_CERTIFICATE_TOOL, // trailing comment',
            '];',
            'const NOT_EXPORTED_TOOLS = [HIDDEN_TOOL];',
        ].join('\n');
        const lists = toolLists(group);
        expect([...lists.keys()]).toEqual(['META_TOOLS', 'CERTIFICATE_TOOLS']);
        expect(lists.get('CERTIFICATE_TOOLS')).toEqual(['INSPECT_CERTIFICATE_TOOL', 'CREATE_CERTIFICATE_TOOL']);
        expect(lists.get('META_TOOLS')).toEqual(['DESCRIBE_ENGINE_TOOL', 'EXPLAIN_CODE_TOOL']);
        const registry = 'export const TOOLS: readonly ToolDefinition[] = [\n    ...ENCODING_TOOLS,\n    ...CERTIFICATE_TOOLS,\n    ...META_TOOLS,\n];\nconst OTHER = [...LATER_TOOLS];';
        expect(registrySpreadOrder(registry)).toEqual(['ENCODING_TOOLS', 'CERTIFICATE_TOOLS', 'META_TOOLS']);
        expect(registrySpreadOrder('const TOOLS = [];')).toEqual([]);
    });

    it('reads the prompt names up to the end of the PROMPTS table', () => {
        const server = "const PROMPTS: readonly PromptDefinition[] = [\n    {\n        name: 'governance_contract',\n    },\n    {\n        name: 'inspect_anything',\n    },\n];\nconst AFTER = [\n    {\n        name: 'not_a_prompt',\n    },\n];";
        expect(promptNames(server)).toEqual(['governance_contract', 'inspect_anything']);
        expect(promptNames('nothing')).toEqual([]);
    });

    it('collects ToolError codes across a line break, the fixed codes of the subclasses, and the wrapper-code table', () => {
        expect(toolErrorCodes("throw new ToolError('VALIDATION_ERROR', m);\nthrow new ToolError(\n    'INPUT_TOO_LARGE',\n    m);")).toEqual(['VALIDATION_ERROR', 'INPUT_TOO_LARGE']);
        expect(toolErrorCodes('new ToolError(code, m)')).toEqual([]);
        expect(subclassErrorCodes("class SecurityError extends ToolError { constructor(m) { super('SECURITY_VIOLATION', m); } }")).toEqual(['SECURITY_VIOLATION']);
        expect(wrapperCodes("{ code: 'VALIDATION_ERROR', meaning: 'x' },\n{ code: 'INPUT_TOO_LARGE' },\n{ code: 'VALIDATION_ERROR' }")).toEqual(['VALIDATION_ERROR', 'INPUT_TOO_LARGE']);
    });

    it('reads the first column of the §6 table only, several codes per cell included', () => {
        const contract = '## 5. Recipes\n\n`NOT_A_ROW`\n\n## 6. Error reference\n\n### 6.1 Wrapper codes\n\n| Code | When | Do |\n|---|---|---|\n| `VALIDATION_ERROR` | bad `INPUT_THING` | fix |\n| `PASSWORD_REQUIRED` / `PASSWORD_INVALID` | x | y |\n\n## 7. Next\n\n| `LATER` | x | y |\n';
        expect(contractErrorRows(contract)).toEqual(['VALIDATION_ERROR', 'PASSWORD_REQUIRED', 'PASSWORD_INVALID']);
        expect(contractErrorRows('# no table')).toEqual([]);
    });

    it('reads the numbered rows of the §1 catalogue', () => {
        const contract = '## 1. Tool catalogue (2 tools)\n\n| # | Tool | Use |\n|---|---|---|\n| 1 | `convert_pem` | x `resolve_oid` |\n| 2 | `resolve_oid` | y |\n\n## 2. Decision tree\n\n| 3 | `not_in_catalogue` | z |\n';
        expect(contractCatalogueTools(contract)).toEqual(['convert_pem', 'resolve_oid']);
        expect(contractCatalogueTools('# none')).toEqual([]);
    });

    it('tokenises tool-shaped names and operator variables', () => {
        expect(snakeTokens('Call `create_csr`, then `inspect_csr` — not `outputMode`, `pkcs12` or create_certificate.')).toEqual(['create_csr', 'inspect_csr']);
        expect(envVarTokens('Set PKINATIVE_MCP_OUTPUT_DIR (and the old PKINATIVE_MPC_OUTPUT_DIR); `PKINATIVE_MCP_*` is the prefix. PKINATIVE_MCP_OUTPUT_DIR again.')).toEqual(['PKINATIVE_MCP_OUTPUT_DIR']);
        expect(ENV_PREFIX).toBe('PKINATIVE_MCP_');
    });

    it('lists the operator variables of server.json once each', () => {
        const text = JSON.stringify({ packages: [{ environmentVariables: [{ name: 'A' }, { name: 'B' }, { name: 'A' }, { description: 'nameless' }] }] });
        expect(serverJsonEnvVars(text)).toEqual(['A', 'B']);
        expect(serverJsonEnvVars('{}')).toEqual([]);
    });
});

describe('mcp-surface: changelog ladder', () => {
    const GOOD = [
        '# Changelog', '', '## [Unreleased]', '', '## [1.1.0] - 2026-11-01', '', '## [1.0.0] - 2026-10-17', '',
        '[Unreleased]: https://github.com/Nizoka/pkinative-mcp/compare/v1.1.0...HEAD',
        '[1.1.0]: https://github.com/Nizoka/pkinative-mcp/compare/v1.0.0...v1.1.0',
        '[1.0.0]: https://github.com/Nizoka/pkinative-mcp/releases/tag/v1.0.0',
    ].join('\n');

    it('parses headings, compare links and the tag link of the first release', () => {
        expect(changelogHeadings(GOOD).map((h) => h.label)).toEqual(['Unreleased', '1.1.0', '1.0.0']);
        const links = changelogCompareLinks(GOOD);
        expect(links.map((l) => l.label)).toEqual(['Unreleased', '1.1.0', '1.0.0']);
        expect(links[0]).toMatchObject({ from: 'v1.1.0', to: 'HEAD' });
        expect(links[2]).toMatchObject({ from: null, to: 'v1.0.0' });
    });

    it('passes a complete ladder', () => {
        expect(checkChangelogLadder(GOOD)).toEqual([]);
    });

    it('fails on a missing rung, a rung comparing the wrong tags, a stale Unreleased and an orphan link', () => {
        expect(checkChangelogLadder(GOOD.replace(/^\[1\.0\.0\]:.*\n?/m, '')).map((f) => f.message)).toEqual([expect.stringMatching(/\[1\.0\.0\] has no link definition/)]);
        expect(checkChangelogLadder(GOOD.replace('compare/v1.0.0...v1.1.0', 'compare/v0.9.0...v1.1.0')).map((f) => f.message)).toEqual([expect.stringMatching(/must compare v1\.0\.0\.\.\.v1\.1\.0/)]);
        expect(checkChangelogLadder(GOOD.replace('compare/v1.1.0...HEAD', 'compare/v1.0.0...HEAD')).map((f) => f.message)).toEqual([expect.stringMatching(/\[Unreleased\] must compare v1\.1\.0\.\.\.HEAD/)]);
        expect(checkChangelogLadder(`${GOOD}\n[0.9.0]: https://github.com/Nizoka/pkinative-mcp/releases/tag/v0.9.0`).map((f) => f.message)).toEqual([expect.stringMatching(/\[0\.9\.0\] has no heading/)]);
    });

    it('holds the real CHANGELOG.md to the ladder', () => {
        expect(checkChangelogLadder(read('CHANGELOG.md'))).toEqual([]);
    });
});

describe('mcp-surface: the real tree agrees with the live server', () => {
    const ecosystem = JSON.parse(read('docs', 'assets', 'ecosystem.json')) as Ecosystem;

    it('A2-006: resolves the same tools, in the same order, as tools/list — the registry spread order over the group files', () => {
        const live = listToolsPayload().tools.map((t) => t.name);
        expect(toolNames(ROOT)).toEqual(live);
        expect(live).toHaveLength(ecosystem.derived.tools);
        // Every group list the registry spreads is found in a group file (or the registry itself), and
        // every <NAME>_TOOL it names maps to a declared tool: a list the walk cannot resolve would shorten
        // the order silently, which the equality above catches, and this names the culprit.
        const registry = read('src', 'tools', '_registry.ts');
        const spread = registrySpreadOrder(registry);
        expect(spread.length).toBeGreaterThanOrEqual(6);
        const defined = definedTools(ROOT);
        const declared = declaredTools(ROOT);
        expect(defined.size).toBe(live.length);
        expect(new Set(declared.values())).toEqual(new Set(live));
        // The group order of the manifest is the spread order: the concatenation of its groups is tools/list.
        expect(Object.values(ecosystem.derived.toolGroups).flat()).toEqual(live);
        expect(Object.keys(ecosystem.derived.toolGroups)).toHaveLength(spread.length);
    });

    it('resolves the same prompts as prompts/list and as the PROMPTS table', async () => {
        const client = await connectLegacy();
        const live = (await client.request<{ prompts: Array<{ name: string }> }>('prompts/list')).prompts.map((p) => p.name);
        await client.close();
        expect(promptNames(read('src', 'server.ts'))).toEqual(live);
        expect(live).toEqual(__prompts.map((p) => p.name));
        expect(live).toHaveLength(ecosystem.derived.prompts);
    });

    it('finds every error code the source emits, each with a §6 row in the agent contract, the wrapper table among them', () => {
        const codes = errorCodes(ROOT);
        expect(codes).toContain('VALIDATION_ERROR');
        expect(codes).toContain('SECURITY_VIOLATION');
        expect(codes).toContain('GOVERNANCE_VIOLATION');
        expect(codes).toHaveLength(ecosystem.derived.errorCodes);
        const rows = contractErrorRows(read('docs', 'AGENT_CONTRACT.md'));
        expect(codes.filter((c) => !rows.includes(c))).toEqual([]);
        const table = wrapperCodes(read('src', 'wrapper-codes.ts'));
        expect(table).toHaveLength(ecosystem.declared.wrapperCodes);
        expect(table).toEqual(WRAPPER_CODES.map((w) => w.code));
        expect(table.filter((c) => !rows.includes(c))).toEqual([]);
    });

    it('lists the catalogue rows of the agent contract in tools/list order', () => {
        expect(contractCatalogueTools(read('docs', 'AGENT_CONTRACT.md'))).toEqual(listToolsPayload().tools.map((t) => t.name));
    });

    it('A2-006: reads the operator variables from server.json — nine, prefixed, the ones the instructions name', () => {
        const vars = serverJsonEnvVars(read('server.json'));
        expect(vars).toHaveLength(ecosystem.derived.envVars);
        expect(vars).toHaveLength(9);
        for (const v of vars) expect(v.startsWith(ENV_PREFIX), v).toBe(true);
        expect(new Set(vars).size).toBe(vars.length);
        // Every variable server.json declares is one a document can name; the tokeniser recognises it.
        expect(envVarTokens(vars.join(' '))).toEqual(vars);
    });

    it('derives the figures docs/assets/ecosystem.json quotes, every one non-zero', () => {
        const derived = computeDerived(ROOT);
        for (const [key, value] of Object.entries(derived)) expect(value, key).toBeGreaterThan(0);
        // `testFiles` moves with every suite added and is the docs rule's to hold (verify:docs fails on the
        // drift and names the figure); the counters that describe the server surface are held exactly here.
        const { toolGroups: _groups, testFiles: declaredTestFiles, ...figures } = ecosystem.derived;
        const { testFiles, ...computed } = derived;
        expect(computed).toEqual(figures);
        expect(testFiles).toBeGreaterThanOrEqual(declaredTestFiles);
        expect(derived.corpusConformant + derived.corpusRefused).toBe(derived.corpusEntries);
    });
});
