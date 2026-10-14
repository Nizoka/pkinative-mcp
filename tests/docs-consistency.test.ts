/**
 * Documentation ↔ code consistency. The docs quote counts, names, codes and
 * environment variables that live in the source; this suite fails when they
 * drift so a doc edit (or a code edit) cannot silently desynchronise them.
 *
 * Sources of truth:
 *   toolNames() (src/tools/_registry.ts)    — the 34-tool surface, in registration order
 *   __prompts (src/server.ts)               — the 7 prompts
 *   WRAPPER_CODE_NAMES (src/wrapper-codes.ts) — the 21 wrapper codes
 *   PKI_ERROR_CODES / PKI_REASON_CODES / PKI_DIAGNOSTIC_CODES — the 57 / 43 / 97 engine vocabularies
 *   LIMIT_KEYS (src/limits.ts)              — the 22 named limits
 *   ENV_VARS (below, = server.json)         — the 9 operator variables
 *   docs/assets/ecosystem.json              — every count and version the documents quote
 *
 * Every document is guarded with `it.skipIf(!existsSync(file))` so the suite
 * stays green while the docs are being written and activates as they land.
 * scripts/verify-docs.ts holds the same documents from the outside (text
 * parsers, no import of src/); this suite holds them from the inside.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { MAX_INPUT_BYTES_ENV, MAX_KDF_ITERATIONS_ENV, MAX_PATHS_EXPLORED_ENV } from '../src/caps.js';
import { PKINATIVE_NODE_FLOOR, PKINATIVE_VERSION } from '../src/engine.js';
import { GOVERNANCE_CONTRACT_SUMMARY } from '../src/governance.js';
import { LIMIT_KEYS } from '../src/limits.js';
import { PKI_DIAGNOSTIC_CODES, PKI_ERROR_CODES, PKI_REASON_CODES } from '../src/pki-errors.js';
import { OUTPUT_DIR_ENV } from '../src/sandbox.js';
import { PASSWORD_ENV } from '../src/secrets.js';
import { __prompts, __serverInstructions, listToolsPayload, toolNames } from '../src/server.js';
import { AT_ENV } from '../src/time.js';
import { UNEXPOSED_EXPORTS } from '../src/tools/describe-engine.js';
import { PKINATIVE_MCP_VERSION, TOOL_API_VERSION } from '../src/version.js';
import { WRAPPER_CODE_NAMES } from '../src/wrapper-codes.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const file = (rel: string): string => path.join(ROOT, rel);
const read = (rel: string): string => readFileSync(file(rel), 'utf8');
const has = (rel: string): boolean => existsSync(file(rel));

const TOOLS = toolNames();
const TOOL_COUNT = TOOLS.length;
const PROMPTS = __prompts.map((p) => p.name);

const ENV_VARS = [OUTPUT_DIR_ENV, 'PKINATIVE_MCP_CACHE_DIR', 'PKINATIVE_MCP_PORT', 'PKINATIVE_MCP_HTTP_TOKEN', PASSWORD_ENV, AT_ENV, MAX_INPUT_BYTES_ENV, MAX_KDF_ITERATIONS_ENV, MAX_PATHS_EXPLORED_ENV] as const;

const CONTRACT_SECTIONS = [
    `## 1. Tool catalogue (${TOOL_COUNT} tools)`,
    '## 2.',
    '## 3.',
    '## 4.',
    '## 5.',
    '## 6. Error reference',
] as const;

interface Manifest {
    verifiedOn: string;
    packages: Record<string, { version: string; pin: string | null }>;
    declared: Record<string, unknown>;
    derived: Record<string, unknown> & { toolGroups: Record<string, string[]> };
}
const MANIFEST = 'docs/assets/ecosystem.json';
const manifest = (): Manifest => JSON.parse(read(MANIFEST)) as Manifest;

/** Slice a markdown document between a heading and the next heading of the same or higher level. */
function section(text: string, heading: string): string {
    const start = text.indexOf(heading);
    expect(start, `heading not found: ${heading}`).toBeGreaterThanOrEqual(0);
    const level = /^#+/.exec(heading)?.[0].length ?? 1;
    const rest = text.slice(start + heading.length);
    const next = new RegExp(`^#{1,${level}} `, 'm').exec(rest);
    return next === null ? rest : rest.slice(0, next.index);
}

/** Data rows of the first markdown table in `text` (header + separator skipped), split into cells. */
function tableRows(text: string): string[][] {
    const lines = text.split('\n').map((l) => l.trim()).filter((l) => l.startsWith('|'));
    const rows: string[][] = [];
    let seenSeparator = false;
    for (const line of lines) {
        if (/^\|\s*:?-{2,}/.test(line)) {
            seenSeparator = true;
            continue;
        }
        if (!seenSeparator) continue;
        rows.push(line.slice(1, line.endsWith('|') ? -1 : undefined).split('|').map((c) => c.trim()));
    }
    return rows;
}

const lines = (rel: string): Array<[number, string]> => read(rel).split('\n').map((l, i) => [i + 1, l]);

describe('the code-side sources of truth', () => {
    it('exposes 34 tools, 7 prompts, 21 wrapper codes, 57 / 43 / 97 engine codes, 22 limits and 9 environment variables', () => {
        expect(TOOL_COUNT).toBe(34);
        expect(PROMPTS).toHaveLength(7);
        expect(WRAPPER_CODE_NAMES).toHaveLength(21);
        expect(PKI_ERROR_CODES).toHaveLength(57);
        expect(PKI_REASON_CODES).toHaveLength(43);
        expect(PKI_DIAGNOSTIC_CODES).toHaveLength(97);
        expect(LIMIT_KEYS).toHaveLength(22);
        expect(ENV_VARS).toHaveLength(9);
        expect(new Set(ENV_VARS).size).toBe(9);
        for (const v of ENV_VARS) expect(v).toMatch(/^PKINATIVE_MCP_[A-Z_]+$/);
    });

    it('registers the tools in the documented order and groups', () => {
        expect(TOOLS).toEqual([
            'convert_pem', 'resolve_oid', 'compute_fingerprint', 'decode_asn1', 'encode_asn1',
            'inspect_certificate', 'create_certificate', 'encode_x509_structure', 'decode_extension', 'check_certificate_name', 'check_certificate_purpose', 'inspect_csr', 'create_csr',
            'verify_certificate_chain', 'build_certificate_path', 'validate_certificate_path', 'inspect_crl', 'check_crl_revocation', 'create_ocsp_request', 'inspect_ocsp_response', 'check_ocsp_status',
            'sign_cms', 'verify_cms', 'inspect_cms', 'amend_cms', 'create_timestamp_request', 'inspect_timestamp', 'verify_timestamp',
            'inspect_private_key', 'inspect_pkcs12', 'open_pkcs12',
            'describe_engine', 'explain_code', 'draft_governance_issue',
        ]);
        expect(PROMPTS).toEqual(['governance_contract', 'draft_issue_workflow', 'verify_before_trust', 'issue_certificate', 'sign_and_timestamp', 'offline_revocation', 'open_keys_safely']);
    });

    it('every tool name and every prompt name appears in SERVER_INSTRUCTIONS, with the tool count', () => {
        for (const t of TOOLS) expect(__serverInstructions, t).toContain(t);
        for (const p of PROMPTS) expect(__serverInstructions, p).toContain(p);
        expect(__serverInstructions).toContain(`${TOOL_COUNT} tools`);
        expect(__serverInstructions).toContain(`v${PKINATIVE_VERSION}`);
        expect(__serverInstructions).toContain(`Tool API ${TOOL_API_VERSION}`);
        expect(Buffer.byteLength(__serverInstructions)).toBeLessThanOrEqual(8 * 1024);
    });

    it('the annotations are the documented kinds: read-only readers, non-destructive artefact tools, idempotent encoders, never open-world', () => {
        const PRODUCES = new Set(['create_certificate', 'create_csr', 'create_ocsp_request', 'create_timestamp_request', 'sign_cms']);
        const WRITES = new Set(['encode_asn1', 'encode_x509_structure', 'amend_cms', 'convert_pem', 'open_pkcs12', 'draft_governance_issue']);
        for (const t of listToolsPayload().tools) {
            const a = t.annotations as { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean };
            expect(a.openWorldHint, t.name).toBe(false);
            expect(a.destructiveHint, t.name).toBe(false);
            if (PRODUCES.has(t.name)) {
                expect(a.readOnlyHint, t.name).toBe(false);
                expect(a.idempotentHint, t.name).toBe(false);
            } else if (WRITES.has(t.name)) {
                expect(a.readOnlyHint, t.name).toBe(false);
                expect(a.idempotentHint, t.name).toBe(true);
            } else {
                expect(a.readOnlyHint, t.name).toBe(true);
                expect(a.idempotentHint, t.name).toBe(true);
            }
        }
    });
});

describe('docs/assets/ecosystem.json — the manifest every document quotes', () => {
    it('exists and carries the live counts, versions and tool groups in registration order', () => {
        expect(has(MANIFEST)).toBe(true);
        const m = manifest();
        expect(m.packages['pkinative-mcp']?.version).toBe(PKINATIVE_MCP_VERSION);
        expect(m.packages['pkinative']?.version).toBe(PKINATIVE_VERSION);
        expect(m.packages['pkinative']?.pin).toBe((JSON.parse(read('package.json')) as { dependencies: Record<string, string> }).dependencies['pkinative']);
        expect(m.derived['tools']).toBe(TOOL_COUNT);
        expect(m.derived['prompts']).toBe(PROMPTS.length);
        expect(m.derived['envVars']).toBe(ENV_VARS.length);
        expect(Object.values(m.derived.toolGroups).flat()).toEqual(TOOLS);
        expect(Object.keys(m.derived.toolGroups)).toHaveLength(6);
        expect(m.declared['wrapperCodes']).toBe(WRAPPER_CODE_NAMES.length);
        expect(m.declared['engineErrorCodes']).toBe(PKI_ERROR_CODES.length);
        expect(m.declared['engineReasonCodes']).toBe(PKI_REASON_CODES.length);
        expect(m.declared['engineDiagnosticCodes']).toBe(PKI_DIAGNOSTIC_CODES.length);
        expect(m.declared['engineLimits']).toBe(LIMIT_KEYS.length);
        expect(m.declared['toolApiVersion']).toBe(TOOL_API_VERSION);
        expect(m.declared['nodeFloor']).toBe(PKINATIVE_NODE_FLOOR);
        expect(m.declared['instructionsBytes']).toBe(Buffer.byteLength(__serverInstructions));
        expect(m.declared['legacyRevisions']).toEqual(['2024-10-07', '2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25']);
        expect(m.declared['mcpRevision']).toBe('2026-07-28');
        expect(m.verifiedOn).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });

    it('declares the engine export split the vendored registry carries (294 = 117 runtime + 177 type-only)', () => {
        const core = JSON.parse(read('src/data/pkinative/core-exports.json')) as { counts: { exports: number; capability: number; typeOnly: number }; exports: Array<{ name: string; reach: string }> };
        const m = manifest();
        expect(core.counts).toEqual({ exports: 294, capability: 117, typeOnly: 177 });
        expect(core.exports).toHaveLength(core.counts.exports);
        expect(core.exports.filter((e) => e.reach === 'capability')).toHaveLength(core.counts.capability);
        expect(core.exports.filter((e) => e.reach === 'type-only')).toHaveLength(core.counts.typeOnly);
        expect(m.declared['engineExports']).toBe(core.counts.exports);
        expect(m.declared['runtimeExports']).toBe(core.counts.capability);
        expect(m.declared['typeExports']).toBe(core.counts.typeOnly);
    });
});

describe('docs/AGENT_CONTRACT.md', () => {
    const present = has('docs/AGENT_CONTRACT.md');

    it.skipIf(!present)('has the six numbered sections with the tool count in the catalogue heading', () => {
        const contract = read('docs/AGENT_CONTRACT.md');
        for (const h of CONTRACT_SECTIONS) expect(contract, h).toContain(h);
    });

    it.skipIf(!present)('§1 lists every tool in registration order (name in backticks in column 2)', () => {
        const rows = tableRows(section(read('docs/AGENT_CONTRACT.md'), CONTRACT_SECTIONS[0]));
        expect(rows.length, 'catalogue table data rows').toBe(TOOL_COUNT);
        expect(rows.map((r) => r[1])).toEqual(TOOLS.map((t) => `\`${t}\``));
    });

    it.skipIf(!present)('§6 documents every wrapper code in backticks, in the `| `CODE` | … |` row form', () => {
        const errors = section(read('docs/AGENT_CONTRACT.md'), '## 6. Error reference');
        const missing = WRAPPER_CODE_NAMES.filter((c) => !new RegExp(`^\\|\\s*\`${c}\`\\s*\\|`, 'm').test(errors));
        expect(missing, `wrapper codes without a row in docs/AGENT_CONTRACT.md §6: ${missing.join(', ')}`).toEqual([]);
        expect(errors).toMatch(new RegExp(`Wrapper codes \\(${WRAPPER_CODE_NAMES.length}\\)|${WRAPPER_CODE_NAMES.length} wrapper codes`));
        // The engine vocabularies are documented there too, every code in a row of its own.
        for (const [codes, what] of [[PKI_ERROR_CODES, 'PKI_*'], [PKI_REASON_CODES, 'PKI_REASON_*'], [PKI_DIAGNOSTIC_CODES, 'PKI_DIAG_*']] as const) {
            const absent = codes.filter((c) => !new RegExp(`^\\|\\s*\`${c}\`\\s*\\|`, 'm').test(errors));
            expect(absent, `${what} codes without a row in docs/AGENT_CONTRACT.md §6: ${absent.join(', ')}`).toEqual([]);
        }
    });

    it.skipIf(!present)('names every environment variable, every prompt and every tool', () => {
        const contract = read('docs/AGENT_CONTRACT.md');
        for (const v of ENV_VARS) expect(contract, v).toContain(v);
        for (const p of PROMPTS) expect(contract, p).toContain(p);
        for (const t of TOOLS) expect(contract, t).toContain(`\`${t}\``);
    });
});

describe('README.md', () => {
    const present = has('README.md');

    it.skipIf(!present)('names every tool in backticks and quotes the tool count', () => {
        const readme = read('README.md');
        for (const t of TOOLS) expect(readme, t).toContain(`\`${t}\``);
        expect(readme).toContain(`${TOOL_COUNT} tools`);
    });

    it.skipIf(!present)('names every environment variable and every prompt', () => {
        const readme = read('README.md');
        for (const v of ENV_VARS) expect(readme, v).toContain(v);
        for (const p of PROMPTS) expect(readme, p).toContain(p);
    });
});

describe('llms.txt', () => {
    it.skipIf(!has('llms.txt'))('names every tool, quotes the tool count and the package version', () => {
        const llms = read('llms.txt');
        for (const t of TOOLS) expect(llms, t).toContain(t);
        expect(llms).toContain(`${TOOL_COUNT} tools`);
        for (const m of llms.matchAll(/pkinative-mcp (?:v|@)?(\d+\.\d+\.\d+)/g)) expect(m[1], `llms.txt: "${m[0]}"`).toBe(PKINATIVE_MCP_VERSION);
    });
});

describe('tool count and version in the package, registry and citation metadata', () => {
    it('package.json description quotes the tool count; mcpName is the registry name', () => {
        const pkg = JSON.parse(read('package.json')) as { description: string; mcpName: string; version: string };
        expect(pkg.description).toContain(`${TOOL_COUNT} tools`);
        expect(pkg.mcpName).toBe('io.github.Nizoka/pkinative-mcp');
        expect(pkg.version).toBe(PKINATIVE_MCP_VERSION);
    });

    it('server.json description quotes the tool count and its environment variables are exactly the nine, the two secrets flagged', () => {
        const server = JSON.parse(read('server.json')) as { description: string; packages: Array<{ environmentVariables?: Array<{ name: string; isSecret?: boolean }> }> };
        expect(server.description).toContain(`${TOOL_COUNT} tools`);
        const vars = server.packages[0]?.environmentVariables ?? [];
        expect(vars.map((v) => v.name).sort()).toEqual([...ENV_VARS].sort());
        for (const secret of ['PKINATIVE_MCP_HTTP_TOKEN', PASSWORD_ENV]) expect(vars.find((v) => v.name === secret)?.isSecret, `${secret} is a secret`).toBe(true);
        for (const v of vars) if (v.name !== 'PKINATIVE_MCP_HTTP_TOKEN' && v.name !== PASSWORD_ENV) expect(v.isSecret, `${v.name} is not a secret`).not.toBe(true);
    });

    it.skipIf(!has('CITATION.cff'))('CITATION.cff carries the package version', () => {
        expect(read('CITATION.cff')).toMatch(new RegExp(`^version:\\s*["']?${PKINATIVE_MCP_VERSION.replace(/\./g, '\\.')}["']?\\s*$`, 'm'));
    });

    it.skipIf(!has('AGENTS.md'))('AGENTS.md quotes the tool and prompt counts', () => {
        expect(read('AGENTS.md')).toContain(`${TOOL_COUNT} tools`);
        expect(read('AGENTS.md')).toContain(`${PROMPTS.length} prompts`);
    });

    it.skipIf(!has('CLAUDE.md'))('CLAUDE.md starts with @AGENTS.md', () => {
        expect(read('CLAUDE.md').split('\n').find((l) => l.trim() !== '')?.trim()).toBe('@AGENTS.md');
    });
});

describe('every "<N> tools" figure in the counted documents equals the live count', () => {
    const COUNTED = ['README.md', 'AGENTS.md', 'llms.txt', 'CLAUDE.md', 'CITATION.cff', 'SECURITY.md', 'CONTRIBUTING.md', 'docs/AI_GUIDE.md', 'docs/AGENT_CONTRACT.md', 'docs/KNOWLEDGE_BASE.md', 'docs/API_STABILITY.md', 'CHANGELOG.md', `release-notes/v${PKINATIVE_MCP_VERSION}.md`] as const;
    for (const rel of COUNTED) {
        it.skipIf(!has(rel))(`${rel}`, () => {
            const text = read(rel);
            // "rides on 31 tools", "(23 tools)", "on the 23 tools that": a subset, not the catalogue (the same rule as the manifest's tool-count assertion).
            for (const m of text.matchAll(/(?<![#.\d])(?<!\b(?:on|across|among|within|for)\s)(?<!\b(?:on|across|among|within|for)\sthe\s)(?<!\()\b(\d+) tools\b/g)) expect(Number(m[1]), `${rel}: "${m[0]}"`).toBe(TOOL_COUNT);
            for (const m of text.matchAll(/Tools \((\d+)\)/g)) expect(Number(m[1]), `${rel}: "${m[0]}"`).toBe(TOOL_COUNT);
            for (const m of text.matchAll(/\b(\d+) prompts\b/g)) expect(Number(m[1]), `${rel}: "${m[0]}"`).toBe(PROMPTS.length);
            for (const m of text.matchAll(/\b(\d+) wrapper codes\b/g)) expect(Number(m[1]), `${rel}: "${m[0]}"`).toBe(WRAPPER_CODE_NAMES.length);
            for (const m of text.matchAll(/\b(\d+) `?PKI_\*`? error codes\b/g)) expect(Number(m[1]), `${rel}: "${m[0]}"`).toBe(PKI_ERROR_CODES.length);
            for (const m of text.matchAll(/\b(\d+) `?PKI_REASON_\*`? (?:verdict )?reasons\b/g)) expect(Number(m[1]), `${rel}: "${m[0]}"`).toBe(PKI_REASON_CODES.length);
            for (const m of text.matchAll(/\b(\d+) `?PKI_DIAG_\*`? diagnostics\b/g)) expect(Number(m[1]), `${rel}: "${m[0]}"`).toBe(PKI_DIAGNOSTIC_CODES.length);
            for (const m of text.matchAll(/\b(\d+) (?:environment|operator) variables\b/g)) expect(Number(m[1]), `${rel}: "${m[0]}"`).toBe(ENV_VARS.length);
        });
    }
});

describe('docs/data/*.json ↔ the frozen vocabularies', () => {
    const registry = <T>(rel: string): T => JSON.parse(read(rel)) as T;

    it('errors.json carries exactly the 57 PKI_* codes of the mapping table, reasons.json the 43, diagnostics.json the 97, limits.json the 22', () => {
        for (const dir of ['src/data/pkinative', 'docs/data']) {
            const errors = registry<{ errors: Array<{ code: string }> }>(`${dir}/errors.json`);
            expect(errors.errors.map((e) => e.code).sort(), dir).toEqual([...PKI_ERROR_CODES].sort());
            const reasons = registry<{ reasons: Array<{ code: string }> }>(`${dir}/reasons.json`);
            expect(reasons.reasons.map((e) => e.code).sort(), dir).toEqual([...PKI_REASON_CODES].sort());
            const diagnostics = registry<{ diagnostics: Array<{ code: string }> }>(`${dir}/diagnostics.json`);
            expect(diagnostics.diagnostics.map((e) => e.code).sort(), dir).toEqual([...PKI_DIAGNOSTIC_CODES].sort());
            const limits = registry<{ limits: Array<{ limit: string }> }>(`${dir}/limits.json`);
            expect(limits.limits.map((e) => e.limit).sort(), dir).toEqual([...LIMIT_KEYS].sort());
        }
    });

    it('the docs/data mirrors are byte-identical to the vendored src/data/pkinative registries and pin the installed engine version', () => {
        for (const name of ['errors.json', 'reasons.json', 'diagnostics.json', 'limits.json', 'core-exports.json']) {
            expect(readFileSync(file(`docs/data/${name}`)).equals(readFileSync(file(`src/data/pkinative/${name}`))), name).toBe(true);
            const data = registry<{ package?: string; pkinative?: string; verifiedOn?: string }>(`docs/data/${name}`);
            if (name === 'core-exports.json') expect(data.pkinative, name).toBe(PKINATIVE_VERSION);
            else expect(data.package, name).toBe('pkinative');
        }
        const files = readdirSync(file('docs/data')).filter((f) => f.endsWith('.json'));
        expect(files.sort()).toEqual(['core-exports.json', 'diagnostics.json', 'errors.json', 'interop.json', 'limits.json', 'reasons.json']);
    });
});

describe('docs/KNOWLEDGE_BASE.md — the 117-export ledger', () => {
    const KB = 'docs/KNOWLEDGE_BASE.md';
    const ledgerSection = (): string => {
        const text = read(KB);
        const heading = /^## 8\. .*$/m.exec(text)?.[0];
        expect(heading, 'docs/KNOWLEDGE_BASE.md has a "## 8." section (the export ledger)').toBeDefined();
        return section(text, heading!);
    };

    it.skipIf(!has(KB))('§8 names every runtime export of core-exports.json in backticks', () => {
        const core = JSON.parse(read('docs/data/core-exports.json')) as { exports: Array<{ name: string; reach: string }> };
        const ledger = ledgerSection();
        const missing = core.exports.filter((e) => e.reach === 'capability' && !ledger.includes(`\`${e.name}\``)).map((e) => e.name);
        expect(missing, `runtime exports missing from KB §8: ${missing.join(', ')}`).toEqual([]);
        expect(read(KB)).toContain('117');
    });

    it.skipIf(!has(KB))('the knowledge base grades the deliberately unexposed surface, and the five UNEXPOSED_EXPORTS entries are the documented ones', () => {
        const text = read(KB);
        expect(text).toMatch(/unexposed/i);
        expect(UNEXPOSED_EXPORTS.map((u) => u.export)).toEqual([
            'ExternalSigner.produceSignature',
            'PkiParseOptions.onDiagnostic',
            'password: Uint8Array',
            'Certificate.der / tbsDer / *.valueDer echoes',
            'The 177 type exports',
        ]);
        for (const u of UNEXPOSED_EXPORTS) expect(u.rationale.length).toBeGreaterThan(30);
    });
});

describe('every PKINATIVE_MCP_* token in the documents is one of the nine environment variables', () => {
    // Code identifiers are the only other tokens allowed to carry the prefix.
    const ALLOWED = new Set<string>([...ENV_VARS, 'PKINATIVE_MCP_VERSION']);
    const DOCS = ['README.md', 'AGENTS.md', 'llms.txt', 'CLAUDE.md', 'SECURITY.md', 'CONTRIBUTING.md', 'SUPPORT.md', 'CHANGELOG.md', 'server.json', 'package.json', '.github/AGENT_RULES.md', '.github/copilot-instructions.md', '.github/ai-governance.json'] as const;
    const walkDocs = (dir: string, out: string[] = []): string[] => {
        if (!existsSync(dir)) return out;
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) walkDocs(full, out);
            else if (/\.(?:md|json|txt|yml)$/.test(entry.name)) out.push(path.relative(ROOT, full).split(path.sep).join('/'));
        }
        return out;
    };
    const files = [...DOCS.filter((f) => has(f)), ...walkDocs(file('docs')), ...walkDocs(file('release-notes')), ...walkDocs(file('.github/workflows')), ...walkDocs(file('.github/instructions')), ...walkDocs(file('examples'))];

    it('names exactly the nine variables (plus the version constant) across the documents', () => {
        const unknown = new Set<string>();
        for (const rel of files) {
            for (const m of read(rel).matchAll(/PKINATIVE_MCP_[A-Z][A-Z0-9_]*[A-Z0-9]/g)) if (!ALLOWED.has(m[0])) unknown.add(`${rel}: ${m[0]}`);
        }
        expect([...unknown]).toEqual([]);
        expect(files.length).toBeGreaterThan(5);
    });

    it('the nine variables all appear in server.json (registered) and, when present, in the README (documented)', () => {
        for (const v of ENV_VARS) {
            expect(read('server.json'), v).toContain(v);
            if (has('README.md')) expect(read('README.md'), v).toContain(v);
        }
    });
});

describe('version strings outside the lock-step files quote the package version', () => {
    it('GOVERNANCE_CONTRACT_SUMMARY carries (v<PKINATIVE_MCP_VERSION>) and src/version.ts equals package.json', () => {
        expect(GOVERNANCE_CONTRACT_SUMMARY).toContain(`(v${PKINATIVE_MCP_VERSION})`);
        expect(PKINATIVE_MCP_VERSION).toBe((JSON.parse(read('package.json')) as { version: string }).version);
    });

    it('server.json carries the version twice', () => {
        const server = JSON.parse(read('server.json')) as { version: string; packages: Array<{ version: string }> };
        expect(server.version).toBe(PKINATIVE_MCP_VERSION);
        for (const p of server.packages) expect(p.version).toBe(PKINATIVE_MCP_VERSION);
    });
});

describe('release notes and CHANGELOG name the same tools under Added', () => {
    const NOTES = `release-notes/v${PKINATIVE_MCP_VERSION}.md`;
    const featTools = (text: string): string[] => [...new Set([...text.matchAll(/feat\(tool\):\s*`?([a-z0-9_]+)`?/g)].map((m) => m[1]!))].sort();

    it.skipIf(!has(NOTES))('the release note names every tool as a feat(tool) bullet under Added', () => {
        expect(featTools(section(read(NOTES), '## Added'))).toEqual([...TOOLS].sort());
    });

    it.skipIf(!has(NOTES) || !has('CHANGELOG.md'))('every feat(tool) bullet of the release note appears in CHANGELOG [version], and vice versa', () => {
        const notes = featTools(section(read(NOTES), '## Added'));
        const changelog = featTools(section(read('CHANGELOG.md'), `## [${PKINATIVE_MCP_VERSION}]`));
        expect(changelog).toEqual(notes);
    });
});

describe('the claims the documents make about themselves hold', () => {
    const readOnly = new Map(listToolsPayload().tools.map((t) => [t.name, (t.annotations as { readOnlyHint?: boolean } | undefined)?.readOnlyHint === true]));

    it.skipIf(!has('docs/KNOWLEDGE_BASE.md') && !has('README.md'))('every SERVER_INSTRUCTIONS byte figure quoted in a document is the measured one', () => {
        const measured = Buffer.byteLength(__serverInstructions);
        for (const rel of ['docs/KNOWLEDGE_BASE.md', 'README.md', 'docs/AI_GUIDE.md', 'docs/API_STABILITY.md', 'AGENTS.md'].filter(has)) {
            for (const [n, l] of lines(rel)) {
                for (const m of l.matchAll(/SERVER_INSTRUCTIONS`?[^\n]{0,60}?≈?\s*([\d,]+)\s*bytes/g)) {
                    expect(Number(m[1]!.replace(/,/g, '')), `${rel}:${n}`).toBe(measured);
                }
                for (const m of l.matchAll(/instructions[^\n]{0,40}?\(?([\d,]{4,})\s*bytes/gi)) {
                    expect(Number(m[1]!.replace(/,/g, '')), `${rel}:${n}`).toBe(measured);
                }
            }
        }
    });

    it.skipIf(!has('docs/API_STABILITY.md'))('API_STABILITY says "read-only" exactly for the tools whose readOnlyHint is true, where it carries an annotations line per tool', () => {
        const text = read('docs/API_STABILITY.md');
        let seen = 0;
        for (const [tool, ro] of readOnly) {
            if (!text.includes(`### \`${tool}\``)) continue;
            const ann = section(text, `### \`${tool}\``).split('\n').find((l) => l.trim().startsWith('- **Annotations:**'));
            if (ann === undefined) continue;
            seen++;
            expect(/(?<!not )\bread-only\b/.test(ann), `${tool}: "${ann}"`).toBe(ro);
        }
        expect(seen).toBeGreaterThanOrEqual(0);
    });

    it('no document says build_certificate_path checks signatures, or that inspect_certificate is a verdict', () => {
        for (const rel of ['README.md', 'AGENTS.md', 'llms.txt', 'docs/AI_GUIDE.md', 'docs/AGENT_CONTRACT.md', 'docs/guides/VERIFICATION.md'].filter(has)) {
            for (const [n, l] of lines(rel)) {
                if (l.includes('build_certificate_path') && /\bverif(?:y|ies|ied) (?:the )?signatures?\b/i.test(l)) {
                    expect(l, `${rel}:${n}`).toMatch(/never|not|no signature|NOT|without/);
                }
            }
        }
    });

    it('every "no network" statement names no fetch of CRL, OCSP or TSA material', () => {
        for (const rel of ['README.md', 'SECURITY.md', 'docs/guides/SECURITY.md', 'llms.txt'].filter(has)) {
            const text = read(rel);
            if (/no network/i.test(text)) expect(text).toMatch(/CRL|OCSP|TSA|fetch/);
        }
    });
});
