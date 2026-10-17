import { describe, it, expect, beforeAll } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';

import { PKINATIVE_VERSION } from '../src/engine.js';
import { callToolDirect, createServer, ensureEngineReady, toolDefinition, toolNames, __serverMetadata, __serverInstructions, __prompts, SERVER_CACHE_HINTS } from '../src/server.js';
import { TOOL_API_VERSION, PKINATIVE_MCP_VERSION } from '../src/version.js';
import { connectLegacy, McpRpcError } from './_mcp-harness.js';
import { AT, fixtureInput, fixtureText } from './_pki-fixtures.js';

/** One-shot JSON-RPC request through the in-memory transport (legacy era). */
async function rpc<T = Record<string, unknown>>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    const client = await connectLegacy();
    try {
        return await client.request<T>(method, params);
    } finally {
        await client.close();
    }
}

const OUTPUT_ENV = 'PKINATIVE_MCP_OUTPUT_DIR';

/** The 34 tools of pkinative-mcp 1.0.0, in registration order (= tools/list order). */
export const ALL_TOOLS = [
    // encodings
    'convert_pem', 'resolve_oid', 'compute_fingerprint', 'decode_asn1', 'encode_asn1',
    // certificates and requests
    'inspect_certificate', 'create_certificate', 'encode_x509_structure', 'decode_extension', 'check_certificate_name', 'check_certificate_purpose', 'inspect_csr', 'create_csr',
    // paths, CRLs, OCSP
    'verify_certificate_chain', 'build_certificate_path', 'validate_certificate_path', 'inspect_crl', 'check_crl_revocation', 'create_ocsp_request', 'inspect_ocsp_response', 'check_ocsp_status',
    // CMS and time-stamps
    'sign_cms', 'verify_cms', 'inspect_cms', 'amend_cms', 'create_timestamp_request', 'inspect_timestamp', 'verify_timestamp',
    // keys
    'inspect_private_key', 'inspect_pkcs12', 'open_pkcs12',
    // meta
    'describe_engine', 'explain_code', 'draft_governance_issue',
];

/** Tools that never write (readOnlyHint true): reads, verdicts, engine, explain. open_pkcs12 and convert_pem may write a sandbox file. */
const READ_ONLY_TOOLS = ALL_TOOLS.filter((n) => /^(inspect_|check_|verify_|validate_|build_|resolve_|compute_|decode_)/.test(n) || n === 'describe_engine' || n === 'explain_code');
/** Tools whose output is not idempotent (random serial / nonce, wall-clock time, randomised signatures). */
const PRODUCING_TOOLS = ['create_certificate', 'create_csr', 'sign_cms', 'create_ocsp_request', 'create_timestamp_request'];

const ALL_PROMPTS = ['draft_issue_workflow', 'governance_contract', 'issue_certificate', 'offline_revocation', 'open_keys_safely', 'sign_and_timestamp', 'verify_before_trust'];

describe('B2-053 / A2-044: projection and the error boundary', () => {
    it('B2-053: a nested fields path that matches nothing is reported in _meta.unmatchedFields, next to the paths that matched', async () => {
        const r = await callToolDirect('inspect_certificate', { certificate: fixtureInput('leaf.crt.pem'), fields: ['subjectString', 'subject.nope', 'extensions.kind', 'validity.notBefore.nowhere'] });
        expect(r.isError).not.toBe(true);
        const meta = r._meta as { unmatchedFields?: string[]; availableFields?: string[] } | undefined;
        expect(meta?.unmatchedFields).toEqual(['subject.nope', 'validity.notBefore.nowhere']);
        expect(Object.keys(r.structuredContent as object).sort()).toEqual(['extensions', 'subjectString']);
    });

    it('A2-044: a call-stack exhaustion under a raised limits.maxDepth is a coded ENGINE_ERROR naming the remedy, never an uncoded failure', async () => {
        // 6000 nested SEQUENCEs around one NULL, lengths in long form where needed.
        let der = Buffer.from([0x05, 0x00]);
        for (let i = 0; i < 6000; i++) {
            const len = der.length;
            const header = len < 0x80 ? Buffer.from([0x30, len]) : len < 0x100 ? Buffer.from([0x30, 0x81, len]) : len < 0x10000 ? Buffer.from([0x30, 0x82, len >> 8, len & 0xff]) : Buffer.from([0x30, 0x83, len >> 16, (len >> 8) & 0xff, len & 0xff]);
            der = Buffer.concat([header, der]);
        }
        const r = await callToolDirect('decode_asn1', { input: { derBase64: der.toString('base64') }, limits: { maxDepth: 10_000, maxNodes: 20_000 } });
        expect(r.isError).toBe(true);
        const error = (r._meta as { error?: { code?: string; data?: { remedy?: string } } } | undefined)?.error;
        expect(error?.code).toMatch(/^(ENGINE_ERROR|PKI_[A-Z_]+)$/);
        if (error?.code === 'ENGINE_ERROR') expect(error.data?.remedy).toContain('maxDepth');
        expect((r.content[0] as { text: string }).text).toMatch(/failed \[[A-Z_]+\]:/);
    }, 60_000);
});

describe('server', () => {
    beforeAll(async () => {
        delete process.env[OUTPUT_ENV];
        await ensureEngineReady();
    });

    it('exposes stable metadata', () => {
        expect(__serverMetadata.name).toBe('pkinative-mcp');
        expect(__serverMetadata.version).toBe(PKINATIVE_MCP_VERSION);
        expect(__serverMetadata.engineVersion).toBe(PKINATIVE_VERSION);
    });

    it('advertises a human-readable title and description in serverInfo (MCP Implementation)', () => {
        expect(typeof __serverMetadata.title).toBe('string');
        expect(__serverMetadata.title.length).toBeGreaterThan(0);
        expect(__serverMetadata.description).toMatch(/MCP server/i);
        expect(__serverMetadata.description).toMatch(new RegExp(`${ALL_TOOLS.length} tools`));
        expect(__serverMetadata.description).toMatch(/no network ever/);
    });

    it('registers exactly the 34 tools of 1.0.0, in catalogue order', () => {
        expect(toolNames()).toEqual(ALL_TOOLS);
    });

    it('SERVER_INSTRUCTIONS advertises the decision tree, security posture and pitfalls for AI clients', () => {
        expect(__serverInstructions).toContain(`pkinative-mcp: ${ALL_TOOLS.length} tools over the pkinative v${PKINATIVE_VERSION}`);
        expect(__serverInstructions).toContain(`Tool API ${TOOL_API_VERSION}`);
        expect(__serverInstructions).toContain('MCP 2026-07-28');
        expect(__serverInstructions).toContain('DECISION TREE');
        expect(__serverInstructions).toContain('SECURITY POSTURE');
        expect(__serverInstructions).toContain('COMMON PITFALLS');
        expect(__serverInstructions).toContain('No network, ever');
        for (const t of toolNames()) expect(__serverInstructions, t).toContain(t);
        for (const p of __prompts) expect(__serverInstructions, p.name).toContain(p.name);
        expect(__serverInstructions).toContain('PKINATIVE_MCP_OUTPUT_DIR');
        expect(__serverInstructions).toContain('PKINATIVE_MCP_PASSWORD');
        expect(__serverInstructions).toContain('pkinative://output/');
        expect(Buffer.byteLength(__serverInstructions, 'utf8')).toBeLessThanOrEqual(8 * 1024);
    });

    it('exposes MCP prompts for the AI-governance contract, the issue workflow and five recipes', async () => {
        const promptList = (await rpc('prompts/list')) as { prompts: Array<{ name: string; title?: string; description?: string }> };
        expect(promptList.prompts.map((p) => p.name).sort()).toEqual(ALL_PROMPTS);
        for (const p of promptList.prompts) {
            expect(typeof p.title, p.name).toBe('string');
            expect((p.description ?? '').length, p.name).toBeGreaterThan(20);
        }
        for (const [name, tool] of [
            ['verify_before_trust', 'verify_certificate_chain'],
            ['issue_certificate', 'create_certificate'],
            ['sign_and_timestamp', 'sign_cms'],
            ['offline_revocation', 'check_ocsp_status'],
            ['open_keys_safely', 'open_pkcs12'],
            ['draft_issue_workflow', 'draft_governance_issue'],
        ] as const) {
            const recipe = (await rpc('prompts/get', { name })) as { description: string; messages: Array<{ role: string; content: { type: string; text: string } }> };
            expect(recipe.messages[0]?.role).toBe('user');
            expect(recipe.messages[0]?.content.type).toBe('text');
            expect(recipe.messages[0]?.content.text, name).toContain(tool);
        }
        const got = (await rpc('prompts/get', { name: 'governance_contract' })) as { messages: Array<{ role: string; content: { type: string; text: string } }> };
        expect(got.messages[0]?.content.text).toMatch(/DRAFTSMAN/);
        const keys = (await rpc('prompts/get', { name: 'open_keys_safely' })) as { messages: Array<{ content: { text: string } }> };
        expect(keys.messages[0]?.content.text).toContain('PKINATIVE_MCP_PASSWORD');
        const err = await rpc('prompts/get', { name: 'nope' }).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(McpRpcError);
        expect((err as McpRpcError).code).toBe(-32602);
        expect((err as McpRpcError).message).toContain('[UNKNOWN_PROMPT]');
    });

    it('lists every tool with apiVersion, 1–2 examples, a title, a long description and annotations', async () => {
        const response = (await rpc('tools/list')) as {
            tools: Array<{ name: string; title?: string; description: string; _meta?: { apiVersion?: string; examples?: Array<{ title: string; input: unknown }> }; annotations?: Record<string, boolean> }>;
        };
        expect(response.tools.map((t) => t.name)).toEqual(toolNames());
        for (const t of response.tools) {
            expect(t._meta?.apiVersion, t.name).toBe(TOOL_API_VERSION);
            expect(Array.isArray(t._meta?.examples), t.name).toBe(true);
            expect((t._meta?.examples ?? []).length, t.name).toBeGreaterThan(0);
            expect((t._meta?.examples ?? []).length, `${t.name}: at most 2 examples (token budget)`).toBeLessThanOrEqual(2);
            for (const ex of t._meta?.examples ?? []) {
                expect(typeof ex.title).toBe('string');
                expect(ex.input !== null && typeof ex.input === 'object').toBe(true);
            }
            expect(typeof t.title, t.name).toBe('string');
            expect(t.description.length, t.name).toBeGreaterThan(80);
        }
    });

    it("every tool description names a sibling tool or carries an explicit 'prefer' / 'use it' / 'when' cue", async () => {
        const response = (await rpc('tools/list')) as { tools: Array<{ name: string; description: string }> };
        const names = response.tools.map((t) => t.name);
        const offenders: string[] = [];
        for (const t of response.tools) {
            const siblings = names.filter((n) => n !== t.name && t.description.includes(n));
            const cue = /prefer|use it|when/i.test(t.description);
            if (siblings.length === 0 && !cue) offenders.push(t.name);
        }
        expect(offenders).toEqual([]);
        const byName = new Map(response.tools.map((t) => [t.name, t.description]));
        expect(byName.get('inspect_certificate')).toContain('verify_certificate_chain');
        expect(byName.get('describe_engine')).toMatch(/Call it first|whenever/);
    });

    it('annotations: readOnlyHint exactly for the read / verdict tools, openWorldHint false everywhere, never destructive, idempotent unless the tool produces', async () => {
        const response = (await rpc('tools/list')) as { tools: Array<{ name: string; annotations?: Record<string, boolean> }> };
        const readOnly = response.tools.filter((t) => t.annotations?.['readOnlyHint'] === true).map((t) => t.name).sort();
        expect(readOnly).toEqual([...READ_ONLY_TOOLS].sort());
        for (const t of response.tools) {
            expect(t.annotations, `${t.name} has annotations`).toBeDefined();
            expect(t.annotations!['openWorldHint'], t.name).toBe(false);
            expect(t.annotations!['destructiveHint'], t.name).toBe(false);
            expect(t.annotations!['idempotentHint'], t.name).toBe(!PRODUCING_TOOLS.includes(t.name));
        }
        for (const name of PRODUCING_TOOLS) expect(toolDefinition(name)?.cacheable === false || toolDefinition(name)?.annotations.idempotentHint === false, name).toBe(true);
    });

    it('tool input schemas are JSON Schema 2020-12 compatible (dialect-agnostic)', async () => {
        const response = (await rpc('tools/list')) as { tools: Array<{ name: string; inputSchema: Record<string, unknown>; outputSchema?: Record<string, unknown> }> };
        const FORBIDDEN = new Set(['$ref', '$defs', 'definitions', 'dependencies', '$schema']);
        const scan = (node: unknown, toolName: string, at: string): void => {
            if (Array.isArray(node)) {
                node.forEach((v, i) => scan(v, toolName, `${at}[${i}]`));
                return;
            }
            if (node === null || typeof node !== 'object') return;
            for (const [key, value] of Object.entries(node)) {
                expect(FORBIDDEN.has(key), `${toolName}${at}.${key} is dialect-sensitive`).toBe(false);
                if ((key === 'exclusiveMinimum' || key === 'exclusiveMaximum') && typeof value === 'boolean') {
                    throw new Error(`${toolName}${at}.${key} uses the draft-04 boolean form`);
                }
                scan(value, toolName, `${at}.${key}`);
            }
        };
        for (const t of response.tools) {
            expect(t.inputSchema['type']).toBe('object');
            expect(t.inputSchema['additionalProperties']).toBe(false);
            scan(t.inputSchema, t.name, '.inputSchema');
            expect(t.outputSchema, `${t.name} advertises an outputSchema`).toBeDefined();
            expect(t.outputSchema?.['type']).toBe('object');
            expect(t.outputSchema?.['additionalProperties']).toBe(false);
            scan(t.outputSchema, t.name, '.outputSchema');
        }
    });

    it('rejects unknown tools with JSON-RPC -32602 on the wire (callToolDirect keeps the isError form for in-process callers)', async () => {
        await expect(rpc('tools/call', { name: 'nope', arguments: {} })).rejects.toMatchObject({ code: -32602, message: expect.stringContaining('[UNKNOWN_TOOL] Unknown tool: nope') });
        const direct = await callToolDirect('nope', {});
        expect(direct.isError).toBe(true);
        expect((direct.content[0] as { text: string }).text).toBe('Unknown tool: nope');
    });

    it('round-trips create_certificate → inspect_certificate → verify_certificate_chain through the wire; the artefact arrives once, as an embedded resource', async () => {
        const client = await connectLegacy();
        try {
            type Res = { isError?: boolean; content: Array<{ type: string; text?: string; resource?: { uri?: string; blob?: string; text?: string; mimeType?: string } }>; structuredContent?: Record<string, unknown> };
            const created = (await client.callTool('create_certificate', { spec: { serialNumber: 42, subject: { CN: 'wire' }, notBefore: AT, validityDays: 3, extensions: { basicConstraints: { ca: true } } }, signer: { key: fixtureInput('ed25519.key.pem') } })) as Res;
            expect(created.isError).not.toBe(true);
            expect(created.content[0]?.text ?? '').toContain('self-signed');
            expect(created.structuredContent).toMatchObject({ mode: 'base64', encoding: 'pem', sha256: expect.stringMatching(/^[0-9a-f]{64}$/), diagnostics: [] });
            expect(created.structuredContent?.['base64']).toBeUndefined();
            const block = created.content.find((c) => c.type === 'resource');
            expect(block?.resource?.mimeType).toBe('application/x-pem-file');
            expect(block?.resource?.uri).toMatch(/^data:application\/x-pem-file;base64,/);
            const pem = block?.resource?.text ?? '';
            expect(pem).toMatch(/^-----BEGIN CERTIFICATE-----/);
            const inspected = (await client.callTool('inspect_certificate', { certificate: { pem }, checkSelfSignature: true, verbosity: 'summary' })) as Res;
            expect(inspected.structuredContent).toMatchObject({ serialNumberHex: '2a', selfIssued: true, signatureValid: true });
            const verdict = (await client.callTool('verify_certificate_chain', { leaf: { pem }, trustAnchors: [{ pem }], at: AT, verbosity: 'summary' })) as Res;
            expect(verdict.isError).not.toBe(true);
            expect(verdict.content[0]?.text).toContain('OK');
            expect(verdict.structuredContent).toMatchObject({ valid: true, pathLength: 1 });
        } finally {
            await client.close();
        }
    });

    it('returns success payload for a file-mode tool call with a resource_link, and lists it as a resource', async () => {
        const sandboxDir = await fs.mkdtemp(path.join(os.tmpdir(), 'pkinative-mcp-server-file-'));
        process.env[OUTPUT_ENV] = sandboxDir;
        try {
            const response = (await rpc('tools/call', {
                name: 'create_certificate',
                arguments: { spec: { serialNumber: 7, subject: { CN: 'file' }, notBefore: AT, validityDays: 1 }, signer: { key: { pem: fixtureText('ed25519.key.pem') } }, outputMode: 'file', outputPath: 'from-server/file.crt.pem' },
            })) as { isError?: boolean; content: Array<{ type: string; text?: string; uri?: string; name?: string }>; structuredContent?: { mode?: string; filePath?: string } };
            expect(response.isError).not.toBe(true);
            expect(response.content[0]?.text ?? '').toContain('written to');
            expect(response.structuredContent?.mode).toBe('file');
            expect(response.structuredContent?.filePath).toBe(path.join(sandboxDir, 'from-server', 'file.crt.pem'));
            const link = response.content.find((c) => c.type === 'resource_link');
            expect(link).toMatchObject({ uri: 'pkinative://output/from-server/file.crt.pem', name: 'from-server/file.crt.pem', mimeType: 'application/x-pem-file' });
            const listed = await rpc<{ resources: Array<{ uri: string }> }>('resources/list');
            expect(listed.resources.map((r) => r.uri)).toEqual(['pkinative://output/from-server/file.crt.pem']);
            const read = await rpc<{ contents: Array<{ uri: string; mimeType: string; text?: string }> }>('resources/read', { uri: 'pkinative://output/from-server/file.crt.pem' });
            expect(read.contents[0]?.text).toMatch(/^-----BEGIN CERTIFICATE-----/);
        } finally {
            delete process.env[OUTPUT_ENV];
            await fs.rm(sandboxDir, { recursive: true, force: true });
        }
    });

    it('surfaces tool validation failures as isError responses with the coded envelope', async () => {
        const response = (await rpc('tools/call', { name: 'create_certificate', arguments: { spec: 'nope' } })) as { isError?: boolean; content: Array<{ text: string }>; _meta?: { error?: { code: string; message: string } } };
        expect(response.isError).toBe(true);
        expect(response.content[0]?.text).toMatch(/^create_certificate failed \[VALIDATION_ERROR\]: /);
        expect(response._meta?.error?.code).toBe('VALIDATION_ERROR');
        const none = await callToolDirect('inspect_certificate', { certificate: {} });
        expect((none._meta as { error: { code: string; message: string } }).error.message).toContain('exactly one of pem / derBase64 / path');
    });

    it('carries a PKI_* refusal in the error envelope (_meta.error.code / data) with the engine class and detail', async () => {
        const direct = await callToolDirect('inspect_certificate', { certificate: { derBase64: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]).toString('base64') } });
        expect(direct.isError).toBe(true);
        expect((direct.content[0] as { text: string }).text).toMatch(/^inspect_certificate failed \[PKI_[A-Z0-9_]+\]: Cannot read the certificate: /);
        const error = (direct._meta as { error: { code: string; message: string; data: Record<string, unknown> } }).error;
        expect(error.code).toMatch(/^PKI_/);
        expect(error.data['errorClass']).toBe('parse');
        expect(String(error.data['engineError'])).toMatch(/^Pki/);
        const wire = (await rpc('tools/call', { name: 'inspect_certificate', arguments: { certificate: fixtureInput('leaf.crt.pem'), limits: { maxDepth: 2 } } })) as { isError?: boolean; _meta?: { error?: { code: string; data?: Record<string, unknown> } } };
        expect(wire.isError).toBe(true);
        expect(wire._meta?.error?.code).toBe('PKI_LIMIT_EXCEEDED');
        expect(wire._meta?.error?.data).toMatchObject({ errorClass: 'limit', limit: 'maxDepth', configured: 2 });
    });

    it('a negative verdict is a report (valid:false), never isError', async () => {
        const r = await callToolDirect('verify_certificate_chain', { leaf: fixtureInput('leaf.crt.pem'), candidates: [fixtureInput('inter.crt.pem')], trustAnchors: [fixtureInput('root.crt.pem')], at: '2050-01-01T00:00:00Z' });
        expect(r.isError).not.toBe(true);
        expect((r.content[0] as { text: string }).text).toContain('NOT OK');
        expect(r.structuredContent).toMatchObject({ valid: false });
    });

    it('advertises the MCP resources capability with list, read and templates handlers', async () => {
        delete process.env[OUTPUT_ENV];
        const res = await rpc<{ resources: unknown[] }>('resources/list');
        expect(res.resources).toEqual([]);
        const templates = await rpc<{ resourceTemplates: unknown[] }>('resources/templates/list');
        expect(templates.resourceTemplates).toEqual([]);
        await expect(rpc('resources/read', { uri: 'pkinative://output/nope.crt' })).rejects.toMatchObject({ code: -32602 });
    });

    it('lists tools in a deterministic order and constructs with valid cache hints', async () => {
        const a = (await rpc<{ tools: Array<{ name: string }> }>('tools/list')).tools.map((t) => t.name);
        const b = (await rpc<{ tools: Array<{ name: string }> }>('tools/list')).tools.map((t) => t.name);
        expect(a).toEqual(b);
        expect(SERVER_CACHE_HINTS['tools/list']).toEqual({ ttlMs: 86_400_000, cacheScope: 'public' });
        expect(SERVER_CACHE_HINTS['prompts/list'].cacheScope).toBe('public');
        expect(SERVER_CACHE_HINTS['server/discover']).toEqual({ ttlMs: 3_600_000, cacheScope: 'public' });
        for (const key of ['resources/list', 'resources/templates/list', 'resources/read'] as const) {
            expect(SERVER_CACHE_HINTS[key], key).toEqual({ ttlMs: 0, cacheScope: 'private' });
        }
        expect(() => createServer()).not.toThrow();
    });
});

describe('token-frugal projection (verbosity / fields) over the wire', () => {
    type CallResponse = { isError?: boolean; structuredContent?: Record<string, unknown>; _meta?: Record<string, unknown> };

    async function call(name: string, args: Record<string, unknown>): Promise<CallResponse> {
        const r = (await rpc('tools/call', { name, arguments: args })) as CallResponse;
        expect(r.isError, `${name}: ${JSON.stringify(r)}`.slice(0, 300)).not.toBe(true);
        return r;
    }

    it("inspect_certificate: full keeps the extensions array; verbosity='summary' collapses to scalars; fields projects dot-paths", async () => {
        const full = await call('inspect_certificate', { certificate: fixtureInput('leaf.crt.pem') });
        expect(Array.isArray(full.structuredContent!['extensions'])).toBe(true);
        expect(full.structuredContent!['diagnosticCount']).toBeUndefined();
        const summary = await call('inspect_certificate', { certificate: fixtureInput('leaf.crt.pem'), verbosity: 'summary' });
        expect(summary.structuredContent).toMatchObject({ serialNumberHex: '1001', publicKey: 'ec', diagnosticCount: 0 });
        expect(summary.structuredContent!['extensions']).toBeUndefined();
        const fields = await call('inspect_certificate', { certificate: fixtureInput('leaf.crt.pem'), fields: ['serialNumber.hex', 'extensions.kind'] });
        expect(fields.structuredContent).toEqual({ serialNumber: { hex: '1001' }, extensions: expect.arrayContaining([{ kind: 'subjectAltName' }]) });
    });

    it("describe_engine verbosity='summary' and fields shapes", async () => {
        const eng = await call('describe_engine', { verbosity: 'summary' });
        expect(Object.keys(eng.structuredContent!).sort()).toEqual(['capabilities', 'engine', 'network', 'sandbox', 'server']);
        const fields = await call('describe_engine', { fields: ['server.toolCount', 'network', 'ceilings.env'] });
        expect(fields.structuredContent).toEqual({ server: { toolCount: ALL_TOOLS.length }, network: 'none', ceilings: { env: ['PKINATIVE_MCP_MAX_INPUT_BYTES', 'PKINATIVE_MCP_MAX_KDF_ITERATIONS', 'PKINATIVE_MCP_MAX_PATHS_EXPLORED'] } });
    });

    it('unmatched fields are reported in _meta.unmatchedFields over the wire', async () => {
        const res = await call('inspect_certificate', { certificate: fixtureInput('leaf.crt.pem'), fields: ['serialnumber'] });
        expect(res.structuredContent).toEqual({});
        expect(res._meta).toMatchObject({ unmatchedFields: ['serialnumber'] });
        expect((res._meta as { availableFields: string[] }).availableFields).toContain('serialNumber');
    });
});
