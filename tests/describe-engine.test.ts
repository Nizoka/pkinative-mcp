/**
 * Tests for `describe_engine` — the offline capability manifest.
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { DEFAULT_PKI_LIMITS, KEY_PURPOSES, KEY_USAGE_BITS, OID_REGISTRY } from 'pkinative';

import { describeEngine, describeSummary, DOCTRINE, UNEXPOSED_EXPORTS } from '../src/tools/describe-engine.js';
import { callToolDirect, toolNames } from '../src/server.js';
import { CAPS, __resetCeilingsForTests } from '../src/caps.js';
import { PKINATIVE_VERSION } from '../src/engine.js';
import { PKI_DIAGNOSTIC_CODES, PKI_ERROR_CODES, PKI_REASON_CODES } from '../src/pki-errors.js';
import { TOOL_API_VERSION, PKINATIVE_MCP_VERSION } from '../src/version.js';
import { WRAPPER_CODE_NAMES } from '../src/wrapper-codes.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const ENV = ['PKINATIVE_MCP_MAX_INPUT_BYTES', 'PKINATIVE_MCP_MAX_KDF_ITERATIONS', 'PKINATIVE_MCP_MAX_PATHS_EXPLORED'] as const;

describe('describe_engine', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_AT'];
        for (const name of ENV) delete process.env[name];
        __resetCeilingsForTests();
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_AT'];
        for (const name of ENV) delete process.env[name];
        __resetCeilingsForTests();
    });

    it('reports the server, engine and runtime shape', async () => {
        const out = await describeEngine({});
        expect(out.server).toEqual({ name: 'pkinative-mcp', version: PKINATIVE_MCP_VERSION, toolApiVersion: TOOL_API_VERSION, protocol: expect.stringContaining('MCP 2026-07-28'), toolCount: toolNames().length });
        expect(out.engine).toEqual({ name: 'pkinative', version: PKINATIVE_VERSION, nodeFloor: expect.stringContaining('22.22.2') });
        expect(out.capabilities).toMatchObject({ canVerify: true, canSign: true, canDecrypt: true, node: process.version, nodeFloorSatisfied: true, platform: process.platform });
        expect(out.randomness).toEqual({ engine: 'none', wrapper: 'node:crypto', usedBy: expect.arrayContaining([expect.stringContaining('create_certificate')]) });
        expect(out.defaultLimits).toEqual({ ...DEFAULT_PKI_LIMITS });
        expect(Object.keys(out.defaultLimits)).toHaveLength(22);
        expect(out.caps).toEqual(CAPS);
        expect(out.network).toBe('none');
    });

    it('lists the three frozen vocabularies, the wrapper codes, the purposes and the doctrine', async () => {
        const out = await describeEngine({});
        expect(out.registries.errorCodes).toHaveLength(57);
        expect(out.registries.errorCodes.map((e) => e.code)).toEqual([...PKI_ERROR_CODES]);
        expect(out.registries.errorCodes.every((e) => e.code.startsWith('PKI_') && e.errorClass.length > 0 && e.engineClass.startsWith('Pki'))).toBe(true);
        expect(out.registries.reasonCodes).toHaveLength(43);
        expect(out.registries.reasonCodes).toEqual([...PKI_REASON_CODES]);
        expect(out.registries.diagnosticCodes).toHaveLength(97);
        expect(out.registries.diagnosticCodes.map((d) => d.code)).toEqual([...PKI_DIAGNOSTIC_CODES]);
        expect(out.registries.diagnosticCodes.every((d) => d.severity === 'warning' || d.severity === 'info')).toBe(true);
        expect(out.registries.wrapperCodes).toEqual([...WRAPPER_CODE_NAMES]);
        expect(out.registries.purposes).toEqual([...Object.keys(KEY_PURPOSES), 'any']);
        expect(out.registries.keyUsageBits).toEqual([...KEY_USAGE_BITS.keys()]);
        expect(out.registries.oidRegistryCount).toBe(OID_REGISTRY.length);
        expect(out.registries.ocspNonceOid).toBe('1.3.6.1.5.5.7.48.1.2');
        expect(out.refusals).toBe(DOCTRINE);
        expect(out.refusals.map((r) => r.what)).toEqual(expect.arrayContaining(['No network, ever', 'No key generation', 'No key export']));
        expect(out.unexposed).toBe(UNEXPOSED_EXPORTS);
        for (const u of out.unexposed) {
            expect(u.export.length).toBeGreaterThan(0);
            expect(u.rationale.length).toBeGreaterThan(0);
        }
    });

    it('sandbox, cache and pinned-instant flags react to the environment', async () => {
        const off = await describeEngine({});
        expect(off.sandbox).toMatchObject({ enabled: false, cacheEnabled: false, pinnedInstant: null });
        expect(off.sandbox.secretExtensions).toEqual(['.key', '.p8', '.p12', '.pfx']);
        expect(off.sandbox.outputExtensions).not.toContain('.p12');
        expect(off.sandbox.inputExtensions).toContain('.p12');
        sandbox = await makeSandbox();
        process.env['PKINATIVE_MCP_CACHE_DIR'] = sandbox;
        process.env['PKINATIVE_MCP_AT'] = '2027-01-01T00:00:00Z';
        const on = await describeEngine({});
        expect(on.sandbox).toMatchObject({ enabled: true, cacheEnabled: true, pinnedInstant: '2027-01-01T00:00:00.000Z' });
    });

    it('ceilings reflect the operator environment', async () => {
        const defaults = await describeEngine({});
        expect(defaults.ceilings).toEqual({ maxInputBytes: 64 * 1024 * 1024, maxKdfIterations: 10_000_000, maxPathsExplored: 1000, env: [...ENV] });
        process.env['PKINATIVE_MCP_MAX_INPUT_BYTES'] = '1048576';
        process.env['PKINATIVE_MCP_MAX_KDF_ITERATIONS'] = '500';
        process.env['PKINATIVE_MCP_MAX_PATHS_EXPLORED'] = '2';
        __resetCeilingsForTests();
        const custom = await describeEngine({});
        expect(custom.ceilings).toMatchObject({ maxInputBytes: 1_048_576, maxKdfIterations: 500, maxPathsExplored: 2 });
    });

    it('rejects unknown arguments', async () => {
        await expect(describeEngine({ verbose: true })).rejects.toMatchObject({ code: 'VALIDATION_ERROR' });
        const ok = await describeEngine(undefined);
        expect(ok.network).toBe('none');
    });

    it('summary / fields projection through the wire; never cached', async () => {
        const full = await describeEngine({});
        expect(Object.keys(describeSummary(full))).toEqual(['server', 'engine', 'capabilities', 'sandbox', 'network']);
        const r = await callToolDirect('describe_engine', { verbosity: 'summary' });
        expect(r.isError).toBeUndefined();
        expect(Object.keys(r.structuredContent as object)).toEqual(['server', 'engine', 'capabilities', 'sandbox', 'network']);
        expect((r.content[0] as { text: string }).text).toContain('pkinative-mcp');
        expect((r.content[0] as { text: string }).text).toContain('network=none');
        const fields = await callToolDirect('describe_engine', { fields: ['defaultLimits', 'ceilings.maxPathsExplored', 'sandbox.enabled', 'nope'] });
        expect(fields.structuredContent).toEqual({ defaultLimits: { ...DEFAULT_PKI_LIMITS }, ceilings: { maxPathsExplored: 1000 }, sandbox: { enabled: false } });
        expect(fields._meta).toMatchObject({ unmatchedFields: ['nope'] });
        sandbox = await makeSandbox();
        process.env['PKINATIVE_MCP_CACHE_DIR'] = sandbox;
        await callToolDirect('describe_engine', {});
        const again = await callToolDirect('describe_engine', {});
        expect((again._meta as { cached?: boolean } | undefined)?.cached).toBeUndefined();
    });
});
