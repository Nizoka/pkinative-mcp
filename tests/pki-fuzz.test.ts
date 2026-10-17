/**
 * Hostile-input suite for the whole catalogue: mutated DER fixtures through
 * every reader and verdict tool, and hostile values on every top-level input
 * property (and inside every PKI input) of every tool.
 *
 * The invariant, for every generated call:
 *
 *     the call succeeds, OR it fails with a ToolError that carries a code
 *     from the documented vocabulary (the wrapper codes or a PKI_* code),
 *     AND no result ever carries a secret needle.
 *
 * A failure without a code is an unexpected throw that escaped a handler; an
 * ENGINE_ERROR on a mutated input means the boundary let through something
 * the engine then choked on. Both are findings. Seeded (tests/_fuzz.ts): the
 * same cases on every machine, no flakiness.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { prepareSandbox, removeSandbox } from '../scripts/helpers/io.js';
import { PKI_ERROR_CODES } from '../src/pki-errors.js';
import { callToolDirect, ensureEngineReady, listToolsPayload, toolDefinition, toolNames } from '../src/server.js';
import { WRAPPER_CODE_NAMES } from '../src/wrapper-codes.js';
import { errorCodeOf, HOSTILE_VALUES, mutate, rng, type Rng } from './_fuzz.js';
import { assertResultClean } from './_pki-assert.js';
import { AT, fixtureBytes, fixtureInput, PASSWORD } from './_pki-fixtures.js';

/** Every code a call may fail with. */
const DOCUMENTED_CODES = new Set<string>([...WRAPPER_CODE_NAMES, ...PKI_ERROR_CODES]);

interface Outcome { readonly ok: boolean; readonly code: string | null; readonly verdict: boolean | null }

async function attempt(tool: string, args: Record<string, unknown>, label: string): Promise<Outcome> {
    const result = await callToolDirect(tool, args);
    assertResultClean(result, `${tool} ${label}`);
    if (result.isError !== true) {
        const valid = (result.structuredContent as { valid?: unknown } | undefined)?.valid;
        return { ok: true, code: null, verdict: typeof valid === 'boolean' ? valid : null };
    }
    const code = errorCodeOf(result as never);
    const text = (result.content.find((c) => c.type === 'text') as { text?: string } | undefined)?.text ?? '';
    expect(code, `${label}: a failure must carry a ToolError code — got: ${text.slice(0, 200)}`).not.toBeNull();
    expect(DOCUMENTED_CODES.has(code!), `${label}: ${code} is not in the documented vocabulary`).toBe(true);
    expect(code, `${label}: the boundary let a mutated input reach the engine unguarded`).not.toBe('ENGINE_ERROR');
    return { ok: false, code, verdict: null };
}

const b64 = (bytes: Uint8Array): { derBase64: string } => ({ derBase64: Buffer.from(bytes).toString('base64') });
const ROOT = fixtureInput('root.crt.pem');
const INTER = fixtureInput('inter.crt.pem');

/** Each reader / verdict tool with the fixture it reads and how the mutant is passed. */
const MUTATION_TARGETS: ReadonlyArray<{ readonly tool: string; readonly fixture: string; readonly args: (mutant: Uint8Array) => Record<string, unknown> }> = [
    { tool: 'inspect_certificate', fixture: 'leaf.crt.der', args: (m) => ({ certificate: b64(m), issuer: INTER }) },
    { tool: 'decode_asn1', fixture: 'leaf.crt.der', args: (m) => ({ input: b64(m) }) },
    { tool: 'compute_fingerprint', fixture: 'leaf.crt.der', args: (m) => ({ input: b64(m), mode: 'key-id' }) },
    { tool: 'convert_pem', fixture: 'leaf.crt.pem', args: (m) => ({ input: { pem: Buffer.from(m).toString('latin1') }, mode: 'decode', extractIndex: 0 }) },
    { tool: 'inspect_csr', fixture: 'leaf.csr.der', args: (m) => ({ request: b64(m) }) },
    { tool: 'inspect_crl', fixture: 'inter.crl.der', args: (m) => ({ crl: b64(m), issuer: INTER }) },
    { tool: 'check_crl_revocation', fixture: 'inter.crl.der', args: (m) => ({ certificate: fixtureInput('leaf.crt.pem'), crl: b64(m), issuer: INTER, at: AT }) },
    { tool: 'inspect_ocsp_response', fixture: 'leaf.ocsp.der', args: (m) => ({ response: b64(m) }) },
    { tool: 'check_ocsp_status', fixture: 'leaf.ocsp.der', args: (m) => ({ response: b64(m), certificate: fixtureInput('leaf.crt.pem'), issuer: INTER, at: AT }) },
    { tool: 'inspect_cms', fixture: 'attached.p7s', args: (m) => ({ signedData: b64(m) }) },
    { tool: 'verify_cms', fixture: 'attached.p7s', args: (m) => ({ signedData: b64(m), trustAnchors: [ROOT], at: AT }) },
    { tool: 'amend_cms', fixture: 'attached.p7s', args: (m) => ({ signedData: b64(m), operation: 'add-unsigned-attribute', attribute: '300d06032a0304310606042a030405' }) },
    { tool: 'inspect_timestamp', fixture: 'content.tsr', args: (m) => ({ input: b64(m) }) },
    { tool: 'verify_timestamp', fixture: 'content.tst', args: (m) => ({ token: b64(m), data: { base64: Buffer.from(fixtureBytes('content.txt')).toString('base64') }, trustAnchors: [ROOT], at: AT }) },
    { tool: 'inspect_private_key', fixture: 'leaf.key.der', args: (m) => ({ key: b64(m) }) },
    { tool: 'inspect_pkcs12', fixture: 'leaf.p12', args: (m) => ({ pkcs12: b64(m), password: PASSWORD }) },
    { tool: 'open_pkcs12', fixture: 'leaf.p12', args: (m) => ({ pkcs12: b64(m), password: PASSWORD }) },
    { tool: 'verify_certificate_chain', fixture: 'leaf.crt.der', args: (m) => ({ leaf: b64(m), candidates: [INTER], trustAnchors: [ROOT], at: AT }) },
    { tool: 'build_certificate_path', fixture: 'inter.crt.der', args: (m) => ({ leaf: fixtureInput('leaf.crt.pem'), candidates: [b64(m)], trustAnchors: [ROOT], at: AT }) },
    { tool: 'validate_certificate_path', fixture: 'inter.crt.der', args: (m) => ({ path: [fixtureInput('leaf.crt.pem'), b64(m)], trustAnchors: [ROOT], at: AT }) },
    { tool: 'decode_extension', fixture: 'leaf.crt.der', args: (m) => ({ oid: '2.5.29.17', valueHex: Buffer.from(m).toString('hex') }) },
    { tool: 'check_certificate_name', fixture: 'leaf.crt.der', args: (m) => ({ certificate: b64(m), host: 'leaf.example.test' }) },
    { tool: 'check_certificate_purpose', fixture: 'leaf.crt.der', args: (m) => ({ certificate: b64(m), purpose: 'serverAuth' }) },
    { tool: 'create_ocsp_request', fixture: 'leaf.crt.der', args: (m) => ({ certificate: b64(m), issuer: INTER }) },
];

const CASES_PER_TARGET = 40;

let sandbox: string | null = null;

beforeAll(async () => {
    await ensureEngineReady();
    sandbox = prepareSandbox('pkinative-mcp-fuzz-');
    expect(DOCUMENTED_CODES.size).toBeGreaterThan(70);
});

afterAll(() => {
    removeSandbox(sandbox);
    sandbox = null;
});

describe('mutated DER fixtures never escape a handler', () => {
    it('every reader and verdict tool is covered by a mutation target', () => {
        const covered = new Set(MUTATION_TARGETS.map((t) => t.tool));
        const readers = toolNames().filter((n) => /^(inspect|verify|check|validate|build|decode|open|amend|convert|compute)_/.test(n));
        for (const r of readers) expect(covered.has(r), `${r} has no mutation target`).toBe(true);
    });

    for (const [index, target] of MUTATION_TARGETS.entries()) {
        it(`${target.tool} × ${CASES_PER_TARGET} mutants of ${target.fixture}`, async () => {
            const r = rng(1000 + index);
            const original = fixtureBytes(target.fixture);
            const seen = new Map<string, number>();
            for (let i = 0; i < CASES_PER_TARGET; i++) {
                const mutant = mutate(original, r);
                const outcome = await attempt(target.tool, target.args(mutant), `${target.tool} case ${i}`);
                const key = outcome.ok ? (outcome.verdict === false ? 'valid:false' : 'OK') : outcome.code!;
                seen.set(key, (seen.get(key) ?? 0) + 1);
            }
            // A mutation campaign that never produces a refusal or a negative verdict is not mutating the bytes that matter.
            expect([...seen.keys()].some((k) => k !== 'OK'), `${target.tool}: ${JSON.stringify([...seen])}`).toBe(true);
        }, 120_000);
    }
});

/** A value of the hostile table, or a PKI-input object holding one. */
function hostileFor(schema: Record<string, unknown>, r: Rng): unknown {
    const props = schema['properties'] as Record<string, unknown> | undefined;
    const items = schema['items'] as Record<string, unknown> | undefined;
    const isPkiInput = props !== undefined && 'pem' in props && 'derBase64' in props;
    const isBundle = items !== undefined && (items['properties'] as Record<string, unknown> | undefined)?.['pem'] !== undefined;
    const roll = r.int(0, 3);
    if (isPkiInput && roll < 2) return { [r.pick(['pem', 'derBase64', 'path'])]: r.pick(HOSTILE_VALUES) };
    if (isBundle && roll < 2) return [{ [r.pick(['pem', 'derBase64', 'path'])]: r.pick(HOSTILE_VALUES) }];
    return r.pick(HOSTILE_VALUES);
}

describe('hostile values on every top-level input property of every tool', () => {
    const tools = listToolsPayload().tools;

    for (const [index, tool] of tools.entries()) {
        it(`${tool.name}`, async () => {
            const def = toolDefinition(tool.name)!;
            const base: Record<string, unknown> = { ...(def.examples?.[0]?.input ?? {}) };
            const properties = (tool.inputSchema as { properties?: Record<string, Record<string, unknown>> }).properties ?? {};
            const r = rng(2000 + index);
            let refusals = 0;
            let calls = 0;
            // An unknown key, at the top level, is always VALIDATION_ERROR.
            const unknown = await attempt(tool.name, { ...base, notAnInput: 1 }, `${tool.name} unknown key`);
            expect(unknown.code).toBe('VALIDATION_ERROR');
            for (const [name, schema] of Object.entries(properties)) {
                for (let i = 0; i < 12; i++) {
                    const value = hostileFor(schema, r);
                    const outcome = await attempt(tool.name, { ...base, [name]: value }, `${tool.name}.${name} = ${JSON.stringify(value)?.slice(0, 80)}`);
                    calls++;
                    if (!outcome.ok) refusals++;
                }
            }
            if (calls > 0) expect(refusals, `${tool.name}: hostile values were all accepted`).toBeGreaterThan(0);
        }, 180_000);
    }
});
