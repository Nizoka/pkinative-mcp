/**
 * Autonomous-agent proof (scenario S0–S18): a scripted client with no human
 * in the loop drives the server end to end on every transport × era pair —
 *   T1 stdio legacy (2025-11-25 `initialize`)   T2 stdio modern (2026-07-28 envelope)
 *   T3 HTTP legacy (stateless fallback)         T4 HTTP modern + bearer token
 * — with the operator environment an operator would set (a sandbox holding
 * the 42 OpenSSL fixtures under `fixtures/`, a cache directory, a lowered
 * path-building ceiling).
 *
 * Invariants asserted over the whole run: no interactive step, no unexpected
 * `isError`, every error carries `_meta.error.code` and a remedy in its
 * message, a cache hit is visible on the wire (`_meta.cached`), a negative
 * verdict is a report and never an error, no result and no stderr line
 * carries a secret needle, stdout carries nothing but JSON-RPC frames (stdio),
 * every produced artefact parses as DER and verifies, and the session shuts
 * down cleanly.
 *
 * The stdio transports need `npm run build` (dist/cli.js); locally they are
 * skipped when dist/ is absent, under CI a missing dist/ fails.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { cpSync, existsSync, promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { PKI_DIAGNOSTIC_CODES, PKI_ERROR_CODES, PKI_REASON_CODES } from '../src/pki-errors.js';
import { toolNames } from '../src/server.js';
import {
    AGENT_TRANSPORTS,
    expectCleanStdioExit,
    hasDist,
    isModernTransport,
    isStdioTransport,
    McpRpcError,
    openAgent,
    SERVER_INFO_KEY,
    type AgentCallToolResult,
    type AgentClient,
    type AgentCloseReport,
} from './_agent-client.js';
import { assertNoSecret, assertResultClean, assertValidDer } from './_pki-assert.js';
import { AT, FIXTURES, fixtureText, PASSWORD } from './_pki-fixtures.js';

const TOKEN = 'autonomy-scenario-token-0123456789';
/** Inside the 90-day validity of the leaf S6 issues from 2027-01-01. */
const LATER = '2027-02-01T00:00:00Z';
/** The nonce the fixture OCSP request carries (tests/fixtures/PROVENANCE.md). */
const OCSP_NONCE = '1538349c433373ed058c291909df5b3e';

const fx = (name: string): { path: string } => ({ path: `fixtures/${name}` });
const ROOT = fx('root.crt.pem');
const INTER = fx('inter.crt.pem');
const LEAF = fx('leaf.crt.pem');

/**
 * The remedy every error message must name, keyed by the codes this
 * scenario provokes on purpose.
 */
const REMEDY_BY_CODE: Readonly<Record<string, RegExp>> = {
    LIMIT_CEILING_EXCEEDED: /PKINATIVE_MCP_MAX_PATHS_EXPLORED/,
    OUTPUT_EXISTS: /exist/i,
    SECURITY_VIOLATION: /sandbox|never|inspect_private_key|inspect_pkcs12|key-bearing|relative/i,
    VALIDATION_ERROR: /allowSha1|password|not both|exactly one|unknown|expected|must|invalid|unrecognized|stamp|imprint/i,
    GOVERNANCE_VIOLATION: /must be true/,
    MISSING_OUTPUT_PATH: /outputPath/,
    NOT_FOUND: /explain_code|list|code/i,
    PKI_PEM_UNEXPECTED_LABEL: /CERTIFICATE|label/,
};

const sc = (r: AgentCallToolResult): Record<string, unknown> => r.structuredContent as Record<string, unknown>;
const text0 = (r: AgentCallToolResult): string => (r.content[0] as { text?: string })?.text ?? '';
const meta = (r: AgentCallToolResult): Record<string, unknown> => (r._meta ?? {}) as Record<string, unknown>;
const errorMeta = (r: AgentCallToolResult): { code: string; message: string; data?: Record<string, unknown> } =>
    (r._meta as { error: { code: string; message: string; data?: Record<string, unknown> } }).error;
/** The embedded-resource bytes of an artefact result (blob for DER, text for PEM). */
function artefactOf(r: AgentCallToolResult): { base64: string; bytes: Uint8Array; mimeType: string } {
    const block = r.content.find((c) => c.type === 'resource') as { resource?: { blob?: string; text?: string; mimeType?: string } } | undefined;
    expect(block?.resource, 'embedded resource block').toBeDefined();
    const res = block!.resource!;
    const bytes = res.text !== undefined
        ? new Uint8Array(Buffer.from(res.text.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64'))
        : new Uint8Array(Buffer.from(res.blob ?? '', 'base64'));
    assertValidDer(bytes);
    return { base64: Buffer.from(bytes).toString('base64'), bytes, mimeType: res.mimeType ?? '' };
}
function linkOf(r: AgentCallToolResult): { uri: string; mimeType: string } {
    const link = r.content.find((c) => c.type === 'resource_link') as { uri: string; mimeType: string } | undefined;
    expect(link, 'resource_link block').toBeDefined();
    return link!;
}
function ok(r: AgentCallToolResult): AgentCallToolResult {
    expect(r.isError, text0(r)).not.toBe(true);
    assertResultClean(r);
    return r;
}
function refused(r: AgentCallToolResult, code: string): AgentCallToolResult {
    expect(r.isError, `expected ${code}: ${text0(r)}`).toBe(true);
    expect(errorMeta(r).code).toBe(code);
    expect(text0(r)).toContain(`[${code}]`);
    assertResultClean(r);
    return r;
}
/** A negative verdict is a report: valid false, reasons, never isError. */
function verdict(r: AgentCallToolResult, valid: boolean, ...codes: string[]): Record<string, unknown> {
    ok(r);
    const s = sc(r);
    expect(s['valid'], text0(r)).toBe(valid);
    const reasonCodes = (s['reasonCodes'] as string[] | undefined) ?? ((s['reasons'] as Array<{ code: string }> | undefined) ?? []).map((x) => x.code);
    for (const c of codes) expect(reasonCodes, text0(r)).toContain(c);
    if (valid) expect(reasonCodes).toEqual([]);
    return s;
}

describe.each(AGENT_TRANSPORTS)('autonomous scenario over %s', (transport) => {
    const stdio = isStdioTransport(transport);
    const modern = isModernTransport(transport);

    describe.skipIf(stdio && !hasDist)('S0–S18', () => {
        let sandbox: string;
        let cacheDir: string;
        let agent: AgentClient;
        let report: AgentCloseReport | null = null;
        // Cross-step state.
        let signedBase64: string;
        let signatureHex: string;

        beforeAll(async () => {
            sandbox = await fs.mkdtemp(path.join(os.tmpdir(), `pkinative-autonomy-${transport}-`));
            cpSync(FIXTURES, path.join(sandbox, 'fixtures'), { recursive: true });
            cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), `pkinative-autonomy-cache-${transport}-`));
            agent = await openAgent(transport, {
                env: {
                    PKINATIVE_MCP_OUTPUT_DIR: sandbox,
                    PKINATIVE_MCP_CACHE_DIR: cacheDir,
                    PKINATIVE_MCP_MAX_PATHS_EXPLORED: '50',
                },
                ...(transport === 'http-modern' ? { token: TOKEN } : {}),
            });
        }, 30_000);

        afterAll(async () => {
            if (report === null) report = await agent.close();
            await fs.rm(sandbox, { recursive: true, force: true });
            await fs.rm(cacheDir, { recursive: true, force: true });
        });

        it('S0 handshake: server identity and the decision tree arrive on the opening exchange', () => {
            const h = agent.handshake;
            expect(String(h['instructions'])).toContain('DECISION TREE');
            expect(String(h['instructions'])).toContain('No network, ever');
            if (modern) {
                expect(h['resultType']).toBe('complete');
                expect(h['supportedVersions']).toContain('2026-07-28');
                expect(((h['_meta'] as Record<string, unknown>)[SERVER_INFO_KEY] as { name: string }).name).toBe('pkinative-mcp');
            } else {
                expect(h['protocolVersion']).toBe('2025-11-25');
                expect((h['serverInfo'] as { name: string }).name).toBe('pkinative-mcp');
            }
        });

        it('S1 tools/list: the 34-tool catalogue in registration order (public 24 h cache hint on the modern era)', async () => {
            const list = await agent.request<{ tools: Array<{ name: string; inputSchema: unknown; outputSchema?: unknown; annotations?: Record<string, unknown> }>; ttlMs?: number; cacheScope?: string; resultType?: string }>('tools/list');
            expect(list.tools.map((t) => t.name)).toEqual(toolNames());
            expect(list.tools).toHaveLength(34);
            for (const t of list.tools) {
                expect(t.inputSchema, t.name).toBeDefined();
                expect(t.annotations?.['openWorldHint'], t.name).toBe(false);
            }
            if (modern) {
                expect(list.resultType).toBe('complete');
                expect(list.ttlMs).toBe(86_400_000);
                expect(list.cacheScope).toBe('public');
            } else {
                expect(list.ttlMs).toBeUndefined();
            }
        });

        it('S2 describe_engine: sandbox, cache, the lowered ceiling, no network, the three code vocabularies', async () => {
            const r = ok(await agent.callTool('describe_engine', {}));
            const d = sc(r);
            expect(d['sandbox']).toMatchObject({ enabled: true, cacheEnabled: true, pinnedInstant: null });
            expect(d['ceilings']).toMatchObject({ maxPathsExplored: 50, env: ['PKINATIVE_MCP_MAX_INPUT_BYTES', 'PKINATIVE_MCP_MAX_KDF_ITERATIONS', 'PKINATIVE_MCP_MAX_PATHS_EXPLORED'] });
            expect(d['network']).toBe('none');
            expect((d['server'] as { toolCount: number }).toolCount).toBe(34);
            const reg = d['registries'] as { errorCodes: unknown[]; reasonCodes: unknown[]; diagnosticCodes: unknown[]; wrapperCodes: unknown[] };
            expect(reg.errorCodes).toHaveLength(PKI_ERROR_CODES.length);
            expect(reg.reasonCodes).toHaveLength(PKI_REASON_CODES.length);
            expect(reg.diagnosticCodes).toHaveLength(PKI_DIAGNOSTIC_CODES.length);
            expect((d['refusals'] as unknown[]).length).toBeGreaterThan(8);
            expect(meta(r)['cached']).toBeUndefined();
        });

        it('S3 inspect_certificate: facts from the sandbox (never cached), then an inline call served from the cache on its second run', async () => {
            const fromPath = ok(await agent.callTool('inspect_certificate', { certificate: LEAF, issuer: INTER, verbosity: 'summary' }));
            expect(sc(fromPath)).toMatchObject({ subjectString: expect.stringContaining('example.test'), signatureValid: true, selfIssued: false });
            expect(meta(fromPath)['cached']).toBeUndefined();
            const inline = { certificate: { pem: fixtureText('leaf.crt.pem') }, fingerprints: ['SHA-256'], verbosity: 'summary' };
            const first = ok(await agent.callTool('inspect_certificate', inline));
            expect(meta(first)['cached']).toBeUndefined();
            const second = ok(await agent.callTool('inspect_certificate', inline));
            expect(meta(second)['cached']).toBe(true);
            expect(second.structuredContent).toEqual(first.structuredContent);
            if (modern) expect((second._meta as Record<string, unknown>)[SERVER_INFO_KEY]).toBeDefined();
        });

        it('S4 verify_certificate_chain: the trust verdict — valid for the host and purpose, revoked from offline evidence, expired at a later instant', async () => {
            const base = { leaf: LEAF, candidates: [INTER], trustAnchors: [ROOT], at: AT };
            const good = verdict(await agent.callTool('verify_certificate_chain', { ...base, serverName: { host: 'a.wild.example.test' }, purposes: ['serverAuth'], verbosity: 'summary' }), true);
            expect(good['pathLength']).toBe(3);
            expect(good['evaluatedAt']).toBe('2027-01-01T00:00:00.000Z');
            const revoked = verdict(await agent.callTool('verify_certificate_chain', { ...base, leaf: fx('revoked.crt.pem'), crls: [fx('inter.crl.pem')], ocspResponses: [fx('revoked.ocsp.der')], requireRevocation: true, verbosity: 'summary' }), false, 'PKI_REASON_REVOKED');
            expect(revoked['revocationEvidence']).toMatchObject({ crls: 1, ocspResponses: 1, required: true });
            const expired = verdict(await agent.callTool('verify_certificate_chain', { ...base, at: '2050-01-01T00:00:00Z', verbosity: 'summary' }), false);
            expect((expired['reasonCodes'] as string[]).some((c) => /EXPIRED|VALIDITY|NOT_YET/.test(c))).toBe(true);
            const wrongName = verdict(await agent.callTool('verify_certificate_chain', { ...base, serverName: { host: 'evil.test' }, verbosity: 'summary' }), false);
            expect((wrongName['reasonCodes'] as string[]).some((c) => /NAME/.test(c))).toBe(true);
        });

        it('S5 check_certificate_name / check_certificate_purpose: the single-question verdicts', async () => {
            verdict(await agent.callTool('check_certificate_name', { certificate: LEAF, host: 'a.wild.example.test' }), true);
            verdict(await agent.callTool('check_certificate_name', { certificate: LEAF, host: 'evil.test' }), false);
            verdict(await agent.callTool('check_certificate_name', { certificate: LEAF, ip: '192.0.2.1' }), true);
            verdict(await agent.callTool('check_certificate_purpose', { certificate: LEAF, purpose: 'serverAuth' }), true);
            verdict(await agent.callTool('check_certificate_purpose', { certificate: LEAF, purpose: 'codeSigning' }), false);
        });

        it('S6 issuance in file mode: a self-signed CA, a CSR, a leaf issued from it — each a resource_link, verified before it leaves, never overwritten', async () => {
            const caSpec = { serialNumber: 1, subject: { C: 'FR', O: 'Acme', CN: 'Acme Autonomy CA' }, notBefore: AT, validityDays: 3650, extensions: { basicConstraints: { ca: true, pathLen: 0 }, keyUsage: ['keyCertSign', 'cRLSign'] } };
            const ca = ok(await agent.callTool('create_certificate', { spec: caSpec, signer: { key: fx('ed25519.key.pem') }, outputMode: 'file', outputPath: 'issued/ca.crt.pem' }));
            expect(linkOf(ca).uri).toBe('pkinative://output/issued/ca.crt.pem');
            expect(linkOf(ca).mimeType).toBe('application/x-pem-file');
            expect(linkOf(ca).uri.endsWith('.pem')).toBe(true);
            expect(sc(ca)['summary']).toMatchObject({ selfSigned: true, signatureVerified: true, randomSerial: false });
            expect(existsSync(path.join(sandbox, 'issued', 'ca.crt.pem'))).toBe(true);
            expect(JSON.stringify(ca)).not.toContain(sandbox);

            const csr = ok(await agent.callTool('create_csr', { spec: { subject: { CN: 'svc.example.test' }, extensions: { subjectAltName: { dns: ['svc.example.test'] }, keyUsage: ['digitalSignature'], extendedKeyUsage: ['serverAuth'] } }, signer: { key: fx('leaf.key.pem') }, encoding: 'der', outputMode: 'file', outputPath: 'issued/svc.csr' }));
            expect(linkOf(csr).uri).toBe('pkinative://output/issued/svc.csr');
            expect(sc(csr)['summary']).toMatchObject({ signatureVerified: true });

            const leaf = ok(await agent.callTool('create_certificate', {
                spec: { serialNumber: '0x1a2b3c', subject: { CN: 'svc.example.test' }, notBefore: AT, validityDays: 90, extensions: { subjectAltName: { dns: ['svc.example.test'] }, extendedKeyUsage: ['serverAuth'], keyUsage: ['digitalSignature'] } },
                issuerCertificate: { path: 'issued/ca.crt.pem' },
                subjectPublicKey: { path: 'issued/svc.csr' },
                signer: { key: fx('ed25519.key.pem') },
                outputMode: 'file',
                outputPath: 'issued/svc.crt.pem',
            }));
            expect(linkOf(leaf).uri).toBe('pkinative://output/issued/svc.crt.pem');
            expect(sc(leaf)['summary']).toMatchObject({ selfSigned: false, signatureVerified: true, publicKeyFrom: expect.stringMatching(/csr|request|subjectPublicKey/i) });

            const chain = verdict(await agent.callTool('verify_certificate_chain', { leaf: { path: 'issued/svc.crt.pem' }, trustAnchors: [{ path: 'issued/ca.crt.pem' }], at: LATER, serverName: { host: 'svc.example.test' }, purposes: ['serverAuth'], verbosity: 'summary' }), true);
            expect(chain['pathLength']).toBe(2);

            refused(await agent.callTool('create_certificate', { spec: caSpec, signer: { key: fx('ed25519.key.pem') }, outputMode: 'file', outputPath: 'issued/ca.crt.pem' }), 'OUTPUT_EXISTS');
            refused(await agent.callTool('create_certificate', { spec: caSpec, signer: { key: fx('ed25519.key.pem') }, outputMode: 'file', outputPath: 'issued/ca.key' }), 'SECURITY_VIOLATION');
            refused(await agent.callTool('create_certificate', { spec: caSpec, signer: { key: fx('ed25519.key.pem') }, outputMode: 'file' }), 'MISSING_OUTPUT_PATH');
        });

        it('S7 CMS: sign detached, verify under the root, a tampered content is a negative verdict, the signature value is readable for a counter-stamp', async () => {
            const signed = ok(await agent.callTool('sign_cms', { content: fx('content.txt'), detached: true, certificate: LEAF, chain: [INTER], signingTime: AT, signer: { key: fx('leaf.key.pem') } }));
            const art = artefactOf(signed);
            expect(art.mimeType).toBe('application/pkcs7-signature');
            expect(sc(signed)['summary']).toMatchObject({ detached: true, signatureVerified: true, certificatesEmbedded: 2 });
            expect(meta(signed)['cached']).toBeUndefined();
            signedBase64 = art.base64;

            verdict(await agent.callTool('verify_cms', { signedData: { derBase64: signedBase64 }, content: fx('content.txt'), trustAnchors: [ROOT], requireSigningCertificate: true, requireAlgorithmProtection: true, at: AT, verbosity: 'summary' }), true);
            verdict(await agent.callTool('verify_cms', { signedData: { derBase64: signedBase64 }, content: { text: 'not the signed content' }, trustAnchors: [ROOT], at: AT, verbosity: 'summary' }), false, 'PKI_REASON_CMS_DIGEST_MISMATCH');
            verdict(await agent.callTool('verify_cms', { signedData: { derBase64: signedBase64 }, content: fx('content.txt'), trustAnchors: [fx('ed25519.crt.pem')], at: AT, verbosity: 'summary' }), false, 'PKI_REASON_NO_TRUST_ANCHOR');

            const facts = ok(await agent.callTool('inspect_cms', { signedData: { derBase64: signedBase64 }, signerCertificate: LEAF, content: fx('content.txt'), fields: ['signerInfos.signature', 'signerSignature'] }));
            const infos = sc(facts)['signerInfos'] as Array<{ signature: string }>;
            signatureHex = infos[0]!.signature;
            expect(signatureHex).toMatch(/^[0-9a-f]{64,}$/);
            expect(meta(facts)['unmatchedFields']).toBeUndefined();
        });

        it('S8 RFC 3161: a request over the signature value (random nonce never cached), the fixture response verified against its request, the wrong data refused', async () => {
            const req = ok(await agent.callTool('create_timestamp_request', { digestHex: await sha256Hex(Buffer.from(signatureHex, 'hex')), nonce: 'random' }));
            expect(artefactOf(req).mimeType).toBe('application/timestamp-query');
            expect(sc(req)['summary']).toMatchObject({ hashAlgorithm: 'SHA-256', randomNonce: true });
            expect(meta(req)['cached']).toBeUndefined();
            const again = ok(await agent.callTool('create_timestamp_request', { digestHex: await sha256Hex(Buffer.from(signatureHex, 'hex')), nonce: 'random' }));
            expect(meta(again)['cached']).toBeUndefined();
            expect(artefactOf(again).base64).not.toBe(artefactOf(req).base64);

            const fixed = ok(await agent.callTool('create_timestamp_request', { data: fx('content.txt'), nonce: '42' }));
            expect(sc(fixed)['summary']).toMatchObject({ hashAlgorithm: 'SHA-256', randomNonce: false });

            const good = verdict(await agent.callTool('verify_timestamp', { response: fx('content.tsr'), request: fx('content.tsq'), data: fx('content.txt'), trustAnchors: [ROOT], candidates: [INTER], at: AT, verbosity: 'summary' }), true);
            expect(good['valid']).toBe(true);
            verdict(await agent.callTool('verify_timestamp', { response: fx('content.tsr'), data: { text: 'other data' }, trustAnchors: [ROOT], candidates: [INTER], at: AT, verbosity: 'summary' }), false, 'PKI_REASON_TSP_IMPRINT_MISMATCH');

            const stamped = ok(await agent.callTool('inspect_timestamp', { input: fx('content.tsr'), verbosity: 'summary' }));
            expect(sc(stamped)['as']).toBe('response');
            const amended = refused(await agent.callTool('amend_cms', { signedData: { derBase64: signedBase64 }, operation: 'add-timestamp', token: fx('content.tsr') }), 'VALIDATION_ERROR');
            expect(errorMeta(amended).data?.['detail']).toBe('PKI_REASON_TSP_IMPRINT_MISMATCH');
        });

        it('S9 offline revocation: CRL and OCSP verdicts at the pinned instant, the revoked leaf reported, never thrown', async () => {
            verdict(await agent.callTool('check_crl_revocation', { certificate: LEAF, crl: fx('inter.crl.pem'), issuer: INTER, at: AT, verbosity: 'summary' }), true);
            const revoked = verdict(await agent.callTool('check_crl_revocation', { certificate: fx('revoked.crt.pem'), crl: fx('inter.crl.der'), issuer: INTER, at: AT, verbosity: 'summary' }), false, 'PKI_REASON_REVOKED');
            expect(revoked['signatureVerified']).toBe(true);
            const good = verdict(await agent.callTool('check_ocsp_status', { response: fx('leaf.ocsp.der'), certificate: LEAF, issuer: INTER, nonce: OCSP_NONCE, requireNonce: true, at: AT, verbosity: 'summary' }), true);
            expect(good['status']).toBe('good');
            const bad = verdict(await agent.callTool('check_ocsp_status', { response: fx('revoked.ocsp.der'), certificate: fx('revoked.crt.pem'), issuer: INTER, responder: fx('ocsp.crt.pem'), at: AT, verbosity: 'summary' }), false, 'PKI_REASON_REVOKED');
            expect(bad['status']).toBe('revoked');
            const ocspReq = ok(await agent.callTool('create_ocsp_request', { certificate: LEAF, issuer: INTER, hashAlgorithm: 'SHA-256', nonce: '0a0b0c0d' }));
            expect(artefactOf(ocspReq).mimeType).toBe('application/ocsp-request');
            const facts = ok(await agent.callTool('inspect_ocsp_response', { response: fx('leaf.ocsp.der'), verbosity: 'summary' }));
            expect(sc(facts)['responseStatus'] ?? sc(facts)['status']).toBeDefined();
        });

        it('S10 keys: describe without a password, open with it, import an encrypted key — not one key byte in any result', async () => {
            const described = ok(await agent.callTool('inspect_pkcs12', { pkcs12: fx('leaf.p12'), verbosity: 'summary' }));
            expect(sc(described)['macKind']).not.toBeNull();
            const opened = verdict(await agent.callTool('open_pkcs12', { pkcs12: fx('leaf.p12'), password: PASSWORD, verbosity: 'summary' }), true);
            expect(opened).toMatchObject({ integrity: 'verified', keyCount: 1 });
            const full = ok(await agent.callTool('open_pkcs12', { pkcs12: fx('leaf.p12'), password: PASSWORD, exportCertificates: true }));
            const bundle = artefactOf(full);
            expect(bundle.mimeType).toMatch(/pem|pkix-cert/);
            const key = ok(await agent.callTool('inspect_private_key', { key: fx('leaf.key.enc.pem'), tryImport: true, password: PASSWORD, keyType: 'ec-p256', fields: ['imported', 'encryption.scheme'] }));
            expect(sc(key)['imported']).toBeDefined();
            const plain = ok(await agent.callTool('inspect_private_key', { key: fx('leaf.key.pem'), verbosity: 'summary' }));
            expect(sc(plain)).toMatchObject({ kind: 'ec', encrypted: false });
            const wrongResult = await agent.callTool('open_pkcs12', { pkcs12: fx('leaf.p12'), password: 'not-the-password', verbosity: 'summary' });
            const wrong = verdict(wrongResult, false, 'PKI_REASON_PKCS12_MAC_MISMATCH');
            expect(wrong['integrity']).toBe('mismatch');
            expect(JSON.stringify(wrongResult)).not.toContain('not-the-password');
            for (const r of [described, opened, full, key, plain]) expect(meta(r as never)['cached'] ?? undefined).toBeUndefined();
        });

        it('S11 resources: the sandbox is listed (never a key-bearing file), read as text or blob, and a key is never served', async () => {
            const list = await agent.request<{ resources: Array<{ uri: string; mimeType: string }>; cacheScope?: string; ttlMs?: number }>('resources/list');
            const uris = list.resources.map((r) => r.uri);
            expect(uris).toContain('pkinative://output/issued/ca.crt.pem');
            expect(uris).toContain('pkinative://output/issued/svc.crt.pem');
            expect(uris).toContain('pkinative://output/fixtures/leaf.crt.pem');
            for (const u of uris) expect(u, 'a key-bearing file is listed').not.toMatch(/\.(key|p8|p12|pfx)$/);
            if (modern) {
                expect(list.cacheScope).toBe('private');
                expect(list.ttlMs).toBe(0);
            }
            const templates = await agent.request<{ resourceTemplates: Array<{ uriTemplate: string }> }>('resources/templates/list');
            expect(templates.resourceTemplates[0]?.uriTemplate).toContain('pkinative://output/');
            const pem = await agent.request<{ contents: Array<{ uri: string; mimeType: string; text?: string; blob?: string }> }>('resources/read', { uri: 'pkinative://output/issued/ca.crt.pem' });
            expect(pem.contents[0]?.text).toContain('-----BEGIN CERTIFICATE-----');
            const der = await agent.request<{ contents: Array<{ uri: string; mimeType: string; text?: string; blob?: string }> }>('resources/read', { uri: 'pkinative://output/issued/svc.csr' });
            expect(der.contents[0]?.blob).toBeDefined();
            assertValidDer(new Uint8Array(Buffer.from(der.contents[0]!.blob!, 'base64')));
            await expect(agent.request('resources/read', { uri: 'pkinative://output/fixtures/leaf.key.pem' })).rejects.toThrow(McpRpcError);
            await expect(agent.request('resources/read', { uri: 'pkinative://output/fixtures/leaf.p12' })).rejects.toThrow(/SECURITY_VIOLATION|never served/);
            await expect(agent.request('resources/read', { uri: 'pkinative://output/missing.crt' })).rejects.toMatchObject({ code: -32602 });
        });

        it('S12 hostile inputs: legacy PKCS#12 is a verdict, SHA-1 / a stray password / traversal / an absolute path / a key where a certificate is expected are refusals — none echoes a key', async () => {
            const legacy = verdict(await agent.callTool('open_pkcs12', { pkcs12: fx('legacy.p12'), password: PASSWORD, verbosity: 'summary' }), false, 'PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED');
            expect(legacy['valid']).toBe(false);
            refused(await agent.callTool('sign_cms', { content: { text: 'x' }, certificate: LEAF, signer: { key: fx('leaf.key.pem'), hash: 'SHA-1' } }), 'VALIDATION_ERROR');
            refused(await agent.callTool('inspect_certificate', { certificate: LEAF, password: PASSWORD }), 'VALIDATION_ERROR');
            refused(await agent.callTool('inspect_certificate', { certificate: { path: '../outside.pem' } }), 'SECURITY_VIOLATION');
            refused(await agent.callTool('inspect_certificate', { certificate: { path: path.join(sandbox, 'fixtures', 'leaf.crt.pem') } }), 'SECURITY_VIOLATION');
            refused(await agent.callTool('inspect_certificate', { certificate: fx('leaf.key.pem') }), 'PKI_PEM_UNEXPECTED_LABEL');
            refused(await agent.callTool('convert_pem', { mode: 'decode', input: fx('leaf.key.pem'), extractIndex: 0 }), 'SECURITY_VIOLATION');
            refused(await agent.callTool('decode_asn1', { input: fx('leaf.key.der') }), 'SECURITY_VIOLATION');
            const truncated = await agent.callTool('inspect_certificate', { certificate: { derBase64: Buffer.from(fixtureText('leaf.crt.pem').replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64').subarray(0, 40).toString('base64') } });
            expect(truncated.isError).toBe(true);
            expect(errorMeta(truncated).code).toMatch(/^PKI_/);
            refused(await agent.callTool('inspect_certificate', { certificate: fx('leaf.crt.pem'), bogus: true }), 'VALIDATION_ERROR');
        });

        it('S13 operator ceilings: a per-call limit above the ceiling is refused and names the environment variable', async () => {
            const r = refused(await agent.callTool('verify_certificate_chain', { leaf: LEAF, candidates: [INTER], trustAnchors: [ROOT], at: AT, limits: { maxPathsExplored: 51 } }), 'LIMIT_CEILING_EXCEEDED');
            expect(errorMeta(r).message).toContain('PKINATIVE_MCP_MAX_PATHS_EXPLORED');
            ok(await agent.callTool('verify_certificate_chain', { leaf: LEAF, candidates: [INTER], trustAnchors: [ROOT], at: AT, limits: { maxPathsExplored: 50 }, verbosity: 'summary' }));
        });

        it('S14 protocol errors: unknown tool / resource / prompt are JSON-RPC -32602, never isError', async () => {
            await expect(agent.request('tools/call', { name: 'no_such_tool', arguments: {} })).rejects.toMatchObject({ code: -32602, message: expect.stringContaining('[UNKNOWN_TOOL]') });
            await expect(agent.request('prompts/get', { name: 'no_such_prompt' })).rejects.toMatchObject({ code: -32602 });
            await expect(agent.request('resources/read', { uri: 'pkinative://output/nothing/here.crt' })).rejects.toMatchObject({ code: -32602 });
        });

        it('S15 draft_governance_issue: a file-mode draft is written (never submitted); a skipped duplicate search is a GOVERNANCE_VIOLATION', async () => {
            const draft = {
                title: 'parseCertificateList refuses a delta CRL with an empty revokedCertificates list',
                summary: 'A delta CRL whose revokedCertificates SEQUENCE is absent is refused although RFC 5280 makes the field OPTIONAL.',
                issueType: 'bug',
                targetRepo: 'pkinative',
                reproduction: { command: 'inspect_crl { crl: { path: "fixtures/empty-delta.crl" } }', result: 'PKI_X509_STRUCTURE_INVALID at revokedCertificates' },
                expectedBehavior: 'The delta CRL parses with entryCount 0.',
                affectedPackages: ['pkinative', 'pkinative-mcp'],
                duplicateSearchPerformed: true,
            };
            const r = ok(await agent.callTool('draft_governance_issue', { ...draft, outputMode: 'file', outputPath: 'drafts/delta-crl.md' }));
            expect(text0(r)).toContain('DRAFT ONLY');
            expect(existsSync(path.join(sandbox, 'drafts', 'delta-crl.md'))).toBe(true);
            expect(meta(r)['cached']).toBeUndefined();
            refused(await agent.callTool('draft_governance_issue', { ...draft, duplicateSearchPerformed: false }), 'GOVERNANCE_VIOLATION');
        });

        it('S16 prompts: the seven recipes are listed and verify_before_trust names verify_certificate_chain', async () => {
            const list = await agent.request<{ prompts: Array<{ name: string }>; ttlMs?: number }>('prompts/list');
            expect(list.prompts.map((p) => p.name).sort()).toEqual(['draft_issue_workflow', 'governance_contract', 'issue_certificate', 'offline_revocation', 'open_keys_safely', 'sign_and_timestamp', 'verify_before_trust']);
            if (modern) expect(list.ttlMs).toBe(86_400_000);
            const got = await agent.request<{ messages: Array<{ content: { text: string } }> }>('prompts/get', { name: 'verify_before_trust' });
            expect(got.messages[0]?.content.text).toContain('verify_certificate_chain');
        });

        it('S17 explain_code: a reason explained, a vocabulary listed', async () => {
            const one = ok(await agent.callTool('explain_code', { code: 'PKI_REASON_REVOKED' }));
            expect(sc(one)).toMatchObject({ code: 'PKI_REASON_REVOKED', kind: 'reason' });
            const all = ok(await agent.callTool('explain_code', { list: true, kind: 'diagnostic', fields: ['count'] }));
            expect(sc(all)['count']).toBe(PKI_DIAGNOSTIC_CODES.length);
            refused(await agent.callTool('explain_code', { code: 'NOT_A_CODE_AT_ALL' }), 'NOT_FOUND');
        });

        it('S18 shutdown: every error carried a code and a remedy, no secret left the server, stdout stayed JSON-only, the session closed cleanly', async () => {
            expect(agent.errors.length).toBeGreaterThan(10);
            for (const { tool, result } of agent.errors) {
                const m = errorMeta(result);
                expect(m.code, `${tool}: an error without a code`).toMatch(/^[A-Z][A-Z0-9_]+$/);
                expect(text0(result)).toBe(`${tool} failed [${m.code}]: ${m.message}`);
                const remedy = REMEDY_BY_CODE[m.code];
                if (remedy !== undefined) expect(m.message, `${m.code} message must name the remedy`).toMatch(remedy);
                else expect(m.code, `${m.code} is not a code this scenario provokes`).toMatch(/^PKI_/);
                assertResultClean(result);
            }
            report = await agent.close();
            assertNoSecret(report.stderr, 'stderr');
            if (stdio) {
                for (const line of report.stdoutLines) {
                    const frame = JSON.parse(line) as { jsonrpc?: string };
                    expect(frame.jsonrpc, 'a non JSON-RPC line on stdout').toBe('2.0');
                }
                expectCleanStdioExit(report);
            }
        });
    });
});

async function sha256Hex(bytes: Uint8Array): Promise<string> {
    const { createHash } = await import('node:crypto');
    return createHash('sha256').update(bytes).digest('hex');
}
