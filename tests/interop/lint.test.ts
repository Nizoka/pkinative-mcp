// Linting what create_certificate writes: zlint v3 and DigiCert pkilint judge
// the corpus certificates — CA and leaf, in every signature family the server
// signs with — because the mapping from a JSON spec to extensions
// (src/x509-spec.ts) is wrapper code the engine's own linting never sees. An
// ERROR or FATAL fails; a WARNING or NOTICE must be reviewed in
// scripts/data/lint-waivers.json, and a waiver that matches nothing is stale.
// Skipped when a linter is absent, unless REQUIRE_LINT=1 (the gate's publish
// profile sets it).
//   ZLINT=<path to zlint>        default: zlint on PATH
//   PKILINT_PYTHON=<python>      default: python3, python, py — the one that imports pkilint
// Ported from pkinative-cli's tests/interop/lint.test.ts, over callToolDirect.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { callToolDirect, toolNames } from '../../src/server.js';
import { fixtureInput } from '../_pki-fixtures.js';

const ROOT = resolve(import.meta.dirname, '..', '..');
const required = process.env['REQUIRE_LINT'] === '1';

const run = (cmd: string, args: string[]) => spawnSync(cmd, args, { encoding: 'utf8', windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
const ZLINT = process.env['ZLINT'] ?? 'zlint';
const zlintFound = run(ZLINT, ['-list-lints-source']).status === 0;
const PYTHON = [process.env['PKILINT_PYTHON'], 'python3', 'python', 'py'].find((p) => p !== undefined && run(p, ['-c', 'import pkilint.bin.lint_pkix_cert']).status === 0);
const canCreate = toolNames().includes('create_certificate');

interface Finding { readonly lint: string; readonly severity: string }
interface Waiver { readonly tool: string; readonly lint: string; readonly artefacts: readonly string[]; readonly reason: string }

const WAIVERS = (JSON.parse(readFileSync(join(ROOT, 'scripts', 'data', 'lint-waivers.json'), 'utf8')) as { waivers: Waiver[] }).waivers;
const AT = { notBefore: '2026-01-01T00:00:00Z', validityDays: 365 };

interface Artefact { readonly id: string; readonly der: string; readonly pem: string; readonly issuer?: string }

/** The certificates linted: a CA per signature family, and leaves under two of them. */
async function artefacts(dir: string): Promise<Artefact[]> {
    const ca = (cn: string) => ({ subject: { C: 'FR', O: 'pkinative-mcp lint', CN: cn }, ...AT, extensions: { basicConstraints: { ca: true, critical: true }, keyUsage: { usages: ['keyCertSign', 'cRLSign'], critical: true } } });
    const leaf = (cn: string, usages: string[]) => ({ subject: { C: 'FR', O: 'pkinative-mcp lint', CN: cn }, ...AT, extensions: { basicConstraints: { ca: false, critical: true }, keyUsage: { usages, critical: true }, extendedKeyUsage: ['serverAuth'], subjectAltName: { dns: [cn] } } });
    const plan: Array<{ id: string; spec: object; signer: Record<string, unknown>; subjectPublicKey?: Record<string, unknown>; issuer?: string }> = [
        { id: 'ec-ca', spec: ca('Lint EC CA'), signer: { key: fixtureInput('leaf.key.pem') } },
        { id: 'rsa-pkcs1-ca', spec: ca('Lint RSA PKCS1 CA'), signer: { key: fixtureInput('rsa.key.pem'), rsaScheme: 'pkcs1' } },
        { id: 'rsa-pss-ca', spec: ca('Lint RSA PSS CA'), signer: { key: fixtureInput('rsa.key.pem'), rsaScheme: 'pss' } },
        { id: 'ed25519-ca', spec: ca('Lint Ed25519 CA'), signer: { key: fixtureInput('ed25519.key.pem') } },
        { id: 'ec-leaf', spec: leaf('ec-leaf.example.test', ['digitalSignature', 'keyEncipherment']), signer: { key: fixtureInput('leaf.key.pem') }, subjectPublicKey: fixtureInput('rsa.crt.pem'), issuer: 'ec-ca' },
        { id: 'ed25519-leaf', spec: leaf('ed-leaf.example.test', ['digitalSignature']), signer: { key: fixtureInput('ed25519.key.pem') }, subjectPublicKey: fixtureInput('leaf.pub.pem'), issuer: 'ed25519-ca' },
    ];
    const out: Artefact[] = [];
    const issued = new Map<string, string>();
    for (const p of plan) {
        const r = await callToolDirect('create_certificate', {
            spec: p.spec, signer: p.signer, encoding: 'der',
            ...(p.subjectPublicKey !== undefined ? { subjectPublicKey: p.subjectPublicKey } : {}),
            ...(p.issuer !== undefined ? { issuerCertificate: { derBase64: issued.get(p.issuer) } } : {}),
        });
        expect(r.isError, `${p.id}: ${(r.content[0] as { text?: string }).text ?? ''}`).not.toBe(true);
        const blob = (r.content.find((c) => c.type === 'resource') as { resource?: { blob?: string } } | undefined)?.resource?.blob ?? '';
        issued.set(p.id, blob);
        const der = join(dir, `${p.id}.der`);
        const pem = join(dir, `${p.id}.pem`);
        writeFileSync(der, Buffer.from(blob, 'base64'));
        writeFileSync(pem, `-----BEGIN CERTIFICATE-----\n${blob.replace(/(.{64})/g, '$1\n').trim()}\n-----END CERTIFICATE-----\n`);
        out.push({ id: p.id, der, pem, ...(p.issuer !== undefined ? { issuer: p.issuer } : {}) });
    }
    return out;
}

/** The unwaived findings, the errors, and the waivers of `tool` nothing matched. */
function judge(tool: string, results: Array<{ id: string; findings: readonly Finding[] }>): string[] {
    const problems: string[] = [];
    const used = new Set<Waiver>();
    for (const r of results) {
        for (const f of r.findings) {
            const severity = f.severity.toLowerCase();
            if (severity === 'error' || severity === 'fatal') {
                problems.push(`${tool}: ${f.lint} (${f.severity}) on ${r.id}`);
                continue;
            }
            if (severity === 'info') continue;
            const waiver = WAIVERS.find((w) => w.tool === tool && w.lint === f.lint && w.artefacts.some((a) => a === '*' || a === r.id));
            if (waiver === undefined) problems.push(`${tool}: ${f.lint} (${f.severity}) on ${r.id} is not reviewed in scripts/data/lint-waivers.json`);
            else used.add(waiver);
        }
    }
    for (const w of WAIVERS.filter((x) => x.tool === tool && !used.has(x))) problems.push(`${tool}: the waiver of ${w.lint} matched nothing — it is stale`);
    return problems;
}

describe('lint of the certificates create_certificate writes', () => {
    let dir = '';
    beforeAll(() => { dir = mkdtempSync(join(tmpdir(), 'pkinative-mcp-lint-')); });
    afterAll(() => { if (dir) rmSync(dir, { recursive: true, force: true }); });

    it('finds the linters when REQUIRE_LINT=1', () => {
        if (required) expect({ zlint: zlintFound, pkilint: PYTHON !== undefined }).toEqual({ zlint: true, pkilint: true });
    });

    it.skipIf(!zlintFound || !canCreate)('passes zlint (RFC 5280, RFC 5480, RFC 3279, RFC 8813 and community lints)', async () => {
        const set = await artefacts(dir);
        const r = run(ZLINT, ['-includeSources', 'RFC5280,RFC5480,RFC5891,RFC3279,RFC8813,Community', '-format', 'der', ...set.map((a) => a.der)]);
        const lines = r.stdout.split('\n').filter((l) => l.startsWith('{'));
        expect(lines, r.stderr).toHaveLength(set.length);
        const results = set.map((a, i) => ({
            id: a.id,
            findings: Object.entries(JSON.parse(lines[i] as string) as Record<string, { result: string }>)
                .filter(([, v]) => !['pass', 'NA', 'NE'].includes(v.result))
                .map(([lint, v]) => ({ lint, severity: v.result === 'warn' ? 'warning' : v.result })),
        }));
        expect(judge('zlint', results)).toEqual([]);
    }, 120_000);

    it.skipIf(PYTHON === undefined || !canCreate)('passes pkilint (RFC 5280 certificate and signer-signee profiles)', async () => {
        const set = await artefacts(dir);
        const manifest = join(dir, 'manifest.json');
        writeFileSync(manifest, JSON.stringify({ artefacts: set.map((a) => ({ id: a.id, pem: a.pem, ...(a.issuer !== undefined ? { issuer: a.issuer } : {}) })) }));
        const r = spawnSync(PYTHON as string, [join(ROOT, 'scripts', 'validators', 'pkilint-driver.py'), manifest], { encoding: 'utf8', windowsHide: true, env: { ...process.env, PYTHONIOENCODING: 'utf-8' } });
        expect(r.status, r.stderr).toBe(0);
        const results = r.stdout.split('\n').filter((l) => l.startsWith('{')).map((l) => JSON.parse(l) as { id?: string; findings?: Finding[] }).filter((x) => x.id !== undefined);
        expect(results.length).toBe(set.length + set.filter((a) => a.issuer !== undefined).length);
        expect(judge('pkilint', results.map((x) => ({ id: x.id as string, findings: x.findings ?? [] })))).toEqual([]);
    }, 120_000);
});
