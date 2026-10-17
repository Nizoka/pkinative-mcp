/**
 * A2-005 — Sample regression gate, ported from pdfnative-mcp 1.7.0
 * (tests/samples-regression.test.ts) onto this repository's three-mode
 * fingerprint (scripts/lib/sample-fingerprint.ts).
 *
 * The sample set lives in the git-ignored `test-output/samples/`, which only
 * `npm run test:generate` populates (it drives the BUILT server, so
 * `npm run build` comes first) together with `manifest.json`, the mode the
 * generator chose for every file. This suite SKIPS the corpus half when the
 * set is absent in a plain local run; under the gate's ci / publish
 * profiles, which run build → test:generate before test:coverage and set
 * GATE_REQUIRE_ARTIFACTS=1, a missing set FAILS this file instead. The
 * committed baseline (tests/_fixtures/samples.sha256.json) is held in every
 * run: its chain, its provenance, and the justification of every `tbs` row
 * — read back from the example that produced it, never from a flag.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

import { describe, expect, it } from 'vitest';

import { loadExamples, type Example } from '../scripts/lib/example-runner.js';
import {
    BASELINE_AT, BASELINE_PATH, HOST_MEMBERS, IDENTICAL_SAMPLE_GROUPS, MANIFEST_PATH, OUTPUT_DIR, REPO_ROOT, VOLATILE_MEMBERS,
    argsAskRandom, canonicalJson, chainSince, compareToBaseline, currentVersion, derOf, fingerprint, fingerprintAll, firstElementOfSequence,
    hasRandomFlag, loadBaseline, loadManifest, looksSigned, modeFor, relPath, semanticProjection, sha256Hex, signerIsRandomised, stripHost, stripVolatile,
    unexpectedDuplicates, walkSamples,
    type Baseline, type Fingerprint, type FingerprintMode,
} from '../scripts/lib/sample-fingerprint.js';
import { listToolsPayload } from '../src/server.js';
import { AT, fixtureBytes, fixtureText } from './_pki-fixtures.js';

/** The release that introduced the chain: there is no earlier pkinative-mcp to chain from. */
const CHAIN_ORIGIN = '1.0.0';
const MODES: readonly FingerprintMode[] = ['bytes', 'tbs', 'semantic'];
/** What verify-samples writes when no manifest exists yet — a baseline that still carries it was never accounted for. */
const TEMPLATE_PROVENANCE = /^Initial baseline: every entry is anchored/;

const samples = [...walkSamples(OUTPUT_DIR)];
const haveCorpus = samples.length > 0 && existsSync(MANIFEST_PATH);
if (!haveCorpus && process.env['GATE_REQUIRE_ARTIFACTS'] === '1') {
    throw new Error('test-output/samples/ is empty but GATE_REQUIRE_ARTIFACTS=1: the gate generates the samples before test:coverage — run `npm run build && npm run test:generate`');
}

const rank = (v: string): number => {
    const [a = 0, b = 0, c = 0] = v.split('.').map(Number);
    return a * 1e6 + b * 1e3 + c;
};

/** `create-certificate-issue-leaf.step1.crt` → the example and the step (0-based) that wrote it; `x.json` → the sidecar. */
function locate(rel: string): { readonly example: string; readonly step: number; readonly sidecar: boolean } {
    const m = /^([A-Za-z0-9_-]+)(?:\.step(\d+))?\.([a-z0-9]+)$/.exec(rel);
    expect(m, `${rel} is not <example>[.stepN].<ext>`).not.toBeNull();
    const [, example, step, ext] = m as RegExpExecArray;
    return { example: example as string, step: step === undefined ? 0 : Number(step) - 1, sidecar: ext === 'json' };
}

const examples = new Map<string, Example>(loadExamples().map((e) => [e.name, e]));
const annotationsOf = new Map(listToolsPayload().tools.map((t) => [t.name, t.annotations as { readOnlyHint?: boolean; idempotentHint?: boolean } | undefined]));

/** The example step behind a sample path, or a failure naming the sample. */
function stepOf(rel: string): { readonly tool: string; readonly args: Readonly<Record<string, unknown>> } {
    const at = locate(rel);
    const example = examples.get(at.example);
    expect(example, `${rel}: no examples/${at.example}.json`).toBeDefined();
    const step = example!.steps[at.step];
    expect(step, `${rel}: examples/${at.example}.json has no step ${at.step + 1}`).toBeDefined();
    return { tool: step!.tool, args: step!.arguments };
}

// ── The generated set against the baseline ───────────────────────────

describe.skipIf(!haveCorpus)('sample regression: the generated set against the baseline', () => {
    it('A2-005: every tracked sample still emits what its reference release emitted', () => {
        const baseline = loadBaseline();
        expect(baseline, `missing baseline at ${BASELINE_PATH}`).not.toBeNull();

        const { entries, unreadable, unlisted, missing } = fingerprintAll();
        expect(unreadable, 'samples that could not be fingerprinted').toEqual([]);
        expect(unlisted, 'files on disk the manifest does not list').toEqual([]);
        expect(missing, 'manifest entries with no file on disk').toEqual([]);

        const { changed, removed } = compareToBaseline(entries, baseline!);
        expect(changed, 'samples whose output changed').toEqual([]);
        expect(removed, 'baseline entries with no generated sample').toEqual([]);
        // `added` is deliberately not asserted: a sample introduced by the release under development
        // has no earlier reference to be held to. `verify-samples --strict` is the opt-in gate for that.
    });

    it('A2-005: the manifest is the generator\'s: one of the three modes per file, the example and tool named, a sidecar for every semantic artefact', () => {
        const manifest = loadManifest()!;
        expect(manifest.generatedBy).toBe('scripts/generate-samples.ts');
        expect(manifest.at).toBe(BASELINE_AT);
        const rels = Object.keys(manifest.entries);
        expect(rels.length).toBe(samples.length);
        for (const rel of rels) {
            const entry = manifest.entries[rel]!;
            expect(MODES, `${rel}: mode ${entry.mode}`).toContain(entry.mode);
            expect(entry.tool.length, `${rel}: tool`).toBeGreaterThan(0);
            expect(examples.has(entry.example), `${rel}: example ${entry.example}`).toBe(true);
            const at = locate(rel);
            expect(at.example).toBe(entry.example);
            if (at.sidecar) {
                expect(entry.mode, `${rel}: a JSON result is always semantic`).toBe('semantic');
                expect(entry.sidecar).toBeUndefined();
            } else if (entry.mode === 'semantic') {
                expect(entry.sidecar, `${rel}: a semantic artefact stands for its sidecar`).toBe(`${entry.example}.json`);
                expect(existsSync(join(OUTPUT_DIR, entry.sidecar!)), `${rel}: sidecar on disk`).toBe(true);
            } else {
                expect(entry.sidecar).toBeUndefined();
            }
        }
    });

    it('A2-005: the recorded mode is what modeFor re-derives from the example, the tool annotations and the bytes', () => {
        const manifest = loadManifest()!;
        for (const [rel, entry] of Object.entries(manifest.entries)) {
            if (locate(rel).sidecar) continue;
            const { tool, args } = stepOf(rel);
            expect(tool, rel).toBe(entry.tool);
            const artefact = new Uint8Array(readFileSync(join(OUTPUT_DIR, rel)));
            expect(modeFor({ annotations: annotationsOf.get(tool), args, artefact }), rel).toBe(entry.mode);
        }
    });

    it('never holds two samples meant to differ to the same bytes', () => {
        const baseline = loadBaseline()!;
        expect(unexpectedDuplicates(baseline.entries)).toEqual([]);
        expect(unexpectedDuplicates(fingerprintAll().entries)).toEqual([]);
        for (const group of IDENTICAL_SAMPLE_GROUPS) {
            for (const path of group) expect(baseline.entries[path], `${path} listed as identical but absent`).toBeDefined();
        }
    });

    it('a tbs sample holds the signed part only: the signature may change, what was signed may not', () => {
        const manifest = loadManifest()!;
        const tbsRows = Object.entries(manifest.entries).filter(([, e]) => e.mode === 'tbs');
        expect(tbsRows.length).toBeGreaterThan(0);
        for (const [rel, entry] of tbsRows) {
            const bytes = readFileSync(join(OUTPUT_DIR, rel));
            const der = derOf(bytes);
            expect(looksSigned(der), `${rel} is not SEQUENCE { tbs, alg, BIT STRING }`).toBe(true);
            const tbs = firstElementOfSequence(der);
            expect(tbs[0]).toBe(0x30);
            expect(tbs.length).toBeLessThan(der.length);
            expect(fingerprint(join(OUTPUT_DIR, rel), entry).hash).toBe(sha256Hex(tbs));
            // Flip the last byte (inside the signature BIT STRING): the bytes hash moves, the tbs hash does not.
            const tampered = new Uint8Array(der);
            tampered[tampered.length - 1] = (tampered[tampered.length - 1]! ^ 0xff) & 0xff;
            expect(sha256Hex(tampered)).not.toBe(sha256Hex(der));
            expect(sha256Hex(firstElementOfSequence(tampered))).toBe(sha256Hex(tbs));
        }
    });

    it('a semantic artefact stands for its sidecar\'s projection, prefixed so the pair never shares a hash', () => {
        const manifest = loadManifest()!;
        const row = Object.entries(manifest.entries).find(([, e]) => e.mode === 'semantic' && e.sidecar !== undefined);
        expect(row, 'a semantic artefact with a sidecar').toBeDefined();
        const [rel, entry] = row!;
        const sidecarText = readFileSync(join(OUTPUT_DIR, entry.sidecar!), 'utf8');
        const artefact = fingerprint(join(OUTPUT_DIR, rel), entry);
        expect(artefact.hash).toBe(sha256Hex(`artefact\n${semanticProjection(sidecarText)}`));
        expect(artefact.hash).not.toBe(fingerprint(join(OUTPUT_DIR, entry.sidecar!), { mode: 'semantic' }).hash);
        expect(artefact.size).toBe(readFileSync(join(OUTPUT_DIR, rel)).length);
    });

    it('covers every executable example with a sidecar, and carries artefacts of more than one kind', () => {
        const rels = samples.map(relPath);
        const sidecars = new Set(rels.filter((r) => r.endsWith('.json')).map((r) => locate(r).example));
        const executable = [...examples.values()].filter((e) => !e.documentationOnly).map((e) => e.name);
        expect([...sidecars].sort()).toEqual(executable.sort());
        const extensions = new Set(rels.map((r) => r.slice(r.lastIndexOf('.'))));
        for (const ext of ['.json', '.pem', '.crt', '.csr', '.tsq']) expect(extensions, ext).toContain(ext);
        expect(rels.length).toBeGreaterThanOrEqual(90);
    });
});

// ── The committed baseline ───────────────────────────────────────────

describe('committed baseline', () => {
    const baseline = loadBaseline();

    it('A2-005: ships, pinned to UTC and to the sample instant, with a provenance that is not the template placeholder', () => {
        expect(existsSync(BASELINE_PATH)).toBe(true);
        expect(baseline).not.toBeNull();
        expect(baseline!.timezone).toBe('UTC');
        expect(baseline!.at).toBe(BASELINE_AT);
        expect(BASELINE_AT).toBe(AT);
        expect(Number.isNaN(Date.parse(baseline!.at))).toBe(false);
        expect(baseline!.provenance.length).toBeGreaterThan(80);
        expect(baseline!.provenance).not.toMatch(TEMPLATE_PROVENANCE);
        for (const mode of MODES) expect(baseline!.$comment, `$comment explains mode ${mode}`).toContain(`\`${mode}\``);
    });

    it('anchors every entry to a release between the chain origin and the baseline itself, in one of the three modes', () => {
        const ceiling = rank(baseline!.baselineVersion);
        expect(baseline!.baselineVersion).toMatch(/^\d+\.\d+\.\d+$/);
        expect(ceiling).toBeLessThanOrEqual(rank(currentVersion()));
        const entries = Object.entries(baseline!.entries);
        expect(entries.length).toBeGreaterThanOrEqual(90);
        for (const [path, entry] of entries) {
            expect(entry.since, `${path} has no \`since\``).toMatch(/^\d+\.\d+\.\d+$/);
            expect(rank(entry.since), `${path} claims a reference from the future`).toBeLessThanOrEqual(ceiling);
            expect(rank(entry.since), `${path} predates the chain`).toBeGreaterThanOrEqual(rank(CHAIN_ORIGIN));
            expect(MODES, `${path}: mode`).toContain(entry.mode);
            expect(entry.hash, `${path}: hash`).toMatch(/^[0-9a-f]{64}$/);
            expect(entry.size, `${path}: size`).toBeGreaterThan(0);
        }
        // The keys are sorted, so a rebaseline diff stays readable.
        expect(entries.map(([p]) => p)).toEqual([...entries.map(([p]) => p)].sort());
    });

    it('carries forward references from the previous release once there is one', () => {
        // The chain is the point: after the first release, a large share of the entries must still be
        // held to what the previous release emitted, not silently re-anchored to the current tree.
        if (baseline!.baselineVersion === CHAIN_ORIGIN) return;
        const inherited = Object.values(baseline!.entries).filter((e) => e.since !== baseline!.baselineVersion).length;
        expect(inherited).toBeGreaterThan(20);
    });

    it('A2-005: every tbs row is justified by a randomised signer (ECDSA / RSA-PSS), every bytes row by a deterministic one or a read-only tool, every semantic artefact by the RNG', () => {
        const counts: Record<FingerprintMode, number> = { bytes: 0, tbs: 0, semantic: 0 };
        for (const [rel, entry] of Object.entries(baseline!.entries)) {
            counts[entry.mode] += 1;
            if (locate(rel).sidecar) {
                expect(entry.mode, `${rel}: a JSON result is semantic`).toBe('semantic');
                continue;
            }
            const { tool, args } = stepOf(rel);
            const randomised = signerIsRandomised(args);
            const asksRandom = argsAskRandom(args);
            const readOnly = annotationsOf.get(tool)?.readOnlyHint === true;
            switch (entry.mode) {
                case 'tbs':
                    expect(randomised, `${rel}: tbs mode needs an ECDSA or RSA-PSS signer (${tool})`).toBe(true);
                    expect(asksRandom, `${rel}: a 'random' input would make the TBS itself unrepeatable`).toBe(false);
                    break;
                case 'bytes':
                    expect(asksRandom, `${rel}: bytes mode cannot hold a 'random' input`).toBe(false);
                    expect(readOnly || !randomised, `${rel}: bytes mode needs a deterministic signer (Ed25519, RSA PKCS#1 v1.5) or a read-only tool (${tool})`).toBe(true);
                    break;
                case 'semantic':
                    expect(asksRandom || randomised, `${rel}: a semantic artefact needs a 'random' input or a randomised signer whose structure is not SEQUENCE { tbs, alg, BIT STRING } (${tool})`).toBe(true);
                    break;
            }
        }
        for (const mode of MODES) expect(counts[mode], `no ${mode} entry in the baseline`).toBeGreaterThan(0);
    });

    it('names an example for every entry, and a sidecar entry for every executable example', () => {
        const sidecars = new Set<string>();
        for (const rel of Object.keys(baseline!.entries)) {
            const at = locate(rel);
            expect(examples.has(at.example), `${rel}: examples/${at.example}.json`).toBe(true);
            if (at.sidecar) sidecars.add(at.example);
        }
        const executable = [...examples.values()].filter((e) => !e.documentationOnly).map((e) => e.name).sort();
        expect([...sidecars].sort()).toEqual(executable);
    });
});

// ── Chaining ─────────────────────────────────────────────────────────

describe('baseline chaining', () => {
    const fp = (hash: string, mode: FingerprintMode = 'bytes'): Fingerprint => ({ mode, hash, size: 1 });
    const prior = {
        baselineVersion: '1.0.0',
        entries: { kept: { mode: 'bytes', hash: 'aa', size: 1, since: '1.0.0' } },
    } as unknown as Baseline;

    it('A2-005: keeps the original release for an unchanged sample', () => {
        expect(chainSince({ kept: fp('aa') }, prior, '1.1.0')['kept']!.since).toBe('1.0.0');
    });

    it('re-anchors a sample whose hash changed, so the rebaseline is visible', () => {
        expect(chainSince({ kept: fp('bb') }, prior, '1.1.0')['kept']!.since).toBe('1.1.0');
    });

    it('stamps a sample the previous manifest never held', () => {
        expect(chainSince({ fresh: fp('cc') }, prior, '1.1.0')['fresh']!.since).toBe('1.1.0');
    });

    it('re-anchors when only the fingerprint mode changed', () => {
        expect(chainSince({ kept: fp('aa', 'tbs') }, prior, '1.1.0')['kept']!.since).toBe('1.1.0');
    });

    it('stamps everything when there is no previous manifest', () => {
        const out = chainSince({ a: fp('1'), b: fp('2') }, null, '1.0.0');
        expect(Object.values(out).every((e) => e.since === '1.0.0')).toBe(true);
    });

    it('emits keys in sorted order, so the manifest diff stays readable', () => {
        expect(Object.keys(chainSince({ z: fp('1'), a: fp('2'), m: fp('3') }, null, '1.0.0'))).toEqual(['a', 'm', 'z']);
    });

    it('compareToBaseline reports changed, added and removed, and a mode change counts as a change', () => {
        const base = { baselineVersion: '1.0.0', entries: { a: { mode: 'bytes', hash: '1', size: 1, since: '1.0.0' }, b: { mode: 'bytes', hash: '2', size: 1, since: '1.0.0' }, c: { mode: 'bytes', hash: '3', size: 1, since: '1.0.0' } } } as unknown as Baseline;
        expect(compareToBaseline({ a: fp('1'), b: fp('2', 'tbs'), d: fp('4') }, base)).toEqual({ changed: ['b'], added: ['d'], removed: ['c'] });
    });
});

// ── The fingerprint helpers ──────────────────────────────────────────

describe('sample fingerprint helpers', () => {
    it('serialises object keys in a stable order', () => {
        expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
        expect(canonicalJson({ a: 2, b: 1 })).toBe('{"a":2,"b":1}');
        expect(canonicalJson([{ z: 1, y: 2 }])).toBe('[{"y":2,"z":1}]');
        expect(canonicalJson(null)).toBe('null');
    });

    it('hashes strings and bytes consistently', () => {
        expect(sha256Hex('abc')).toBe(sha256Hex(new TextEncoder().encode('abc')));
        expect(sha256Hex('abc')).not.toBe(sha256Hex('abd'));
    });

    it('normalises sample paths to forward slashes', () => {
        expect(relPath(join(OUTPUT_DIR, 'create-csr.step1.csr'))).toBe('create-csr.step1.csr');
        expect(relPath(join(OUTPUT_DIR, 'nested', 'x.json'))).toBe('nested/x.json');
    });

    it('reports unexpected duplicates', () => {
        const entries = { 'a.crt': { hash: '1' }, 'b.crt': { hash: '1' }, 'c.crt': { hash: '2' } };
        expect(unexpectedDuplicates(entries)).toEqual([['a.crt', 'b.crt']]);
        expect(unexpectedDuplicates({ 'a.crt': { hash: '1' }, 'c.crt': { hash: '2' } })).toEqual([]);
    });

    it('strips the volatile members at every depth, and the RNG-derived members next to a raised random flag', () => {
        expect(VOLATILE_MEMBERS).toEqual(['evaluatedAt', 'sha256', 'sizeBytes', 'filePath']);
        const value = {
            a: { evaluatedAt: 'x', sha256: 'y', keep: 1 },
            summary: { randomSerial: true, serialNumber: '0x1234', other: 2 },
            nonce: { randomNonce: true, nonce: '7', nonceHex: '07', hashAlgorithm: 'SHA-256' },
            list: [{ sizeBytes: 3, filePath: 'p', k: 1 }],
            pinned: { randomSerial: false, serialNumber: '1' },
        };
        expect(stripVolatile(value)).toEqual({
            a: { keep: 1 },
            summary: { randomSerial: true, other: 2 },
            nonce: { randomNonce: true, hashAlgorithm: 'SHA-256' },
            list: [{ k: 1 }],
            pinned: { randomSerial: false, serialNumber: '1' },
        });
        expect(hasRandomFlag(value)).toBe(true);
        expect(hasRandomFlag({ summary: { randomSerial: false, serialNumber: '1' } })).toBe(false);
        expect(hasRandomFlag([{ deep: { randomNonce: true } }])).toBe(true);
        expect(hasRandomFlag(null)).toBe(false);
    });

    it('projects structuredContent without the volatile members, a refusal with its code, a sequence step by step, and an inline hex artefact drawn from the RNG as absent', () => {
        const a = JSON.stringify({ content: [{ type: 'text', text: 'prose' }], structuredContent: { z: 1, sha256: 'x', evaluatedAt: 'now', nested: { sizeBytes: 9, ok: true } } });
        const b = JSON.stringify({ structuredContent: { nested: { ok: true, sizeBytes: 1 }, z: 1, sha256: 'y', evaluatedAt: 'later' }, content: [] });
        expect(semanticProjection(a)).toBe(semanticProjection(b));
        expect(semanticProjection(a)).toBe('{"structuredContent":{"nested":{"ok":true},"z":1}}');
        const refused = JSON.stringify({ isError: true, content: [{ type: 'text', text: 'x failed [VALIDATION_ERROR]: m' }], _meta: { error: { code: 'VALIDATION_ERROR', message: 'm', data: {} } } });
        expect(semanticProjection(refused)).toBe('{"code":"VALIDATION_ERROR","isError":true,"message":"m","structuredContent":null}');
        const steps = JSON.stringify({ steps: [{ structuredContent: { a: 1 } }, { isError: true, _meta: { error: { code: 'NOT_FOUND' } } }] });
        expect(semanticProjection(steps)).toBe('{"steps":[{"structuredContent":{"a":1}},{"code":"NOT_FOUND","isError":true,"message":null,"structuredContent":null}]}');
        const randomHex = JSON.stringify({ structuredContent: { hex: '3082', summary: { randomNonce: true, nonce: '9', nonceHex: '09' } } });
        expect(semanticProjection(randomHex)).toBe('{"structuredContent":{"summary":{"randomNonce":true}}}');
        const pinnedHex = JSON.stringify({ structuredContent: { hex: '3082', summary: { randomNonce: false, nonce: '42' } } });
        expect(semanticProjection(pinnedHex)).toBe('{"structuredContent":{"hex":"3082","summary":{"nonce":"42","randomNonce":false}}}');
    });

    it('neutralises the host members: the same describe_engine and draft_governance_issue results project identically from win32 / Node 22 and linux / Node 24', () => {
        expect(HOST_MEMBERS).toEqual({ capabilities: ['node', 'platform'], environment: ['node', 'os'] });
        const engine = (node: string, platform: string): string => JSON.stringify({ structuredContent: { server: { toolCount: 34 }, capabilities: { canVerify: true, canSign: true, canDecrypt: true, node, nodeFloorSatisfied: true, platform }, network: 'none' } });
        expect(semanticProjection(engine('v22.20.0', 'win32'))).toBe(semanticProjection(engine('v24.11.0', 'linux')));
        expect(semanticProjection(engine('v22.20.0', 'win32'))).toBe('{"structuredContent":{"capabilities":{"canDecrypt":true,"canSign":true,"canVerify":true,"nodeFloorSatisfied":true},"network":"none","server":{"toolCount":34}}}');
        const draft = (node: string, os: string): string => JSON.stringify({ structuredContent: {
            title: 't', sizeBytes: 10 + node.length + os.length,
            draftMarkdown: `# t\n\n## Environment\n\n- Node: ${node}\n- OS: ${os}\n- pkinative-mcp: 1.0.0\n- Affected packages: pkinative\n`,
            compliance: { zeroDependencyConfirmed: true, environment: { node, os, pkinativeMcp: '1.0.0' } },
        } });
        expect(semanticProjection(draft('v22.20.0', 'win32 10.0.26200'))).toBe(semanticProjection(draft('v24.11.0', 'linux 6.11.0-1018-azure')));
        expect(semanticProjection(draft('v22.20.0', 'win32 10.0.26200'))).toContain('- Node: <host>\\n- OS: <host>\\n- pkinative-mcp: 1.0.0');
        expect(semanticProjection(draft('v22.20.0', 'win32 10.0.26200'))).toContain('"environment":{"pkinativeMcp":"1.0.0"}');
        // Only the two carriers are touched: a `node` or `os` member elsewhere, and a `capabilities` array, are behaviour.
        expect(stripHost({ node: 1, os: 'x', capabilities: ['a'], nested: { environment: { os: 'y', keep: 1 }, text: 'OS: not a list line' } })).toEqual({ node: 1, os: 'x', capabilities: ['a'], nested: { environment: { keep: 1 }, text: 'OS: not a list line' } });
        expect(semanticProjection(JSON.stringify({ structuredContent: { node: 1 } }))).toBe('{"structuredContent":{"node":1}}');
    });

    it('reads the DER of a PEM or raw file, recognises a signed structure, and cuts out its first element', () => {
        const pemDer = derOf(fixtureBytes('leaf.crt.pem'));
        const rawDer = fixtureBytes('leaf.crt.der');
        expect(Buffer.from(pemDer).equals(Buffer.from(rawDer))).toBe(true);
        expect(derOf(rawDer)).toBe(rawDer);
        for (const name of ['leaf.crt.der', 'leaf.csr.der', 'inter.crl.der', 'rsa.crt.der']) expect(looksSigned(fixtureBytes(name)), name).toBe(true);
        // A TimeStampReq starts with an INTEGER, a ContentInfo with an OID, a PKCS#12 with an INTEGER: none is { tbs, alg, BIT STRING }.
        for (const name of ['content.tsq', 'attached.p7s', 'leaf.p12', 'leaf.ocsp-req.der']) expect(looksSigned(fixtureBytes(name)), name).toBe(false);
        expect(looksSigned(new Uint8Array([0x02, 0x01, 0x05]))).toBe(false);
        expect(looksSigned(new Uint8Array([0x30, 0x80]))).toBe(false);
        const tbs = firstElementOfSequence(rawDer);
        expect(tbs[0]).toBe(0x30);
        expect(tbs.length).toBeLessThan(rawDer.length);
        expect(() => firstElementOfSequence(new Uint8Array([0x02, 0x01, 0x05]))).toThrow(/not a SEQUENCE/);
        expect(() => firstElementOfSequence(new Uint8Array([...rawDer, 0x00]))).toThrow(/trailing bytes/);
        expect(() => firstElementOfSequence(new Uint8Array([0x30, 0x00]))).toThrow(/empty/);
        expect(() => derOf(Buffer.from('-----BEGIN X-----\nabc\n', 'utf8'))).toThrow(/no block/);
    });

    it('A2-005: tells a deterministic signer (Ed25519, RSA PKCS#1 v1.5) from a randomised one (ECDSA, RSA-PSS), inline or by fixture name', () => {
        const key = (name: string): { signer: { key: { pem: string } } } => ({ signer: { key: { pem: fixtureText(name) } } });
        expect(signerIsRandomised(key('ed25519.key.pem'))).toBe(false);
        expect(signerIsRandomised(key('leaf.key.pem'))).toBe(true);
        expect(signerIsRandomised({ ...key('rsa.key.pem'), signer: { ...key('rsa.key.pem').signer, rsaScheme: 'pkcs1' } })).toBe(false);
        expect(signerIsRandomised({ signer: { key: { pem: fixtureText('rsa.key.pem') }, rsaScheme: 'pss' } })).toBe(true);
        expect(signerIsRandomised({ signer: { key: { pem: fixtureText('rsa.key.pem') } } })).toBe(true);
        // By file name, the way the examples carry their signer; a PKCS#12 goes by its name alone.
        expect(signerIsRandomised({ signer: { key: { path: 'fixtures/ed25519.key.pem' } } })).toBe(false);
        expect(signerIsRandomised({ signer: { key: { path: 'fixtures/leaf.key.pem' } } })).toBe(true);
        expect(signerIsRandomised({ signer: { key: { path: 'fixtures/rsa.key.pem' }, rsaScheme: 'pkcs1' } })).toBe(false);
        expect(signerIsRandomised({ signer: { p12: { path: 'fixtures/ed25519.p12' } } })).toBe(false);
        expect(signerIsRandomised({ signer: { p12: { path: 'fixtures/leaf.p12' } } })).toBe(true);
        // The encrypted EC key does not parse without its password: the name decides.
        expect(signerIsRandomised({ signer: { key: { path: 'fixtures/leaf.key.enc.pem' } } })).toBe(true);
        // Unknown material is assumed randomised — the mode that can only hold a sample less strictly, never flake.
        expect(signerIsRandomised({ signer: { key: { derBase64: Buffer.from('not a key').toString('base64') } } })).toBe(true);
        expect(signerIsRandomised({ signer: { key: {} } })).toBe(true);
        expect(signerIsRandomised({})).toBe(false);
        expect(signerIsRandomised(undefined)).toBe(false);
    });

    it('spots a \'random\' request anywhere in the arguments', () => {
        expect(argsAskRandom({ spec: { serialNumber: 'random' } })).toBe(true);
        expect(argsAskRandom({ nonce: 'random' })).toBe(true);
        expect(argsAskRandom({ spec: { serialNumber: 1 }, nonce: '42', note: 'randomly' })).toBe(false);
        expect(argsAskRandom(undefined)).toBe(false);
        expect(argsAskRandom({ a: [{ b: 'random' }] })).toBe(true);
    });

    it('A2-005: modeFor — semantic for a JSON result or a \'random\' input, bytes for a read-only tool or a deterministic signer, tbs for a randomised signature over { tbs, alg, BIT STRING }, semantic otherwise', () => {
        const ed = { signer: { key: { path: 'fixtures/ed25519.key.pem' } } };
        const ec = { signer: { key: { path: 'fixtures/leaf.key.pem' } } };
        const cert = fixtureBytes('leaf.crt.der');
        expect(modeFor({ annotations: undefined, args: ec, artefact: null })).toBe('semantic');
        expect(modeFor({ annotations: undefined, args: { ...ed, spec: { serialNumber: 'random' } }, artefact: cert })).toBe('semantic');
        expect(modeFor({ annotations: { readOnlyHint: true }, args: ec, artefact: cert })).toBe('bytes');
        expect(modeFor({ annotations: { readOnlyHint: false }, args: ed, artefact: cert })).toBe('bytes');
        expect(modeFor({ annotations: undefined, args: undefined, artefact: cert })).toBe('bytes');
        expect(modeFor({ annotations: undefined, args: ec, artefact: cert })).toBe('tbs');
        expect(modeFor({ annotations: undefined, args: ec, artefact: fixtureBytes('leaf.crt.pem') })).toBe('tbs');
        expect(modeFor({ annotations: undefined, args: ec, artefact: fixtureBytes('attached.p7s') })).toBe('semantic');
        expect(modeFor({ annotations: undefined, args: ec, artefact: new Uint8Array([0x30, 0x80]) })).toBe('semantic');
    });
});

// ── Environment independence ─────────────────────────────────────────

describe('sample generation is environment-independent', () => {
    // Reproducibility needs more than a pinned clock. `toLocaleString()` with no explicit locale follows
    // the machine's: on a fr-FR developer machine 1500 formats as "1 500" with U+202F, on a C/en-US CI runner as "1,500".
    const LOCALE_SENSITIVE = /\.toLocale(?:String|DateString|TimeString)\(\s*\)/;

    function* walkTs(dir: string): Generator<string> {
        for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
            const p = join(dir, entry.name);
            if (entry.isDirectory()) yield* walkTs(p);
            else if (entry.name.endsWith('.ts')) yield p;
        }
    }

    it('never formats numbers or dates without an explicit locale', () => {
        const offenders: string[] = [];
        for (const dir of ['scripts', 'src']) {
            for (const file of walkTs(join(REPO_ROOT, dir))) {
                readFileSync(file, 'utf8')
                    .split('\n')
                    .forEach((line, i) => {
                        if (LOCALE_SENSITIVE.test(line)) offenders.push(`${relative(REPO_ROOT, file)}:${i + 1}`);
                    });
            }
        }
        expect(offenders, "pass an explicit locale, e.g. toLocaleString('en-US')").toEqual([]);
    });

    it('runs the generators, the verifiers and the gate in UTC with the operator knobs scrubbed, and the test runner in UTC', () => {
        expect(readFileSync(join(REPO_ROOT, 'scripts', 'helpers', 'tz.ts'), 'utf8')).toContain("process.env.TZ = 'UTC'");
        for (const script of ['generate-samples.ts', 'verify-samples.ts', 'generate-pki-corpus.ts', 'validate-pki.ts', 'gate.ts']) {
            const source = readFileSync(join(REPO_ROOT, 'scripts', script), 'utf8');
            const firstImport = /^import\s+['"]([^'"]+)['"];/m.exec(source)?.[1];
            expect(firstImport, `${script}: the hermetic side-effect import must come first`).toBe('./helpers/hermetic.js');
        }
        // vitest.config.ts sets `env.TZ`, so a date formatted inside a test renders the same on every machine.
        expect(process.env['TZ']).toBe('UTC');
        expect(new Date(0).getTimezoneOffset()).toBe(0);
    });
});
