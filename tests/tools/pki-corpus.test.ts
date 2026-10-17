// The corpus table (scripts/lib/pki-corpus.ts) and its declaration
// (docs/data/interop.json), held together without running a tool: ids,
// placeholders, dependency order, determinism claims, the negative canaries
// and the OpenSSL command ids.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { fixtureExists, fixtureBytes } from '../../scripts/helpers/io.js';
import { COMMAND_IDS, COMMANDS } from '../../scripts/lib/interop-tools.js';
import {
    CONFORMANT, CORPUS, KNOWN_OPENSSL_GAPS, REFUSED, SHA256_OID_HEX, checkOcspRequest, checkTimestampRequest, corpusDependencies, opensslAtLeast, opensslCommandsUsed, opensslGapFor,
    placeholdersOf, resolvePlaceholders,
} from '../../scripts/lib/pki-corpus.js';
import { countStatuses, fileNameFor } from '../../scripts/lib/pki-corpus-manifest.js';
import { fixtureBase64, fixtureText } from '../_pki-fixtures.js';

const ROOT = resolve(import.meta.dirname, '..', '..');
const interop = JSON.parse(readFileSync(resolve(ROOT, 'docs', 'data', 'interop.json'), 'utf8')) as { schemaVersion: number; declared: { conformant: number; refused: number }; opensslCommands: string[]; levels: Array<{ level: number }>; knownGaps: unknown };

describe('pki-corpus: the table', () => {
    it('has unique ids and a kind, tool and arguments on every entry', () => {
        const ids = CORPUS.map((e) => e.id);
        expect(new Set(ids).size).toBe(ids.length);
        for (const e of CORPUS) {
            expect(e.kind, e.id).toMatch(/^(cert|csr|cms-attached|cms-detached|tsq|ocsp-req|pem)$/);
            expect(e.tool, e.id).toMatch(/^[a-z][a-z0-9_]+$/);
            expect(typeof e.arguments, e.id).toBe('object');
        }
    });

    it('splits into conformant entries (with expectations) and negative canaries (with a code), never both', () => {
        expect(CONFORMANT.length + REFUSED.length).toBe(CORPUS.length);
        for (const e of CONFORMANT) expect(e.expect, e.id).toBeDefined();
        for (const e of REFUSED) {
            expect(e.expectRefused, e.id).toMatch(/^[A-Z][A-Z0-9_]+$/);
            expect(e.expect, e.id).toBeUndefined();
        }
        expect(REFUSED.length).toBeGreaterThanOrEqual(5);
        expect(REFUSED.map((e) => e.expectRefused)).toEqual(expect.arrayContaining(['VALIDATION_ERROR', 'PKI_KEY_ENCRYPTION_UNSUPPORTED', 'RSA_SCHEME_REQUIRED']));
    });

    it('covers a CA and a leaf per signature family, every artefact kind and every tool the corpus is for', () => {
        const ids = CORPUS.map((e) => e.id);
        for (const id of ['ca-ed25519', 'ca-rsa-pkcs1', 'ca-rsa-pss', 'ca-ec', 'leaf-ed25519', 'leaf-rsa-pkcs1', 'leaf-rsa-pss', 'leaf-ec', 'inter-pathlen0', 'leaf-under-inter']) expect(ids).toContain(id);
        expect(new Set(CORPUS.map((e) => e.kind))).toEqual(new Set(['cert', 'csr', 'cms-attached', 'cms-detached', 'tsq', 'ocsp-req', 'pem']));
        expect(new Set(CONFORMANT.map((e) => e.tool))).toEqual(new Set(['create_certificate', 'create_csr', 'sign_cms', 'create_timestamp_request', 'create_ocsp_request', 'convert_pem']));
    });

    it('every placeholder names a fixture that exists, an earlier entry, a content fixture or the password', () => {
        const seen = new Set<string>();
        for (const e of CORPUS) {
            for (const token of placeholdersOf(e.arguments)) {
                const [kind, value] = token.split(':', 2) as [string, string | undefined];
                if (kind === 'fixture' || kind === 'content') expect(fixtureExists(value ?? ''), `${e.id}: <${token}>`).toBe(true);
                else if (kind === 'corpus') expect(seen.has(value ?? ''), `${e.id}: <${token}> must be an EARLIER entry`).toBe(true);
                else expect(token, e.id).toBe('password:test-only');
            }
            for (const rt of e.expect?.roundTrip ?? []) {
                for (const token of placeholdersOf(rt.arguments)) {
                    const [kind, value] = token.split(':', 2) as [string, string | undefined];
                    if (kind === 'corpus') expect(seen.has(value ?? '') || value === e.id, `${e.id} round trip: <${token}>`).toBe(true);
                    else if (kind === 'fixture' || kind === 'content') expect(fixtureExists(value ?? ''), `${e.id} round trip: <${token}>`).toBe(true);
                }
            }
            for (const check of e.expect?.openssl ?? []) {
                for (const ref of [check.caFile, check.content, ...(check.untrusted ?? [])]) {
                    if (ref === undefined) continue;
                    if (ref.startsWith('fixture:')) expect(fixtureExists(ref.slice(8)), `${e.id}: ${ref}`).toBe(true);
                    else expect(seen.has(ref.slice(7)) || ref.slice(7) === e.id, `${e.id}: ${ref}`).toBe(true);
                }
            }
            seen.add(e.id);
        }
    });

    it('claims determinism only for Ed25519 / RSA PKCS#1 signers and the unsigned artefacts', () => {
        for (const e of CONFORMANT) {
            const signer = (e.arguments['signer'] as { key?: string; rsaScheme?: string } | undefined);
            const randomised = signer !== undefined && (signer.rsaScheme === 'pss' || (signer.key?.includes('leaf.key') ?? false));
            expect(e.expect?.deterministic, e.id).toBe(!randomised);
        }
    });

    it('uses only known OpenSSL command ids, and docs/data/interop.json declares the counts and the commands', () => {
        for (const id of opensslCommandsUsed()) expect(COMMAND_IDS).toContain(id);
        expect(interop.schemaVersion).toBe(1);
        expect(interop.declared).toEqual({ conformant: CONFORMANT.length, refused: REFUSED.length });
        expect(interop.opensslCommands).toEqual(COMMAND_IDS.map((id) => COMMANDS[id].describe));
        expect(interop.levels.map((l) => l.level)).toEqual([0, 1]);
    });

    it('declares every known gap of the judge once, with a floor, a reason and a proof, over checks the table really runs; docs/data/interop.json and CONFORMANCE.md carry the same table', () => {
        expect(KNOWN_OPENSSL_GAPS.map((g) => g.id)).toEqual(['cms-eddsa']);
        const checks = new Set(CONFORMANT.flatMap((e) => (e.expect?.openssl ?? []).map((c) => `${e.id}:${c.command}`)));
        for (const gap of KNOWN_OPENSSL_GAPS) {
            expect(gap.minOpenssl).toMatch(/^3\.\d+$/);
            expect(gap.reason.length, gap.id).toBeGreaterThan(40);
            expect(gap.proof.length, gap.id).toBeGreaterThan(40);
            expect(gap.match.length, gap.id).toBeGreaterThan(0);
            for (const m of gap.match) expect(checks.has(m), `${gap.id} covers ${m}, which no entry runs`).toBe(true);
        }
        expect(opensslGapFor('cms-ed25519-attached', 'cms-verify-attached')?.minOpenssl).toBe('3.5');
        expect(opensslGapFor('cms-attached', 'cms-verify-attached')).toBeUndefined();
        expect(opensslGapFor('cms-ed25519-attached', 'x509-text')).toBeUndefined();
        expect(interop.knownGaps).toEqual(KNOWN_OPENSSL_GAPS);
        const guide = readFileSync(resolve(ROOT, 'docs', 'guides', 'CONFORMANCE.md'), 'utf8');
        for (const gap of KNOWN_OPENSSL_GAPS) {
            expect(guide, `CONFORMANCE.md names the gap ${gap.id}`).toContain(`\`${gap.id}\``);
            expect(guide, `CONFORMANCE.md names the floor of ${gap.id}`).toContain(`OpenSSL ${gap.minOpenssl}`);
        }
        const v = (major: number, minor: number) => ({ major, minor });
        expect(opensslAtLeast(v(3, 0), '3.5')).toBe(false);
        expect(opensslAtLeast(v(3, 4), '3.5')).toBe(false);
        expect(opensslAtLeast(v(3, 5), '3.5')).toBe(true);
        expect(opensslAtLeast(v(3, 6), '3.5')).toBe(true);
        expect(opensslAtLeast(v(4, 0), '3.5')).toBe(true);
        expect(opensslAtLeast(v(3, 10), '3.5')).toBe(true);
    });

    it('names a file per kind', () => {
        expect(fileNameFor('x', 'cert')).toBe('x.crt');
        expect(fileNameFor('x', 'pem')).toBe('x.pem');
        expect(fileNameFor('x', 'cms-detached')).toBe('x.p7s');
        expect(fileNameFor('x', 'other')).toBe('x.der');
    });
});

describe('pki-corpus: placeholders', () => {
    it('resolves fixtures (PEM text / DER base64), content, the password and earlier entries by kind', () => {
        const produced = new Map([
            ['ca', { bytes: new Uint8Array([0x30, 0x00]), kind: 'cert' as const }],
            ['p', { bytes: new TextEncoder().encode('-----BEGIN X-----\n-----END X-----\n'), kind: 'pem' as const }],
        ]);
        const resolved = resolvePlaceholders({
            a: '<fixture:leaf.crt.pem>', b: '<fixture:leaf.crt.der>', c: '<content:content.txt>', d: '<password:test-only>', e: '<corpus:ca>', f: '<corpus:p>', g: ['<corpus:ca>'], h: 'plain',
        }, produced) as Record<string, unknown>;
        expect(resolved['a']).toEqual({ pem: fixtureText('leaf.crt.pem') });
        expect(resolved['b']).toEqual({ derBase64: fixtureBase64('leaf.crt.der') });
        expect(resolved['c']).toEqual({ base64: fixtureBytes('content.txt').toString('base64') });
        expect(resolved['d']).toBe('test-only-password');
        expect(resolved['e']).toEqual({ derBase64: 'MAA=' });
        expect(resolved['f']).toEqual({ pem: '-----BEGIN X-----\n-----END X-----\n' });
        expect(resolved['g']).toEqual([{ derBase64: 'MAA=' }]);
        expect(resolved['h']).toBe('plain');
    });

    it('refuses an entry consumed before it is produced, an unknown fixture and an unknown token', () => {
        expect(() => resolvePlaceholders({ x: '<corpus:later>' }, new Map())).toThrow(/consumed before it is produced/);
        expect(() => resolvePlaceholders({ x: '<fixture:nope.pem>' }, new Map())).toThrow(/unknown fixture/);
        expect(() => resolvePlaceholders({ x: '<magic>' }, new Map())).toThrow(/not a corpus placeholder/);
    });

    it('lists the corpus dependencies of an argument object', () => {
        expect(corpusDependencies({ a: '<corpus:x>', b: [{ c: '<corpus:y>' }], d: '<fixture:leaf.crt.pem>' })).toEqual(['x', 'y']);
    });
});

describe('pki-corpus: engine checks over the OpenSSL-made fixtures', () => {
    it('accepts the fixture OCSP request for the leaf (a SHA-256 CertID, as PROVENANCE.md says) and rejects it for the revoked certificate', () => {
        expect(checkOcspRequest('leaf.crt.pem', 'inter.crt.pem', SHA256_OID_HEX)(fixtureBytes('leaf.ocsp-req.der'))).toBeNull();
        expect(checkOcspRequest('revoked.crt.pem', 'inter.crt.pem', SHA256_OID_HEX)(fixtureBytes('leaf.ocsp-req.der'))).toMatch(/serialNumber is 1001, expected 1002/);
        expect(checkOcspRequest('leaf.crt.pem', 'root.crt.pem', SHA256_OID_HEX)(fixtureBytes('leaf.ocsp-req.der'))).toMatch(/issuerNameHash/);
    });

    it('accepts the fixture time-stamp request against the content it covers (no nonce in the fixture)', () => {
        const problem = checkTimestampRequest('content.txt', 'sha256', SHA256_OID_HEX, '2a')(fixtureBytes('content.tsq'));
        expect(problem).toMatch(/nonce is/);
    });
});

describe('pki-corpus: manifest helpers', () => {
    it('counts statuses', () => {
        expect(countStatuses([
            { id: 'a', tool: 't', kind: 'cert', status: 'written' },
            { id: 'b', tool: 't', kind: 'cert', status: 'refused' },
            { id: 'c', tool: 't', kind: 'cert', status: 'skipped' },
            { id: 'd', tool: 't', kind: 'cert', status: 'xpass' },
            { id: 'e', tool: 't', kind: 'cert', status: 'refused-other' },
            { id: 'f', tool: 't', kind: 'cert', status: 'failed' },
        ])).toEqual({ written: 1, refused: 1, refusedOther: 1, xpass: 1, skipped: 1, failed: 1 });
    });
});
