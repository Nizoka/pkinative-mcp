// Pure helpers of the OpenSSL plumbing (scripts/lib/interop-tools.ts): the
// version gate, the locator, the command builders and the outcome
// classifiers — fed inline output, nothing spawned.

import { describe, it, expect } from 'vitest';

import {
    COMMANDS, COMMAND_IDS, classifyCmsVerify, classifyDump, classifyReqVerify, classifyVerify, judgeOpensslVersion, locateOpenssl, parseOpensslVersion,
} from '../../scripts/lib/interop-tools.js';

describe('interop-tools: version', () => {
    it('parses the first line of `openssl version`', () => {
        expect(parseOpensslVersion('OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)\n')).toEqual({ product: 'OpenSSL', major: 3, minor: 5, patch: 5, raw: 'OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)' });
        expect(parseOpensslVersion('LibreSSL 3.9.2')).toMatchObject({ product: 'LibreSSL', major: 3, minor: 9 });
        expect(parseOpensslVersion('OpenSSL 1.1.1w  11 Sep 2023')).toMatchObject({ product: 'OpenSSL', major: 1, minor: 1, patch: 1 });
        expect(parseOpensslVersion('')).toBeNull();
        expect(parseOpensslVersion('command not found')).toBeNull();
    });

    it('accepts OpenSSL 3.x only, with the three reasons the gate prints', () => {
        expect(judgeOpensslVersion(parseOpensslVersion('OpenSSL 3.0.13 30 Jan 2024'))).toBeNull();
        expect(judgeOpensslVersion(parseOpensslVersion('OpenSSL 3.5.5 27 Jan 2026'))).toBeNull();
        expect(judgeOpensslVersion(null)).toBe('openssl not on PATH');
        expect(judgeOpensslVersion(parseOpensslVersion('LibreSSL 3.9.2'))).toBe('LibreSSL is not OpenSSL');
        expect(judgeOpensslVersion(parseOpensslVersion('OpenSSL 1.1.1w  11 Sep 2023'))).toBe('OpenSSL < 3.0');
        expect(judgeOpensslVersion(parseOpensslVersion('BoringSSL 1.0'))).toBe('BoringSSL is not OpenSSL');
    });
});

describe('interop-tools: locate', () => {
    it('prefers OPENSSL_BIN when it exists, refuses a dangling override, falls back to PATH, then null', () => {
        expect(locateOpenssl({ env: { OPENSSL_BIN: '/opt/openssl/bin/openssl' }, exists: (p) => p === '/opt/openssl/bin/openssl', probePath: () => '/usr/bin/openssl' })).toBe('/opt/openssl/bin/openssl');
        expect(locateOpenssl({ env: { OPENSSL_BIN: '/nowhere' }, exists: () => false, probePath: () => '/usr/bin/openssl' })).toBeNull();
        expect(locateOpenssl({ env: {}, exists: () => false, probePath: () => '/usr/bin/openssl' })).toBe('/usr/bin/openssl');
        expect(locateOpenssl({ env: { OPENSSL_BIN: '  ' }, exists: () => false, probePath: () => null })).toBeNull();
    });
});

describe('interop-tools: command builders', () => {
    it('build the documented command lines', () => {
        expect(COMMANDS['x509-text'].build({ file: 'a.crt' })).toEqual(['x509', '-inform', 'DER', '-in', 'a.crt', '-noout', '-text']);
        expect(COMMANDS['verify'].build({ file: 'leaf.crt', caFile: 'ca.crt', untrusted: ['inter.crt'], attime: 1798761600 })).toEqual(['verify', '-CAfile', 'ca.crt', '-untrusted', 'inter.crt', '-attime', '1798761600', 'leaf.crt']);
        expect(COMMANDS['verify-sslserver'].build({ file: 'leaf.crt', caFile: 'ca.crt' })).toEqual(['verify', '-CAfile', 'ca.crt', '-purpose', 'sslserver', 'leaf.crt']);
        expect(COMMANDS['req-verify'].build({ file: 'r.csr' })).toEqual(['req', '-inform', 'DER', '-in', 'r.csr', '-noout', '-verify']);
        expect(COMMANDS['cms-verify-detached'].build({ file: 's.p7s', caFile: 'root.pem', content: 'c.txt', outFile: 'o' })).toEqual(['cms', '-verify', '-binary', '-inform', 'DER', '-in', 's.p7s', '-CAfile', 'root.pem', '-purpose', 'any', '-content', 'c.txt', '-out', 'o']);
        expect(COMMANDS['cms-verify-attached'].build({ file: 's.p7s', caFile: 'root.pem', outFile: 'o', attime: 1 })).toEqual(['cms', '-verify', '-binary', '-inform', 'DER', '-in', 's.p7s', '-CAfile', 'root.pem', '-purpose', 'any', '-attime', '1', '-out', 'o']);
        expect(COMMANDS['asn1parse'].build({ file: 'x' })).toEqual(['asn1parse', '-inform', 'DER', '-in', 'x']);
        expect(COMMANDS['ocsp-req-text'].build({ file: 'q.orq' })).toEqual(['ocsp', '-reqin', 'q.orq', '-req_text']);
        expect(COMMANDS['ts-query-text'].build({ file: 'q.tsq' })).toEqual(['ts', '-query', '-in', 'q.tsq', '-text']);
    });

    it('refuse a context missing what the command needs', () => {
        expect(() => COMMANDS['verify'].build({ file: 'leaf.crt' })).toThrow(/needs caFile/);
        expect(() => COMMANDS['cms-verify-detached'].build({ file: 's', caFile: 'c', outFile: 'o' })).toThrow(/needs content/);
    });

    it('every command id has a describe string and the ids are the table keys', () => {
        for (const id of COMMAND_IDS) {
            expect(COMMANDS[id].id).toBe(id);
            expect(COMMANDS[id].describe.length).toBeGreaterThan(5);
        }
    });
});

describe('interop-tools: classifiers', () => {
    it('verify: `<file>: OK` on stdout is the only pass', () => {
        expect(classifyVerify({ status: 0, stdout: 'leaf.crt: OK\n', stderr: '' })).toEqual({ ok: true, detail: 'OK' });
        const r = classifyVerify({ status: 2, stdout: 'leaf.crt: verification failed\n', stderr: 'C = FR, CN = x\nerror 10 at 0 depth lookup: certificate has expired\n' });
        expect(r.ok).toBe(false);
        expect(r.detail).toBe('error 10 at 0 depth lookup: certificate has expired');
        expect(classifyVerify({ status: 0, stdout: 'leaf.crt: OK (not really)\n', stderr: '' }).ok).toBe(false);
        expect(classifyVerify({ status: null, stdout: '', stderr: 'spawn failed' })).toEqual({ ok: false, detail: 'spawn failed' });
    });

    it('req -verify: the self-signature line, on either stream', () => {
        expect(classifyReqVerify({ status: 0, stdout: '', stderr: 'Certificate request self-signature verify OK\n' }).ok).toBe(true);
        expect(classifyReqVerify({ status: 0, stdout: 'verify OK\n', stderr: '' }).ok).toBe(true);
        expect(classifyReqVerify({ status: 1, stdout: '', stderr: 'Certificate request self-signature verify failure\n' })).toEqual({ ok: false, detail: 'Certificate request self-signature verify failure' });
    });

    it('cms -verify: the verdict is on stderr', () => {
        expect(classifyCmsVerify({ status: 0, stdout: '', stderr: 'CMS Verification successful\n' })).toEqual({ ok: true, detail: 'CMS Verification successful' });
        expect(classifyCmsVerify({ status: 4, stdout: '', stderr: 'Verification failure\n80000000:error:17800065:CMS routines:cms_signerinfo_verify_cert:certificate verify error\n' }).ok).toBe(false);
        expect(classifyCmsVerify({ status: 0, stdout: 'CMS Verification successful', stderr: '' }).ok).toBe(false);
    });

    it('dumps: exit 0 and the marker in stdout', () => {
        const judge = classifyDump(/Serial Number:/);
        expect(judge({ status: 0, stdout: 'OCSP Request Data:\n    Serial Number: 1001\n', stderr: '' })).toEqual({ ok: true, detail: 'Serial Number: present' });
        expect(judge({ status: 0, stdout: 'nothing', stderr: '' })).toEqual({ ok: false, detail: 'Serial Number: not found in the dump' });
        expect(judge({ status: 1, stdout: '', stderr: 'unable to load request\n' })).toEqual({ ok: false, detail: 'unable to load request' });
    });
});
