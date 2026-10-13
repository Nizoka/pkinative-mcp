/**
 * Tests for `src/resources.ts` — the sandbox exposed as pkinative://output/
 * resources: listing (recursive, sorted, bounded, never a key-bearing file),
 * reading (text or blob, never key material, inside the real sandbox) and
 * the URI helpers.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, promises as fs, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { MAX_LISTED_RESOURCES, MAX_RESOURCE_READ_BYTES, MAX_RESOURCE_WALK_DEPTH } from '../src/caps.js';
import { ToolError } from '../src/errors.js';
import { listResources, listResourceTemplates, mimeTypeFor, readResource, resourceLinkForPath, resourceUriForPath, RESOURCE_URI_PREFIX } from '../src/resources.js';
import { SECRET_EXTENSIONS } from '../src/sandbox.js';
import { assertNoSecret } from './_pki-assert.js';
import { fixture, fixtureBytes, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

function probeLinks(): { file: boolean; dir: boolean } {
    const base = mkdtempSync(path.join(os.tmpdir(), 'pkinative-mcp-res-probe-'));
    const target = mkdtempSync(path.join(os.tmpdir(), 'pkinative-mcp-res-target-'));
    const out = { file: false, dir: false };
    try {
        writeFileSync(path.join(target, 't.txt'), 'x');
        try {
            symlinkSync(path.join(target, 't.txt'), path.join(base, 'f.txt'), 'file');
            out.file = true;
        } catch {
            /* no privilege */
        }
        try {
            symlinkSync(target, path.join(base, 'd'), process.platform === 'win32' ? 'junction' : 'dir');
            out.dir = true;
        } catch {
            /* no privilege */
        }
    } finally {
        rmSync(base, { recursive: true, force: true });
        rmSync(target, { recursive: true, force: true });
    }
    return out;
}

const LINKS = probeLinks();

async function rejectionOf(p: Promise<unknown>): Promise<ToolError> {
    try {
        await p;
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to reject');
}

describe('without a sandbox', () => {
    it('lists nothing, offers no template, maps no path', async () => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        expect(await listResources()).toEqual([]);
        expect(listResourceTemplates()).toEqual([]);
        expect(resourceUriForPath('/anywhere/x.crt')).toBeNull();
        expect(resourceLinkForPath('/anywhere/x.crt')).toBeNull();
        const err = await rejectionOf(readResource(`${RESOURCE_URI_PREFIX}x.crt`));
        expect(err.code).toBe('SECURITY_VIOLATION');
    });
});

describe('helpers', () => {
    it('RESOURCE_URI_PREFIX and mimeTypeFor by extension (case-insensitive, octet-stream when unknown)', () => {
        expect(RESOURCE_URI_PREFIX).toBe('pkinative://output/');
        const table: Array<[string, string]> = [
            ['a.pem', 'application/x-pem-file'], ['a.pub', 'application/x-pem-file'], ['a.crt', 'application/pkix-cert'], ['a.cer', 'application/pkix-cert'], ['a.der', 'application/pkix-cert'],
            ['a.csr', 'application/pkcs10'], ['a.p10', 'application/pkcs10'], ['a.crl', 'application/pkix-crl'], ['a.p7s', 'application/pkcs7-signature'], ['a.p7b', 'application/pkcs7-mime'],
            ['a.p7c', 'application/pkcs7-mime'], ['a.p7m', 'application/pkcs7-mime'], ['a.cms', 'application/pkcs7-mime'], ['a.orq', 'application/ocsp-request'], ['a.ocsp', 'application/ocsp-response'],
            ['a.ors', 'application/ocsp-response'], ['a.tsq', 'application/timestamp-query'], ['a.tsr', 'application/timestamp-reply'], ['a.tst', 'application/vnd.etsi.timestamp-token'],
            ['a.bin', 'application/octet-stream'], ['a.asn1', 'application/octet-stream'], ['a.md', 'text/markdown'], ['a.txt', 'text/plain'], ['a.json', 'application/json'],
            ['a.CRT', 'application/pkix-cert'], ['dir/a.PeM', 'application/x-pem-file'], ['a.unknownext', 'application/octet-stream'], ['noext', 'application/octet-stream'],
            ['a.key', 'application/octet-stream'], ['a.p12', 'application/octet-stream'],
        ];
        for (const [name, mime] of table) expect(mimeTypeFor(name), name).toBe(mime);
    });

    it('resourceUriForPath / resourceLinkForPath map an absolute sandbox path and refuse the rest', async () => {
        const dir = await makeSandbox();
        try {
            expect(resourceUriForPath(path.join(dir, 'sub', 'a.crt'))).toBe(`${RESOURCE_URI_PREFIX}sub/a.crt`);
            expect(resourceLinkForPath(path.join(dir, 'sub', 'a.crt'))).toEqual({ uri: `${RESOURCE_URI_PREFIX}sub/a.crt`, name: 'sub/a.crt', title: 'a.crt', mimeType: 'application/pkix-cert' });
            expect(resourceLinkForPath(path.join(dir, 'leaf.pem'))).toEqual({ uri: `${RESOURCE_URI_PREFIX}leaf.pem`, name: 'leaf.pem', title: 'leaf.pem', mimeType: 'application/x-pem-file' });
            expect(resourceUriForPath(path.join(os.tmpdir(), 'outside.crt'))).toBeNull();
            expect(resourceUriForPath(path.join(dir, '..', 'sibling.crt'))).toBeNull();
            expect(resourceUriForPath(dir)).toBeNull();
            expect(resourceLinkForPath(dir)).toBeNull();
        } finally {
            await cleanupSandbox(dir);
        }
    });

    it('listResourceTemplates describes the address space and names the sandbox variable', async () => {
        const dir = await makeSandbox();
        try {
            const templates = listResourceTemplates();
            expect(templates).toHaveLength(1);
            expect(templates[0]).toMatchObject({ uriTemplate: `${RESOURCE_URI_PREFIX}{+path}`, name: 'sandbox-file', mimeType: 'application/pkix-cert' });
            expect(templates[0]?.description).toContain('PKINATIVE_MCP_OUTPUT_DIR');
            expect(templates[0]?.description).toContain('.key .p8 .p12 .pfx');
        } finally {
            await cleanupSandbox(dir);
        }
    });
});

describe('listResources', () => {
    let sandbox: string | null = null;

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    it('lists regular files recursively, sorted, with MIME and size, and NEVER a key-bearing file', async () => {
        sandbox = await makeSandbox();
        await fs.mkdir(path.join(sandbox, 'nested', 'deep'), { recursive: true });
        await fs.mkdir(path.join(sandbox, 'empty'));
        await fs.copyFile(fixture('leaf.crt.pem'), path.join(sandbox, 'leaf.crt.pem'));
        await fs.copyFile(fixture('root.crt.der'), path.join(sandbox, 'nested', 'root.crt.der'));
        await fs.copyFile(fixture('inter.crl.der'), path.join(sandbox, 'nested', 'deep', 'inter.crl'));
        await fs.writeFile(path.join(sandbox, 'notes.md'), '# notes');
        await fs.writeFile(path.join(sandbox, 'data.unknown'), 'x');
        for (const ext of SECRET_EXTENSIONS) await fs.copyFile(fixture('leaf.key.pem'), path.join(sandbox, `secret${ext}`));
        await fs.copyFile(fixture('leaf.p12'), path.join(sandbox, 'nested', 'bundle.PFX'));
        const resources = await listResources();
        expect(resources.map((r) => r.uri)).toEqual([
            `${RESOURCE_URI_PREFIX}data.unknown`,
            `${RESOURCE_URI_PREFIX}leaf.crt.pem`,
            `${RESOURCE_URI_PREFIX}nested/deep/inter.crl`,
            `${RESOURCE_URI_PREFIX}nested/root.crt.der`,
            `${RESOURCE_URI_PREFIX}notes.md`,
        ]);
        expect(resources[1]).toEqual({ uri: `${RESOURCE_URI_PREFIX}leaf.crt.pem`, name: 'leaf.crt.pem', title: 'leaf.crt.pem', description: 'File at leaf.crt.pem (1005 bytes) in the pkinative-mcp sandbox.', mimeType: 'application/x-pem-file', size: 1005 });
        expect(resources[2]).toMatchObject({ name: 'nested/deep/inter.crl', title: 'inter.crl', mimeType: 'application/pkix-crl' });
        expect(resources[3]).toMatchObject({ name: 'nested/root.crt.der', title: 'root.crt.der', mimeType: 'application/pkix-cert', size: 471 });
        expect(resources[0]?.mimeType).toBe('application/octet-stream');
        expect(resources[4]?.mimeType).toBe('text/markdown');
        expect(JSON.stringify(resources)).not.toMatch(/secret\.|bundle\.PFX/i);
        assertNoSecret(JSON.stringify(resources));
    });

    it('stops at MAX_RESOURCE_WALK_DEPTH and MAX_LISTED_RESOURCES', async () => {
        sandbox = await makeSandbox();
        // A file whose directory sits at the walk depth is listed; one level deeper is not.
        const segments = Array.from({ length: MAX_RESOURCE_WALK_DEPTH + 1 }, (_, i) => `d${i + 1}`);
        await fs.mkdir(path.join(sandbox, ...segments), { recursive: true });
        await fs.writeFile(path.join(sandbox, ...segments.slice(0, MAX_RESOURCE_WALK_DEPTH), 'at-depth.crt'), 'x');
        await fs.writeFile(path.join(sandbox, ...segments, 'too-deep.crt'), 'x');
        const depth = await listResources();
        expect(depth.map((r) => r.name)).toEqual([`${segments.slice(0, MAX_RESOURCE_WALK_DEPTH).join('/')}/at-depth.crt`]);
        // The count cap.
        await fs.mkdir(path.join(sandbox, 'many'));
        await Promise.all(Array.from({ length: MAX_LISTED_RESOURCES + 5 }, (_, i) => fs.writeFile(path.join(sandbox as string, 'many', `f${String(i).padStart(4, '0')}.crt`), 'x')));
        const capped = await listResources();
        expect(capped).toHaveLength(MAX_LISTED_RESOURCES);
        expect(capped.map((r) => r.name)).toEqual([...capped.map((r) => r.name)].sort());
    }, 60_000);
});

describe('readResource', () => {
    let sandbox: string | null = null;

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    it('text for PEM / md / txt / json, a base64 blob for DER; URI-encoded paths decode', async () => {
        sandbox = await makeSandbox();
        await fs.mkdir(path.join(sandbox, 'my dir'));
        await fs.copyFile(fixture('leaf.crt.pem'), path.join(sandbox, 'my dir', 'leaf.crt.pem'));
        await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'leaf.crt.der'));
        await fs.copyFile(fixture('leaf.pub.pem'), path.join(sandbox, 'leaf.pub'));
        await fs.writeFile(path.join(sandbox, 'notes.md'), '# notes');
        await fs.writeFile(path.join(sandbox, 'notes.txt'), 'plain');
        await fs.writeFile(path.join(sandbox, 'data.json'), '{"a":1}');
        expect(await readResource(`${RESOURCE_URI_PREFIX}my%20dir/leaf.crt.pem`)).toEqual({ uri: `${RESOURCE_URI_PREFIX}my%20dir/leaf.crt.pem`, mimeType: 'application/x-pem-file', text: fixtureText('leaf.crt.pem') });
        expect(await readResource(`${RESOURCE_URI_PREFIX}my dir/leaf.crt.pem`)).toMatchObject({ text: fixtureText('leaf.crt.pem') });
        const der = await readResource(`${RESOURCE_URI_PREFIX}leaf.crt.der`);
        expect(der).toEqual({ uri: `${RESOURCE_URI_PREFIX}leaf.crt.der`, mimeType: 'application/pkix-cert', blob: Buffer.from(fixtureBytes('leaf.crt.der')).toString('base64') });
        expect(der).not.toHaveProperty('text');
        expect(await readResource(`${RESOURCE_URI_PREFIX}leaf.pub`)).toMatchObject({ mimeType: 'application/x-pem-file', text: fixtureText('leaf.pub.pem') });
        expect(await readResource(`${RESOURCE_URI_PREFIX}notes.md`)).toMatchObject({ mimeType: 'text/markdown', text: '# notes' });
        expect(await readResource(`${RESOURCE_URI_PREFIX}notes.txt`)).toMatchObject({ mimeType: 'text/plain', text: 'plain' });
        expect(await readResource(`${RESOURCE_URI_PREFIX}data.json`)).toMatchObject({ mimeType: 'application/json', text: '{"a":1}' });
    });

    it('UNKNOWN_RESOURCE for a bad scheme, an empty path, a missing file or a directory', async () => {
        sandbox = await makeSandbox();
        await fs.mkdir(path.join(sandbox, 'folder'));
        for (const uri of ['file:///etc/passwd', 'zipnative://output/x.crt', 'pkinative://x.crt', RESOURCE_URI_PREFIX, `${RESOURCE_URI_PREFIX}missing.crt`, `${RESOURCE_URI_PREFIX}folder`]) {
            const err = await rejectionOf(readResource(uri));
            expect(err.code, uri).toBe('UNKNOWN_RESOURCE');
            expect(err.message, uri).not.toContain(sandbox);
        }
    });

    it('SECURITY_VIOLATION for an escape, a key-bearing extension, and a PEM holding a private key', async () => {
        sandbox = await makeSandbox();
        await fs.copyFile(fixture('leaf.key.pem'), path.join(sandbox, 'x.pem'));
        await fs.copyFile(fixture('leaf.key.enc.pem'), path.join(sandbox, 'enc.txt'));
        await fs.copyFile(fixture('rsa.key.pem'), path.join(sandbox, 'notes.md'));
        await fs.copyFile(fixture('leaf.key.pem'), path.join(sandbox, 'leaf.key'));
        await fs.copyFile(fixture('leaf.p12'), path.join(sandbox, 'leaf.p12'));
        for (const uri of [`${RESOURCE_URI_PREFIX}../escape.crt`, `${RESOURCE_URI_PREFIX}..%2Fescape.crt`, `${RESOURCE_URI_PREFIX}/etc/passwd`, `${RESOURCE_URI_PREFIX}C:%5Cx.crt`, `${RESOURCE_URI_PREFIX}a%00b.crt`]) {
            expect((await rejectionOf(readResource(uri))).code, uri).toBe('SECURITY_VIOLATION');
        }
        for (const ext of SECRET_EXTENSIONS) {
            const err = await rejectionOf(readResource(`${RESOURCE_URI_PREFIX}leaf${ext}`));
            expect(err.code, ext).toBe('SECURITY_VIOLATION');
            expect(err.message, ext).toContain('never served');
            expect(err.data, ext).toEqual({ remedy: 'inspect_private_key' });
        }
        expect((await rejectionOf(readResource(`${RESOURCE_URI_PREFIX}LEAF.P12`))).code).toBe('SECURITY_VIOLATION');
        for (const name of ['x.pem', 'enc.txt', 'notes.md']) {
            const err = await rejectionOf(readResource(`${RESOURCE_URI_PREFIX}${name}`));
            expect(err.code, name).toBe('SECURITY_VIOLATION');
            expect(err.message, name).toContain('private-key PEM block');
            assertNoSecret(JSON.stringify({ message: err.message, data: err.data }), name);
        }
        // The listing still shows the mislabelled files (a listing is not a read); the key-bearing extensions never appear.
        expect((await listResources()).map((r) => r.name)).toEqual(['enc.txt', 'notes.md', 'x.pem']);
    });

    it('OUTPUT_TOO_LARGE above the read cap, decided on the size before any read', async () => {
        sandbox = await makeSandbox();
        const big = path.join(sandbox, 'big.bin');
        const handle = await fs.open(big, 'w');
        try {
            await handle.truncate(MAX_RESOURCE_READ_BYTES + 1);
        } finally {
            await handle.close();
        }
        const err = await rejectionOf(readResource(`${RESOURCE_URI_PREFIX}big.bin`));
        expect(err.code).toBe('OUTPUT_TOO_LARGE');
        expect(err.message).toContain(String(MAX_RESOURCE_READ_BYTES));
        expect((await listResources()).map((r) => [r.name, r.size])).toEqual([['big.bin', MAX_RESOURCE_READ_BYTES + 1]]);
    });

    it.skipIf(!LINKS.dir)('a directory link pointing outside the sandbox is refused on read (the listing never follows it either)', async () => {
        sandbox = await makeSandbox();
        const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'pkinative-mcp-res-outside-'));
        try {
            await fs.copyFile(fixture('leaf.crt.der'), path.join(outside, 'secret.crt'));
            await fs.symlink(outside, path.join(sandbox, 'jump'), process.platform === 'win32' ? 'junction' : 'dir');
            const err = await rejectionOf(readResource(`${RESOURCE_URI_PREFIX}jump/secret.crt`));
            expect(err.code).toBe('SECURITY_VIOLATION');
            expect(err.message).toContain('real location');
            expect(err.message).not.toContain(outside);
            // A link that stays inside is fine.
            await fs.mkdir(path.join(sandbox, 'real'));
            await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'real', 'in.crt'));
            await fs.symlink(path.join(sandbox, 'real'), path.join(sandbox, 'alias'), process.platform === 'win32' ? 'junction' : 'dir');
            expect((await readResource(`${RESOURCE_URI_PREFIX}alias/in.crt`)).mimeType).toBe('application/pkix-cert');
        } finally {
            await fs.rm(outside, { recursive: true, force: true });
        }
    });

    it.skipIf(!LINKS.file)('a FILE symlink pointing outside the sandbox is refused on read', async () => {
        sandbox = await makeSandbox();
        const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'pkinative-mcp-res-outside-'));
        try {
            await fs.copyFile(fixture('leaf.crt.der'), path.join(outside, 'secret.crt'));
            await fs.symlink(path.join(outside, 'secret.crt'), path.join(sandbox, 'link.crt'), 'file');
            expect((await rejectionOf(readResource(`${RESOURCE_URI_PREFIX}link.crt`))).code).toBe('SECURITY_VIOLATION');
        } finally {
            await fs.rm(outside, { recursive: true, force: true });
        }
    });
});
