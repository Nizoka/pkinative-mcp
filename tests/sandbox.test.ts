/**
 * Tests for `src/sandbox.ts` — the single filesystem boundary: every read
 * and write resolves against PKINATIVE_MCP_OUTPUT_DIR, refuses NUL /
 * absolute / UNC / traversal paths, enforces the extension allow-lists,
 * never writes a key-bearing file, never overwrites (`wx`), and re-checks
 * the real path of the file (reads) and of the parent (writes) so a planted
 * symlink or junction cannot redirect I/O outside the sandbox.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, promises as fs, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { SecurityError, ToolError } from '../src/errors.js';
import {
    assertAncestorInside,
    assertRealpathInside,
    discardPartial,
    ensureParent,
    getOutputSandbox,
    hasAllowedExtension,
    isSecretPath,
    mapWriteError,
    openExclusiveWriteStream,
    OUTPUT_DIR_ENV,
    OUTPUT_EXTENSIONS,
    PKI_INPUT_EXTENSIONS,
    relativeLabel,
    openSandboxFile,
    readExactly,
    readInputFile,
    resolveOutputFile,
    resolveSandboxPath,
    SECRET_EXTENSIONS,
    TEXT_OUTPUT_EXTENSIONS,
    writeExclusive,
} from '../src/sandbox.js';
import { fixture } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox, SANDBOX_ENV } from './_sandbox.js';

/** Whether this host lets the test process create file symlinks and directory links (win32 without Developer Mode refuses file symlinks). */
function probeLinks(): { file: boolean; dir: boolean } {
    const base = mkdtempSync(path.join(os.tmpdir(), 'pkinative-mcp-link-probe-'));
    const target = mkdtempSync(path.join(os.tmpdir(), 'pkinative-mcp-link-target-'));
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
const DIR_LINK_KIND = process.platform === 'win32' ? 'junction' : 'dir';

async function rejectionOf(p: Promise<unknown>): Promise<ToolError> {
    try {
        await p;
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to reject');
}

function thrown(fn: () => unknown): ToolError {
    try {
        fn();
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to throw');
}

describe('constants', () => {
    it('names the canonical environment variable and partitions the extensions', () => {
        expect(OUTPUT_DIR_ENV).toBe('PKINATIVE_MCP_OUTPUT_DIR');
        expect(OUTPUT_DIR_ENV).toBe(SANDBOX_ENV);
        expect(SECRET_EXTENSIONS).toEqual(['.key', '.p8', '.p12', '.pfx']);
        for (const ext of SECRET_EXTENSIONS) {
            expect(PKI_INPUT_EXTENSIONS, ext).toContain(ext);
            expect(OUTPUT_EXTENSIONS, ext).not.toContain(ext);
        }
        expect(OUTPUT_EXTENSIONS).toEqual(PKI_INPUT_EXTENSIONS.filter((e) => !SECRET_EXTENSIONS.includes(e)));
        expect(OUTPUT_EXTENSIONS).toContain('.pem');
        expect(OUTPUT_EXTENSIONS).toContain('.crt');
        expect(TEXT_OUTPUT_EXTENSIONS).toEqual(['.md', '.txt', '.json', '.pem']);
        expect(PKI_INPUT_EXTENSIONS.every((e) => e.startsWith('.') && e === e.toLowerCase())).toBe(true);
    });

    it('isSecretPath / hasAllowedExtension are case-insensitive suffix checks', () => {
        expect(isSecretPath('a/leaf.key')).toBe(true);
        expect(isSecretPath('a/LEAF.P12')).toBe(true);
        expect(isSecretPath('a/bundle.pfx')).toBe(true);
        expect(isSecretPath('a/key.p8')).toBe(true);
        expect(isSecretPath('a/leaf.key.pem')).toBe(false);
        expect(isSecretPath('a/leaf.crt')).toBe(false);
        expect(hasAllowedExtension('x/y.CRT', PKI_INPUT_EXTENSIONS)).toBe(true);
        expect(hasAllowedExtension('x/y.exe', PKI_INPUT_EXTENSIONS)).toBe(false);
        expect(hasAllowedExtension('x/y', [])).toBe(false);
    });
});

describe('sandbox resolution', () => {
    let sandbox: string | null = null;

    beforeEach(async () => {
        sandbox = await makeSandbox('pkinative-mcp-sandbox-');
    });
    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    it('resolves the variable to an absolute directory; blank means disabled', () => {
        expect(getOutputSandbox()).toBe(path.resolve(sandbox as string));
        process.env[OUTPUT_DIR_ENV] = '   ';
        expect(getOutputSandbox()).toBeNull();
        delete process.env[OUTPUT_DIR_ENV];
        expect(getOutputSandbox()).toBeNull();
    });

    it('sandbox unset → SECURITY_VIOLATION on every entry point, naming the variable', async () => {
        delete process.env[OUTPUT_DIR_ENV];
        expect(() => resolveOutputFile('a.crt')).toThrow(SecurityError);
        expect(() => resolveSandboxPath('a')).toThrow(SecurityError);
        expect(thrown(() => resolveOutputFile('a.crt')).message).toContain(OUTPUT_DIR_ENV);
        expect((await rejectionOf(readInputFile('a.crt', null))).code).toBe('SECURITY_VIOLATION');
        expect((await rejectionOf(assertRealpathInside(os.tmpdir()))).code).toBe('SECURITY_VIOLATION');
        expect((await rejectionOf(assertAncestorInside(os.tmpdir()))).code).toBe('SECURITY_VIOLATION');
        expect((await rejectionOf(ensureParent(path.join(os.tmpdir(), 'x', 'y.crt'), 'x/y.crt'))).code).toBe('SECURITY_VIOLATION');
        expect((await rejectionOf(writeExclusive(path.join(os.tmpdir(), 'x.crt'), new Uint8Array([1]), 'x.crt'))).code).toBe('SECURITY_VIOLATION');
        expect((await rejectionOf(openExclusiveWriteStream(path.join(os.tmpdir(), 'x.crt'), 'x.crt'))).code).toBe('SECURITY_VIOLATION');
    });

    it('rejects a NUL byte', async () => {
        expect(() => resolveOutputFile('foo\0bar.crt')).toThrow(SecurityError);
        expect(() => resolveSandboxPath('foo\0bar')).toThrow(SecurityError);
        expect((await rejectionOf(readInputFile('foo\0bar.crt', null))).code).toBe('SECURITY_VIOLATION');
    });

    it('rejects absolute, drive-letter and UNC paths (both separators, on every platform)', async () => {
        for (const p of ['C:\\x\\evil.crt', 'C:/x/evil.crt', '\\\\server\\share\\evil.crt', '/etc/passwd', path.join(sandbox as string, 'inside.crt')]) {
            expect(() => resolveOutputFile(p), p).toThrow(SecurityError);
            expect(() => resolveSandboxPath(p), p).toThrow(SecurityError);
            expect((await rejectionOf(readInputFile(p, null))).code, p).toBe('SECURITY_VIOLATION');
        }
    });

    it("rejects '..' traversal and the sandbox root itself; a '..' that stays inside is fine", () => {
        expect(() => resolveOutputFile('../escape.crt')).toThrow(SecurityError);
        expect(() => resolveOutputFile('sub/../../escape.crt')).toThrow(SecurityError);
        expect(() => resolveSandboxPath('..')).toThrow(SecurityError);
        expect(() => resolveSandboxPath('.')).toThrow(SecurityError);
        expect(() => resolveSandboxPath('sub/..')).toThrow(SecurityError);
        expect(() => resolveSandboxPath('')).toThrow(ToolError);
        expect(thrown(() => resolveOutputFile('../escape.crt')).message).toContain('escapes the sandbox');
        expect(resolveSandboxPath('a/../b')).toBe(path.join(sandbox as string, 'b'));
        expect(resolveOutputFile('a/../b.crt')).toBe(path.join(sandbox as string, 'b.crt'));
    });

    it('rejects an empty or non-string path with INVALID_PATH', () => {
        for (const bad of ['', undefined, 42, null, {}]) {
            expect(thrown(() => resolveOutputFile(bad)).code, String(bad)).toBe('INVALID_PATH');
            expect(thrown(() => resolveSandboxPath(bad)).code, String(bad)).toBe('INVALID_PATH');
        }
        expect(thrown(() => resolveOutputFile('', OUTPUT_EXTENSIONS, 'draftPath')).message).toContain('draftPath');
    });

    it('resolveOutputFile enforces the extension allow-list (INVALID_EXTENSION) and accepts every output extension in any case', () => {
        const err = thrown(() => resolveOutputFile('notes.exe'));
        expect(err.code).toBe('INVALID_EXTENSION');
        expect(err.message).toContain('.crt');
        expect(err.data).toEqual({ extensions: OUTPUT_EXTENSIONS });
        for (const ext of OUTPUT_EXTENSIONS) {
            expect(resolveOutputFile(`out/file${ext.toUpperCase()}`), ext).toBe(path.join(sandbox as string, 'out', `file${ext.toUpperCase()}`));
        }
        expect(resolveOutputFile('drafts/issue.md', ['.md'])).toBe(path.join(sandbox as string, 'drafts', 'issue.md'));
        expect(thrown(() => resolveOutputFile('drafts/issue.txt', ['.md'], 'draftPath')).message).toContain('draftPath');
        expect(resolveOutputFile('x.pem', TEXT_OUTPUT_EXTENSIONS)).toBe(path.join(sandbox as string, 'x.pem'));
    });

    it('resolveOutputFile refuses a key-bearing extension with SECURITY_VIOLATION even when the allow-list names it', () => {
        for (const ext of SECRET_EXTENSIONS) {
            const err = thrown(() => resolveOutputFile(`out/key${ext}`, [...OUTPUT_EXTENSIONS, ...SECRET_EXTENSIONS]));
            expect(err.code, ext).toBe('SECURITY_VIOLATION');
            expect(err).toBeInstanceOf(SecurityError);
            expect(err.message, ext).toContain('never writes private keys');
            expect(thrown(() => resolveOutputFile(`KEY${ext.toUpperCase()}`)).code, ext).toBe('SECURITY_VIOLATION');
        }
    });

    it('readInputFile honours PKI_INPUT_EXTENSIONS (or none) and reports INPUT_NOT_FOUND for a missing file or a directory', async () => {
        const dir = sandbox as string;
        expect((await rejectionOf(readInputFile('in.exe', PKI_INPUT_EXTENSIONS))).code).toBe('INVALID_EXTENSION');
        const missing = await rejectionOf(readInputFile('nope.crt', PKI_INPUT_EXTENSIONS, 'certificate.path'));
        expect(missing.code).toBe('INPUT_NOT_FOUND');
        expect(missing.message).toContain('certificate.path');
        expect(missing.message).toContain("'nope.crt'");
        expect(missing.message).not.toContain(dir);
        expect(missing.data).toEqual({ path: 'nope.crt', remedy: 'resources/list' });
        await fs.mkdir(path.join(dir, 'folder.crt'));
        const folder = await rejectionOf(readInputFile('folder.crt', PKI_INPUT_EXTENSIONS));
        expect(folder.code).toBe('INPUT_NOT_FOUND');
        expect(folder.message).toContain('not a regular file');
        await fs.copyFile(fixture('leaf.crt.der'), path.join(dir, 'leaf.crt.der'));
        const read = await readInputFile('leaf.crt.der', PKI_INPUT_EXTENSIONS);
        expect(read.resolved).toBe(path.join(dir, 'leaf.crt.der'));
        expect(Buffer.from(read.bytes).equals(await fs.readFile(fixture('leaf.crt.der')))).toBe(true);
        // `before` sees the size and the resolved path once the file is open and proven, before any byte is read.
        const seen: Array<[number, string]> = [];
        await readInputFile('leaf.crt.der', PKI_INPUT_EXTENSIONS, 'certificate.path', (size, resolved) => { seen.push([size, resolved]); });
        expect(seen).toEqual([[701, path.join(dir, 'leaf.crt.der')]]);
        const capped = await rejectionOf(readInputFile('leaf.crt.der', PKI_INPUT_EXTENSIONS, 'certificate.path', () => { throw new ToolError('INPUT_TOO_LARGE', 'cap'); }));
        expect(capped.code).toBe('INPUT_TOO_LARGE');
        // No allow-list: any name (content.path semantics).
        await fs.writeFile(path.join(dir, 'payload.bin.whatever'), Buffer.alloc(10));
        expect((await readInputFile('payload.bin.whatever', null, 'content.path')).bytes).toEqual(new Uint8Array(10));
        // Backslashes resolve on win32 and stay inside on POSIX (a file name there).
        if (process.platform === 'win32') {
            await fs.mkdir(path.join(dir, 'sub'));
            await fs.copyFile(fixture('leaf.crt.der'), path.join(dir, 'sub', 'leaf.crt.der'));
            expect((await readInputFile('sub\\leaf.crt.der', PKI_INPUT_EXTENSIONS)).bytes.byteLength).toBe(701);
            expect((await rejectionOf(readInputFile('..\\leaf.crt.der', PKI_INPUT_EXTENSIONS))).code).toBe('SECURITY_VIOLATION');
        }
    });

    it.skipIf(!LINKS.file)('readInputFile: a dangling symlink is INPUT_NOT_FOUND', async () => {
        await fs.symlink(path.join(sandbox as string, 'gone.crt'), path.join(sandbox as string, 'dangling.crt'), 'file');
        expect((await rejectionOf(readInputFile('dangling.crt', null))).code).toBe('INPUT_NOT_FOUND');
    });

    it('openSandboxFile / readExactly: one open handle — the size and the bytes are those of the same file, a file that grew or shrank under the read is IO_ERROR, a directory is not-a-file, nothing is absent', async () => {
        const dir = sandbox as string;
        await fs.copyFile(fixture('leaf.crt.der'), path.join(dir, 'held.crt'));
        await fs.mkdir(path.join(dir, 'folder'));
        expect(await openSandboxFile(path.join(dir, 'nope.crt'))).toBe('absent');
        expect(await openSandboxFile(path.join(dir, 'folder'))).toBe('not-a-file');
        const opened = await openSandboxFile(path.join(dir, 'held.crt'), 'certificate.path');
        expect(opened).not.toBeTypeOf('string');
        const { handle, size } = opened as { handle: import('node:fs').promises.FileHandle; size: number };
        try {
            expect(size).toBe(701);
            // Grown after the open (another writer appended): the announced size no longer describes the bytes.
            await fs.appendFile(path.join(dir, 'held.crt'), Buffer.from([0x00]));
            const grew = await rejectionOf(readExactly(handle, size, "certificate.path 'held.crt'"));
            expect(grew.code).toBe('IO_ERROR');
            expect(grew.message).toContain('grew');
            expect(grew.message).not.toContain(dir);
            // Shrunk: a short read is the same refusal.
            await fs.truncate(path.join(dir, 'held.crt'), 100);
            const shrank = await rejectionOf(readExactly(handle, size, "certificate.path 'held.crt'"));
            expect(shrank.code).toBe('IO_ERROR');
            expect(shrank.message).toContain('shrank');
            // Back to the announced size: exactly those bytes.
            await fs.copyFile(fixture('leaf.crt.der'), path.join(dir, 'held.crt'));
            expect(Buffer.from(await readExactly(handle, size)).equals(await fs.readFile(fixture('leaf.crt.der')))).toBe(true);
            // Announcing fewer bytes than the file holds is a growth too: the probe byte past `size` is read.
            expect((await rejectionOf(readExactly(handle, 0))).code).toBe('IO_ERROR');
        } finally {
            await handle.close();
        }
        // An empty file is exactly zero bytes.
        await fs.writeFile(path.join(dir, 'empty.crt'), new Uint8Array(0));
        expect((await readInputFile('empty.crt', PKI_INPUT_EXTENSIONS)).bytes.byteLength).toBe(0);
    });

    it.skipIf(!LINKS.file)('readInputFile: a FILE symlink inside the sandbox pointing outside is SECURITY_VIOLATION (the real path of the file itself is checked)', async () => {
        const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'pkinative-mcp-outside-'));
        try {
            await fs.copyFile(fixture('leaf.crt.der'), path.join(outside, 'secret.crt'));
            await fs.symlink(path.join(outside, 'secret.crt'), path.join(sandbox as string, 'link.crt'), 'file');
            const err = await rejectionOf(readInputFile('link.crt', PKI_INPUT_EXTENSIONS, 'certificate.path'));
            expect(err.code).toBe('SECURITY_VIOLATION');
            expect(err.message).toContain('real location');
            expect(err.message).toContain("'link.crt'");
            expect(err.message).not.toContain(outside);
            expect(err.message).not.toContain(sandbox as string);
        } finally {
            await fs.rm(outside, { recursive: true, force: true });
        }
    });

    it.skipIf(!LINKS.dir)('a link that stays INSIDE the sandbox is fine (the check is about the real location, not the link)', async () => {
        const dir = sandbox as string;
        await fs.mkdir(path.join(dir, 'real'));
        await fs.copyFile(fixture('leaf.crt.der'), path.join(dir, 'real', 'in.crt'));
        await fs.symlink(path.join(dir, 'real'), path.join(dir, 'alias'), DIR_LINK_KIND);
        expect((await readInputFile('alias/in.crt', PKI_INPUT_EXTENSIONS)).bytes.byteLength).toBe(701);
        await expect(assertRealpathInside(path.join(dir, 'alias'))).resolves.toBeUndefined();
        await expect(assertAncestorInside(path.join(dir, 'alias', 'new', 'x.crt'))).resolves.toBeUndefined();
    });

    it('relativeLabel is POSIX-style relative to the sandbox (basename when disabled)', () => {
        expect(relativeLabel(path.join(sandbox as string, 'a', 'b.crt'))).toBe('a/b.crt');
        expect(relativeLabel(path.join(sandbox as string, 'b.crt'))).toBe('b.crt');
        delete process.env[OUTPUT_DIR_ENV];
        expect(relativeLabel(path.join(sandbox as string, 'a', 'b.crt'))).toBe('b.crt');
    });
});

describe('exclusive writes', () => {
    let sandbox: string | null = null;

    beforeEach(async () => {
        sandbox = await makeSandbox('pkinative-mcp-write-');
    });
    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    it('writeExclusive creates parent directories and never overwrites (OUTPUT_EXISTS); discardPartial is silent', async () => {
        const target = path.join(sandbox as string, 'deep', 'er', 'file.crt');
        await writeExclusive(target, new Uint8Array([7, 8]), 'deep/er/file.crt');
        expect([...(await fs.readFile(target))]).toEqual([7, 8]);
        const err = await rejectionOf(writeExclusive(target, new Uint8Array([9]), 'deep/er/file.crt'));
        expect(err.code).toBe('OUTPUT_EXISTS');
        expect(err.message).toContain("'deep/er/file.crt'");
        expect(err.message).toContain('never overwrites');
        expect(err.message).not.toContain(sandbox as string);
        expect(err.data).toEqual({ path: 'deep/er/file.crt' });
        expect([...(await fs.readFile(target))]).toEqual([7, 8]);
        await discardPartial(target);
        await expect(fs.stat(target)).rejects.toThrow();
        await discardPartial(target); // already gone: silent
    });

    it('ensureParent maps a file in the way of the parent directory to a wrapper code without the absolute path', async () => {
        const dir = sandbox as string;
        await fs.writeFile(path.join(dir, 'blocker'), 'x');
        const err = await rejectionOf(ensureParent(path.join(dir, 'blocker', 'child.crt'), 'blocker/child.crt'));
        // `mkdir -p` over a file is EEXIST on win32 (→ OUTPUT_EXISTS) and ENOTDIR on POSIX (→ IO_ERROR with the errno).
        expect(['IO_ERROR', 'OUTPUT_EXISTS']).toContain(err.code);
        expect(err.message).toContain("'blocker/child.crt'");
        expect(err.message).not.toContain(dir);
        expect(err.data).toMatchObject({ path: 'blocker/child.crt' });
        if (err.code === 'IO_ERROR') expect(typeof err.data?.['errno']).toBe('string');
    });

    it('openExclusiveWriteStream + discardPartial: the streamed primitive refuses an existing file without touching it', async () => {
        const dir = sandbox as string;
        const target = path.join(dir, 'streamed', 'out.p7s');
        const stream = await openExclusiveWriteStream(target, 'streamed/out.p7s');
        await new Promise<void>((resolve, reject) => stream.end(Buffer.from([1, 2, 3]), (err?: Error | null) => (err ? reject(err) : resolve())));
        expect([...(await fs.readFile(target))]).toEqual([1, 2, 3]);
        const err = await rejectionOf(openExclusiveWriteStream(target, 'streamed/out.p7s'));
        expect(err.code).toBe('OUTPUT_EXISTS');
        expect(err.data).toEqual({ path: 'streamed/out.p7s' });
        expect([...(await fs.readFile(target))]).toEqual([1, 2, 3]);
        await discardPartial(target);
        await expect(fs.stat(target)).rejects.toThrow();
    });

    it('IO_ERROR: an unwritable file name is mapped without leaking the absolute path', async () => {
        // win32 refuses '<' in a file name (EINVAL); POSIX refuses a 300-byte name (ENAMETOOLONG).
        const bad = process.platform === 'win32' ? 'bad<name>.crt' : `${'a'.repeat(300)}.crt`;
        const resolved = resolveOutputFile(bad);
        const err = await rejectionOf(writeExclusive(resolved, new Uint8Array([1]), bad));
        expect(err.code).toBe('IO_ERROR');
        expect(err.message).toContain(bad);
        expect(err.message).not.toContain(sandbox as string);
        expect(err.data?.['path']).toBe(bad);
        expect(typeof err.data?.['errno']).toBe('string');
        const streamed = await rejectionOf(openExclusiveWriteStream(resolved, bad));
        expect(streamed.code).toBe('IO_ERROR');
    });

    it('mapWriteError distinguishes EEXIST from other errnos, elides quoted paths and tolerates non-Error values', () => {
        const exists = Object.assign(new Error('exists'), { code: 'EEXIST' });
        expect(mapWriteError(exists, 'x.crt')).toMatchObject({ code: 'OUTPUT_EXISTS', data: { path: 'x.crt' } });
        const denied = Object.assign(new Error("EACCES: permission denied, open '/secret/place/x.crt'"), { code: 'EACCES' });
        const mapped = mapWriteError(denied, 'x.crt');
        expect(mapped).toBeInstanceOf(ToolError);
        expect(mapped.code).toBe('IO_ERROR');
        expect(mapped.message).not.toContain('/secret/place');
        expect(mapped.message).toContain("'…'");
        expect(mapped.message).toContain('EACCES');
        expect(mapped.data).toEqual({ path: 'x.crt', errno: 'EACCES' });
        const plain = mapWriteError(new Error('no code here'), 'y.crt');
        expect(plain.code).toBe('IO_ERROR');
        expect(plain.message).toContain('error');
        expect(plain.data).toEqual({ path: 'y.crt' });
        expect(mapWriteError('boom', 'z.crt')).toMatchObject({ code: 'IO_ERROR', message: expect.stringContaining('boom'), data: { path: 'z.crt' } });
    });

    it.skipIf(!LINKS.dir)('a symlinked / junction DIRECTORY pointing outside the sandbox is refused on write (assertRealpathInside, assertAncestorInside, ensureParent, writeExclusive, the stream)', async () => {
        const dir = sandbox as string;
        const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'pkinative-mcp-outside-'));
        try {
            await fs.symlink(outside, path.join(dir, 'escape'), DIR_LINK_KIND);
            await expect(assertRealpathInside(dir)).resolves.toBeUndefined();
            const direct = await rejectionOf(assertRealpathInside(path.join(dir, 'escape')));
            expect(direct.code).toBe('SECURITY_VIOLATION');
            expect(direct.message).toBe("Refusing outputPath 'escape': its real location (a symlink or junction) is outside the sandbox.");
            expect(direct.message).not.toContain(outside);
            // The deepest EXISTING ancestor is the link: nothing is created under it, not even a directory.
            const ancestor = await rejectionOf(assertAncestorInside(path.join(dir, 'escape', 'new', 'deeper', 'x.crt'), 'outputPath'));
            expect(ancestor.code).toBe('SECURITY_VIOLATION');
            expect((await rejectionOf(ensureParent(path.join(dir, 'escape', 'new', 'x.crt'), 'escape/new/x.crt'))).code).toBe('SECURITY_VIOLATION');
            expect((await rejectionOf(writeExclusive(path.join(dir, 'escape', 'out.crt'), new Uint8Array([1]), 'escape/out.crt'))).code).toBe('SECURITY_VIOLATION');
            expect((await rejectionOf(openExclusiveWriteStream(path.join(dir, 'escape', 'out2.crt'), 'escape/out2.crt'))).code).toBe('SECURITY_VIOLATION');
            await expect(fs.stat(path.join(outside, 'out.crt'))).rejects.toThrow();
            await expect(fs.stat(path.join(outside, 'out2.crt'))).rejects.toThrow();
            await expect(fs.stat(path.join(outside, 'new'))).rejects.toThrow();
            // The read side refuses the same link.
            await fs.copyFile(fixture('leaf.crt.der'), path.join(outside, 'secret.crt'));
            expect((await rejectionOf(readInputFile('escape/secret.crt', PKI_INPUT_EXTENSIONS))).code).toBe('SECURITY_VIOLATION');
            // A regular file next to the link still reads: the guard is about the real path, not the presence of a link.
            await fs.copyFile(fixture('leaf.crt.der'), path.join(dir, 'ok.crt'));
            expect((await readInputFile('ok.crt', PKI_INPUT_EXTENSIONS)).bytes.byteLength).toBe(701);
        } finally {
            await fs.rm(outside, { recursive: true, force: true });
        }
    });
});

describe.skipIf(process.platform !== 'win32')('win32 edge cases', () => {
    let sandbox: string | null = null;

    beforeEach(async () => {
        sandbox = await makeSandbox('pkinative-mcp-win32-');
    });
    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    it('a case-folded name collision on NTFS is OUTPUT_EXISTS (the server never overwrites)', async () => {
        await writeExclusive(resolveOutputFile('Report.crt'), new Uint8Array([1]), 'Report.crt');
        const err = await rejectionOf(writeExclusive(resolveOutputFile('report.crt'), new Uint8Array([2]), 'report.crt'));
        expect(err.code).toBe('OUTPUT_EXISTS');
        expect((await fs.readFile(path.join(sandbox as string, 'Report.crt')))[0]).toBe(1);
    });

    it("a reserved device name ('CON.crt') never escapes the sandbox: refused as IO_ERROR / OUTPUT_EXISTS, or (Windows 11) written as a regular file inside it", async () => {
        const dir = sandbox as string;
        const write = (): Promise<void> => writeExclusive(resolveOutputFile('CON.crt'), new Uint8Array([1, 2, 3, 4]), 'CON.crt');
        let first: ToolError | null = null;
        try {
            await write();
        } catch (err) {
            first = err as ToolError;
        }
        if (first !== null) {
            expect(['IO_ERROR', 'OUTPUT_EXISTS']).toContain(first.code);
            expect(first.message).not.toContain(dir);
        } else {
            const st = await fs.stat(path.join(dir, 'CON.crt'));
            expect(st.isFile()).toBe(true);
            expect(st.size).toBe(4);
            expect((await rejectionOf(write())).code).toBe('OUTPUT_EXISTS');
        }
        // The bare device name has no allowed extension and never reaches the filesystem.
        expect(thrown(() => resolveOutputFile('CON')).code).toBe('INVALID_EXTENSION');
    });
});
