/**
 * The single filesystem boundary of the server.
 *
 * Every path a tool reads (a `path` member of a PKI input, a `content.path`)
 * or writes (`outputPath`, governance drafts) resolves through this module
 * against the one operator-configured directory `PKINATIVE_MCP_OUTPUT_DIR`.
 * Unset ⇒ every file input and output is disabled and the tools work on
 * inline PEM / base64 only. The guards are the ones the sibling servers apply
 * (NUL bytes, absolute / UNC paths, `..` traversal, extension allow-list) plus
 * a realpath check on the file itself for every read and on the parent for
 * every write, so a symlink or junction planted inside the sandbox cannot
 * redirect I/O outside it.
 *
 * Key material is special: the sandbox never WRITES a private key or a
 * PKCS#12 file (the engine has no writer for them — doctrine), and the
 * resource layer never serves one (see src/resources.ts).
 */
import { promises as fs, createWriteStream, type WriteStream } from 'node:fs';
import path from 'node:path';

import { SecurityError, ToolError } from './errors.js';

/** Canonical environment variable naming the sandbox directory. */
export const OUTPUT_DIR_ENV = 'PKINATIVE_MCP_OUTPUT_DIR';

/** Detect Windows absolute and UNC paths even when running on POSIX CI. */
const WINDOWS_ABSOLUTE_OR_UNC = /^(?:[A-Za-z]:[\\/]|\\\\)/;

/**
 * Extensions a PKI input `path` may name. Bounds what the sandbox reads so it
 * never becomes a general file store (`content.path` — bytes to sign or
 * time-stamp — is not subject to it).
 */
export const PKI_INPUT_EXTENSIONS: readonly string[] = [
    '.pem', '.crt', '.cer', '.der', '.csr', '.p10', '.crl', '.p7s', '.p7b', '.p7c', '.p7m', '.cms',
    '.p12', '.pfx', '.key', '.p8', '.pub', '.ocsp', '.ors', '.orq', '.tsq', '.tsr', '.tst', '.bin', '.asn1',
];

/**
 * Extensions a key-bearing file carries. Never written by any tool (no key
 * writer exists), never listed by `resources/list`, refused by
 * `resources/read` — a private key or a PKCS#12 file leaves the sandbox only
 * through the engine's non-extractable Web Crypto import.
 */
export const SECRET_EXTENSIONS: readonly string[] = ['.key', '.p8', '.p12', '.pfx'];

/** Extensions an artefact `outputPath` may name (every PKI extension minus the key-bearing ones). */
export const OUTPUT_EXTENSIONS: readonly string[] = PKI_INPUT_EXTENSIONS.filter((e) => !SECRET_EXTENSIONS.includes(e));

/** Extensions a text artefact may name (governance drafts, PEM bundles). */
export const TEXT_OUTPUT_EXTENSIONS: readonly string[] = ['.md', '.txt', '.json', '.pem'];

/** Returns the configured sandbox directory (absolute), or `null` when file I/O is disabled. */
export function getOutputSandbox(): string | null {
    const raw = process.env[OUTPUT_DIR_ENV];
    if (raw !== undefined && raw.trim() !== '') return path.resolve(raw);
    return null;
}

function requireSandbox(): string {
    const sandbox = getOutputSandbox();
    if (sandbox === null) {
        throw new SecurityError(
            `File input/output is disabled. Set ${OUTPUT_DIR_ENV} to an allow-listed directory to enable path inputs and outputMode='file', or pass the bytes inline (pem / derBase64).`,
        );
    }
    return sandbox;
}

/**
 * Resolve a relative user path inside the sandbox. Shared by every read and
 * write: rejects NUL bytes, absolute / UNC paths and traversal.
 */
function resolveRelative(userPath: unknown, what: string): { sandbox: string; resolved: string } {
    const sandbox = requireSandbox();
    if (typeof userPath !== 'string' || userPath.length === 0) {
        throw new ToolError('INVALID_PATH', `${what} must be a non-empty string.`);
    }
    if (userPath.includes('\0')) {
        throw new SecurityError(`${what} contains a NUL byte.`);
    }
    if (path.isAbsolute(userPath) || WINDOWS_ABSOLUTE_OR_UNC.test(userPath)) {
        throw new SecurityError(`${what} must be relative to the configured sandbox directory.`);
    }
    const resolved = path.resolve(sandbox, userPath);
    const relative = path.relative(sandbox, resolved);
    if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new SecurityError(`${what} '${userPath}' escapes the sandbox directory.`);
    }
    return { sandbox, resolved };
}

export function hasAllowedExtension(resolved: string, extensions: readonly string[]): boolean {
    const lower = resolved.toLowerCase();
    return extensions.some((ext) => lower.endsWith(ext));
}

/** True when the path names a key-bearing file by extension. */
export function isSecretPath(filePath: string): boolean {
    return hasAllowedExtension(filePath, SECRET_EXTENSIONS);
}

/**
 * Resolve a relative output file path. Throws `INVALID_EXTENSION` when the
 * name does not end in one of `extensions`, and `SECURITY_VIOLATION` when it
 * names a key-bearing extension (nothing in this server writes a key).
 */
export function resolveOutputFile(userPath: unknown, extensions: readonly string[] = OUTPUT_EXTENSIONS, what = 'outputPath'): string {
    const { resolved } = resolveRelative(userPath, what);
    if (isSecretPath(resolved)) {
        throw new SecurityError(`${what} must not name a key-bearing file (${SECRET_EXTENSIONS.join(', ')}): this server never writes private keys or PKCS#12 files.`);
    }
    if (!hasAllowedExtension(resolved, extensions)) {
        throw new ToolError('INVALID_EXTENSION', `${what} must end with one of: ${extensions.join(', ')}.`, { extensions });
    }
    return resolved;
}

/** Resolve a relative directory inside the sandbox (resource reads). */
export function resolveSandboxPath(userPath: unknown, what = 'path'): string {
    return resolveRelative(userPath, what).resolved;
}

/**
 * Resolve a relative input file inside the sandbox and stat it. Throws
 * `INPUT_NOT_FOUND` when absent (message carries the relative path only) and
 * `INVALID_EXTENSION` when `extensions` is given and the name does not match.
 */
export async function resolveInputFile(
    userPath: unknown,
    extensions: readonly string[] | null,
    what = 'path',
): Promise<{ resolved: string; size: number }> {
    const { resolved } = resolveRelative(userPath, what);
    if (extensions !== null && !hasAllowedExtension(resolved, extensions)) {
        throw new ToolError('INVALID_EXTENSION', `${what} must end with one of: ${extensions.join(', ')}.`, { extensions });
    }
    let stat;
    try {
        stat = await fs.stat(resolved);
    } catch {
        throw new ToolError('INPUT_NOT_FOUND', `${what} '${String(userPath)}' does not exist in the sandbox — list the sandbox with resources/list, or pass the bytes inline.`, { path: String(userPath), remedy: 'resources/list' });
    }
    if (!stat.isFile()) {
        throw new ToolError('INPUT_NOT_FOUND', `${what} '${String(userPath)}' is not a regular file — name a file listed by resources/list.`, { path: String(userPath), remedy: 'resources/list' });
    }
    // The read side gets the same defence in depth as the write side: the REAL
    // location of the file itself (not only its parent — a file symlink would
    // otherwise pass) must live inside the real sandbox, so a pre-planted
    // junction / symlink can never redirect a read outside it.
    await assertRealpathInside(resolved, what);
    return { resolved, size: stat.size };
}

/**
 * Defence in depth for writes under a directory the caller chose: after
 * `mkdir -p`, the *real* path of the parent must still live inside the real
 * sandbox (a pre-existing symlinked directory would otherwise redirect the
 * write). Throws `SECURITY_VIOLATION`.
 */
export async function assertRealpathInside(target: string, what = 'outputPath'): Promise<void> {
    const sandbox = requireSandbox();
    const [realSandbox, realTarget] = await Promise.all([fs.realpath(sandbox), fs.realpath(target)]);
    const relative = path.relative(realSandbox, realTarget);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new SecurityError(`Refusing ${what} '${relativeLabel(target)}': its real location (a symlink or junction) is outside the sandbox.`);
    }
}

/** Map a Node fs error on a write to the wrapper codes (never leaks the absolute path). */
export function mapWriteError(err: unknown, label: string): ToolError {
    const code = err instanceof Error ? (err as NodeJS.ErrnoException).code : undefined;
    if (code === 'EEXIST') {
        return new ToolError('OUTPUT_EXISTS', `'${label}' already exists in the sandbox — the server never overwrites; choose another path.`, { path: label });
    }
    const message = err instanceof Error ? err.message : String(err);
    return new ToolError('IO_ERROR', `Could not write '${label}': ${code ?? 'error'} — ${message.replace(/'[^']*'/g, "'…'")}`, { path: label, ...(code !== undefined ? { errno: code } : {}) });
}

/** Write bytes exclusively (`wx`), creating parent directories. */
export async function writeExclusive(resolved: string, bytes: Uint8Array, label: string): Promise<void> {
    await ensureParent(resolved, label);
    try {
        await fs.writeFile(resolved, bytes, { flag: 'wx' });
    } catch (err) {
        throw mapWriteError(err, label);
    }
}

/**
 * The deepest EXISTING ancestor of a path (the sandbox itself at worst). Checked
 * before any `mkdir -p` so a pre-planted junction / symlink can never cause
 * even an empty directory to be created outside the sandbox.
 */
async function deepestExistingAncestor(target: string): Promise<string> {
    let current = target;
    for (;;) {
        try {
            await fs.stat(current);
            return current;
        } catch {
            const parent = path.dirname(current);
            if (parent === current) return current;
            current = parent;
        }
    }
}

/** Check the real path of the deepest existing ancestor BEFORE creating directories under it. */
export async function assertAncestorInside(target: string, what = 'outputPath'): Promise<void> {
    await assertRealpathInside(await deepestExistingAncestor(target), what);
}

/** Create the parent directory (mapping fs failures such as a file in the way) and check its real path. */
export async function ensureParent(resolved: string, label: string): Promise<void> {
    await assertAncestorInside(path.dirname(resolved));
    try {
        await fs.mkdir(path.dirname(resolved), { recursive: true });
    } catch (err) {
        throw mapWriteError(err, label);
    }
    await assertRealpathInside(path.dirname(resolved));
}

/**
 * Open an exclusive write stream (`wx`) after the same guards. The caller
 * owns the stream and must unlink the file on failure via {@link discardPartial}.
 */
export async function openExclusiveWriteStream(resolved: string, label: string): Promise<WriteStream> {
    await ensureParent(resolved, label);
    const stream = createWriteStream(resolved, { flags: 'wx' });
    await new Promise<void>((resolveOpen, reject) => {
        stream.once('open', () => resolveOpen());
        stream.once('error', (err) => reject(mapWriteError(err, label)));
    });
    return stream;
}

/** Remove a partially written file, ignoring errors (the original failure is what matters). */
export async function discardPartial(resolved: string): Promise<void> {
    try {
        await fs.unlink(resolved);
    } catch {
        /* already gone or never created */
    }
}

/** POSIX-style relative label for messages and resource names. */
export function relativeLabel(resolved: string): string {
    const sandbox = getOutputSandbox();
    if (sandbox === null) return path.basename(resolved);
    return path.relative(sandbox, resolved).split(path.sep).join('/');
}
