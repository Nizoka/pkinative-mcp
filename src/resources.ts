/**
 * Native MCP resources — expose sandboxed files as re-referenceable resource URIs.
 *
 * When the host enables the sandbox (`PKINATIVE_MCP_OUTPUT_DIR`), every
 * regular file under it (certificates and requests the tools wrote, objects
 * the operator dropped in for `path` inputs) becomes an addressable MCP
 * resource under the `pkinative://output/<relative-path>` scheme,
 * discoverable via `resources/list` and fetchable via `resources/read`.
 * File-producing tools additionally emit a `resource_link` to what they wrote.
 *
 * Key material never crosses this layer: a `.key` / `.p8` / `.p12` / `.pfx`
 * file is not listed, and a read of one — or of a PEM text holding a private
 * key — is `SECURITY_VIOLATION`. The engine's non-extractable import is the
 * only door a private key has.
 *
 * State is intentionally minimal and bounded: the server holds no in-memory
 * registry — `resources/list` reflects the live contents of the sandbox
 * directory, and every read is re-validated to stay inside it. When the
 * sandbox is disabled, there are simply no resources.
 */
import { promises as fs, type Dirent, type Stats } from 'node:fs';
import path from 'node:path';

import { MAX_LISTED_RESOURCES, MAX_RESOURCE_READ_BYTES, MAX_RESOURCE_WALK_DEPTH as MAX_WALK_DEPTH } from './caps.js';
import { SecurityError, ToolError } from './errors.js';
import { assertRealpathInside, getOutputSandbox, isSecretPath, resolveSandboxPath } from './sandbox.js';

/** URI scheme + authority for sandboxed resources. */
export const RESOURCE_URI_PREFIX = 'pkinative://output/';

const MIME_BY_EXTENSION: Readonly<Record<string, string>> = {
    '.pem': 'application/x-pem-file',
    '.crt': 'application/pkix-cert',
    '.cer': 'application/pkix-cert',
    '.der': 'application/pkix-cert',
    '.csr': 'application/pkcs10',
    '.p10': 'application/pkcs10',
    '.crl': 'application/pkix-crl',
    '.p7s': 'application/pkcs7-signature',
    '.p7b': 'application/pkcs7-mime',
    '.p7c': 'application/pkcs7-mime',
    '.p7m': 'application/pkcs7-mime',
    '.cms': 'application/pkcs7-mime',
    '.pub': 'application/x-pem-file',
    '.orq': 'application/ocsp-request',
    '.ocsp': 'application/ocsp-response',
    '.ors': 'application/ocsp-response',
    '.tsq': 'application/timestamp-query',
    '.tsr': 'application/timestamp-reply',
    '.tst': 'application/vnd.etsi.timestamp-token',
    '.bin': 'application/octet-stream',
    '.asn1': 'application/octet-stream',
    '.md': 'text/markdown',
    '.txt': 'text/plain',
    '.json': 'application/json',
};

/** MIME types delivered as `text` (not `blob`) by `resources/read`. */
const TEXT_MIME: ReadonlySet<string> = new Set(['application/x-pem-file', 'text/markdown', 'text/plain', 'application/json']);

/** MIME type by extension (`application/octet-stream` when unknown). */
export function mimeTypeFor(filePath: string): string {
    return MIME_BY_EXTENSION[path.extname(filePath).toLowerCase()] ?? 'application/octet-stream';
}

export interface ResourceDescriptor {
    readonly uri: string;
    readonly name: string;
    readonly title: string;
    readonly description: string;
    readonly mimeType: string;
    readonly size: number;
}

export interface ResourceContents {
    readonly uri: string;
    readonly mimeType: string;
    readonly blob?: string;
    readonly text?: string;
}

function uriForRelative(relative: string): string {
    return RESOURCE_URI_PREFIX + relative.split(path.sep).join('/');
}

/** Build the resource URI for an absolute file path if it lives inside the sandbox; otherwise `null`. */
export function resourceUriForPath(absPath: string): string | null {
    const sandbox = getOutputSandbox();
    if (sandbox === null) return null;
    const relative = path.relative(sandbox, absPath);
    if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) return null;
    return uriForRelative(relative);
}

/** Build a `resource_link` descriptor for an absolute sandbox path, or `null` when outside the sandbox. */
export function resourceLinkForPath(absPath: string): { uri: string; name: string; title: string; mimeType: string } | null {
    const uri = resourceUriForPath(absPath);
    if (uri === null) return null;
    const relative = uri.slice(RESOURCE_URI_PREFIX.length);
    return { uri, name: relative, title: relative.split('/').pop() ?? relative, mimeType: mimeTypeFor(absPath) };
}

async function walkFiles(sandbox: string, dir: string, depth: number, out: string[]): Promise<void> {
    if (depth > MAX_WALK_DEPTH || out.length >= MAX_LISTED_RESOURCES) return;
    let entries: Dirent[];
    try {
        entries = await fs.readdir(dir, { withFileTypes: true });
        /* v8 ignore next 3 -- unreadable directory is skipped defensively. */
    } catch {
        return;
    }
    for (const entry of entries) {
        if (out.length >= MAX_LISTED_RESOURCES) return;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            await walkFiles(sandbox, full, depth + 1, out);
        } else if (entry.isFile() && !isSecretPath(entry.name)) {
            out.push(path.relative(sandbox, full));
        }
    }
}

/** List every sandboxed regular file (key-bearing files excluded) as an MCP resource. Empty when the sandbox is disabled. */
export async function listResources(): Promise<ResourceDescriptor[]> {
    const sandbox = getOutputSandbox();
    if (sandbox === null) return [];
    const relatives: string[] = [];
    await walkFiles(sandbox, sandbox, 0, relatives);
    relatives.sort();

    const descriptors: ResourceDescriptor[] = [];
    for (const relative of relatives) {
        let size = 0;
        try {
            size = (await fs.stat(path.join(sandbox, relative))).size;
            /* v8 ignore next 1 -- racing deletion between walk and stat. */
        } catch { /* keep size 0 */ }
        const posix = relative.split(path.sep).join('/');
        descriptors.push({
            uri: uriForRelative(relative),
            name: posix,
            title: path.basename(relative),
            description: `File at ${posix} (${size} bytes) in the pkinative-mcp sandbox.`,
            mimeType: mimeTypeFor(relative),
            size,
        });
    }
    return descriptors;
}

const PRIVATE_KEY_LABEL = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----/;

/**
 * Read a `pkinative://output/<relative>` resource. PEM / Markdown / JSON /
 * text come back as `text`, everything else as a base64 `blob`. Re-validates
 * the path against the sandbox before reading and refuses key material.
 *
 * @throws {ToolError} `UNKNOWN_RESOURCE` for a bad scheme or a missing file;
 *         `SECURITY_VIOLATION` when the path escapes the sandbox or names
 *         key material; `OUTPUT_TOO_LARGE` when the file exceeds the read cap.
 */
export async function readResource(uri: string): Promise<ResourceContents> {
    if (!uri.startsWith(RESOURCE_URI_PREFIX)) {
        throw new ToolError('UNKNOWN_RESOURCE', `Unsupported resource URI: ${uri}`);
    }
    const relative = decodeURIComponent(uri.slice(RESOURCE_URI_PREFIX.length));
    if (relative.length === 0) {
        throw new ToolError('UNKNOWN_RESOURCE', 'Resource URI is missing a path.');
    }
    const resolved = resolveSandboxPath(relative, 'resource path');
    if (isSecretPath(resolved)) {
        throw new SecurityError('Key-bearing files (.key .p8 .p12 .pfx) are never served as resources — open them with inspect_private_key / inspect_pkcs12 / open_pkcs12 instead.', { remedy: 'inspect_private_key' });
    }
    let stat: Stats;
    try {
        stat = await fs.stat(resolved);
    } catch {
        throw new ToolError('UNKNOWN_RESOURCE', `No resource found at ${uri}.`);
    }
    if (!stat.isFile()) {
        throw new ToolError('UNKNOWN_RESOURCE', `No resource found at ${uri}.`);
    }
    if (stat.size > MAX_RESOURCE_READ_BYTES) {
        throw new ToolError('OUTPUT_TOO_LARGE', `Resource ${uri} (${stat.size} bytes) exceeds the maximum read size (${MAX_RESOURCE_READ_BYTES} bytes).`);
    }
    // A pre-planted junction / symlink inside the sandbox must not redirect a read outside it.
    await assertRealpathInside(resolved, 'resource path');
    const bytes = await fs.readFile(resolved);
    const mimeType = mimeTypeFor(resolved);
    if (TEXT_MIME.has(mimeType)) {
        const text = bytes.toString('utf8');
        if (PRIVATE_KEY_LABEL.test(text)) {
            throw new SecurityError('The resource holds a private-key PEM block and is never served — open it with inspect_private_key instead.', { remedy: 'inspect_private_key' });
        }
        return { uri, mimeType, text };
    }
    return { uri, mimeType, blob: bytes.toString('base64') };
}

/** MCP resource template describing the sandbox address space (`resources/templates/list`). */
export interface ResourceTemplate {
    readonly uriTemplate: string;
    readonly name: string;
    readonly title: string;
    readonly description: string;
    readonly mimeType: string;
}

/** Static resource-template list (RFC 6570 reserved expansion). Empty when the sandbox is disabled. */
export function listResourceTemplates(): ResourceTemplate[] {
    if (getOutputSandbox() === null) return [];
    return [
        {
            uriTemplate: `${RESOURCE_URI_PREFIX}{+path}`,
            name: 'sandbox-file',
            title: 'Sandbox file (certificates, requests, signatures, revocation data)',
            description:
                'A certificate, request, CMS signature, CRL, OCSP or time-stamp object written by a tool or placed in the sandbox for a path input, addressed by its path relative to PKINATIVE_MCP_OUTPUT_DIR. Key-bearing files (.key .p8 .p12 .pfx) are never listed or served. Enumerate concrete URIs with resources/list.',
            mimeType: 'application/pkix-cert',
        },
    ];
}
