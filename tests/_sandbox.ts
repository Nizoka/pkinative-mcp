/**
 * Temporary sandbox directories for the file-mode tests: `mkdtemp` under the
 * OS temp dir, exported through `PKINATIVE_MCP_OUTPUT_DIR`, removed (and the
 * variable deleted) by `cleanupSandbox` in every `afterEach`.
 */
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const SANDBOX_ENV = 'PKINATIVE_MCP_OUTPUT_DIR';

/** Create a fresh sandbox and point the server at it. */
export async function makeSandbox(prefix = 'pkinative-mcp-'): Promise<string> {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
    process.env[SANDBOX_ENV] = dir;
    return dir;
}

/** Forget the sandbox (env var deleted) and remove the directory. */
export async function cleanupSandbox(dir: string | null): Promise<void> {
    delete process.env[SANDBOX_ENV];
    if (dir !== null) await fs.rm(dir, { recursive: true, force: true });
}

/** Fill a buffer with a repeating pseudo-random 4 KiB block (compressible, but far from a 1024:1 ratio). */
export function patternBytes(size: number, seed = 7): Uint8Array {
    const block = new Uint8Array(4096);
    let state = seed >>> 0;
    for (let i = 0; i < block.length; i++) {
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
        block[i] = state >>> 24;
    }
    const out = new Uint8Array(size);
    for (let offset = 0; offset < size; offset += block.length) {
        out.set(block.subarray(0, Math.min(block.length, size - offset)), offset);
    }
    return out;
}
