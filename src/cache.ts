/**
 * Opt-in content-addressed response cache for pkinative-mcp.
 *
 * Enabled by setting the environment variable `PKINATIVE_MCP_CACHE_DIR` to a
 * writable directory. When disabled (env unset), every cache call short-circuits
 * to a miss and incurs zero filesystem I/O — guaranteeing zero-side-effect
 * behaviour for the default install.
 *
 * Design:
 *   - Key = SHA-256 of canonical JSON `{ tool, apiVersion, input }`.
 *   - Stored entries are JSON files (`<key>.json`) of the form
 *     `{ tool, apiVersion, createdAt, value }` plus an `.lock` discipline
 *     of last-modified time (mtime) used by the LRU eviction sweep.
 *   - TTL: 1 hour (3600 s) per entry.
 *   - Cap: 256 MiB across all `<key>.json` files combined; LRU eviction
 *     by mtime runs whenever a `set` would push the dir past the cap.
 *   - Outputs that write to the sandbox (outputMode='file') are NOT cached,
 *     because the produced filesystem side-effect is part of the contract.
 *   - The cache is purely local; no PII is hashed into the key besides the
 *     caller's input (which the caller already controls).
 *
 * Failure model: every IO error degrades to a transparent miss. The cache MUST
 * never throw an error visible to the MCP client.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { CACHE_MAX_BYTES, CACHE_TTL_SECONDS } from './caps.js';
import { carriesSecret } from './secrets.js';

const ENV_VAR = 'PKINATIVE_MCP_CACHE_DIR';
const TTL_SECONDS = CACHE_TTL_SECONDS;
const MAX_BYTES = CACHE_MAX_BYTES;

interface CacheEntry<V> {
    readonly tool: string;
    readonly apiVersion: string;
    readonly createdAt: number;
    readonly value: V;
}

let warned = false;

function getCacheDir(): string | null {
    const raw = process.env[ENV_VAR];
    if (raw === undefined || raw === '') return null;
    const resolved = resolve(raw);
    try {
        if (!existsSync(resolved)) mkdirSync(resolved, { recursive: true });
        return resolved;
        /* v8 ignore next 7 */
    } catch (err) {
        if (!warned) {
            warned = true;
            process.stderr.write(`[pkinative-mcp] cache disabled: cannot create ${ENV_VAR}=${resolved}: ${err instanceof Error ? err.message : String(err)}\n`);
        }
        return null;
    }
}

/** Stable, deterministic JSON: sort object keys recursively. Arrays preserve order. */
function canonicalize(input: unknown): string {
    return JSON.stringify(input, (_, value): unknown => {
        if (value !== null && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Uint8Array)) {
            const obj = value as Record<string, unknown>;
            const sorted: Record<string, unknown> = {};
            for (const key of Object.keys(obj).sort()) sorted[key] = obj[key];
            return sorted;
        }
        return value;
    });
}

/**
 * True when a secret (a `password`, a `signer`) sits anywhere in the cache
 * input, at any depth the server wraps it (`{ input, pinnedInstant }`). The
 * cache gate of src/server.ts (`isCacheable`) already refuses such a call;
 * this is the local invariant of the key: a secret is never hashed, so the
 * key — a content address, not a password hash — can never be derived from one.
 */
function holdsSecret(value: unknown, depth = 0): boolean {
    if (depth > 4 || value === null || typeof value !== 'object') return false;
    if (Array.isArray(value)) return value.some((v) => holdsSecret(v, depth + 1));
    if (carriesSecret(value)) return true;
    return Object.values(value as Record<string, unknown>).some((v) => holdsSecret(v, depth + 1));
}

/** The content address of a call: SHA-256 of the canonical JSON of `{ tool, apiVersion, input }` — never computed over a secret. */
function computeKey(tool: string, apiVersion: string, input: unknown): string {
    const payload = canonicalize({ tool, apiVersion, input });
    return createHash('sha256').update(payload).digest('hex');
}

/** Resolve to a cached value, or `null` on miss/disabled/expired — and always `null` for an input holding a secret. */
export function getCached<V>(tool: string, apiVersion: string, input: unknown): V | null {
    const dir = getCacheDir();
    if (dir === null || holdsSecret(input)) return null;
    const key = computeKey(tool, apiVersion, input);
    const file = join(dir, `${key}.json`);
    if (!existsSync(file)) return null;
    try {
        const stat = statSync(file);
        const ageSeconds = (Date.now() - stat.mtimeMs) / 1000;
        if (ageSeconds > TTL_SECONDS) {
            try { unlinkSync(file); } catch { /* ignore */ }
            return null;
        }
        const parsed = JSON.parse(readFileSync(file, 'utf8')) as CacheEntry<V>;
        return parsed.value;
        /* v8 ignore next 3 */
    } catch {
        return null;
    }
}

/** Persist a value to the cache. Silently no-ops on disabled / IO errors, and never writes for an input holding a secret. */
export function setCached<V>(tool: string, apiVersion: string, input: unknown, value: V): void {
    const dir = getCacheDir();
    if (dir === null || holdsSecret(input)) return;
    const key = computeKey(tool, apiVersion, input);
    const file = join(dir, `${key}.json`);
    const entry: CacheEntry<V> = { tool, apiVersion, createdAt: Date.now(), value };
    try {
        writeFileSync(file, JSON.stringify(entry), 'utf8');
        enforceCapacity(dir);
        /* v8 ignore next 3 */
    } catch {
        // swallow
    }
}

/** Evict oldest entries (by mtime) until total dir size <= MAX_BYTES. */
function enforceCapacity(dir: string): void {
    try {
        const files = readdirSync(dir)
            .filter((f) => f.endsWith('.json'))
            .map((f) => {
                const full = join(dir, f);
                const s = statSync(full);
                return { full, size: s.size, mtime: s.mtimeMs };
            })
            .sort((a, b) => a.mtime - b.mtime);
        let total = files.reduce((sum, e) => sum + e.size, 0);
        for (const entry of files) {
            if (total <= MAX_BYTES) break;
            try {
                unlinkSync(entry.full);
                total -= entry.size;
                /* v8 ignore next 3 */
            } catch {
                // ignore
            }
        }
        /* v8 ignore next 3 */
    } catch {
        // ignore
    }
}

/** Test-only: reset the warned flag so test suites can re-trigger the warning path. */
export function _resetForTests(): void {
    warned = false;
}
