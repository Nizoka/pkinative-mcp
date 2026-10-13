/**
 * The wire form reserved by pkinative ADR 0018 for its satellites (vendored
 * from pkinative-cli `src/utils/wire.ts`):
 *   bigint            → its decimal string
 *   Uint8Array        → its lowercase hexadecimal string
 *   epochMilliseconds → stays a number
 *   absent optional   → omitted
 *   member names      → unchanged
 * Engine results are frozen JavaScript values that JSON.stringify refuses
 * (bigint); toWire() is the one place that turns them into JSON-safe data.
 * A CryptoKey is described, never exported (pkinative makes its keys
 * non-extractable).
 */
import type { webcrypto } from 'node:crypto';

export type Wire = string | number | boolean | null | readonly Wire[] | { readonly [key: string]: Wire };

const HEX: readonly string[] = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

/** Lowercase hexadecimal of a byte array. */
export function toHex(bytes: Uint8Array): string {
    let out = '';
    for (const b of bytes) out += HEX[b] as string;
    return out;
}

/** Parse a hexadecimal string (`:`, spaces and an `0x` prefix tolerated) into bytes. */
export function fromHex(text: string): Uint8Array | undefined {
    const clean = text.trim().replace(/^0x/i, '').replace(/[\s:]/g, '');
    if (clean.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(clean)) return undefined;
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    return out;
}

// Node exposes the class on globalThis (not on node:crypto's webcrypto) from
// the 22.x line the engines field requires.
const CryptoKeyClass = (globalThis as unknown as { CryptoKey: abstract new () => webcrypto.CryptoKey }).CryptoKey;

function isCryptoKey(value: object): value is webcrypto.CryptoKey {
    return value instanceof CryptoKeyClass;
}

/**
 * Convert any engine result into JSON-safe data under the ADR 0018
 * convention. A cycle is a programming error and throws.
 */
export function toWire(value: unknown): Wire {
    return convert(value, new WeakSet());
}

function convert(value: unknown, seen: WeakSet<object>): Wire {
    switch (typeof value) {
        case 'string':
        case 'boolean':
            return value;
        case 'number':
            return Number.isFinite(value) ? value : String(value);
        case 'bigint':
            return value.toString(10);
        case 'object':
            break;
        default:
            // undefined, functions and symbols have no wire form; callers omit them.
            return null;
    }
    if (value === null) return null;
    if (value instanceof Uint8Array) return toHex(value);
    if (seen.has(value)) throw new TypeError('toWire: cyclic value');
    seen.add(value);
    try {
        if (Array.isArray(value)) return value.map((v: unknown) => (v === undefined ? null : convert(v, seen)));
        if (value instanceof Map) {
            const out: Record<string, Wire> = {};
            for (const [k, v] of value as Map<unknown, unknown>) out[String(k)] = convert(v, seen);
            return out;
        }
        if (value instanceof Set) return [...(value as Set<unknown>)].map((v) => convert(v, seen));
        if (isCryptoKey(value)) {
            return { type: value.type, algorithm: value.algorithm.name, extractable: value.extractable, usages: [...value.usages] };
        }
        if (value instanceof Error) {
            const code = (value as { code?: unknown }).code;
            return { name: value.name, message: value.message, ...(typeof code === 'string' ? { code } : {}) };
        }
        const out: Record<string, Wire> = {};
        for (const [k, v] of Object.entries(value)) {
            if (v === undefined || typeof v === 'function' || typeof v === 'symbol') continue;
            out[k] = convert(v, seen);
        }
        return out;
    } finally {
        seen.delete(value);
    }
}

/** `toWire` typed as a plain record for `structuredContent`. */
export function toWireRecord(value: unknown): Record<string, unknown> {
    const wire = toWire(value);
    return (wire !== null && typeof wire === 'object' && !Array.isArray(wire) ? wire : { value: wire }) as Record<string, unknown>;
}
