/**
 * Seeded fuzzing helpers — deterministic by construction (ported from
 * pdfnative-mcp tests/_fuzz.ts).
 *
 * A fuzz suite that uses `Math.random()` finds a bug once and never again.
 * Every generator here draws from mulberry32 with a fixed seed, so a failure
 * reproduces on every machine from the case number alone, and the suite has
 * the same cost on every run. No dependency: the PRNG is eight lines.
 */

/** mulberry32: a small, well-distributed 32-bit PRNG. */
export function prng(seed: number): () => number {
    let a = seed >>> 0;
    return () => {
        a = (a + 0x6d2b79f5) >>> 0;
        let t = a;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

export interface Rng {
    readonly next: () => number;
    readonly int: (min: number, max: number) => number;
    readonly bool: (p?: number) => boolean;
    readonly pick: <T>(items: readonly T[]) => T;
    readonly some: <T>(items: readonly T[]) => T[];
    readonly float: (min: number, max: number) => number;
}

export function rng(seed: number): Rng {
    const next = prng(seed);
    const int = (min: number, max: number): number => min + Math.floor(next() * (max - min + 1));
    return {
        next,
        int,
        bool: (p = 0.5) => next() < p,
        pick: <T>(items: readonly T[]): T => items[int(0, items.length - 1)] as T,
        some: <T>(items: readonly T[]): T[] => items.filter(() => next() < 0.5),
        float: (min, max) => min + next() * (max - min),
    };
}

/** Values that break naive validators: wrong types, extremes, prototype keys, odd strings, PKI look-alikes. */
export const HOSTILE_VALUES: readonly unknown[] = [
    null, true, false, 0, -1, 1, 1.5, -0, 1e21, -1e21, Number.MAX_SAFE_INTEGER, NaN, Infinity,
    '', ' ', 'null', 'undefined', '__proto__', 'constructor', 'prototype', '0', '-1', '1e9',
    'now', 'random', 'none', '2027-13-01T00:00:00Z', '2027-01-01', '0x', '0xZZ', 'abc', 'ab', 'A'.repeat(65),
    '1.2.840.113549', '1..2', '.1.2', '2.5.4.3.', 'SHA-1', 'sha256', 'MD5',
    '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n', '-----BEGIN PRIVATE KEY-----', 'MIIB', 'data:application/pkix-cert;base64,MIIB',
    '\u0000', '\u202e', '\ud800', 'a'.repeat(300), '<script>', '../../etc/passwd', 'C:\\Windows\\system32', '//server/share', 'fixtures/../../x.pem',
    [], [0], [''], ['x'], [null], [{}], Array.from({ length: 300 }, () => 'x'),
    {}, { __proto__: null }, { constructor: 1 }, { length: 4 }, { pem: '' }, { derBase64: '' }, { path: '' }, { pem: 'x', derBase64: 'x' }, { pem: 'x', path: 'x' },
];

const ERROR_LINE = / failed \[([A-Z][A-Z0-9_]+)\]: /;

export interface FuzzResult {
    readonly isError?: boolean;
    readonly content: ReadonlyArray<{ readonly type: string; readonly text?: string }>;
    readonly _meta?: Record<string, unknown>;
}

/** The ToolError code of a failed call, or null when the failure carries none (an unexpected throw). */
export function errorCodeOf(result: FuzzResult): string | null {
    const meta = (result._meta?.['error'] as { code?: string } | undefined)?.code;
    if (meta !== undefined) return meta;
    const text = result.content.find((c) => c.type === 'text')?.text ?? '';
    return ERROR_LINE.exec(text)?.[1] ?? null;
}

/** Flip, truncate or overwrite bytes of a buffer, deterministically. */
export function mutate(bytes: Uint8Array, r: Rng): Uint8Array {
    const out = new Uint8Array(bytes);
    switch (r.int(0, 5)) {
        case 0: // truncate
            return out.subarray(0, r.int(0, Math.max(0, out.length - 1)));
        case 1: // flip a few bytes anywhere
            for (let i = 0; i < r.int(1, 8); i++) out[r.int(0, out.length - 1)] = r.int(0, 255);
            return out;
        case 2: // corrupt the head (tags and lengths of the outer SEQUENCEs live there)
            for (let i = 0; i < r.int(1, 6); i++) out[r.int(0, Math.min(out.length - 1, 31))] = r.int(0, 255);
            return out;
        case 3: // zero a window
            out.fill(0, r.int(0, out.length - 1), r.int(0, out.length));
            return out;
        case 4: { // inflate a length octet (a claimed length past the buffer, or a long-form length with many octets)
            const at = r.int(1, Math.min(out.length - 1, 15));
            out[at] = r.pick([0x80, 0x84, 0x88, 0xff, 0x7f]);
            return out;
        }
        default: { // duplicate a slice at the end (trailing data)
            const at = r.int(0, out.length - 1);
            return new Uint8Array([...out, ...out.subarray(at, Math.min(out.length, at + r.int(1, 64)))]);
        }
    }
}
