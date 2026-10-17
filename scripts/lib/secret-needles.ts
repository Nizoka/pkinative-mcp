/**
 * pkinative-mcp — the secret-needle table, recomputed from the fixtures
 * ===================================================================
 * `tests/_secrets.ts` derives, at load time, every string a fixture private
 * key can leak as: the raw PEM body, its DER as hex and base64, the private
 * scalars in every encoding (the JWK members, their hex and base64), the
 * body of each encrypted key and the password. This module is the same
 * derivation for the documentation verifier (`no-secret-material` of
 * scripts/verify-docs.ts), which cannot import `tests/`: scripts never
 * import `src/` or the test helpers, and verify:docs runs before any build.
 *
 * The password is deliberately NOT a needle here: `test-only-password` is
 * public TEST-ONLY material that the documents are allowed — and expected —
 * to quote (tests/fixtures/PROVENANCE.md). Everything else in the table is a
 * key byte in some encoding, and a document, example, release note or draft
 * that carries one has leaked a key.
 */

import { createPrivateKey } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** The plain PKCS#8 keys of the fixture set (tests/_secrets.ts KEY_FIXTURES). */
export const KEY_FIXTURES: readonly string[] = ['leaf.key.pem', 'rsa.key.pem', 'ed25519.key.pem'];
/** The DER key and the two encrypted keys (tests/_secrets.ts build()). */
export const DER_KEY_FIXTURE = 'leaf.key.der';
export const ENCRYPTED_KEY_FIXTURES: readonly string[] = ['leaf.key.enc.pem', 'rsa.key.enc.pem'];

/** Shortest needle kept (tests/_secrets.ts keeps `n.length >= 8`). */
export const MIN_NEEDLE_LENGTH = 8;

export function pemBody(text: string): string {
    return text.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

/** The private scalars of a PEM key in base64url (the JWK members), hex and base64. */
export function scalarNeedles(pem: string): string[] {
    const jwk = createPrivateKey(pem).export({ format: 'jwk' }) as Record<string, string | undefined>;
    const out: string[] = [];
    for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
        const value = jwk[member];
        if (value === undefined || value.length < 16) continue;
        const raw = Buffer.from(value, 'base64url');
        out.push(value, raw.toString('hex'), raw.toString('base64'));
    }
    return out;
}

/**
 * The needle table of a fixture directory, computed exactly as
 * tests/_secrets.ts does (minus the password). Returns `[]` when the
 * directory or one of the key fixtures is absent, so a caller can skip
 * rather than fail.
 */
export function buildSecretNeedles(fixturesDir: string): readonly string[] {
    const needed = [...KEY_FIXTURES, DER_KEY_FIXTURE, ...ENCRYPTED_KEY_FIXTURES];
    if (!existsSync(fixturesDir) || needed.some((n) => !existsSync(join(fixturesDir, n)))) return [];
    const needles = new Set<string>();
    for (const name of KEY_FIXTURES) {
        const pem = readFileSync(join(fixturesDir, name), 'utf8');
        const body = pemBody(pem);
        needles.add(body);
        // A key split across lines: the first 48 characters of the body are
        // enough to recognise it in any wrapped rendering.
        needles.add(body.slice(0, 48));
        const der = Buffer.from(body, 'base64');
        needles.add(der.toString('hex'));
        needles.add(der.toString('hex').slice(0, 64));
        for (const n of scalarNeedles(pem)) needles.add(n);
    }
    const derKey = readFileSync(join(fixturesDir, DER_KEY_FIXTURE));
    needles.add(derKey.toString('hex'));
    needles.add(derKey.toString('base64'));
    const [leafEnc, rsaEnc] = ENCRYPTED_KEY_FIXTURES as [string, string];
    const enc = pemBody(readFileSync(join(fixturesDir, leafEnc), 'utf8'));
    needles.add(enc);
    needles.add(enc.slice(0, 48));
    needles.add(pemBody(readFileSync(join(fixturesDir, rsaEnc), 'utf8')).slice(0, 48));
    return [...needles].filter((n) => n.length >= MIN_NEEDLE_LENGTH);
}

export interface SecretFinding {
    /** Character offset of the match in the text. */
    readonly index: number;
    readonly reason: string;
}

/** `-----BEGIN (EC |RSA |ENCRYPTED )?PRIVATE KEY-----` followed by a base64 body of 40+ characters (whitespace ignored). */
export const PRIVATE_KEY_BLOCK = /-----BEGIN (?:EC |RSA |ENCRYPTED )?PRIVATE KEY-----\s*((?:[A-Za-z0-9+/=]+\s*)+)/g;

/** Paths of the development host that a published document must never carry. */
export const DEV_HOST_PATHS: readonly RegExp[] = [/\bD:\\/g, /\/d\/Github\//g, /\bC:\\Users\\/g];

/**
 * Every secret-material finding in a text: a needle of the table (hex
 * needles match case-insensitively), a private-key PEM block with a real
 * body, or a development-host absolute path.
 */
export function findSecretMaterial(text: string, needles: readonly string[]): SecretFinding[] {
    const out: SecretFinding[] = [];
    const lower = text.toLowerCase();
    for (const n of needles) {
        let at = text.indexOf(n);
        if (at === -1 && /^[0-9a-f]+$/.test(n)) at = lower.indexOf(n);
        if (at !== -1) out.push({ index: at, reason: `carries a fixture private-key needle (${n.slice(0, 12)}…, ${n.length} chars)` });
    }
    PRIVATE_KEY_BLOCK.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = PRIVATE_KEY_BLOCK.exec(text)) !== null) {
        const body = (m[1] as string).replace(/\s+/g, '');
        if (body.length >= 40) out.push({ index: m.index, reason: 'carries a PRIVATE KEY PEM block with a base64 body — documents illustrate keys with an ellipsis, never with bytes' });
    }
    for (const re of DEV_HOST_PATHS) {
        re.lastIndex = 0;
        const hit = re.exec(text);
        if (hit !== null) out.push({ index: hit.index, reason: `carries a development-host absolute path (${hit[0]}…) — documents quote relative paths only` });
    }
    return out.sort((a, b) => a.index - b.index);
}
