/**
 * The needle table of the secret-leak tests.
 *
 * Every value is computed from the fixtures at load time, never written as a
 * literal: the raw PEM body of each private key, its DER as hex and base64,
 * the private scalar in hex / base64 / base64url (the JWK `d`), the body of
 * the encrypted key and the password. A needle found anywhere in a result,
 * on stderr, in a cache file or in a transcript is a leak.
 */
import { createPrivateKey } from 'node:crypto';

import { fixtureBytes, fixtureText, PASSWORD } from './_pki-fixtures.js';

const KEY_FIXTURES = ['leaf.key.pem', 'rsa.key.pem', 'ed25519.key.pem'] as const;

function pemBody(text: string): string {
    return text.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

function scalarNeedles(pem: string): string[] {
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

function build(): readonly string[] {
    const needles = new Set<string>([PASSWORD]);
    for (const name of KEY_FIXTURES) {
        const pem = fixtureText(name);
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
    const derKey = Buffer.from(fixtureBytes('leaf.key.der'));
    needles.add(derKey.toString('hex'));
    needles.add(derKey.toString('base64'));
    const enc = pemBody(fixtureText('leaf.key.enc.pem'));
    needles.add(enc);
    needles.add(enc.slice(0, 48));
    const rsaEnc = pemBody(fixtureText('rsa.key.enc.pem'));
    needles.add(rsaEnc.slice(0, 48));
    return [...needles].filter((n) => n.length >= 8);
}

/** Every secret-bearing string the fixtures can leak. */
export const SECRET_NEEDLES: readonly string[] = build();

/** The first needle found in `text`, or null. Case-insensitive for hex. */
export function findNeedle(text: string): string | null {
    const lower = text.toLowerCase();
    for (const n of SECRET_NEEDLES) {
        if (text.includes(n)) return n;
        if (/^[0-9a-f]+$/.test(n) && lower.includes(n)) return n;
    }
    return null;
}
