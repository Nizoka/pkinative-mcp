/**
 * The OpenSSL-made TEST-ONLY PKI under tests/fixtures/pki (see PROVENANCE.md).
 *
 * Every private key here is public test material (password
 * `test-only-password`); the certificates are valid 2026-01-01..2046-01-01, so
 * verdict tests pin `at` to AT.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

export const FIXTURES = resolve(import.meta.dirname, 'fixtures', 'pki');

/** Every fixture name, sorted (42 files pinned by SHA256SUMS). */
export const FIXTURE_FILES: readonly string[] = readdirSync(FIXTURES).sort();

export function fixture(name: string): string {
    return join(FIXTURES, name);
}

export function fixtureBytes(name: string): Uint8Array {
    return new Uint8Array(readFileSync(fixture(name)));
}

export function fixtureBase64(name: string): string {
    return Buffer.from(fixtureBytes(name)).toString('base64');
}

export function fixtureText(name: string): string {
    return readFileSync(fixture(name), 'utf8');
}

/** `{ pem }` or `{ derBase64 }` input fragment for a fixture, by extension. */
export function fixtureInput(name: string): { pem: string } | { derBase64: string } {
    return name.endsWith('.pem') ? { pem: fixtureText(name) } : { derBase64: fixtureBase64(name) };
}

/** 2027-01-01T00:00:00Z: inside the fixtures' validity window. */
export const AT = '2027-01-01T00:00:00Z';

/** The password of every encrypted fixture (PKCS#8 PBES2 and PKCS#12). */
export const PASSWORD = 'test-only-password';
