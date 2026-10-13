import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { FIXTURE_FILES } from './_pki-fixtures.js';
import { findNeedle, SECRET_NEEDLES } from './_secrets.js';

const ROOT = 'tests/fixtures';

/** sha256 of tests/fixtures/SHA256SUMS as copied from pkinative-cli 1.0.0. */
const SUMS_SHA256 = '86fbaff94260378157a339c5d4578734d13dbbe953eead884456445a81f7b8d5';

describe('fixtures', () => {
    const pinned = new Map(
        readFileSync(join(ROOT, 'SHA256SUMS'), 'utf8').trim().split('\n').map((line) => {
            const [sum, path] = line.split(/\s+/) as [string, string];
            return [path, sum];
        }),
    );

    it('pins every file under pki/ and nothing else', () => {
        const present = readdirSync(join(ROOT, 'pki')).map((f) => `pki/${f}`).sort();
        expect([...pinned.keys()].sort()).toEqual(present);
        expect(FIXTURE_FILES.length).toBe(42);
    });

    it('holds every fixture to its checksum', () => {
        for (const [path, sum] of pinned) {
            const actual = createHash('sha256').update(readFileSync(join(ROOT, path))).digest('hex');
            expect(actual, path).toBe(sum);
        }
    });

    it('is the byte-identical copy of the pkinative-cli 1.0.0 fixture set', () => {
        // The SUMS file itself is pinned so the copy can never drift from the
        // CLI's set; a new fixture is a new file with a new entry here.
        const sums = createHash('sha256').update(readFileSync(join(ROOT, 'SHA256SUMS'))).digest('hex');
        expect(sums).toBe(SUMS_SHA256);
    });

    it('stores text fixtures with LF line endings', () => {
        for (const path of pinned.keys()) {
            if (!/\.(pem|txt)$/.test(path)) continue;
            expect(readFileSync(join(ROOT, path), 'utf8').includes('\r'), path).toBe(false);
        }
    });

    it('documents every fixture family in PROVENANCE.md', () => {
        const doc = readFileSync(join(ROOT, 'PROVENANCE.md'), 'utf8');
        for (const path of pinned.keys()) {
            const stem = path.replace(/^pki\//, '').split('.')[0] as string;
            expect(doc.includes(stem), stem).toBe(true);
        }
    });

    it('derives a secret-needle table that recognises every private key form', () => {
        expect(SECRET_NEEDLES.length).toBeGreaterThan(20);
        expect(findNeedle(readFileSync(join(ROOT, 'pki/leaf.key.pem'), 'utf8'))).not.toBeNull();
        expect(findNeedle(Buffer.from(readFileSync(join(ROOT, 'pki/leaf.key.der'))).toString('hex').toUpperCase())).not.toBeNull();
        expect(findNeedle(readFileSync(join(ROOT, 'pki/leaf.crt.pem'), 'utf8'))).toBeNull();
        expect(findNeedle('test-only-password')).toBe('test-only-password');
    });
});
