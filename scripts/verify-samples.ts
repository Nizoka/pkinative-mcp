#!/usr/bin/env tsx
/**
 * pkinative-mcp — Sample regression gate
 * ========================================
 * Fingerprints every generated sample and compares the result to the
 * committed baseline, so a change anywhere in the server — or in the
 * pkinative engine it pins — that alters existing output is caught before it
 * ships.
 *
 * The baseline is a CHAIN, not a snapshot of the current tree. Each entry
 * records the release whose output its hash is (`since`) and keeps it across
 * every later rebaseline that leaves the sample alone, so 1.1.0 will still be
 * held to the bytes v1.0.0 emitted, and so on. An entry whose hash is
 * deliberately re-anchored moves to the release doing the re-anchoring, which
 * is what makes it visible in review. A sample introduced by the release under
 * development has no earlier reference, so it is reported but does not fail —
 * pass `--strict` to require it to be baselined in the same pull request.
 *
 * Usage:
 *   npm run build && npm run test:generate    # populate test-output/samples/
 *   npm run verify:samples                    # compare against the baseline
 *   npx tsx scripts/verify-samples.ts --update   # rewrite the baseline
 *   npx tsx scripts/verify-samples.ts --strict   # also fail on new samples
 *   npx tsx scripts/verify-samples.ts --json     # machine-readable report
 *
 * (PowerShell swallows a bare `--`, so call the script directly when passing
 * flags rather than `npm run verify:samples -- --update`.)
 *
 * The fingerprinting itself lives in `scripts/lib/sample-fingerprint.ts`
 * (modes bytes / tbs / semantic, chosen by the generator and recorded in
 * test-output/samples/manifest.json).
 *
 * Exit codes:
 *   0 — every sample matches the baseline (or --update rewrote it)
 *   1 — a fingerprint changed, a sample vanished, or (--strict) a new sample
 *       is not in the baseline; no baseline yet
 *   2 — bad usage, or test-output/samples/ is empty (run test:generate first)
 */

// Must be first: pins TZ and scrubs operator knobs.
import './helpers/hermetic.js';

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, relative } from 'node:path';

import {
    REPO_ROOT, BASELINE_PATH, BASELINE_AT,
    fingerprintAll, loadBaseline, compareToBaseline, currentVersion, chainSince, unexpectedDuplicates,
    type Fingerprint, type Baseline,
} from './lib/sample-fingerprint.js';

/** Provenance written only when no manifest exists yet. */
const INITIAL_PROVENANCE =
    'Initial baseline: every entry is anchored to the release that created it. Replace this note '
    + 'with the account of how the entries were verified; later rebaselines carry it forward.';

/**
 * Write the baseline, carrying each sample's `since` forward.
 *
 * The provenance note is the maintainer's account of why each group of
 * entries is anchored where it is. It is carried forward verbatim: an
 * --update must never silently replace it. Edit it by hand in the same
 * commit as the rebaseline it explains.
 */
function saveBaseline(entries: Record<string, Fingerprint>, previous: Baseline | null): void {
    mkdirSync(dirname(BASELINE_PATH), { recursive: true });
    const version = currentVersion();
    const sorted = chainSince(entries, previous, version);
    const payload: Baseline = {
        $comment:
            'Fingerprints of every sample in test-output/samples/ (written by the BUILT server, '
            + 'scripts/generate-samples.ts). Regenerate deliberately with '
            + '`npx tsx scripts/verify-samples.ts --update`, and say why in the release notes: a '
            + 'changed hash means existing output changed. Mode `bytes` is a SHA-256 of the file '
            + '(deterministic artefacts: Ed25519 and RSA PKCS#1 signatures, requests, encodings); mode '
            + '`tbs` is a SHA-256 of the signed part only (ECDSA and RSA-PSS draw a random per '
            + 'signature, so the signature value can never repeat but what was signed must); mode '
            + '`semantic` is a SHA-256 of the canonical JSON of the result without its volatile '
            + 'members (evaluatedAt, sha256, sizeBytes, filePath). Each entry\'s `since` names the '
            + 'release whose output the hash is: it is carried forward untouched while the sample is '
            + 'unchanged, and moves to the release doing the rebaseline when the hash changes, so the '
            + 'chain 1.0.0 -> 1.1.0 -> … stays auditable and every re-anchoring is visible in the diff.',
        baselineVersion: version,
        provenance: previous?.provenance ?? INITIAL_PROVENANCE,
        at: BASELINE_AT,
        timezone: 'UTC',
        entries: sorted,
    };
    writeFileSync(BASELINE_PATH, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

function main(): number {
    const args = process.argv.slice(2);
    for (const a of args) {
        if (a !== '--update' && a !== '--json' && a !== '--strict') {
            console.error(`Unknown argument "${a}". Expected --update, --json and/or --strict.`);
            return 2;
        }
    }
    const update = args.includes('--update');
    const jsonMode = args.includes('--json');
    const strict = args.includes('--strict');

    const { entries, unreadable, unlisted, missing } = fingerprintAll();
    const total = Object.keys(entries).length;
    if (total === 0 && unreadable.length === 0) {
        console.error('test-output/samples/ holds no samples — run `npm run build && npm run test:generate` first.');
        return 2;
    }
    // Two samples meant to show a difference must not be the same file.
    const duplicates = unexpectedDuplicates(entries);

    if (update) {
        if (unreadable.length > 0 || unlisted.length > 0 || missing.length > 0 || duplicates.length > 0) {
            for (const u of unreadable) console.error(`✗ ${u.path}: ${u.error}`);
            for (const m of unlisted) console.error(`✗ ${m}: on disk but not in test-output/samples/manifest.json`);
            for (const m of missing) console.error(`✗ ${m}: in the manifest but not on disk`);
            for (const g of duplicates) console.error(`✗ ${g.join(' == ')}: identical bytes (list the pair in IDENTICAL_SAMPLE_GROUPS if that is intended)`);
            console.error('\nRefusing to write a baseline while samples are unreadable, unlisted, missing or unexpectedly identical.');
            return 1;
        }
        const previous = loadBaseline();
        saveBaseline(entries, previous);
        console.log(`Baseline updated: ${total} samples → ${relative(REPO_ROOT, BASELINE_PATH)}`);
        return 0;
    }

    const baseline = loadBaseline();
    if (baseline === null) {
        console.error(
            `No baseline at ${relative(REPO_ROOT, BASELINE_PATH)}.\n`
            + 'Create it with: npx tsx scripts/verify-samples.ts --update',
        );
        return 1;
    }

    const { changed, added, removed } = compareToBaseline(entries, baseline);

    if (jsonMode) {
        console.log(JSON.stringify({
            baselineVersion: baseline.baselineVersion,
            currentVersion: currentVersion(),
            total, changed, added, removed, unreadable, unlisted, missing, duplicates,
        }, null, 2));
    } else {
        for (const u of unreadable) console.error(`✗ unreadable  ${u.path}: ${u.error}`);
        for (const m of unlisted) console.error(`✗ unlisted    ${m} (on disk, not in the manifest)`);
        for (const m of missing) console.error(`✗ missing     ${m} (in the manifest, not on disk)`);
        for (const g of duplicates) console.error(`✗ identical   ${g.join(' == ')} (a pair meant to differ emits the same bytes)`);
        for (const p of changed) {
            const b = baseline.entries[p] as Fingerprint;
            const c = entries[p] as Fingerprint;
            const sizeNote = b.size === c.size ? `${c.size} B` : `${b.size} B → ${c.size} B`;
            console.error(`✗ changed     ${p}  [${c.mode}]  ${sizeNote}`);
        }
        for (const p of removed) console.error(`✗ disappeared ${p} (in the baseline, not generated)`);
        // A sample introduced by the release under development has no earlier
        // reference to be held to, so it informs rather than blocks. Pass
        // --strict to require the baseline to be updated in the same PR.
        for (const p of added) {
            const line = `${strict ? '✗' : '•'} new         ${p} (no prior reference — rebaseline to start tracking it)`;
            if (strict) console.error(line); else console.log(line);
        }
    }

    const failures = changed.length + removed.length + unreadable.length + unlisted.length + missing.length
        + duplicates.length + (strict ? added.length : 0);
    if (failures === 0) {
        if (!jsonMode) {
            const count = (m: string): number => Object.values(entries).filter((e) => e.mode === m).length;
            const tracked = total - added.length;
            console.log(
                `✓ ${tracked} tracked samples match the baseline `
                + `(${count('bytes')} byte-exact, ${count('tbs')} tbs, ${count('semantic')} semantic)`
                + `${added.length > 0 ? `; ${added.length} new, untracked` : ''}.`,
            );
        }
        return 0;
    }

    if (!jsonMode) {
        console.error(
            `\n${failures} sample(s) diverged from the baseline.\n`
            + 'If the change is intended, say so in the release notes and rebaseline with:\n'
            + '  npm run build && npm run test:generate && npx tsx scripts/verify-samples.ts --update',
        );
    }
    return 1;
}

process.exit(main());
