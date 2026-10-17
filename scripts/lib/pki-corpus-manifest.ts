/**
 * pkinative-mcp — the corpus manifest (`test-output/pki/manifest.json`)
 * ======================================================================
 * Written by scripts/generate-pki-corpus.ts, read by scripts/validate-pki.ts.
 * Pure types and helpers: the generator records what happened to every
 * entry of the table (scripts/lib/pki-corpus.ts) and the validator joins
 * the two by `id`, so a run can be judged without re-running the tools.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { TEST_OUTPUT_DIR } from '../helpers/io.js';

export const CORPUS_DIR = join(TEST_OUTPUT_DIR, 'pki');
export const MANIFEST_PATH = join(CORPUS_DIR, 'manifest.json');

/**
 * What the generator saw:
 *   written        a conformant entry produced its bytes (file + sha256)
 *   refused        a negative canary was refused with the expected code
 *   refused-other  a negative canary was refused, but with another code (a FAIL for the validator)
 *   xpass          a negative canary PRODUCED bytes — the server accepted what it must refuse (fatal)
 *   skipped        the tool (or an entry this one consumes) is not registered yet — never a failure
 *   failed         a conformant entry was refused (the generator exits 1; recorded for the report)
 */
export type EntryStatus = 'written' | 'refused' | 'refused-other' | 'xpass' | 'skipped' | 'failed';

export interface ManifestEntry {
    readonly id: string;
    readonly tool: string;
    readonly kind: string;
    readonly status: EntryStatus;
    /** File name under test-output/pki/ (written and xpass entries). */
    readonly file?: string;
    readonly bytes?: number;
    readonly sha256?: string;
    /** `summary.sha256` of a second production for a deterministic entry (equal to `sha256` when the claim holds). */
    readonly sha256Again?: string;
    readonly deterministic?: boolean;
    readonly expectRefused?: string;
    /** The code a refused / refused-other / failed entry came back with. */
    readonly code?: string;
    /** Why an entry was skipped or failed. */
    readonly reason?: string;
}

export interface CorpusManifest {
    readonly generatedBy: string;
    /** The pinned instant every artefact was produced under (`PKINATIVE_MCP_AT`). */
    readonly at: string;
    readonly serverVersion: string;
    readonly tools: readonly string[];
    readonly entries: readonly ManifestEntry[];
}

export function loadManifest(path: string = MANIFEST_PATH): CorpusManifest | null {
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, 'utf8')) as CorpusManifest;
}

export interface StatusCounts {
    readonly written: number;
    readonly refused: number;
    readonly refusedOther: number;
    readonly xpass: number;
    readonly skipped: number;
    readonly failed: number;
}

export function countStatuses(entries: readonly ManifestEntry[]): StatusCounts {
    const n = (s: EntryStatus): number => entries.filter((e) => e.status === s).length;
    return { written: n('written'), refused: n('refused'), refusedOther: n('refused-other'), xpass: n('xpass'), skipped: n('skipped'), failed: n('failed') };
}

/** The file name of an entry under the corpus directory, by kind. */
export function fileNameFor(id: string, kind: string): string {
    const ext: Record<string, string> = { cert: '.crt', csr: '.csr', 'cms-attached': '.p7s', 'cms-detached': '.p7s', tsq: '.tsq', 'ocsp-req': '.orq', pem: '.pem' };
    return `${id}${ext[kind] ?? '.der'}`;
}
