/**
 * pkinative-mcp — Sample fingerprinting core
 * ============================================
 * Shared by the `verify:samples` script and the vitest regression gate, so
 * both compute the identical fingerprint and there is one definition of what
 * "unchanged output" means. Ported from pdfnative-mcp's
 * scripts/lib/sample-fingerprint.ts; the set here is written by the BUILT
 * server through `callToolDirect()` (scripts/generate-samples.ts →
 * test-output/samples/) from the hermetic `examples/*.json`.
 *
 * Three modes, chosen per sample by the generator (`modeFor`) and recorded in
 * `test-output/samples/manifest.json`, never guessed at verification time:
 *   • `bytes`    — SHA-256 of the file. Every deterministic artefact: an
 *     Ed25519 or RSA PKCS#1 v1.5 signature over pinned inputs (serial, nonce,
 *     instants), every request / encoder output, every PEM re-encoding.
 *   • `tbs`      — SHA-256 of the FIRST element of the outer DER SEQUENCE: the
 *     TBSCertificate / CertificationRequestInfo. ECDSA and RSA-PSS draw a
 *     fresh random per signature (RFC 6979 is not what Web Crypto does), so
 *     the signature value cannot repeat — but what was signed is a pure
 *     function of the pinned inputs, and that is what is held.
 *   • `semantic` — SHA-256 of the canonical JSON of `structuredContent` with
 *     the volatile members removed (`evaluatedAt`, `sha256`, `sizeBytes`,
 *     `filePath`) and the host members neutralised (the Node version and the
 *     platform `describe_engine` probes and `draft_governance_issue` records:
 *     the baseline is made on the maintainer's machine and held on every CI
 *     runner). Every read / verdict result, and a randomised artefact
 *     whose outer structure is not `SEQUENCE { tbs, alg, BIT STRING }` (a CMS
 *     SignedData signed by an EC key, whose SignerInfo signature cannot be
 *     cut out by position).
 */

import { createHash, createPrivateKey } from 'node:crypto';
import { basename } from 'node:path';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { OUTPUT_DIR, REPO_ROOT, SAMPLE_AT } from '../helpers/io.js';

export { OUTPUT_DIR, REPO_ROOT };
export const BASELINE_PATH = join(REPO_ROOT, 'tests', '_fixtures', 'samples.sha256.json');
export const MANIFEST_PATH = join(OUTPUT_DIR, 'manifest.json');

export type FingerprintMode = 'bytes' | 'tbs' | 'semantic';

/** Members of a result that change with the run or the host, never with the behaviour. */
export const VOLATILE_MEMBERS: readonly string[] = ['evaluatedAt', 'sha256', 'sizeBytes', 'filePath'];

/**
 * Members that name the host, not the behaviour, by the object that carries
 * them: `describe_engine.capabilities.node` / `.platform` and
 * `draft_governance_issue.compliance.environment.node` / `.os`. The draft
 * markdown repeats the latter as its `- Node:` / `- OS:` lines (`HOST_LINE`).
 */
export const HOST_MEMBERS: Readonly<Record<string, readonly string[]>> = { capabilities: ['node', 'platform'], environment: ['node', 'os'] };
const HOST_LINE = /^- (Node|OS): .*$/gm;

/** The value with the host members removed and the host lines of every string neutralised, at every depth. */
export function stripHost(value: unknown): unknown {
    if (typeof value === 'string') return value.replace(HOST_LINE, '- $1: <host>');
    if (Array.isArray(value)) return value.map(stripHost);
    if (value === null || typeof value !== 'object') return value;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        const members = HOST_MEMBERS[k];
        if (members !== undefined && v !== null && typeof v === 'object' && !Array.isArray(v)) {
            out[k] = stripHost(Object.fromEntries(Object.entries(v as Record<string, unknown>).filter(([m]) => !members.includes(m))));
        } else {
            out[k] = stripHost(v);
        }
    }
    return out;
}

/** What fingerprinting a sample yields, independent of any baseline. */
export interface Fingerprint {
    readonly mode: FingerprintMode;
    readonly hash: string;
    /** Byte length — informational, and a cheap first signal in diffs. */
    readonly size: number;
}

export interface BaselineEntry extends Fingerprint {
    /**
     * Release whose output this fingerprint captures — the sample's oldest
     * verified reference, carried forward untouched by every later
     * rebaseline. A sample first fingerprinted in 1.0.0 reads `"1.0.0"` and
     * has no earlier reference to be compared against; one that reads
     * `"1.0.0"` in a 1.1.0 baseline is still being held to the bytes v1.0.0
     * emitted.
     */
    readonly since: string;
}

export interface Baseline {
    readonly $comment: string;
    /** Release at which the manifest was last written. */
    readonly baselineVersion: string;
    /** How the oldest entries were verified against the previous release. */
    readonly provenance: string;
    readonly at: string;
    readonly timezone: string;
    readonly entries: Record<string, BaselineEntry>;
}

/** What the generator records about each written file, so the verifier never guesses a mode. */
export interface ManifestEntry {
    readonly mode: FingerprintMode;
    readonly tool: string;
    readonly example: string;
    /** For an artefact in `semantic` mode: the sibling JSON whose projection stands for it. */
    readonly sidecar?: string;
}

export interface SampleManifest {
    readonly generatedBy: string;
    readonly at: string;
    readonly entries: Record<string, ManifestEntry>;
}

/** The version in package.json — stamped on newly baselined samples. */
export function currentVersion(): string {
    const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as { version: string };
    return pkg.version;
}

// ── Helpers ──────────────────────────────────────────────────────────

export function sha256Hex(data: Uint8Array | string): string {
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    return createHash('sha256').update(buf).digest('hex');
}

/** Yield every sample under `dir` (everything but the manifest), depth-first, in a stable order. */
export function* walkSamples(dir: string): Generator<string> {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir).sort()) {
        const p = join(dir, entry);
        if (statSync(p).isDirectory()) yield* walkSamples(p);
        else if (p !== MANIFEST_PATH) yield p;
    }
}

/** Repo-relative, forward-slashed path of a sample under `test-output/samples/`. */
export function relPath(abs: string): string {
    return relative(OUTPUT_DIR, abs).split('\\').join('/');
}

/**
 * Canonical JSON: object keys sorted at every depth, so the projection is
 * insertion-order independent and the hash is stable across runs.
 */
export function canonicalJson(value: unknown): string {
    if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

/**
 * Members whose value came from the wrapper RNG, recognised by the flag the
 * summary sets next to them (`randomSerial: true` → `serialNumber`;
 * `randomNonce: true` → `nonce`, `nonceHex`): an example that asks for
 * `'random'` is a showcase of that option, and what it shows cannot repeat.
 */
const RANDOM_FLAGS: ReadonlyArray<readonly [flag: string, members: readonly string[]]> = [
    ['randomSerial', ['serialNumber']],
    ['randomNonce', ['nonce', 'nonceHex']],
];

/** True when a random flag (`randomSerial` / `randomNonce`) is raised anywhere in the value. */
export function hasRandomFlag(value: unknown, depth = 0): boolean {
    if (depth > 8 || value === null || typeof value !== 'object') return false;
    if (Array.isArray(value)) return value.some((v) => hasRandomFlag(v, depth + 1));
    const obj = value as Record<string, unknown>;
    return RANDOM_FLAGS.some(([flag]) => obj[flag] === true) || Object.values(obj).some((v) => hasRandomFlag(v, depth + 1));
}

/** The value with every volatile member removed, at every depth (and the RNG-derived members next to a raised random flag). */
export function stripVolatile(value: unknown, volatile: readonly string[] = VOLATILE_MEMBERS): unknown {
    if (Array.isArray(value)) return value.map((v) => stripVolatile(v, volatile));
    if (value === null || typeof value !== 'object') return value;
    const obj = value as Record<string, unknown>;
    const random = RANDOM_FLAGS.flatMap(([flag, members]) => (obj[flag] === true ? members : []));
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
        if (!volatile.includes(k) && !random.includes(k)) out[k] = stripVolatile(v, volatile);
    }
    return out;
}

/**
 * The semantic projection of a JSON sample: canonical JSON of the
 * `structuredContent` (the contract; the text block repeats it in prose) —
 * or, for a refusal, of `isError` and the code — without the volatile
 * members and with the host members neutralised. A sequence projects every step.
 */
export function semanticProjection(json: string): string {
    const parsed = JSON.parse(json) as Record<string, unknown>;
    const project = (result: Record<string, unknown>): unknown => {
        const error = (result['_meta'] as { error?: { code?: unknown; message?: unknown } } | undefined)?.error;
        const structured = result['structuredContent'] ?? null;
        // An inline `hex` artefact that drew from the RNG (a random nonce or serial reported in its summary) cannot repeat either.
        const volatile = hasRandomFlag(structured) ? [...VOLATILE_MEMBERS, 'hex'] : VOLATILE_MEMBERS;
        return {
            ...(result['isError'] === true ? { isError: true, code: error?.code ?? null, message: error?.message ?? null } : {}),
            structuredContent: stripHost(stripVolatile(structured, volatile)),
        };
    };
    const steps = parsed['steps'];
    return canonicalJson(Array.isArray(steps) ? { steps: (steps as Record<string, unknown>[]).map(project) } : project(parsed));
}

// ── DER ──────────────────────────────────────────────────────────────

interface Tlv {
    readonly tag: number;
    readonly headerLength: number;
    readonly contentLength: number;
    readonly start: number;
}

/** Read one definite-length TLV header at `at`. */
function readTlv(der: Uint8Array, at: number): Tlv {
    const tag = der[at];
    const first = der[at + 1];
    if (tag === undefined || first === undefined) throw new Error('DER: truncated header');
    if ((tag & 0x1f) === 0x1f) throw new Error('DER: high tag numbers are not expected in a certificate or request');
    if (first < 0x80) return { tag, headerLength: 2, contentLength: first, start: at };
    if (first === 0x80) throw new Error('DER: indefinite length');
    const n = first & 0x7f;
    if (n > 4) throw new Error('DER: length too long');
    let len = 0;
    for (let i = 0; i < n; i++) {
        const b = der[at + 2 + i];
        if (b === undefined) throw new Error('DER: truncated length');
        len = len * 256 + b;
    }
    return { tag, headerLength: 2 + n, contentLength: len, start: at };
}

/** The children of a constructed TLV, in order. */
function childrenOf(der: Uint8Array, node: Tlv): Tlv[] {
    const out: Tlv[] = [];
    let at = node.start + node.headerLength;
    const end = at + node.contentLength;
    while (at < end) {
        const child = readTlv(der, at);
        out.push(child);
        at += child.headerLength + child.contentLength;
    }
    if (at !== end) throw new Error('DER: child overruns its parent');
    return out;
}

/** The bytes of a TLV (header included). */
function slice(der: Uint8Array, node: Tlv): Uint8Array {
    return der.subarray(node.start, node.start + node.headerLength + node.contentLength);
}

/** The first element of the outer DER SEQUENCE — the TBS part of a certificate or a request — header included. */
export function firstElementOfSequence(der: Uint8Array): Uint8Array {
    const outer = readTlv(der, 0);
    if (outer.tag !== 0x30) throw new Error('DER: the outer value is not a SEQUENCE');
    if (outer.headerLength + outer.contentLength !== der.length) throw new Error('DER: trailing bytes after the outer SEQUENCE');
    const first = childrenOf(der, outer)[0];
    if (first === undefined) throw new Error('DER: the outer SEQUENCE is empty');
    return slice(der, first);
}

/** True for `SEQUENCE { tbs, AlgorithmIdentifier SEQUENCE, BIT STRING }` — a certificate, a CSR or a CRL. */
export function looksSigned(der: Uint8Array): boolean {
    try {
        const outer = readTlv(der, 0);
        if (outer.tag !== 0x30 || outer.headerLength + outer.contentLength !== der.length) return false;
        const children = childrenOf(der, outer);
        return children.length === 3 && children[0]?.tag === 0x30 && children[1]?.tag === 0x30 && children[2]?.tag === 0x03;
    } catch {
        return false;
    }
}

/** The DER of a PEM text (its first block), or the bytes themselves when they are not PEM. */
export function derOf(bytes: Uint8Array): Uint8Array {
    const head = Buffer.from(bytes.subarray(0, 16)).toString('latin1');
    if (!head.trimStart().startsWith('-----BEGIN')) return bytes;
    const text = Buffer.from(bytes).toString('utf8');
    const m = /-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/.exec(text);
    if (m === null) throw new Error('PEM: no block');
    return new Uint8Array(Buffer.from((m[1] as string).replace(/\s+/g, ''), 'base64'));
}

// ── Mode selection (the generator's decision) ────────────────────────

/** The signer object of a tool call, as the examples write it. */
interface SignerLike {
    readonly key?: { readonly pem?: string; readonly derBase64?: string; readonly path?: string };
    readonly p12?: { readonly pem?: string; readonly derBase64?: string; readonly path?: string };
    readonly rsaScheme?: string;
}

function keyTypeOfPem(pem: string): string | null {
    try {
        return createPrivateKey({ key: pem, format: 'pem' }).asymmetricKeyType ?? null;
    } catch {
        return null;
    }
}

function keyTypeOfDer(der: Buffer): string | null {
    try {
        return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }).asymmetricKeyType ?? null;
    } catch {
        return null;
    }
}

/**
 * True when the signer's signatures cannot repeat: an EC key (ECDSA draws a
 * random k) or an RSA key under the PSS scheme (a random salt). Ed25519 /
 * Ed448 and RSA PKCS#1 v1.5 are deterministic. The key type is read from
 * the PEM / DER when the example carries it inline, else from the fixture
 * file name (`ed25519.*`, `rsa.*`, `leaf.*` = EC P-256); a PKCS#12 goes by
 * its name alone (its key is sealed). Unknown → assumed randomised, the
 * mode that can only cause a sample to be held less strictly, never to
 * flake.
 */
export function signerIsRandomised(args: Readonly<Record<string, unknown>> | undefined): boolean {
    const signer = args?.['signer'] as SignerLike | undefined;
    if (signer === undefined || typeof signer !== 'object') return false;
    const scheme = signer.rsaScheme;
    const source = signer.key ?? signer.p12;
    let type: string | null = null;
    if (source?.pem !== undefined) type = keyTypeOfPem(source.pem);
    else if (source?.derBase64 !== undefined) type = keyTypeOfDer(Buffer.from(source.derBase64, 'base64'));
    if (type === null) {
        const name = basename(source?.path ?? '').toLowerCase();
        if (name.includes('ed25519')) type = 'ed25519';
        else if (name.includes('ed448')) type = 'ed448';
        else if (name.includes('rsa')) type = 'rsa';
        else if (name.length > 0) type = 'ec';
    }
    if (type === 'ed25519' || type === 'ed448') return false;
    if (type === 'rsa' || type === 'rsa-pss') return scheme !== 'pkcs1';
    return true;
}

/** True when a string value anywhere in the arguments asks the wrapper RNG (`serialNumber: 'random'`, `nonce: 'random'`). */
export function argsAskRandom(args: unknown, depth = 0): boolean {
    if (depth > 8 || args === null || typeof args !== 'object') return false;
    for (const v of Object.values(args as Record<string, unknown>)) {
        if (v === 'random') return true;
        if (typeof v === 'object' && argsAskRandom(v, depth + 1)) return true;
    }
    return false;
}

export interface ModeInput {
    /** The tool's `annotations` from `tools/list`. */
    readonly annotations: { readonly readOnlyHint?: boolean; readonly idempotentHint?: boolean } | undefined;
    /** The resolved arguments of the call. */
    readonly args: Readonly<Record<string, unknown>> | undefined;
    /** The artefact bytes (PEM or DER), or null for a JSON-only result. */
    readonly artefact: Uint8Array | null;
}

/**
 * The fingerprint mode of one sample: `semantic` for a JSON result and for
 * an artefact that asked the RNG (a random serial sits inside the TBS, a
 * random nonce inside the request); otherwise `bytes` unless the signer is
 * randomised, then `tbs` when the structure is `SEQUENCE { tbs, alg, BIT
 * STRING }` and `semantic` otherwise.
 */
export function modeFor(input: ModeInput): FingerprintMode {
    if (input.artefact === null) return 'semantic';
    if (argsAskRandom(input.args)) return 'semantic';
    if (input.annotations?.readOnlyHint === true) return 'bytes';
    if (!signerIsRandomised(input.args)) return 'bytes';
    try {
        return looksSigned(derOf(input.artefact)) ? 'tbs' : 'semantic';
    } catch {
        return 'semantic';
    }
}

// ── Fingerprinting ───────────────────────────────────────────────────

/** Fingerprint one sample in the mode the manifest recorded for it. */
export function fingerprint(absPath: string, entry: Pick<ManifestEntry, 'mode' | 'sidecar'>): Fingerprint {
    const bytes = readFileSync(absPath);
    switch (entry.mode) {
        case 'bytes':
            return { mode: 'bytes', hash: sha256Hex(bytes), size: bytes.length };
        case 'tbs':
            return { mode: 'tbs', hash: sha256Hex(firstElementOfSequence(derOf(bytes))), size: bytes.length };
        case 'semantic': {
            // An artefact in semantic mode stands for its sidecar's projection, prefixed so the two
            // entries never share a hash (a shared hash is what flags a collapsed showcase pair).
            if (entry.sidecar !== undefined) return { mode: 'semantic', hash: sha256Hex(`artefact\n${semanticProjection(readFileSync(join(OUTPUT_DIR, entry.sidecar), 'utf8'))}`), size: bytes.length };
            return { mode: 'semantic', hash: sha256Hex(semanticProjection(bytes.toString('utf8'))), size: bytes.length };
        }
    }
}

export function loadManifest(): SampleManifest | null {
    if (!existsSync(MANIFEST_PATH)) return null;
    return JSON.parse(readFileSync(MANIFEST_PATH, 'utf8')) as SampleManifest;
}

export interface FingerprintRun {
    readonly entries: Record<string, Fingerprint>;
    readonly unreadable: { readonly path: string; readonly error: string }[];
    /** Files on disk the manifest does not list, or listed but absent. */
    readonly unlisted: string[];
    readonly missing: string[];
}

/** Fingerprint every sample currently in `test-output/samples/`, in the mode its manifest entry names. */
export function fingerprintAll(): FingerprintRun {
    const entries: Record<string, Fingerprint> = {};
    const unreadable: { path: string; error: string }[] = [];
    const manifest = loadManifest();
    const listed = manifest?.entries ?? {};
    const onDisk = new Set<string>();
    for (const file of walkSamples(OUTPUT_DIR)) {
        const rel = relPath(file);
        onDisk.add(rel);
        const entry = listed[rel];
        if (entry === undefined) continue;
        try {
            entries[rel] = fingerprint(file, entry);
        } catch (err) {
            unreadable.push({ path: rel, error: err instanceof Error ? err.message : String(err) });
        }
    }
    const unlisted = [...onDisk].filter((rel) => !(rel in listed)).sort();
    const missing = Object.keys(listed).filter((rel) => !onDisk.has(rel)).sort();
    return { entries, unreadable, unlisted, missing };
}

export function loadBaseline(): Baseline | null {
    if (!existsSync(BASELINE_PATH)) return null;
    return JSON.parse(readFileSync(BASELINE_PATH, 'utf8')) as Baseline;
}

export interface Comparison {
    readonly changed: string[];
    readonly added: string[];
    readonly removed: string[];
}

export function compareToBaseline(entries: Record<string, Fingerprint>, baseline: Baseline): Comparison {
    const changed: string[] = [];
    const added: string[] = [];
    const removed: string[] = [];
    for (const [rel, entry] of Object.entries(entries)) {
        const base = baseline.entries[rel];
        if (!base) { added.push(rel); continue; }
        if (base.mode !== entry.mode || base.hash !== entry.hash) changed.push(rel);
    }
    for (const rel of Object.keys(baseline.entries)) {
        if (!(rel in entries)) removed.push(rel);
    }
    return { changed, added, removed };
}

/**
 * Stamp each fingerprint with the release whose output it is.
 *
 * An entry that still hashes to what the previous manifest recorded keeps its
 * `since` untouched, which is what gives the chain meaning: an entry reading
 * `1.0.0` really is being held to the bytes v1.0.0 emitted. An entry whose
 * hash changed is being re-anchored to the tree under development, so it
 * takes the current version — otherwise a deliberate rebaseline would hide
 * inside a one-line hash diff instead of announcing itself.
 */
export function chainSince(
    entries: Record<string, Fingerprint>,
    previous: Baseline | null,
    version: string,
): Record<string, BaselineEntry> {
    const out: Record<string, BaselineEntry> = {};
    for (const key of Object.keys(entries).sort()) {
        const entry = entries[key] as Fingerprint;
        const before = previous?.entries[key];
        const unchanged = before !== undefined && before.mode === entry.mode && before.hash === entry.hash;
        out[key] = { ...entry, since: unchanged ? before.since : version };
    }
    return out;
}

/**
 * Samples that are expected to be byte-identical: each group is one output
 * produced two ways. Any other pair sharing a hash is a showcase whose "with"
 * and "without" variants collapsed into the same file. None today.
 */
export const IDENTICAL_SAMPLE_GROUPS: ReadonlyArray<ReadonlyArray<string>> = [];

/**
 * Groups of samples that share a fingerprint without being listed in
 * {@link IDENTICAL_SAMPLE_GROUPS}. Empty when every duplicate is expected.
 */
export function unexpectedDuplicates(entries: Record<string, { readonly hash: string }>): string[][] {
    const byHash = new Map<string, string[]>();
    for (const [rel, entry] of Object.entries(entries)) {
        const group = byHash.get(entry.hash) ?? [];
        group.push(rel);
        byHash.set(entry.hash, group);
    }
    const allowed = IDENTICAL_SAMPLE_GROUPS.map((g) => [...g].sort().join('\n'));
    const out: string[][] = [];
    for (const group of byHash.values()) {
        if (group.length < 2) continue;
        const sorted = [...group].sort();
        if (!allowed.includes(sorted.join('\n'))) out.push(sorted);
    }
    return out.sort((a, b) => (a[0] as string).localeCompare(b[0] as string));
}

/** The instant the baseline records (every sample is pinned to it). */
export const BASELINE_AT = SAMPLE_AT;
