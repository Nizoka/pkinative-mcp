/**
 * Every byte / count bound the server enforces on top of the engine's own
 * `PkiLimits`, plus the operator ceilings read once at boot.
 *
 * The engine bounds *what a DER structure may declare* (the 22 CWE-tagged
 * limits); these bounds keep one JSON-RPC exchange inside a predictable
 * memory envelope and stop an agent from asking for a payload no MCP host
 * can carry. Everything here is a constant so `describe_engine` can advertise
 * it and the docs can be checked against the code.
 */
import { ToolError } from './errors.js';

const KiB = 1024;
const MiB = 1024 * KiB;
const GiB = 1024 * MiB;

/** Largest single JSON-RPC frame accepted on stdio and the HTTP body cap (256 MiB). */
export const STDIO_MAX_FRAME_BYTES = 256 * MiB;
/** Sum of the decoded inline PKI inputs (`pem` / `derBase64`) of one call. */
export const MAX_INLINE_INPUT_BYTES_PER_CALL = 128 * MiB;
/** An inline `content` payload (`text` / `base64`) to sign, verify or time-stamp. */
export const MAX_CONTENT_INLINE_BYTES = 128 * MiB;
/** A `content.path` read fully into memory. */
export const MAX_CONTENT_PATH_BYTES = 1 * GiB;
/** Items of a bundle input (trust anchors, candidates, CRLs, OCSP responses, chains, paths). */
export const MAX_BUNDLE_ITEMS = 256;
/** Largest base64 payload returned inline (certificates, CMS, PEM bundles). */
export const MAX_BASE64_OUTPUT_BYTES = 50 * MiB;
/** Largest file written in `outputMode: 'file'`. */
export const MAX_FILE_OUTPUT_BYTES = 1 * GiB;
/** Largest artefact returned as inline hex (`encoding: 'hex'`). */
export const MAX_HEX_INLINE_BYTES = 64 * KiB;
/** DER `Attribute`s accepted inline by `sign_cms` / `amend_cms`. */
export const MAX_ATTRIBUTES_INLINE = 256;
/** `resolve_oid`: OIDs per call. */
export const MAX_OIDS_PER_CALL = 1000;
/** `resolve_oid` list page bounds. */
export const MAX_LIST_LIMIT = 2000;
export const DEFAULT_LIST_LIMIT = 200;
/** `compute_fingerprint` SHAKE256 output bound (the engine's own bound). */
export const MAX_SHAKE_OUTPUT_BYTES = 1 * MiB;
/** `password` input length (characters). */
export const MAX_PASSWORD_BYTES = 4096;
/** Diagnostics kept per result after de-duplication by (code, path). */
export const MAX_DIAGNOSTICS = 200;
/** `fields` projection paths per call. */
export const MAX_FIELDS_PATHS = 16;
/** `decode_asn1`: bytes of a primitive's content shown in `preview`. */
export const MAX_PREVIEW_BYTES = 32;
/** `decode_asn1`: nodes returned in one tree (the engine's `maxNodes` is the hard bound). */
export const MAX_TREE_NODES = 20_000;
/** `resources/list`: maximum number of sandbox files returned, and the directory-walk depth. */
export const MAX_LISTED_RESOURCES = 1000;
export const MAX_RESOURCE_WALK_DEPTH = 8;
/** `resources/read`: largest payload returned (mirrors the inline output cap). */
export const MAX_RESOURCE_READ_BYTES = MAX_BASE64_OUTPUT_BYTES;
/** Opt-in response cache (`PKINATIVE_MCP_CACHE_DIR`): entry TTL and total size (LRU by mtime). */
export const CACHE_TTL_SECONDS = 3600;
export const CACHE_MAX_BYTES = 256 * MiB;

/** Operator ceilings — environment variable names. */
export const MAX_INPUT_BYTES_ENV = 'PKINATIVE_MCP_MAX_INPUT_BYTES';
export const MAX_KDF_ITERATIONS_ENV = 'PKINATIVE_MCP_MAX_KDF_ITERATIONS';
export const MAX_PATHS_EXPLORED_ENV = 'PKINATIVE_MCP_MAX_PATHS_EXPLORED';

/** Defaults equal the engine defaults, so nothing changes unless the operator says so. */
export const DEFAULT_MAX_INPUT_BYTES_CEILING = 64 * MiB;
export const DEFAULT_MAX_KDF_ITERATIONS_CEILING = 10_000_000;
export const DEFAULT_MAX_PATHS_EXPLORED_CEILING = 1000;

export interface Ceilings {
    /** Upper bound for `limits.maxInputBytes`; also the decoded size cap of one PKI object. */
    readonly maxInputBytes: number;
    /** Upper bound for `limits.maxKdfIterations` and `limits.maxPkcs12KdfIterations` (CPU bound of a hostile PBKDF2). */
    readonly maxKdfIterations: number;
    /** Upper bound for `limits.maxPathsExplored` (the RFC 5280 §6 path-building work bound). */
    readonly maxPathsExplored: number;
}

function parseCeiling(env: NodeJS.ProcessEnv, name: string, fallback: number, minimum: number): number {
    const raw = env[name];
    if (raw === undefined || raw === '') return fallback;
    const trimmed = raw.trim();
    if (!/^\d+$/.test(trimmed)) {
        throw new Error(`${name} must be a non-negative integer (got ${JSON.stringify(raw)}).`);
    }
    const value = Number(trimmed);
    if (!Number.isSafeInteger(value) || value < minimum) {
        throw new Error(`${name} must be an integer >= ${minimum} (got ${JSON.stringify(raw)}).`);
    }
    return value;
}

/**
 * Read the operator ceilings. Called once at boot by the CLI (an invalid value
 * refuses to start — never a silent fallback) and lazily by the tools.
 */
export function readCeilings(env: NodeJS.ProcessEnv = process.env): Ceilings {
    return {
        maxInputBytes: parseCeiling(env, MAX_INPUT_BYTES_ENV, DEFAULT_MAX_INPUT_BYTES_CEILING, 1024),
        maxKdfIterations: parseCeiling(env, MAX_KDF_ITERATIONS_ENV, DEFAULT_MAX_KDF_ITERATIONS_CEILING, 1),
        maxPathsExplored: parseCeiling(env, MAX_PATHS_EXPLORED_ENV, DEFAULT_MAX_PATHS_EXPLORED_CEILING, 1),
    };
}

let _ceilings: Ceilings | null = null;

/** Ceilings for the current process (memoised; `__resetCeilingsForTests` clears). */
export function getCeilings(): Ceilings {
    if (_ceilings === null) _ceilings = readCeilings();
    return _ceilings;
}

/** Test-only hook: forget the memoised ceilings so a test can change the env. */
export function __resetCeilingsForTests(): void {
    _ceilings = null;
}

/**
 * Throw `INPUT_TOO_LARGE` when `observed` exceeds `cap`. An inline input names
 * the sandbox file route as its remedy (`data.remedy: 'path'`); a file input
 * already over the cap can only be split or the ceiling raised.
 */
export function assertInputWithin(observed: number, cap: number, what: string): void {
    if (observed <= cap) return;
    const viaFile = /path/i.test(what);
    const hint = viaFile
        ? `split the input, or raise ${MAX_INPUT_BYTES_ENV} for trusted input only`
        : `pass the bytes through a sandbox file instead (a relative path under PKINATIVE_MCP_OUTPUT_DIR) or send a smaller payload`;
    throw new ToolError('INPUT_TOO_LARGE', `${what} is ${observed} bytes, above the ${cap}-byte cap — ${hint}.`, { what, observed, cap, ...(viaFile ? {} : { remedy: 'path' }) });
}

/** Serialisable view of every cap, for `describe_engine`. */
export const CAPS = {
    stdioMaxFrameBytes: STDIO_MAX_FRAME_BYTES,
    maxInlineInputBytesPerCall: MAX_INLINE_INPUT_BYTES_PER_CALL,
    maxContentInlineBytes: MAX_CONTENT_INLINE_BYTES,
    maxContentPathBytes: MAX_CONTENT_PATH_BYTES,
    maxBundleItems: MAX_BUNDLE_ITEMS,
    maxBase64OutputBytes: MAX_BASE64_OUTPUT_BYTES,
    maxFileOutputBytes: MAX_FILE_OUTPUT_BYTES,
    maxHexInlineBytes: MAX_HEX_INLINE_BYTES,
    maxAttributesInline: MAX_ATTRIBUTES_INLINE,
    maxOidsPerCall: MAX_OIDS_PER_CALL,
    maxListLimit: MAX_LIST_LIMIT,
    defaultListLimit: DEFAULT_LIST_LIMIT,
    maxShakeOutputBytes: MAX_SHAKE_OUTPUT_BYTES,
    maxPasswordBytes: MAX_PASSWORD_BYTES,
    maxDiagnostics: MAX_DIAGNOSTICS,
    maxFieldsPaths: MAX_FIELDS_PATHS,
    maxPreviewBytes: MAX_PREVIEW_BYTES,
    maxTreeNodes: MAX_TREE_NODES,
    maxListedResources: MAX_LISTED_RESOURCES,
    maxResourceWalkDepth: MAX_RESOURCE_WALK_DEPTH,
    maxResourceReadBytes: MAX_RESOURCE_READ_BYTES,
    cacheTtlSeconds: CACHE_TTL_SECONDS,
    cacheMaxBytes: CACHE_MAX_BYTES,
} as const;
