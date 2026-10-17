/**
 * The `limits` input fragment — pkinative's 22 named `PkiLimits` bounds,
 * exposed by name on every engine-touching tool — and the operator ceilings
 * that per-call values may never exceed.
 *
 * Raising a limit is always an explicit decision (the engine's doctrine);
 * there is no "unbounded": the engine refuses one and so does the schema
 * (every value is an integer ≥ 1, so `PKI_LIMIT_INVALID` is unreachable). A
 * value above a ceiling is refused with `LIMIT_CEILING_EXCEEDED` naming the
 * environment variable an operator would raise.
 */
import { z } from 'zod';
import { DEFAULT_PKI_LIMITS, type PkiLimits } from 'pkinative';

import { getCeilings, MAX_INPUT_BYTES_ENV, MAX_KDF_ITERATIONS_ENV, MAX_PATHS_EXPLORED_ENV, type Ceilings } from './caps.js';
import { ToolError } from './errors.js';

/** The 22 `PkiLimits` keys, in engine order. */
export const LIMIT_KEYS = [
    'maxInputBytes',
    'maxDepth',
    'maxNodes',
    'maxIntegerBytes',
    'maxOidBytes',
    'maxBerSegments',
    'maxPemBlocks',
    'maxExtensions',
    'maxGeneralNames',
    'maxNameAttributes',
    'maxPolicies',
    'maxChainLength',
    'maxPolicyNodes',
    'maxRevokedCertificates',
    'maxOcspSingleResponses',
    'maxPathsExplored',
    'maxSignerInfos',
    'maxAttributes',
    'maxCmsCertificatesAndCrls',
    'maxKdfIterations',
    'maxPkcs12Bags',
    'maxPkcs12KdfIterations',
] as const satisfies readonly (keyof PkiLimits)[];

export type LimitKey = (typeof LIMIT_KEYS)[number];

/** What each limit guards (from the engine's docs/data/limits.json), for the schema descriptions. */
const LIMIT_DOCS: Readonly<Record<LimitKey, { readonly cwe: string; readonly guards: string }>> = {
    maxInputBytes: { cwe: 'CWE-400', guards: 'The size of one DER input, or the length of one PEM text.' },
    maxDepth: { cwe: 'CWE-674', guards: 'The nesting depth of constructed values.' },
    maxNodes: { cwe: 'CWE-770', guards: 'The number of values decoded from one input.' },
    maxIntegerBytes: { cwe: 'CWE-407', guards: 'The content length of one INTEGER converted to a bigint.' },
    maxOidBytes: { cwe: 'CWE-400', guards: 'The content length of one OBJECT IDENTIFIER.' },
    maxBerSegments: { cwe: 'CWE-400', guards: 'The segments joined from one BER constructed string.' },
    maxPemBlocks: { cwe: 'CWE-400', guards: 'The blocks read from one PEM text.' },
    maxExtensions: { cwe: 'CWE-400', guards: 'The extensions of one certificate or request.' },
    maxGeneralNames: { cwe: 'CWE-400', guards: 'The GeneralName entries of one field.' },
    maxNameAttributes: { cwe: 'CWE-400', guards: 'The attributes of one distinguished name.' },
    maxPolicies: { cwe: 'CWE-400', guards: 'The policies or policy mappings of one extension.' },
    maxChainLength: { cwe: 'CWE-400', guards: 'The certificates one certification path may hold.' },
    maxPolicyNodes: { cwe: 'CWE-770', guards: 'The live nodes of the RFC 5280 valid_policy_tree.' },
    maxRevokedCertificates: { cwe: 'CWE-400', guards: 'The entries walked in one CRL revokedCertificates list.' },
    maxOcspSingleResponses: { cwe: 'CWE-400', guards: 'The SingleResponse entries of one OCSP response.' },
    maxPathsExplored: { cwe: 'CWE-400', guards: 'The candidate paths explored while building one (the RFC 5280 §6 work bound).' },
    maxSignerInfos: { cwe: 'CWE-400', guards: 'The signers of one SignedData.' },
    maxAttributes: { cwe: 'CWE-400', guards: 'The attributes of one attribute set.' },
    maxCmsCertificatesAndCrls: { cwe: 'CWE-400', guards: 'The certificates and revocation entries one SignedData carries.' },
    maxKdfIterations: { cwe: 'CWE-400', guards: 'The PBKDF2 iteration count honoured in one derivation.' },
    maxPkcs12Bags: { cwe: 'CWE-400', guards: 'The SafeBags read from one PKCS#12, across every SafeContents.' },
    maxPkcs12KdfIterations: { cwe: 'CWE-400', guards: 'The PBKDF2 iterations one PKCS#12 costs in total.' },
};

function limitProperty(key: LimitKey): { readonly type: 'integer'; readonly minimum: 1; readonly description: string } {
    const doc = LIMIT_DOCS[key];
    return { type: 'integer', minimum: 1, description: `${doc.guards} Default ${DEFAULT_PKI_LIMITS[key]}.` };
}

/** JSON Schema fragment for the `limits` input (hand-kept in step with {@link LimitsSchema}). */
export const LIMITS_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    description:
        "Raise pkinative's 22 named security bounds for this call (trusted input only; absent keys keep the engine defaults). A value above an operator ceiling (PKINATIVE_MCP_MAX_INPUT_BYTES, PKINATIVE_MCP_MAX_KDF_ITERATIONS, PKINATIVE_MCP_MAX_PATHS_EXPLORED) is LIMIT_CEILING_EXCEEDED; describe_engine lists the defaults and the ceilings.",
    properties: Object.fromEntries(LIMIT_KEYS.map((key) => [key, limitProperty(key)])) as Record<LimitKey, ReturnType<typeof limitProperty>>,
} as const;

/** Zod twin of {@link LIMITS_INPUT_SCHEMA}. */
export const LimitsSchema = z.strictObject(
    Object.fromEntries(LIMIT_KEYS.map((key) => [key, z.number().int().min(1).optional()])) as Record<LimitKey, z.ZodOptional<z.ZodNumber>>,
);

export type LimitsInput = Partial<Record<LimitKey, number>>;

function ceilingFor(key: LimitKey, ceilings: Ceilings): { ceiling: number; env: string } | null {
    if (key === 'maxInputBytes') return { ceiling: ceilings.maxInputBytes, env: MAX_INPUT_BYTES_ENV };
    if (key === 'maxKdfIterations' || key === 'maxPkcs12KdfIterations') return { ceiling: ceilings.maxKdfIterations, env: MAX_KDF_ITERATIONS_ENV };
    if (key === 'maxPathsExplored') return { ceiling: ceilings.maxPathsExplored, env: MAX_PATHS_EXPLORED_ENV };
    return null;
}

/**
 * Merge caller limits over the engine defaults, enforcing the operator
 * ceilings. Returns `undefined` when nothing was requested and no ceiling is
 * tighter than the engine default (so the engine's own defaults apply verbatim).
 */
export function resolveCallLimits(requested: LimitsInput | undefined, ceilings: Ceilings = getCeilings()): Partial<PkiLimits> | undefined {
    const out: Partial<Record<LimitKey, number>> = {};
    for (const key of LIMIT_KEYS) {
        const value = requested?.[key];
        const bound = ceilingFor(key, ceilings);
        if (value !== undefined) {
            if (bound !== null && value > bound.ceiling) {
                throw new ToolError(
                    'LIMIT_CEILING_EXCEEDED',
                    `limits.${key} = ${value} exceeds the operator ceiling ${bound.ceiling} (${bound.env}). Raise the ceiling in the server environment for trusted input only.`,
                    { limit: key, requested: value, ceiling: bound.ceiling, env: bound.env },
                );
            }
            out[key] = value;
        } else if (bound !== null && bound.ceiling < DEFAULT_PKI_LIMITS[key]) {
            // A ceiling below the engine default tightens the default silently: the
            // operator asked for it, and an agent cannot exceed it anyway.
            out[key] = bound.ceiling;
        }
    }
    return Object.keys(out).length === 0 ? undefined : out;
}

/** The limits that are in force for a call, for reporting (`describe_engine`, summaries). */
export function effectiveLimits(requested: LimitsInput | undefined, ceilings: Ceilings = getCeilings()): PkiLimits {
    return { ...DEFAULT_PKI_LIMITS, ...(resolveCallLimits(requested, ceilings) ?? {}) };
}

/** The effective `maxInputBytes` of a call: the cap every PKI object read is held to. */
export function effectiveMaxInputBytes(requested: LimitsInput | undefined, ceilings: Ceilings = getCeilings()): number {
    return effectiveLimits(requested, ceilings).maxInputBytes;
}
