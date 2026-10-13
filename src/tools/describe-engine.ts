/**
 * Tool: describe_engine — an offline capability preflight (the `pkinative
 * doctor` + `limits` + `schema` of this server): server and engine versions,
 * the Web Crypto capabilities of the host, the engine's 22 default limits,
 * the operator ceilings and the server caps, the sandbox / cache state, the
 * three code vocabularies, the doctrine refusals and the engine exports this
 * server deliberately does not expose as tool inputs (with the reason).
 */
import { ANY_EXTENDED_KEY_USAGE, DEFAULT_PKI_LIMITS, KEY_PURPOSES, KEY_USAGE_BITS, OCSP_NONCE_OID, OID_REGISTRY } from 'pkinative';
import { z } from 'zod';

import { CAPS, getCeilings, MAX_INPUT_BYTES_ENV, MAX_KDF_ITERATIONS_ENV, MAX_PATHS_EXPLORED_ENV } from '../caps.js';
import { PKI_DIAGNOSTIC_SEVERITY, PKI_ERROR_CLASSES } from '../data/pkinative/code-tables.js';
import { PKINATIVE_NODE_FLOOR, PKINATIVE_VERSION, probeRuntime, type RuntimeCapabilities } from '../engine.js';
import { PKI_DIAGNOSTIC_CODES, PKI_ERROR_CLASS, PKI_ERROR_CODES, PKI_REASON_CODES } from '../pki-errors.js';
import { PROJECTION_INPUT_PROPERTIES } from '../projection.js';
import { RANDOMNESS } from '../random.js';
import { getOutputSandbox, OUTPUT_EXTENSIONS, PKI_INPUT_EXTENSIONS, SECRET_EXTENSIONS } from '../sandbox.js';
import { AT_ENV, readPinnedInstant } from '../time.js';
import { PKINATIVE_MCP_VERSION, TOOL_API_VERSION } from '../version.js';
import { WRAPPER_CODE_NAMES } from '../wrapper-codes.js';
import { defineTool, PROJECTION_NOTE, projectableOutputSchema, READ_ONLY } from './_definition.js';
import { parseInput, ProjectionShape } from './_shared.js';

export const DESCRIBE_ENGINE_NAME = 'describe_engine';

export const DESCRIBE_ENGINE_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    properties: { ...PROJECTION_INPUT_PROPERTIES },
} as const;

const InputSchema = z.strictObject({ ...ProjectionShape });

/** The engine's doctrine, surfaced honestly: what this server will NOT do and why. */
export const DOCTRINE: ReadonlyArray<{ readonly what: string; readonly how: string; readonly remedy: string }> = [
    { what: 'No network, ever', how: 'No CRL / OCSP / AIA / TSA fetch, no telemetry, no URL from any argument; create_ocsp_request and create_timestamp_request produce bytes the caller transports.', remedy: 'Fetch the evidence yourself and pass the bytes (crls, ocspResponses, token).' },
    { what: 'No key generation', how: 'pkinative generates nothing (its ADR 0001); there is no generate_key tool.', remedy: 'Bring keys from your HSM, KMS or openssl genpkey; subjectPublicKey comes from a certificate, a CSR or a PUBLIC KEY.' },
    { what: 'No key export', how: 'Signing keys are non-extractable Web Crypto handles; every key / PKCS#12 report is an allow-list view; key-bearing files are never written nor served as resources; convert_pem / decode_asn1 refuse private-key material.', remedy: 'Describe keys with inspect_private_key / inspect_pkcs12; open them with open_pkcs12.' },
    { what: 'No writer for PKCS#8, PKCS#12, CRL, OCSP response or time-stamp response', how: 'The engine has none (its ADR 0003); the catalogue has no create_crl / create_ocsp_response / create_pkcs12.', remedy: 'Use the issuing software or OpenSSL for those artefacts; verify them here.' },
    { what: 'SHA-1 refused by default', how: 'A SHA-1 signature is PKI_CRYPTO_ALGORITHM_REFUSED on read and VALIDATION_ERROR on write.', remedy: 'allowSha1:true for legacy material you already trust.' },
    { what: 'RSA has no default signature scheme', how: 'An RSA key without rsaScheme is RSA_SCHEME_REQUIRED (engine ADR 0015).', remedy: "signer.rsaScheme:'pkcs1'|'pss' (an id-RSASSA-PSS key signs PSS only)." },
    { what: 'Legacy PKCS#12 and PBES1 keys refused', how: 'Only PBES2 (PBKDF2 + AES-CBC) and PBMAC1 are opened; RC2 / 3DES / the RFC 7292 Appendix B MAC are refused with PKI_KEY_ENCRYPTION_UNSUPPORTED / PKI_KEY_MAC_UNSUPPORTED.', remedy: 'Convert once with OpenSSL 3.4+ (openssl pkcs12 -legacy … then -export -pbmac1_pbkdf2); allowUnverifiedIntegrity:true only for a file whose origin you trust.' },
    { what: 'DSA, ML-DSA and unknown key kinds are parsed, never verified or signed', how: 'Their signatures come back as PKI_REASON_SIGNATURE_NOT_CHECKED / UNSUPPORTED_KEY.', remedy: 'Use EC P-256/384/521, RSA, Ed25519 or Ed448 keys.' },
    { what: 'Diagnostics are not errors', how: "strict:true escalates the first warning (PKI_STRICT_DIAGNOSTIC); an 'info' never refuses.", remedy: 'Read diagnostics[] and decide by policy.' },
    { what: 'Limits raise only by explicit input and never above the operator ceilings', how: 'limits.* per call; a value above PKINATIVE_MCP_MAX_INPUT_BYTES / _MAX_KDF_ITERATIONS / _MAX_PATHS_EXPLORED is LIMIT_CEILING_EXCEEDED.', remedy: 'Raise a bound for trusted input only; the operator raises a ceiling in the server environment.' },
    { what: 'Randomness lives in the wrapper', how: "serialNumber:'random' and nonce:'random' draw from node:crypto; every summary that used it says so (randomSerial, randomNonce).", remedy: 'Pass explicit values for reproducible bytes.' },
];

/** Engine surface deliberately not reachable as a tool input, with the reason (every runtime export IS reached by a tool). */
export const UNEXPOSED_EXPORTS: ReadonlyArray<{ readonly export: string; readonly rationale: string }> = [
    { export: 'ExternalSigner.produceSignature', rationale: 'Executable code cannot cross JSON-RPC; only a SigningKey imported from a PKCS#8 / PKCS#12 input signs here.' },
    { export: 'PkiParseOptions.onDiagnostic', rationale: 'Always installed by the server (every result carries diagnostics[]); strict IS exposed.' },
    { export: 'password: Uint8Array', rationale: 'JSON carries UTF-8 strings only; a non-UTF-8 password cannot be expressed.' },
    { export: 'Certificate.der / tbsDer / *.valueDer echoes', rationale: 'The input itself; reports carry facts, fingerprints and (on request) raw extension values, never the whole DER back.' },
    { export: 'The 177 type exports', rationale: 'Reached through the inputs and reports of the 34 tools (docs/data/core-exports.json).' },
];

export interface DescribeEngineResult {
    readonly server: { readonly name: string; readonly version: string; readonly toolApiVersion: string; readonly protocol: string; readonly toolCount: number };
    readonly engine: { readonly name: string; readonly version: string; readonly nodeFloor: string };
    readonly capabilities: RuntimeCapabilities;
    readonly randomness: typeof RANDOMNESS;
    readonly defaultLimits: Record<string, number>;
    readonly ceilings: { readonly maxInputBytes: number; readonly maxKdfIterations: number; readonly maxPathsExplored: number; readonly env: readonly string[] };
    readonly caps: typeof CAPS;
    readonly sandbox: { readonly enabled: boolean; readonly cacheEnabled: boolean; readonly pinnedInstant: string | null; readonly inputExtensions: readonly string[]; readonly outputExtensions: readonly string[]; readonly secretExtensions: readonly string[] };
    readonly network: 'none';
    readonly registries: {
        readonly errorCodes: ReadonlyArray<{ readonly code: string; readonly errorClass: string; readonly engineClass: string }>;
        readonly reasonCodes: readonly string[];
        readonly diagnosticCodes: ReadonlyArray<{ readonly code: string; readonly severity: string }>;
        readonly wrapperCodes: readonly string[];
        readonly purposes: readonly string[];
        readonly keyUsageBits: readonly string[];
        readonly oidRegistryCount: number;
        readonly ocspNonceOid: string;
        readonly anyExtendedKeyUsage: string;
    };
    readonly refusals: typeof DOCTRINE;
    readonly unexposed: typeof UNEXPOSED_EXPORTS;
}

export const DESCRIBE_ENGINE_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['server', 'engine', 'capabilities', 'randomness', 'defaultLimits', 'ceilings', 'caps', 'sandbox', 'network', 'registries', 'refusals', 'unexposed'],
    properties: {
        server: { type: 'object', additionalProperties: false, properties: { name: { type: 'string' }, version: { type: 'string' }, toolApiVersion: { type: 'string' }, protocol: { type: 'string' }, toolCount: { type: 'integer' } } },
        engine: { type: 'object', additionalProperties: false, properties: { name: { type: 'string' }, version: { type: 'string' }, nodeFloor: { type: 'string' } } },
        capabilities: { type: 'object', additionalProperties: false, properties: { canVerify: { type: 'boolean' }, canSign: { type: 'boolean' }, canDecrypt: { type: 'boolean' }, node: { type: 'string' }, nodeFloorSatisfied: { type: 'boolean' }, platform: { type: 'string' } } },
        randomness: { type: 'object', additionalProperties: false, properties: { engine: { type: 'string' }, wrapper: { type: 'string' }, usedBy: { type: 'array', items: { type: 'string' } } } },
        defaultLimits: { type: 'object', additionalProperties: { type: 'number' } },
        ceilings: { type: 'object', additionalProperties: false, properties: { maxInputBytes: { type: 'integer' }, maxKdfIterations: { type: 'integer' }, maxPathsExplored: { type: 'integer' }, env: { type: 'array', items: { type: 'string' } } } },
        caps: { type: 'object', additionalProperties: { type: 'integer' } },
        sandbox: { type: 'object', additionalProperties: false, properties: { enabled: { type: 'boolean' }, cacheEnabled: { type: 'boolean' }, pinnedInstant: { type: ['string', 'null'] }, inputExtensions: { type: 'array', items: { type: 'string' } }, outputExtensions: { type: 'array', items: { type: 'string' } }, secretExtensions: { type: 'array', items: { type: 'string' } } } },
        network: { type: 'string', enum: ['none'] },
        registries: {
            type: 'object',
            additionalProperties: false,
            properties: {
                errorCodes: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { code: { type: 'string' }, errorClass: { type: 'string' }, engineClass: { type: 'string' } } } },
                reasonCodes: { type: 'array', items: { type: 'string' } },
                diagnosticCodes: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { code: { type: 'string' }, severity: { type: 'string' } } } },
                wrapperCodes: { type: 'array', items: { type: 'string' } },
                purposes: { type: 'array', items: { type: 'string' } },
                keyUsageBits: { type: 'array', items: { type: 'string' } },
                oidRegistryCount: { type: 'integer' },
                ocspNonceOid: { type: 'string' },
                anyExtendedKeyUsage: { type: 'string' },
            },
        },
        refusals: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { what: { type: 'string' }, how: { type: 'string' }, remedy: { type: 'string' } } } },
        unexposed: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { export: { type: 'string' }, rationale: { type: 'string' } } } },
    },
} as const;

let _toolCount = 0;
/** Set by the registry at load so the tool can report the catalogue size. */
export function __setToolCount(n: number): void {
    _toolCount = n;
}

export async function describeEngine(rawInput: unknown): Promise<DescribeEngineResult> {
    parseInput(InputSchema, rawInput);
    const ceilings = getCeilings();
    const pinned = readPinnedInstant();
    return {
        server: { name: 'pkinative-mcp', version: PKINATIVE_MCP_VERSION, toolApiVersion: TOOL_API_VERSION, protocol: 'MCP 2026-07-28 + legacy 2024/2025 initialize', toolCount: _toolCount },
        engine: { name: 'pkinative', version: PKINATIVE_VERSION, nodeFloor: PKINATIVE_NODE_FLOOR },
        capabilities: probeRuntime(),
        randomness: RANDOMNESS,
        defaultLimits: { ...DEFAULT_PKI_LIMITS },
        ceilings: { ...ceilings, env: [MAX_INPUT_BYTES_ENV, MAX_KDF_ITERATIONS_ENV, MAX_PATHS_EXPLORED_ENV] },
        caps: CAPS,
        sandbox: {
            enabled: getOutputSandbox() !== null,
            cacheEnabled: (process.env['PKINATIVE_MCP_CACHE_DIR'] ?? '') !== '',
            pinnedInstant: pinned === null ? null : new Date(pinned).toISOString(),
            inputExtensions: PKI_INPUT_EXTENSIONS,
            outputExtensions: OUTPUT_EXTENSIONS,
            secretExtensions: SECRET_EXTENSIONS,
        },
        network: 'none',
        registries: {
            errorCodes: PKI_ERROR_CODES.map((code) => ({ code, errorClass: PKI_ERROR_CLASS[code], engineClass: PKI_ERROR_CLASSES[code] })),
            reasonCodes: [...PKI_REASON_CODES],
            diagnosticCodes: PKI_DIAGNOSTIC_CODES.map((code) => ({ code, severity: PKI_DIAGNOSTIC_SEVERITY[code as keyof typeof PKI_DIAGNOSTIC_SEVERITY] })),
            wrapperCodes: [...WRAPPER_CODE_NAMES],
            purposes: [...Object.keys(KEY_PURPOSES), 'any'],
            keyUsageBits: [...KEY_USAGE_BITS.keys()],
            oidRegistryCount: OID_REGISTRY.length,
            ocspNonceOid: OCSP_NONCE_OID,
            anyExtendedKeyUsage: ANY_EXTENDED_KEY_USAGE,
        },
        refusals: DOCTRINE,
        unexposed: UNEXPOSED_EXPORTS,
    };
}

export function describeSummary(r: DescribeEngineResult): Record<string, unknown> {
    return { server: r.server, engine: r.engine, capabilities: r.capabilities, sandbox: { enabled: r.sandbox.enabled, cacheEnabled: r.sandbox.cacheEnabled, pinnedInstant: r.sandbox.pinnedInstant }, network: r.network };
}

export const DESCRIBE_ENGINE_TOOL = defineTool<DescribeEngineResult>({
    name: DESCRIBE_ENGINE_NAME,
    title: 'Describe engine & server capabilities',
    kind: 'engine',
    description:
        `Offline preflight (no input needed): server / engine / tool-API versions, whether this host's Web Crypto can verify, sign and decrypt (canVerify / canSign / canDecrypt) and satisfies the engine's Node floor, where randomness comes from, the engine's 22 default limits, the operator ceilings (${MAX_INPUT_BYTES_ENV}, ${MAX_KDF_ITERATIONS_ENV}, ${MAX_PATHS_EXPLORED_ENV}), every server cap, the sandbox / cache / ${AT_ENV} state and the extension allow-lists, the 57 PKI_* error codes (with class), 43 PKI_REASON_* and 97 PKI_DIAG_* codes, the wrapper codes, the purposes and key-usage names, the doctrine refusals (what this server will NOT do and the remedy) and the engine surface deliberately not exposed as inputs. network is always 'none'. Call it first in a session, or whenever a cap / ceiling refusal needs interpreting.`,
    inputSchema: DESCRIBE_ENGINE_INPUT_SCHEMA,
    rawOutputSchema: DESCRIBE_ENGINE_OUTPUT_SCHEMA,
    outputSchema: projectableOutputSchema(DESCRIBE_ENGINE_OUTPUT_SCHEMA, {}, `Capability manifest.${PROJECTION_NOTE}`),
    annotations: READ_ONLY,
    cacheable: false,
    examples: [
        { title: 'Which limits and ceilings apply here?', input: { fields: ['defaultLimits', 'ceilings', 'sandbox', 'capabilities'] } },
    ],
    handler: describeEngine,
    text: (r) => `${DESCRIBE_ENGINE_NAME}: ${r.server.name} ${r.server.version} (${r.server.toolCount} tools) on pkinative ${r.engine.version}, Web Crypto verify=${r.capabilities.canVerify} sign=${r.capabilities.canSign} decrypt=${r.capabilities.canDecrypt}, sandbox=${r.sandbox.enabled}, network=none.`,
    summary: describeSummary,
});
