/**
 * MCP server wiring: registers the pkinative tools on a low-level `Server`
 * instance and exposes a `createServer()` factory so the runtime (CLI,
 * tests, embedded host) can choose how to connect a transport.
 */
// MCP TypeScript SDK v2 (`@modelcontextprotocol/server`, spec 2026-07-28 with a
// legacy 2025-xx fallback). We deliberately stay on the low-level `Server` +
// method-string `setRequestHandler` surface: `McpServer.registerTool` requires
// Standard-Schema inputs and validates `structuredContent` against the advertised
// `outputSchema`, which would break the hand-written JSON Schemas, the
// `verbosity`/`fields` projections and the `isError` contract this server promises.
import {
    Server,
    ProtocolError,
    ProtocolErrorCode,
    ResourceNotFoundError,
    type CacheHint,
    type CallToolResult,
    type GetPromptResult,
    type ListToolsResult,
    type ServerOptions,
    type Tool,
} from '@modelcontextprotocol/server';

import { getCached, setCached } from './cache.js';
import { ensureEngineReady, PKINATIVE_VERSION } from './engine.js';
import { ToolError } from './errors.js';
import { DRAFT_ISSUE_WORKFLOW, GOVERNANCE_CONTRACT_SUMMARY } from './governance.js';
import type { OutputResult } from './output.js';
import { isPathInput } from './pki-input.js';
import { readFields, readVerbosity, selectFields } from './projection.js';
import { listResources, listResourceTemplates, readResource, resourceLinkForPath } from './resources.js';
import { carriesSecret, PASSWORD_ENV } from './secrets.js';
import { isClockDependent, readPinnedInstant } from './time.js';
import { PKINATIVE_MCP_VERSION, TOOL_API_VERSION } from './version.js';
import type { ToolDefinition } from './tools/_definition.js';
import { TOOLS } from './tools/_registry.js';

const SERVER_VERSION = PKINATIVE_MCP_VERSION;
const SERVER_NAME = 'pkinative-mcp';

/**
 * Human-readable server identity surfaced in `serverInfo` (MCP `Implementation`).
 * `title` is a display name; `description` mirrors `server.json` so hosts and the
 * MCP registry present consistent metadata during initialization.
 */
const SERVER_TITLE = 'pkinative MCP — X.509, CMS, OCSP, time-stamps and PKCS#12 without a key byte leaving';
/** Mirrors server.json `websiteUrl` (asserted by tests/metadata.test.ts). */
export const SERVER_WEBSITE_URL = 'https://github.com/Nizoka/pkinative-mcp#readme';
const SERVER_DESCRIPTION =
    'Production-grade MCP server for PKI on the zero-dependency pkinative engine: inspect and verify X.509 certificates, ' +
    'CSRs, CRLs, OCSP responses, CMS SignedData and RFC 3161 time-stamps; build and validate certification paths (RFC 5280 §6, ' +
    'server name, purposes, policies, offline CRL / OCSP revocation); create certificates, CSRs, CMS signatures, OCSP and ' +
    'time-stamp requests through non-extractable Web Crypto keys; open PKCS#8 and PKCS#12 without ever returning a key byte; ' +
    'decode and encode ASN.1, PEM and OIDs; OpenSSL interoperability validated in CI; MCP resources for sandbox files; ' +
    'human-in-the-loop AI-governance issue drafting. 34 tools, no network ever, three runtime dependencies (pkinative, the MCP SDK, zod).';

/**
 * MCP 2026-07-28 cache hints (`ttlMs` / `cacheScope`) emitted on the cacheable
 * results. The catalogue (tools, prompts, discovery) is static for a given
 * package version; the sandbox resource listing and produced artefacts are live,
 * per-host user data and must never be cached by shared intermediaries.
 * 2025-era clients never see these fields.
 */
export const SERVER_CACHE_HINTS = {
    'tools/list': { ttlMs: 86_400_000, cacheScope: 'public' },
    'prompts/list': { ttlMs: 86_400_000, cacheScope: 'public' },
    'server/discover': { ttlMs: 3_600_000, cacheScope: 'public' },
    'resources/list': { ttlMs: 0, cacheScope: 'private' },
    'resources/templates/list': { ttlMs: 0, cacheScope: 'private' },
    'resources/read': { ttlMs: 0, cacheScope: 'private' },
} as const satisfies Record<string, CacheHint>;

/**
 * Cache key namespace: the tool API version, the package version and the
 * engine version, so an engine upgrade can never serve bytes written by the
 * previous engine.
 */
const CACHE_API_VERSION = `${TOOL_API_VERSION}/${PKINATIVE_MCP_VERSION}/${PKINATIVE_VERSION}`;

/** True when the call's input requests a file-mode output (filesystem side-effect). */
function isFileOutput(input: unknown): boolean {
    if (input === null || typeof input !== 'object') return false;
    const mode = (input as { outputMode?: unknown }).outputMode;
    return mode === 'file';
}

/** True when a string value anywhere in the input asks for randomness or the wall clock. */
function hasVolatileValue(input: unknown, depth = 0): boolean {
    if (depth > 8 || input === null || typeof input !== 'object') return false;
    for (const v of Object.values(input as Record<string, unknown>)) {
        if (v === 'random' || v === 'now') return true;
        if (typeof v === 'object' && hasVolatileValue(v, depth + 1)) return true;
    }
    return false;
}

/** True when the tool's input schema accepts a password (top level or inside `signer`). */
function acceptsPassword(tool: ToolDefinition): boolean {
    const props = (tool.inputSchema['properties'] ?? {}) as Record<string, unknown>;
    if ('password' in props || 'signer' in props) return true;
    return Object.values(props).some((p) => p !== null && typeof p === 'object' && 'password' in (((p as Record<string, unknown>)['properties'] ?? {}) as Record<string, unknown>));
}

function readPath(input: unknown, dotted: string): unknown {
    let cur: unknown = input;
    for (const seg of dotted.split('.')) {
        if (cur === null || typeof cur !== 'object') return undefined;
        cur = (cur as Record<string, unknown>)[seg];
    }
    return cur;
}

/**
 * True when this call's output may be served from the response cache: never
 * for the non-cacheable tools, sandbox references (a path is a reference, not
 * content), file output, a call carrying a secret, a `'random'` / `'now'`
 * value, or an instant input left to the wall clock.
 */
export function isCacheable(tool: ToolDefinition, input: unknown): boolean {
    if (!tool.cacheable || isFileOutput(input) || isPathInput(input) || carriesSecret(input) || hasVolatileValue(input)) return false;
    // A tool that can take the operator password (PKINATIVE_MCP_PASSWORD) may have
    // used it without any secret in the input: never cache such a call while it is set.
    if (acceptsPassword(tool) && (process.env[PASSWORD_ENV] ?? '') !== '') return false;
    for (const field of tool.instantInputs ?? []) {
        const raw = readPath(input, field);
        if (raw !== undefined && typeof raw !== 'string' && typeof raw !== 'number') return false;
        if (isClockDependent(raw as string | number | undefined)) return false;
    }
    return true;
}

const TOOL_INDEX: ReadonlyMap<string, ToolDefinition> = new Map(TOOLS.map((t) => [t.name, t]));

/**
 * Apply the opt-in token-frugal projection to a read tool's `structuredContent`.
 * `verbosity: 'summary'` swaps the full result for a canonical scalar-only subset;
 * `fields: [...]` then projects to named dot-paths. Defaults return the full result.
 */
function projectStructured(full: Record<string, unknown>, summary: Record<string, unknown>, input: unknown): Record<string, unknown> {
    const base = readVerbosity(input) === 'summary' ? summary : full;
    const fields = readFields(input);
    if (fields.length === 0) return base;
    return selectFields(base, fields) as Record<string, unknown>;
}

/**
 * Surface `fields` paths that matched nothing (a typo, or a field that is only
 * present with another option). Additive: `_meta.unmatchedFields` appears only
 * in that case, so a structured consumer is never left with an empty object
 * and no explanation.
 */
function projectionMeta(full: Record<string, unknown>, summary: Record<string, unknown>, input: unknown): { _meta?: { unmatchedFields: string[]; availableFields: string[] } } {
    const fields = readFields(input);
    if (fields.length === 0) return {};
    const base = readVerbosity(input) === 'summary' ? summary : full;
    const unmatched = fields.filter((f) => {
        const head = f.split('.')[0]?.trim() ?? '';
        return head.length > 0 && !(head in base);
    });
    return unmatched.length === 0 ? {} : { _meta: { unmatchedFields: unmatched, availableFields: Object.keys(base) } };
}

type ContentBlock = CallToolResult['content'][number];

/** The content blocks that deliver an artefact: the embedded resource (base64 mode) or the resource_link (file mode). */
function artefactBlocks(artefact: OutputResult): ContentBlock[] {
    if (artefact.hex !== undefined) return [];
    if (artefact.mode === 'file') {
        const link = artefact.filePath !== undefined ? resourceLinkForPath(artefact.filePath) : null;
        return link !== null ? [{ type: 'resource_link', ...link }] : [];
    }
    const blob = artefact.base64 ?? '';
    const resource = artefact.encoding === 'pem'
        ? { uri: `data:${artefact.mimeType};base64,${blob}`, mimeType: artefact.mimeType, text: Buffer.from(blob, 'base64').toString('utf8') }
        : { uri: `data:${artefact.mimeType};base64,${blob}`, mimeType: artefact.mimeType, blob };
    return [{ type: 'resource', resource }];
}

/** `structuredContent` members of an artefact: everything but the bytes (never duplicated). */
function artefactStructured(artefact: OutputResult): Record<string, unknown> {
    return {
        mode: artefact.mode,
        encoding: artefact.encoding,
        sizeBytes: artefact.sizeBytes,
        sha256: artefact.sha256,
        ...(artefact.filePath !== undefined ? { filePath: artefact.filePath } : {}),
        ...(artefact.hex !== undefined ? { hex: artefact.hex } : {}),
        ...(artefact.summary !== undefined ? { summary: artefact.summary } : {}),
    };
}

function projected(text: string, full: Record<string, unknown>, summary: Record<string, unknown>, input: unknown, extra: ContentBlock[] = []): CallToolResult {
    return {
        content: [{ type: 'text', text }, ...extra],
        structuredContent: projectStructured(full, summary, input),
        ...projectionMeta(full, summary, input),
    };
}

function buildArtefactResult(output: Record<string, unknown>, tool: ToolDefinition): CallToolResult {
    const artefact = output as unknown as OutputResult & Record<string, unknown>;
    // The bytes and the MIME type travel in the content block, never in structuredContent.
    const { base64: _b, hex: _h, mimeType: _m, ...rest } = artefact;
    void _b;
    void _h;
    void _m;
    const structured = { ...rest, ...artefactStructured(artefact) };
    return {
        content: [{ type: 'text', text: tool.text(output) }, ...artefactBlocks(artefact)],
        structuredContent: structured,
    };
}

function buildGovernanceResult(output: Record<string, unknown>, tool: ToolDefinition): CallToolResult {
    return {
        content: [
            { type: 'text', text: tool.text(output) },
            { type: 'text', text: String(output['draftMarkdown'] ?? '') },
        ],
        structuredContent: output,
    };
}

function dispatchOutput(output: Record<string, unknown>, tool: ToolDefinition, input: unknown): CallToolResult {
    switch (tool.kind) {
        case 'artefact':
            return buildArtefactResult(output, tool);
        case 'governance':
            return buildGovernanceResult(output, tool);
        case 'read':
        case 'verdict':
        case 'engine':
        case 'explain': {
            // A read / verdict result may carry one artefact attachment, delivered once as a content block.
            const { artefact, ...full } = output as Record<string, unknown> & { artefact?: OutputResult | undefined };
            const summary = tool.summary !== undefined ? tool.summary(output) : full;
            const blocks = artefact !== undefined ? artefactBlocks(artefact) : [];
            const structured = artefact !== undefined ? { ...full, artefact: artefactStructured(artefact) } : full;
            return projected(tool.text(output), structured, summary, input, blocks);
        }
    }
}

function buildErrorResult(err: unknown, toolName: string): CallToolResult {
    if (err instanceof ToolError) {
        return {
            content: [{ type: 'text', text: `${toolName} failed [${err.code}]: ${err.message}` }],
            isError: true,
            _meta: { error: { code: err.code, message: err.message, ...(err.data !== undefined ? { data: err.data } : {}) } },
        };
    }
    const message = err instanceof Error ? err.message : String(err);
    return {
        content: [{ type: 'text', text: `${toolName} failed: ${message}` }],
        isError: true,
    };
}

interface PromptDefinition {
    readonly name: string;
    readonly title: string;
    readonly description: string;
    readonly text: string;
}

const VERIFY_BEFORE_TRUST_RECIPE = `Verify before you trust — the minimal sequence for any certificate from an untrusted source:
1. inspect_certificate { certificate, verbosity:'summary' } — subject, issuer, validity window, SAN, EKU, diagnostics. A signature.valid from this tool (issuer / checkSelfSignature) is ONE signature against ONE key: it is NOT trust.
2. verify_certificate_chain { leaf, candidates:[intermediates], trustAnchors:[your roots], at:'<ISO instant>', serverName:{host}, purposes:['serverAuth'] } — the RFC 5280 §6 verdict: path building, every signature, validity at 'at', name constraints, policies, key usage. Pin 'at': a verdict depends on the instant and a pinned one is reproducible (and cacheable).
3. Revocation is offline by design: fetch the CRL (crlDistributionPoints) or the OCSP response (authorityInfoAccess; create_ocsp_request builds the request you POST) yourself, then pass crls:[…] / ocspResponses:[…] with requireRevocation:true. Saying "valid" without evidence is a choice you make — the report says revocationChecked:false.
4. Branch on valid and reasons[].code (PKI_REASON_*): never on message text. A negative verdict is valid:false in structuredContent, never isError; isError is reserved for inputs the engine refuses (PKI_* codes) and caller mistakes.
Every step is read-only; nothing leaves the process; this server never fetches anything.`;

const ISSUE_CERTIFICATE_RECIPE = `Issuing certificates with create_csr / create_certificate (no key is ever generated or exported here — bring keys from your HSM, KMS or openssl genpkey):
1. CA: create_certificate { spec:{ subject:{CN:'My CA'}, validityDays:3650, extensions:{ basicConstraints:{ca:true}, keyUsage:['keyCertSign','cRLSign'] } }, signer:{ key:{ path:'ca.key.pem' } } } — self-signed because no issuerCertificate is given; the subject public key is derived from the plain key. subjectKeyIdentifier is added by default.
2. Request: the subject's side runs create_csr { spec:{ subject, extensions:{ subjectAltName:{dns:[…]} } }, signer:{ key:{…} } } (proof of possession is verified before the CSR is returned). inspect_csr shows what it asks for.
3. Leaf: create_certificate { spec:{ subject, extensions:{ subjectAltName, extendedKeyUsage:['serverAuth'], keyUsage:['digitalSignature'] } }, issuerCertificate:{ path:'ca.crt.pem' }, subjectPublicKey:{ path:'request.csr.pem' }, signer:{ key:{ path:'ca.key.pem' } } } — authorityKeyIdentifier is added by default; the result is verified against the issuer before it is returned (summary.signatureVerified).
4. Serial numbers: 'random' (default, 127 bits from node:crypto, summary.randomSerial:true) or a value you manage; notBefore defaults to PKINATIVE_MCP_AT or now (whole seconds) — pin it for reproducible bytes.
5. RSA keys need signer.rsaScheme:'pkcs1'|'pss' (no default); an encrypted PKCS#8 key needs signer.password (or PKINATIVE_MCP_PASSWORD) and signer.keyType unless a certificate / public key input names the type; SHA-1 needs allowSha1:true.
6. Prove it: verify_certificate_chain { leaf, trustAnchors:[the CA], at } → valid:true.`;

const SIGN_AND_TIMESTAMP_RECIPE = `CMS signing and RFC 3161 time-stamping (sign_cms → create_timestamp_request → amend_cms → verify_cms):
1. sign_cms { content:{ path:'report.pdf' }, detached:true, certificate:{…}, chain:[intermediates], signer:{ key:{…} } } — ESS signing-certificate-v2 and CMS algorithm protection are on by default; signingTime defaults to PKINATIVE_MCP_AT or now; the new signature is verified against the certificate before the bytes are returned.
2. A counter time-stamp stamps the SIGNATURE VALUE, not the document: inspect_cms { signedData, fields:['signerInfos.signature'] } → create_timestamp_request { data:{ base64 of those bytes }, nonce:'random' } → POST the .tsq to your TSA yourself (this server never does) → amend_cms { signedData, operation:'add-timestamp', token:{ the .tsr } } (a token whose imprint is not over the signature value is refused before anything is written).
3. verify_cms { signedData, content, trustAnchors, candidates, at, atTimeStamp:true } — every signer's signature, chain, purposes, time-stamps and offline revocation in one verdict. report.valid = unaltered AND trusted; signers[i].intact = unaltered only. Never use signingTime as proof of time: only a verified time-stamp is.
4. inspect_cms.signerSignature (verify_signer) is a key check, not the verdict — it reads no content digest, no chain.`;

const OFFLINE_REVOCATION_RECIPE = `Revocation without a network (the engine never fetches; you carry the evidence):
• Where to fetch: inspect_certificate → extensions crlDistributionPoints (the CRL URL) and authorityInfoAccess (the OCSP responder URL). Fetch the CRL bytes yourself; for OCSP, create_ocsp_request { certificate, issuer, hashAlgorithm:'SHA-256', nonce:'random' } builds the DER you POST (Content-Type application/ocsp-request) and the response bytes come back to you.
• CRL: inspect_crl { crl, find:{ certificate }, issuer } (is the serial listed? is the signature good?) or the verdict check_crl_revocation { certificate, crl, delta?, issuer, at } (RFC 5280 §6.3: scope, freshness via staleTolerance, delta CRL, signature).
• OCSP: inspect_ocsp_response { response } then check_ocsp_status { response, certificate, issuer, responder?, nonce, requireNonce, at } — CertID match, responder signature, responder authorisation (the CA, or a delegate with OCSPSigning; responderTrusted:true for out-of-band trust), freshness.
• The one-call form: verify_certificate_chain { …, crls:[…], ocspResponses:[…], requireRevocation:true } — PKI_REASON_REVOKED is reported only from authenticated evidence; PKI_REASON_REVOCATION_UNKNOWN when none covers a certificate.`;

const OPEN_KEYS_SAFELY_RECIPE = `Keys and PKCS#12 without leaking a byte (inspect_private_key / inspect_pkcs12 / open_pkcs12):
• Describe first, without a password: inspect_private_key { key } tells the format (pkcs8 / encrypted-pkcs8), the algorithm and curve, the PBES2 parameters; inspect_pkcs12 { pkcs12 } tells the MAC kind and lists the bags (certificates by subject, keys by algorithm). No report, ever, carries a key byte: every key view is an allow-list.
• Open: open_pkcs12 { pkcs12, password } → integrity ('verified' | 'unverified' | 'mismatch'), the keys as non-extractable Web Crypto handles (described, never exported), certificates and CRLs; exportCertificates:true returns a PEM bundle of the certificates only. inspect_private_key { key, tryImport:true, password, keyType } proves an encrypted key is usable.
• Doctrine: PBES2 (PBKDF2 + AES-CBC) and PBMAC1 only. A legacy RC2 / 3DES file (openssl -legacy) is refused with the OpenSSL 3.4 conversion remedy; the RFC 7292 Appendix B MAC is never computed — allowUnverifiedIntegrity:true opens such a file only when you trust its origin. An RSA key in a PKCS#12 needs rsaScheme to be imported (there is no default).
• Passwords: pass the password input (it lands in the host's transcript) or set PKINATIVE_MCP_PASSWORD in the server environment (it does not). Never both. A call carrying a password is never cached; a wrong password is PKI_CRYPTO_DECRYPTION_FAILED and the value is never echoed.
• Key-bearing files (.key .p8 .p12 .pfx) in the sandbox are never listed by resources/list nor served by resources/read; nothing in this server writes one.`;

/**
 * MCP prompts: the AI-governance / Human-In-The-Loop contract plus five
 * ready-made recipes. Read-only text; no arguments, no side effects.
 */
const PROMPTS: readonly PromptDefinition[] = [
    {
        name: 'governance_contract',
        title: 'AI-governance & HITL contract',
        description: 'The non-negotiable AI-governance / Human-In-The-Loop contract for pkinative-mcp: the agent is a draftsman, the human is the only gate, zero runtime dependencies, no autonomous GitHub writes, no network, no secret in a draft.',
        text: GOVERNANCE_CONTRACT_SUMMARY,
    },
    {
        name: 'draft_issue_workflow',
        title: 'Human-in-the-loop issue workflow',
        description: 'Step-by-step workflow for drafting a GitHub issue with the draft_governance_issue tool and handing it to a human for review and submission.',
        text: DRAFT_ISSUE_WORKFLOW,
    },
    {
        name: 'verify_before_trust',
        title: 'Verify before you trust',
        description: 'The minimal sequence (inspect_certificate → verify_certificate_chain with a pinned instant → offline revocation evidence) to run on any certificate before relying on it, and why a verified signature is not trust.',
        text: VERIFY_BEFORE_TRUST_RECIPE,
    },
    {
        name: 'issue_certificate',
        title: 'Issue a CA, a CSR and a leaf certificate',
        description: 'How create_csr / create_certificate chain together (self-signed CA, request, issued leaf), what is derived, what is verified before the bytes are returned, and the key / scheme / instant rules.',
        text: ISSUE_CERTIFICATE_RECIPE,
    },
    {
        name: 'sign_and_timestamp',
        title: 'Sign content and add an RFC 3161 time-stamp',
        description: 'sign_cms, the counter time-stamp over the signature value (create_timestamp_request → your TSA → amend_cms), and verify_cms as the one verdict.',
        text: SIGN_AND_TIMESTAMP_RECIPE,
    },
    {
        name: 'offline_revocation',
        title: 'Revocation without a network',
        description: 'Where to fetch CRL / OCSP evidence yourself, how create_ocsp_request builds the request you send, and how check_crl_revocation / check_ocsp_status / verify_certificate_chain judge the bytes you bring.',
        text: OFFLINE_REVOCATION_RECIPE,
    },
    {
        name: 'open_keys_safely',
        title: 'Keys and PKCS#12 without leaking a byte',
        description: 'inspect_private_key / inspect_pkcs12 / open_pkcs12: describe before opening, PBES2 / PBMAC1 doctrine, the legacy-file remedy, the two password channels, and why no report ever holds a key byte.',
        text: OPEN_KEYS_SAFELY_RECIPE,
    },
];

const PROMPT_INDEX: ReadonlyMap<string, PromptDefinition> = new Map(PROMPTS.map((p) => [p.name, p]));

const SERVER_INSTRUCTIONS = `pkinative-mcp: ${TOOLS.length} tools over the pkinative v${PKINATIVE_VERSION} PKI engine (zero dependencies, pure TypeScript, Web Crypto for every signature). Tool API ${TOOL_API_VERSION}. MCP 2026-07-28 (stateless) with automatic fallback to the 2025-era handshake. Every tool has typed input/output schemas and executable _meta.examples; read tools never modify input; artefact tools are reproducible when serial, nonce and instants are pinned; every option is opt-in.

DECISION TREE:
  • What is this object? → convert_pem (labels of a PEM text) then inspect_certificate / inspect_csr / inspect_crl / inspect_ocsp_response / inspect_cms / inspect_timestamp / inspect_private_key / inspect_pkcs12 (facts + diagnostics; verbosity:'summary' for the scalars)
  • Is this certificate trustworthy? → verify_certificate_chain (RFC 5280 §6 verdict: path, signatures, validity at 'at', name, purposes, policies, offline CRL / OCSP revocation) — NOT inspect_certificate.signature
  • Does the name / purpose fit? → check_certificate_name (host name vs SAN, RFC 6125) / check_certificate_purpose (extended key usage) — both run inside verify_certificate_chain when serverName / purposes are given
  • Why did a path fail / which path? → build_certificate_path (discovery, signatures NOT checked) / validate_certificate_path (a path you ordered, signatures checked)
  • Is it revoked? → check_crl_revocation / check_ocsp_status with the bytes YOU fetched (create_ocsp_request builds the request); the engine never fetches
  • Sign / is this signature good? → sign_cms (CMS SignedData, attached or detached) · verify_cms (the verdict: signatures, chains, time-stamps, revocation) vs inspect_cms (facts; signerSignature is a key check, not trust)
  • Time-stamps → create_timestamp_request / inspect_timestamp / verify_timestamp; counter-stamp a CMS signer with amend_cms add-timestamp
  • Issue / request → create_csr / create_certificate (keys come from you; nothing generates or exports a key here)
  • Keys → inspect_private_key / inspect_pkcs12 (no password needed) / open_pkcs12 (password; key handles described, never exported)
  • Raw bytes → decode_asn1 / encode_asn1 / encode_x509_structure / decode_extension / resolve_oid / compute_fingerprint
  • What can this server do here? → describe_engine (versions, Web Crypto capabilities, limits, ceilings, caps, sandbox, the 57 / 43 / 97 code vocabularies, refusals)
  • A code you do not understand → explain_code (PKI_* error, PKI_REASON_*, PKI_DIAG_* or a wrapper code)
  • Propose an upstream change → draft_governance_issue (local draft, never submitted)

SECURITY POSTURE:
  • No network, ever: no CRL / OCSP / AIA / TSA fetch, no telemetry, no URL from any argument. The only filesystem boundary is PKINATIVE_MCP_OUTPUT_DIR (path inputs read from it, outputMode:'file' written under it, never overwritten); key-bearing files are never written nor served as resources.
  • No key leaves: signing keys are non-extractable Web Crypto handles; every key / PKCS#12 report is an allow-list view; passwords (input or PKINATIVE_MCP_PASSWORD, never both) are never echoed, logged or cached.
  • Doctrine, surfaced not hidden: no key generation or export, no PKCS#8 / PKCS#12 / CRL / OCSP-response writer; RSA needs rsaScheme (no default); SHA-1 only with allowSha1:true; PBES2 / PBMAC1 only (legacy PKCS#12 refused with the OpenSSL 3.4 conversion); DSA / ML-DSA parsed but never verified; the 22 engine limits can be raised per call but never above the operator ceilings (LIMIT_CEILING_EXCEEDED names the variable).

COMMON PITFALLS:
  • Every PKI input is an object with exactly one of pem / derBase64 / path. pem is RFC 7468 text (starts with -----BEGIN); derBase64 is the DER as base64 exactly once (no data: URI, not PEM); path is relative to the sandbox. A single-object input holding several PEM blocks is refused — use convert_pem extractIndex or a bundle input.
  • Verdict tools (verify_*, check_*, validate_*, build_*, open_pkcs12) return valid:false + reasons[] in structuredContent for a negative verdict — never isError. Branch on reasons[].code. isError means the input itself was refused (a PKI_* code) or the call was wrong.
  • Pin 'at' (ISO 8601) for reproducible, cacheable verdicts; omitted = PKINATIVE_MCP_AT or the wall clock (never cached). build_certificate_path never checks signatures (PKI_REASON_SIGNATURE_NOT_CHECKED is always present).
  • A counter time-stamp stamps the signer's signature value (inspect_cms fields:['signerInfos.signature']), not the content. The OCSP CertID hash defaults to SHA-1 (RFC 6960); ask for 'SHA-256' explicitly.
  • An encrypted PKCS#8 key needs its type (signer.keyType, or a certificate / public key input); an RSA key always needs rsaScheme.
  • verbosity:'summary' keeps the scalar verdict; fields:[…] projects dot-paths — unmatched paths are reported in _meta.unmatchedFields.

TOKEN-FRUGAL READS & RESOURCES: read and verdict tools accept verbosity:'summary' and fields:[…]. Produced artefacts arrive once as an embedded resource block (PEM as text, DER as blob; never duplicated in structuredContent); in file mode the result carries a resource_link and the file is listed under resources/list as pkinative://output/<path>. Prompts: verify_before_trust, issue_certificate, sign_and_timestamp, offline_revocation, open_keys_safely, governance_contract, draft_issue_workflow. Docs: docs/AI_GUIDE.md, docs/guides/*.md.`;

/** Wire-level `tools/list` payload (deterministic order = registration order, per MCP 2026-07-28 guidance). */
export function listToolsPayload(): ListToolsResult {
    return { tools: TOOLS.map(describeTool) };
}

function describeTool(t: ToolDefinition): Tool {
    return {
        name: t.name,
        title: t.title,
        description: t.description,
        inputSchema: t.inputSchema as Tool['inputSchema'],
        ...(t.outputSchema !== undefined ? { outputSchema: t.outputSchema as Tool['outputSchema'] } : {}),
        annotations: t.annotations,
        _meta: {
            apiVersion: TOOL_API_VERSION,
            ...(t.examples !== undefined ? { examples: t.examples } : {}),
        },
    };
}

/** Registered tool names, in registration order (docs-consistency canary). */
export function toolNames(): string[] {
    return TOOLS.map((t) => t.name);
}

/** The registered definition of a tool (tests, the corpus tooling). */
export function toolDefinition(name: string): ToolDefinition | undefined {
    return TOOL_INDEX.get(name);
}

/**
 * Execute one tool call exactly as the `tools/call` handler does (cache lookup,
 * handler, result shaping, error → `isError`). Transport-agnostic so tests and
 * the corpus tooling can exercise the contract without a connection.
 */
export async function callToolDirect(name: string, args: unknown): Promise<CallToolResult> {
    const tool = TOOL_INDEX.get(name);
    if (tool === undefined) {
        return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
        };
    }
    try {
        const input = args ?? {};
        const cacheable = isCacheable(tool, input);
        // A-031: a tool whose result depends on an instant is keyed on the operator pin too — an omitted
        // `at` resolves to PKINATIVE_MCP_AT, and a verdict cached under one pin must miss under another.
        const cacheInput = tool.instantInputs !== undefined ? { input, pinnedInstant: readPinnedInstant() } : input;
        if (cacheable) {
            const hit = getCached<Record<string, unknown>>(name, CACHE_API_VERSION, cacheInput);
            if (hit !== null) {
                const result = dispatchOutput(hit, tool, input);
                return { ...result, _meta: { ...(result._meta ?? {}), cached: true } };
            }
        }
        const output = await tool.handler(input);
        if (cacheable) {
            setCached(name, CACHE_API_VERSION, cacheInput, output);
        }
        return dispatchOutput(output, tool, input);
    } catch (err) {
        return buildErrorResult(err, name);
    }
}

/**
 * Build a fresh, connection-less `Server`. Cheap and side-effect free, so the
 * HTTP entry point can call it once per request (MCP 2026-07-28 is stateless)
 * while stdio pins a single instance per process.
 */
export function createServer(): Server {
    const server = new Server(
        { name: SERVER_NAME, version: SERVER_VERSION, title: SERVER_TITLE, description: SERVER_DESCRIPTION, websiteUrl: SERVER_WEBSITE_URL },
        {
            capabilities: { tools: {}, prompts: {}, resources: {} },
            instructions: SERVER_INSTRUCTIONS,
            cacheHints: SERVER_CACHE_HINTS,
        } satisfies ServerOptions,
    );

    // Native MCP resources: expose sandbox files as re-referenceable
    // pkinative://output/… URIs (empty when the sandbox is disabled).
    server.setRequestHandler('resources/list', async () => ({
        resources: (await listResources()).map((r) => ({
            uri: r.uri,
            name: r.name,
            title: r.title,
            description: r.description,
            mimeType: r.mimeType,
            size: r.size,
        })),
    }));

    server.setRequestHandler('resources/templates/list', async () => ({
        resourceTemplates: listResourceTemplates(),
    }));

    server.setRequestHandler('resources/read', async (request) => {
        const uri = request.params.uri;
        try {
            const contents = await readResource(uri);
            return { contents: [contents.text !== undefined ? { uri: contents.uri, mimeType: contents.mimeType, text: contents.text } : { uri: contents.uri, mimeType: contents.mimeType, blob: contents.blob ?? '' }] };
        } catch (err) {
            // Spec 2026-07-28: resource-not-found is -32602 (Invalid params) on every revision.
            if (err instanceof ToolError) {
                if (err.code === 'UNKNOWN_RESOURCE') throw new ResourceNotFoundError(uri, err.message);
                throw new ProtocolError(ProtocolErrorCode.InvalidParams, `[${err.code}] ${err.message}`);
            }
            throw err;
        }
    });

    server.setRequestHandler('prompts/list', async () => ({
        prompts: PROMPTS.map((p) => ({ name: p.name, title: p.title, description: p.description })),
    }));

    server.setRequestHandler('prompts/get', async (request): Promise<GetPromptResult> => {
        const prompt = PROMPT_INDEX.get(request.params.name);
        if (prompt === undefined) {
            throw new ProtocolError(ProtocolErrorCode.InvalidParams, `[UNKNOWN_PROMPT] Unknown prompt: ${request.params.name}`);
        }
        return {
            description: prompt.description,
            messages: [{ role: 'user', content: { type: 'text', text: prompt.text } }],
        };
    });

    server.setRequestHandler('tools/list', async () => listToolsPayload());

    server.setRequestHandler('tools/call', async (request): Promise<CallToolResult> => {
        const { name, arguments: args } = request.params;
        const tool = TOOL_INDEX.get(name);
        if (tool === undefined) {
            // MCP 2026-07-28 server/tools §Error Handling: "Unknown tool" is a protocol
            // error (-32602), not an `isError` execution result.
            throw new ProtocolError(ProtocolErrorCode.InvalidParams, `[UNKNOWN_TOOL] Unknown tool: ${name}`);
        }
        const result = await callToolDirect(name, args);
        // Identity for object-shaped structuredContent; keeps the wire projection the
        // SDK expects for the negotiated protocol revision.
        return server.projectCallToolResult(result, tool.outputSchema as Record<string, unknown> | undefined);
    });

    return server;
}

export { ensureEngineReady };

export const __serverMetadata = { name: SERVER_NAME, version: SERVER_VERSION, title: SERVER_TITLE, description: SERVER_DESCRIPTION, websiteUrl: SERVER_WEBSITE_URL, engineVersion: PKINATIVE_VERSION } as const;
export const __serverInstructions = SERVER_INSTRUCTIONS;
export const __prompts = PROMPTS;
