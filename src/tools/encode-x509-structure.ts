/**
 * Tool: encode_x509_structure — one X.509 building block to DER from a JSON
 * spec, through pkinative's structural encoders (the 15 structures of
 * `pkinative cert encode`): a Name, one attribute, a Validity, an SPKI, an
 * AlgorithmIdentifier, an Attribute, one Extension or an Extensions
 * SEQUENCE, and the extension values (basicConstraints, keyUsage,
 * extendedKeyUsage, subjectAltName, SKI, AKI). `signature-algorithm` takes a
 * signer instead of a spec: the AlgorithmIdentifier a key would write.
 * Deterministic: the same spec gives the same bytes (WRITES).
 */
import {
    computeKeyIdentifier,
    encodeAlgorithmIdentifier,
    encodeAttribute,
    encodeAuthorityKeyIdentifier,
    encodeBasicConstraints,
    encodeDistinguishedName,
    encodeExtendedKeyUsage,
    encodeExtension,
    encodeExtensions,
    encodeKeyUsage,
    encodeNameAttribute,
    encodeSignatureAlgorithm,
    encodeSubjectAltName,
    encodeSubjectKeyIdentifier,
    encodeSubjectPublicKeyInfo,
    encodeValidity,
    getExtension,
    parseCertificate,
} from 'pkinative';
import { z } from 'zod';

import { DIAGNOSTICS_OUTPUT_PROPERTIES, type DiagnosticsReport } from '../diagnostics.js';
import { ToolError } from '../errors.js';
import { parseNameAttribute, parseNameSpec, specError } from '../names.js';
import { ARTEFACT_OUTPUT_PROPERTIES, emitArtefact, outputInputProperties, outputShape, type OutputResult } from '../output.js';
import { createParseContext, PARSE_INPUT_PROPERTIES, type ParseContext } from '../parse-context.js';
import { guard } from '../pki-errors.js';
import { LABELS, loadPkiObject, PkiInputSchema, SECRET_LABELS, type PkiInputFields } from '../pki-input.js';
import { ALLOW_SHA1_INPUT_PROPERTY, loadSigner, SIGNER_INPUT_SCHEMA, SignerSchema } from '../signer.js';
import { loadPublicKey } from '../spki.js';
import { parseInstant } from '../time.js';
import { purposeOid } from '../trust.js';
import { buildExtensions, critical, generalNames, hexValue, isSpec, keyUsages, onlyMembers, type Spec } from '../x509-spec.js';
import { defineTool, WRITES } from './_definition.js';
import { AllowSha1Shape, parseInput, ParseShape, withDiagnostics } from './_shared.js';

export const ENCODE_X509_STRUCTURE_NAME = 'encode_x509_structure';

const STRUCTURES = [
    'name', 'name-attribute', 'validity', 'spki', 'algorithm-identifier', 'attribute', 'extension', 'extensions',
    'basic-constraints', 'key-usage', 'extended-key-usage', 'subject-alt-name', 'subject-key-identifier',
    'authority-key-identifier', 'signature-algorithm',
] as const;

export const X509_STRUCTURES: readonly string[] = STRUCTURES;
export type X509Structure = (typeof STRUCTURES)[number];

const SPEC_DESCRIPTION =
    'The structure\'s members (a closed object; an unknown member is refused with VALIDATION_ERROR naming it). '
    + 'name: a distinguished name — { "C": "FR", "O": "Acme", "CN": "x" } or an array of RDNs [[{ "type", "value", "stringType"? }], …]. '
    + 'name-attribute: { "type": "CN" | registry name | dotted OID, "value", "stringType"?: utf8|printable|ia5|numeric }. '
    + 'validity: { "notBefore", "notAfter" } — both ISO 8601 instants or epoch ms (required; no implicit now; whole seconds). '
    + 'spki: { "algorithm": dotted OID, "publicKey": hex of the BIT STRING content, "parameters"?: hex DER }. '
    + 'algorithm-identifier: { "oid", "parameters"?: hex DER }. attribute: { "oid", "values": [hex DER, …] }. '
    + 'extension: { "oid", "critical"?: false, "value": hex of the extnValue content }. '
    + 'extensions: the same closed object as create_certificate\'s spec.extensions (basicConstraints, keyUsage, extendedKeyUsage, subjectAltName, issuerAltName, subjectKeyIdentifier / authorityKeyIdentifier as hex, raw[]) — no key is at hand, so true for a key identifier is refused. '
    + 'basic-constraints: { "ca": boolean, "pathLen"?: n }. key-usage: ["digitalSignature", …] or { "usages": [...] }. '
    + 'extended-key-usage: ["serverAuth", "1.3.6.1.5.5.7.3.2", …] or { "purposes": [...] }. '
    + 'subject-alt-name: { "dns": [], "email": [], "uri": [], "ip": [], "registeredId": [], "directoryName": [<name>] }. '
    + 'subject-key-identifier: { "keyId": hex } or { "publicKey": <pem | derBase64 | path of a certificate, a CSR or a PUBLIC KEY> } (RFC 5280 §4.2.1.2 SHA-1 of the key bits). '
    + 'authority-key-identifier: { "keyId": hex } or { "issuerCertificate": <pem | derBase64 | path> } (its subjectKeyIdentifier, else the SHA-1 of its key bits). '
    + 'signature-algorithm takes no spec (signer decides it).';

export const ENCODE_X509_STRUCTURE_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['structure'],
    properties: {
        structure: { type: 'string', enum: [...STRUCTURES], description: 'The X.509 building block to encode.' },
        spec: { anyOf: [{ type: 'object', additionalProperties: {} }, { type: 'array', items: {} }], description: SPEC_DESCRIPTION },
        signer: { ...SIGNER_INPUT_SCHEMA, description: `signature-algorithm only: ${SIGNER_INPUT_SCHEMA.description} Nothing is signed here — only the AlgorithmIdentifier the key would write (RSA-PSS carries its digest and salt length).` },
        label: { type: 'string', minLength: 1, maxLength: 64, pattern: '^[A-Z0-9][A-Z0-9 -]*$', description: "The RFC 7468 label for encoding:'pem' (required then, refused otherwise); a key-bearing label is refused." },
        ...ALLOW_SHA1_INPUT_PROPERTY,
        ...PARSE_INPUT_PROPERTIES,
        ...outputInputProperties('hex', '.der .bin .asn1 for der; .pem for pem'),
    },
} as const;

const InputSchema = z.strictObject({
    structure: z.enum(STRUCTURES),
    spec: z.union([z.looseObject({}), z.array(z.unknown())]).optional(),
    signer: SignerSchema.optional(),
    label: z.string().min(1).max(64).regex(/^[A-Z0-9][A-Z0-9 -]*$/).optional(),
    ...AllowSha1Shape,
    ...ParseShape,
    ...outputShape('hex'),
}).superRefine((v, ctx) => {
    if (v.structure === 'signature-algorithm') {
        if (v.signer === undefined) ctx.addIssue({ code: 'custom', message: 'signature-algorithm takes signer (the key decides the algorithm)', path: ['signer'] });
        if (v.spec !== undefined) ctx.addIssue({ code: 'custom', message: 'signature-algorithm takes no spec: signer decides it', path: ['spec'] });
    } else {
        if (v.spec === undefined) ctx.addIssue({ code: 'custom', message: `${v.structure} needs spec`, path: ['spec'] });
        if (v.signer !== undefined) ctx.addIssue({ code: 'custom', message: 'signer applies to signature-algorithm only', path: ['signer'] });
    }
    if (v.encoding === 'pem' && v.label === undefined) ctx.addIssue({ code: 'custom', message: "encoding:'pem' needs label (the RFC 7468 label to write)", path: ['label'] });
    if (v.encoding !== 'pem' && v.label !== undefined) ctx.addIssue({ code: 'custom', message: "label applies to encoding:'pem' only", path: ['label'] });
});

export interface EncodeX509StructureResult extends OutputResult, DiagnosticsReport {
    readonly summary: {
        readonly structure: X509Structure;
        readonly sizeBytes: number;
    };
}

export const ENCODE_X509_STRUCTURE_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['mode', 'encoding', 'sizeBytes', 'sha256', 'summary', 'diagnostics', 'diagnosticCounts'],
    properties: {
        ...ARTEFACT_OUTPUT_PROPERTIES,
        summary: {
            type: 'object',
            additionalProperties: false,
            required: ['structure', 'sizeBytes'],
            properties: {
                structure: { type: 'string', enum: [...STRUCTURES] },
                sizeBytes: { type: 'integer', minimum: 0, description: 'Size of the DER.' },
            },
        },
        ...DIAGNOSTICS_OUTPUT_PROPERTIES,
    },
} as const;

const DOTTED = /^\d+(\.\d+)+$/;

/** The spec as a closed object of `members` (the message names the structure's members). */
function objectSpec(spec: unknown, members: readonly string[]): Spec {
    if (!isSpec(spec)) throw specError('$', `expected an object { ${members.map((m) => `"${m}"`).join(', ')} }`);
    return onlyMembers(spec, members, '');
}

function oidMember(s: Spec, key: string): string {
    const v = s[key];
    if (typeof v !== 'string' || !DOTTED.test(v)) throw specError(key, 'expected a dotted OID string');
    return v;
}

function requiredHex(s: Spec, key: string, what: string): Uint8Array {
    if (s[key] === undefined) throw specError(key, `required: ${what}`);
    return hexValue(s[key], key);
}

function optionalHex(s: Spec, key: string): Uint8Array | undefined {
    return s[key] === undefined ? undefined : hexValue(s[key], key);
}

/** An array of strings, or `{ <key>: [...] }`. */
function stringList(spec: unknown, key: string): string[] {
    const list = Array.isArray(spec) ? spec : isSpec(spec) ? onlyMembers(spec, [key], '')[key] : undefined;
    if (!Array.isArray(list) || !list.every((v) => typeof v === 'string')) throw specError(Array.isArray(spec) ? '$' : key, `expected an array of strings (or { "${key}": [...] })`);
    return list;
}

/** A required explicit instant member, in whole seconds (an encoded Validity names its own instants: no 'now'). */
function instantMember(s: Spec, key: string): number {
    const v = s[key];
    if (v === undefined) throw specError(key, 'required: an ISO 8601 instant or epoch milliseconds');
    if ((typeof v !== 'string' && typeof v !== 'number') || v === 'now') throw specError(key, 'expected an explicit instant (ISO 8601 or epoch milliseconds), never "now"');
    let ms: number;
    try {
        ms = parseInstant(v, key);
    } catch {
        throw specError(key, `expected an instant (ISO 8601 or epoch milliseconds), got "${String(v)}"`);
    }
    return Math.floor(ms / 1000) * 1000;
}

/** A PKI input object inside the spec (exactly one of pem / derBase64 / path). */
function pkiInputMember(value: unknown, path: string): PkiInputFields {
    const parsed = PkiInputSchema.safeParse(value);
    if (!parsed.success) throw specError(path, 'expected exactly one of pem / derBase64 / path');
    return parsed.data;
}

function exactlyOne(s: Spec, a: string, b: string): void {
    if ((s[a] === undefined) === (s[b] === undefined)) throw specError('$', `give exactly one of "${a}" or "${b}"`);
}

async function encodeFromSpec(structure: Exclude<X509Structure, 'signature-algorithm'>, spec: unknown, ctx: ParseContext): Promise<Uint8Array> {
    const build = ctx.options.limits !== undefined ? { limits: ctx.options.limits } : {};
    const encode = (fn: () => Uint8Array): Uint8Array => guard(`Cannot encode the ${structure}`, fn);
    switch (structure) {
        case 'name': {
            const name = parseNameSpec(spec, '$');
            return encode(() => encodeDistinguishedName(name, build));
        }
        case 'name-attribute': {
            const attribute = parseNameAttribute(spec, '$');
            return encode(() => encodeNameAttribute(attribute));
        }
        case 'validity': {
            const s = objectSpec(spec, ['notBefore', 'notAfter']);
            const notBefore = instantMember(s, 'notBefore');
            const notAfter = instantMember(s, 'notAfter');
            if (notAfter <= notBefore) throw specError('notAfter', 'must be after notBefore');
            return encode(() => encodeValidity(notBefore, notAfter));
        }
        case 'spki': {
            const s = objectSpec(spec, ['algorithm', 'publicKey', 'parameters']);
            const algorithm = oidMember(s, 'algorithm');
            const publicKey = requiredHex(s, 'publicKey', 'the key as hex (the BIT STRING content)');
            const parameters = optionalHex(s, 'parameters');
            return encode(() => encodeSubjectPublicKeyInfo(algorithm, publicKey, parameters));
        }
        case 'algorithm-identifier': {
            const s = objectSpec(spec, ['oid', 'parameters']);
            const oid = oidMember(s, 'oid');
            const parameters = optionalHex(s, 'parameters');
            return encode(() => (parameters === undefined ? encodeAlgorithmIdentifier(oid) : encodeAlgorithmIdentifier(oid, parameters)));
        }
        case 'attribute': {
            const s = objectSpec(spec, ['oid', 'values']);
            const oid = oidMember(s, 'oid');
            const raw = s['values'];
            if (!Array.isArray(raw)) throw specError('values', 'expected an array of hex strings (the DER of each value)');
            const values = raw.map((v: unknown, i) => hexValue(v, `values[${i}]`));
            return encode(() => encodeAttribute(oid, values));
        }
        case 'extension': {
            const s = objectSpec(spec, ['oid', 'critical', 'value']);
            const description = { oid: oidMember(s, 'oid'), critical: critical(s, '', false), value: requiredHex(s, 'value', 'the extnValue content as hex') };
            return encode(() => encodeExtension(description));
        }
        case 'extensions': {
            if (!isSpec(spec)) throw specError('$', 'expected the extensions object ({ "basicConstraints", "keyUsage", … })');
            const descriptions = buildExtensions(spec, { subjectKeyBits: undefined, issuerKeyId: undefined, defaults: { ski: false, aki: false } });
            return encode(() => encodeExtensions(descriptions, build));
        }
        case 'basic-constraints': {
            const s = objectSpec(spec, ['ca', 'pathLen']);
            const ca = s['ca'];
            const pathLen = s['pathLen'];
            if (typeof ca !== 'boolean') throw specError('ca', 'expected a boolean');
            if (pathLen !== undefined && (typeof pathLen !== 'number' || !Number.isSafeInteger(pathLen) || pathLen < 0)) throw specError('pathLen', 'expected a non-negative integer');
            return encode(() => encodeBasicConstraints({ cA: ca, ...(typeof pathLen === 'number' ? { pathLenConstraint: pathLen } : {}) }));
        }
        case 'key-usage': {
            const usages = keyUsages(stringList(spec, 'usages'), Array.isArray(spec) ? '$' : 'usages');
            return encode(() => encodeKeyUsage(usages));
        }
        case 'extended-key-usage': {
            const purposes = stringList(spec, 'purposes').map((p) => purposeOid(p, Array.isArray(spec) ? 'spec $' : 'spec purposes'));
            return encode(() => encodeExtendedKeyUsage(purposes));
        }
        case 'subject-alt-name': {
            const names = generalNames(spec, '$');
            return encode(() => encodeSubjectAltName(names));
        }
        case 'subject-key-identifier': {
            const s = objectSpec(spec, ['keyId', 'publicKey']);
            exactlyOne(s, 'keyId', 'publicKey');
            const keyId = s['keyId'] !== undefined
                ? hexValue(s['keyId'], 'keyId')
                : computeKeyIdentifier((await loadPublicKey(pkiInputMember(s['publicKey'], 'publicKey'), 'spec publicKey', ctx)).bits);
            return encode(() => encodeSubjectKeyIdentifier(keyId));
        }
        default: {
            const s = objectSpec(spec, ['keyId', 'issuerCertificate']);
            exactlyOne(s, 'keyId', 'issuerCertificate');
            let keyId: Uint8Array;
            if (s['keyId'] !== undefined) {
                keyId = hexValue(s['keyId'], 'keyId');
            } else {
                const obj = await loadPkiObject(pkiInputMember(s['issuerCertificate'], 'issuerCertificate'), 'spec issuerCertificate', LABELS.certificate, ctx);
                const issuer = guard('Cannot read the issuer certificate', () => parseCertificate(obj.der, ctx.options));
                const ski = guard('Cannot read the issuer key identifier', () => getExtension(issuer, 'subjectKeyIdentifier'));
                keyId = ski !== undefined ? ski.keyIdentifier : computeKeyIdentifier(issuer.subjectPublicKeyInfo.publicKey.bytes);
            }
            return encode(() => encodeAuthorityKeyIdentifier(keyId));
        }
    }
}

export async function encodeX509Structure(rawInput: unknown): Promise<EncodeX509StructureResult> {
    const input = parseInput(InputSchema, rawInput);
    const ctx = createParseContext(input);
    if (input.label !== undefined && SECRET_LABELS.includes(input.label)) {
        throw new ToolError('VALIDATION_ERROR', `label: "${input.label}" names private-key material; nothing here writes a key.`, { path: 'label' });
    }
    let der: Uint8Array;
    if (input.structure === 'signature-algorithm') {
        // The key decides the algorithm; the type of an encrypted key comes from signer.keyType (no certificate is at hand).
        const loaded = await loadSigner(input.signer as z.infer<typeof SignerSchema>, input.allowSha1, undefined, ctx);
        der = guard('Cannot encode the signature-algorithm', () => encodeSignatureAlgorithm(loaded.signer));
    } else {
        der = await encodeFromSpec(input.structure, input.spec, ctx);
    }
    const artefact = await emitArtefact(der, {
        mode: input.outputMode,
        encoding: input.encoding,
        outputPath: input.outputPath,
        pemLabel: input.label ?? 'X509 STRUCTURE',
        mimeType: 'application/octet-stream',
        derExtensions: ['.der', '.bin', '.asn1'],
    });
    return withDiagnostics({ ...artefact, summary: { structure: input.structure, sizeBytes: der.length } }, ctx.sink.report());
}

export const ENCODE_X509_STRUCTURE_TOOL = defineTool<EncodeX509StructureResult>({
    name: ENCODE_X509_STRUCTURE_NAME,
    title: 'Encode X.509 structure (one building block to DER, from a JSON spec)',
    kind: 'artefact',
    description:
        "Encode ONE X.509 building block to DER through pkinative's structural encoders, deterministically (the same spec gives the same bytes): `structure` is name, name-attribute, validity, spki, algorithm-identifier, attribute, extension, extensions, basic-constraints, key-usage, extended-key-usage, subject-alt-name, subject-key-identifier, authority-key-identifier or signature-algorithm; `spec` holds that structure's members (closed objects — an unknown or missing member is refused with VALIDATION_ERROR naming `spec <path>`; validity takes explicit notBefore AND notAfter, never an implicit now; a key identifier comes as hex or is computed from a certificate / CSR / PUBLIC KEY input). signature-algorithm takes `signer` instead of a spec (the key is imported NON-EXTRACTABLE and only its algorithm is read: ECDSA, Ed25519/Ed448, RSA with the REQUIRED rsaScheme — KEY_TYPE_REQUIRED for an encrypted key without keyType, SECRET_REQUIRED without a password). Output hex by default (structuredContent.hex, ≤ 64 KiB), or DER / PEM (PEM needs `label`), inline or as a sandbox file (never overwritten). The bytes are a fragment, not a signed object: nothing here signs. Use encode_asn1 for arbitrary ASN.1 and create_certificate / create_csr for whole objects.",
    inputSchema: ENCODE_X509_STRUCTURE_INPUT_SCHEMA,
    outputSchema: ENCODE_X509_STRUCTURE_OUTPUT_SCHEMA,
    annotations: WRITES,
    cacheable: true,
    examples: [
        { title: 'A subjectAltName value (DNS, wildcard, IP)', input: { structure: 'subject-alt-name', spec: { dns: ['svc.example.test', '*.wild.example.test'], ip: ['192.0.2.1'] } } },
        { title: 'The AlgorithmIdentifier an RSA-PSS signature would carry', input: { structure: 'signature-algorithm', signer: { key: { path: 'fixtures/rsa.key.pem' }, rsaScheme: 'pss' } } },
    ],
    handler: encodeX509Structure,
    text: (r) => `${ENCODE_X509_STRUCTURE_NAME}: ${r.summary.structure} encoded, ${r.sizeBytes} bytes DER, sha256 ${r.sha256.slice(0, 16)}…${r.mode === 'file' ? `, written to ${r.filePath ?? ''}` : r.encoding === 'hex' ? ' (hex in structuredContent.hex)' : ` (${r.encoding} delivered as the embedded resource below)`}.`,
});
