/**
 * The JSON node spec of `encode_asn1` (vendored from pkinative-cli
 * `src/commands/asn1-spec.ts`). Every node is an object with a `type`:
 *
 *   { "type": "boolean", "value": true }
 *   { "type": "integer" | "enumerated", "value": "12345" | 42 | "0x7f" }
 *   { "type": "null" }
 *   { "type": "bit-string", "hex": "0a0b", "unusedBits": 0 }
 *   { "type": "named-bits", "bits": [0, 5] }
 *   { "type": "octet-string", "hex": "00ff" }
 *   { "type": "oid" | "relative-oid", "value": "1.2.840.113549" }
 *   { "type": "string", "stringType": "utf8", "value": "text" }
 *   { "type": "time", "value": "2027-01-01T00:00:00Z", "timeType": "rfc5280" }
 *   { "type": "sequence" | "set" | "set-of", "children": [ … ] }
 *   { "type": "explicit" | "implicit", "tag": 0, "class": "context", "inner": { … } }
 *   { "type": "tlv", "class": "universal", "tag": 4, "constructed": false, "hex": "…" }
 *   { "type": "der", "hex": "…" }        pre-encoded bytes, checked to be one DER object
 *
 * Each node runs through the engine's own encoder; a malformed spec is
 * VALIDATION_ERROR naming the JSON path of the faulty node. Nesting is
 * bounded by the engine's maxDepth limit.
 */
import {
    DEFAULT_PKI_LIMITS,
    decodeAsn1,
    encodeBitString,
    encodeBoolean,
    encodeEnumerated,
    encodeExplicit,
    encodeImplicit,
    encodeInteger,
    encodeNamedBits,
    encodeNull,
    encodeObjectIdentifier,
    encodeOctetString,
    encodeRelativeOid,
    encodeSequence,
    encodeSet,
    encodeSetOf,
    encodeString,
    encodeTime,
    encodeTlv,
    type Asn1StringType,
    type TagClass,
} from 'pkinative';

import { ToolError } from './errors.js';
import type { ParseContext } from './parse-context.js';
import { guard } from './pki-errors.js';
import { parseInstant } from './time.js';
import { fromHex } from './wire.js';

type Spec = Readonly<Record<string, unknown>>;

export const ASN1_NODE_TYPES = ['boolean', 'integer', 'enumerated', 'null', 'bit-string', 'named-bits', 'octet-string', 'oid', 'relative-oid', 'string', 'time', 'sequence', 'set', 'set-of', 'explicit', 'implicit', 'tlv', 'der'] as const;
const TAG_CLASSES: readonly TagClass[] = ['universal', 'application', 'context', 'private'];
const STRING_TYPES: readonly Asn1StringType[] = ['utf8', 'numeric', 'printable', 'teletex', 'ia5', 'visible', 'universal', 'bmp'];
const TIME_TYPES = ['UTCTime', 'GeneralizedTime', 'rfc5280'] as const;

/** The members each node type defines (besides `type`); anything else is refused by name (B-009). */
const MEMBERS: Readonly<Record<(typeof ASN1_NODE_TYPES)[number], readonly string[]>> = {
    boolean: ['value'], integer: ['value'], enumerated: ['value'], null: [],
    'bit-string': ['hex', 'unusedBits'], 'named-bits': ['bits'], 'octet-string': ['hex'],
    oid: ['value'], 'relative-oid': ['value'], string: ['stringType', 'value'], time: ['value', 'timeType'],
    sequence: ['children'], set: ['children'], 'set-of': ['children'],
    explicit: ['tag', 'class', 'inner'], implicit: ['tag', 'class', 'inner'],
    tlv: ['class', 'tag', 'constructed', 'hex'], der: ['hex'],
};

function specError(path: string, message: string): ToolError {
    return new ToolError('VALIDATION_ERROR', `asn1 spec ${path}: ${message}`, { path });
}

function isSpec(value: unknown): value is Spec {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function field<T>(spec: Spec, path: string, key: string, check: (v: unknown) => v is T, what: string): T {
    const value = spec[key];
    if (!check(value)) throw specError(`${path}.${key}`, `expected ${what}`);
    return value;
}

const isString = (v: unknown): v is string => typeof v === 'string';
const isBoolean = (v: unknown): v is boolean => typeof v === 'boolean';
const isTagNumber = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const isArray = (v: unknown): v is readonly unknown[] => Array.isArray(v);

function hexField(spec: Spec, path: string, key = 'hex'): Uint8Array {
    const bytes = fromHex(field(spec, path, key, isString, 'a hexadecimal string'));
    if (bytes === undefined) throw specError(`${path}.${key}`, 'expected a hexadecimal string');
    return bytes;
}

function integerField(spec: Spec, path: string): bigint {
    const value = spec['value'];
    if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
    if (typeof value === 'string' && /^-?(\d+|0x[0-9a-f]+)$/i.test(value.trim())) {
        const v = value.trim();
        return v.startsWith('-') ? -BigInt(v.slice(1)) : BigInt(v);
    }
    throw specError(`${path}.value`, 'expected a safe integer, or a decimal or 0x-hex string');
}

function choiceField<T extends string>(spec: Spec, path: string, key: string, choices: readonly T[], fallback?: T): T {
    const value = spec[key];
    if (value === undefined && fallback !== undefined) return fallback;
    if (typeof value === 'string' && (choices as readonly string[]).includes(value)) return value as T;
    throw specError(`${path}.${key}`, `expected one of ${choices.join('|')}`);
}

/** Encode one spec node (recursively) through the engine's encoders. */
export function encodeSpec(root: unknown, ctx: ParseContext): Uint8Array {
    const maxDepth = ctx.options.limits?.maxDepth ?? DEFAULT_PKI_LIMITS.maxDepth;
    const visit = (spec: unknown, path: string, depth: number): Uint8Array => {
        if (depth > maxDepth) {
            throw new ToolError('PKI_LIMIT_EXCEEDED', `asn1 spec ${path}: nesting exceeds maxDepth (${maxDepth}).`, {
                errorClass: 'limit', limit: 'maxDepth', configured: maxDepth, observed: depth, remedy: 'limits.maxDepth (trusted input only)',
            });
        }
        if (!isSpec(spec)) throw specError(path, 'expected an object with a "type"');
        const type = field(spec, path, 'type', isString, 'a string');
        if (Object.hasOwn(MEMBERS, type)) {
            const allowed = MEMBERS[type as keyof typeof MEMBERS];
            for (const key of Object.keys(spec)) {
                if (key !== 'type' && !allowed.includes(key)) throw specError(`${path}.${key}`, `unknown member for type "${type}" (${['type', ...allowed].join(', ')})`);
            }
        }
        const children = (): Uint8Array[] => field(spec, path, 'children', isArray, 'an array').map((c, i) => visit(c, `${path}.children[${i}]`, depth + 1));
        const tagOptions = (): { tagClass: TagClass } => ({ tagClass: choiceField(spec, path, 'class', TAG_CLASSES, 'context') });
        return guard(`asn1 spec ${path}`, () => {
            switch (type) {
                case 'boolean': return encodeBoolean(field(spec, path, 'value', isBoolean, 'a boolean'));
                case 'integer': return encodeInteger(integerField(spec, path));
                case 'enumerated': return encodeEnumerated(integerField(spec, path));
                case 'null': return encodeNull();
                case 'bit-string': {
                    const unused = spec['unusedBits'] ?? 0;
                    if (!isTagNumber(unused) || unused > 7) throw specError(`${path}.unusedBits`, 'expected an integer from 0 to 7');
                    return encodeBitString(hexField(spec, path), unused);
                }
                case 'named-bits': {
                    const bits = field(spec, path, 'bits', isArray, 'an array of bit numbers');
                    if (!bits.every(isTagNumber)) throw specError(`${path}.bits`, 'expected an array of bit numbers');
                    return encodeNamedBits(bits);
                }
                case 'octet-string': return encodeOctetString(hexField(spec, path));
                case 'oid': return encodeObjectIdentifier(field(spec, path, 'value', isString, 'a dotted OID'));
                case 'relative-oid': return encodeRelativeOid(field(spec, path, 'value', isString, 'a dotted relative OID'));
                case 'string': return encodeString(choiceField(spec, path, 'stringType', STRING_TYPES), field(spec, path, 'value', isString, 'a string'));
                case 'time': {
                    const value = spec['value'];
                    const ms = typeof value === 'number' ? value : parseInstant(field(spec, path, 'value', isString, 'an instant'), `${path}.value`);
                    return encodeTime(ms, choiceField(spec, path, 'timeType', TIME_TYPES, 'rfc5280'));
                }
                case 'sequence': return encodeSequence(children());
                case 'set': return encodeSet(children());
                case 'set-of': return encodeSetOf(children());
                case 'explicit': return encodeExplicit(field(spec, path, 'tag', isTagNumber, 'a tag number'), visit(spec['inner'], `${path}.inner`, depth + 1), tagOptions());
                case 'implicit': return encodeImplicit(field(spec, path, 'tag', isTagNumber, 'a tag number'), visit(spec['inner'], `${path}.inner`, depth + 1), tagOptions());
                case 'tlv': return encodeTlv(
                    choiceField(spec, path, 'class', TAG_CLASSES),
                    field(spec, path, 'tag', isTagNumber, 'a tag number'),
                    field(spec, path, 'constructed', isBoolean, 'a boolean'),
                    hexField(spec, path),
                );
                case 'der': {
                    const bytes = hexField(spec, path);
                    decodeAsn1(bytes, ctx.options);
                    return bytes;
                }
                default: throw specError(`${path}.type`, `unknown type "${type}" (${ASN1_NODE_TYPES.join(', ')})`);
            }
        });
    };
    return visit(root, '$', 0);
}

/** JSON Schema of one spec node (non-recursive on purpose — no $ref; nesting is described in prose and validated by the handler). */
export const ASN1_NODE_SPEC_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['type'],
    description: 'An ASN.1 node spec: { type, … } with type one of boolean (value), integer / enumerated (value: integer or decimal / 0x-hex string), null, bit-string (hex, unusedBits), named-bits (bits[]), octet-string (hex), oid / relative-oid (value), string (stringType utf8|numeric|printable|teletex|ia5|visible|universal|bmp, value), time (value instant, timeType UTCTime|GeneralizedTime|rfc5280), sequence / set / set-of (children[] of nodes), explicit / implicit (tag, class universal|application|context|private, inner node), tlv (class, tag, constructed, hex), der (hex of one DER object). Nesting is bounded by limits.maxDepth.',
    properties: {
        type: { type: 'string', enum: [...ASN1_NODE_TYPES], description: 'The node type.' },
        value: { anyOf: [{ type: 'string' }, { type: 'number' }, { type: 'boolean' }], description: 'boolean: true/false; integer / enumerated: an integer or a decimal / 0x-hex string; oid / relative-oid: dotted; string: the text; time: an ISO 8601 instant or epoch ms.' },
        hex: { type: 'string', description: 'Content bytes as hex (bit-string, octet-string, tlv, der).' },
        unusedBits: { type: 'integer', minimum: 0, maximum: 7, description: 'bit-string: unused trailing bits (default 0).' },
        bits: { type: 'array', items: { type: 'integer', minimum: 0 }, description: 'named-bits: the bit numbers set.' },
        stringType: { type: 'string', enum: [...STRING_TYPES], description: 'string: the ASN.1 string type.' },
        timeType: { type: 'string', enum: [...TIME_TYPES], description: "time: UTCTime, GeneralizedTime or 'rfc5280' (the type RFC 5280 mandates for the year; default)." },
        children: { type: 'array', items: { type: 'object' }, description: 'sequence / set / set-of: the child nodes (set-of is sorted per DER).' },
        tag: { type: 'integer', minimum: 0, description: 'explicit / implicit / tlv: the tag number.' },
        class: { type: 'string', enum: [...TAG_CLASSES], description: "explicit / implicit (default 'context') / tlv: the tag class." },
        constructed: { type: 'boolean', description: 'tlv: whether the TLV is constructed.' },
        inner: { type: 'object', description: 'explicit / implicit: the wrapped node.' },
    },
} as const;
