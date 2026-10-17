/** Encodings group (registration order): convert_pem, resolve_oid, compute_fingerprint, decode_asn1, encode_asn1. */
import type { ToolDefinition } from './_definition.js';
import { COMPUTE_FINGERPRINT_TOOL } from './compute-fingerprint.js';
import { CONVERT_PEM_TOOL } from './convert-pem.js';
import { DECODE_ASN1_TOOL } from './decode-asn1.js';
import { ENCODE_ASN1_TOOL } from './encode-asn1.js';
import { RESOLVE_OID_TOOL } from './resolve-oid.js';

export const ENCODING_TOOLS: readonly ToolDefinition[] = [
    CONVERT_PEM_TOOL,
    RESOLVE_OID_TOOL,
    COMPUTE_FINGERPRINT_TOOL,
    DECODE_ASN1_TOOL,
    ENCODE_ASN1_TOOL,
];
