/**
 * The `TRUST` fragment of the verdict tools (`verify_certificate_chain`,
 * `verify_cms`, `verify_timestamp`, `check_*`): the trust anchors the caller
 * supplies, untrusted candidates, the revocation evidence (CRL and OCSP
 * bytes the caller fetched out of band — this server never fetches), the
 * evaluation instant and the policy inputs of RFC 5280 §6.
 */
import { ANY_EXTENDED_KEY_USAGE, KEY_PURPOSES } from 'pkinative';
import { z } from 'zod';

import { ToolError } from './errors.js';
import { pkiBundleSchema, PkiBundleSchema } from './pki-input.js';
import { instantSchema } from './time.js';

export const PURPOSE_NAMES = Object.keys(KEY_PURPOSES) as readonly string[];

/** `serverAuth`, `any`, or a dotted OID → the purpose OID. */
export function purposeOid(name: string, path: string): string {
    if (name === 'any') return ANY_EXTENDED_KEY_USAGE;
    if (Object.hasOwn(KEY_PURPOSES, name)) return KEY_PURPOSES[name as keyof typeof KEY_PURPOSES];
    if (/^\d+(\.\d+)+$/.test(name)) return name;
    throw new ToolError('VALIDATION_ERROR', `${path}: unknown purpose "${name}" (${PURPOSE_NAMES.join(', ')}, any, or a dotted OID).`, { path });
}

/** JSON Schema properties of the `TRUST` fragment. */
export const TRUST_INPUT_PROPERTIES = {
    trustAnchors: pkiBundleSchema('Trust anchors (root certificates you trust)', ' At least one is required: a verdict is relative to the anchors you name.'),
    candidates: pkiBundleSchema('Untrusted intermediate certificates the path may use', ' Optional; the certificates embedded in a CMS message are also candidates.'),
    crls: pkiBundleSchema('CRLs (DER or X509 CRL PEM) for offline revocation', ' Optional; this server never fetches a CRL — pass the bytes you obtained.'),
    ocspResponses: pkiBundleSchema('OCSP responses (DER) for offline revocation', ' Optional; this server never queries a responder — pass the bytes you obtained.'),
    at: instantSchema('The instant the verdict is evaluated at.'),
    requireRevocation: { type: 'boolean', default: false, description: 'Require fresh revocation evidence for every certificate below the anchor (PKI_REASON_REVOCATION_UNKNOWN otherwise); default false = revocation is checked when evidence is given.' },
    purposes: { type: 'array', maxItems: 16, items: { type: 'string', minLength: 1 }, description: `Extended key usages the leaf must allow: ${PURPOSE_NAMES.join(', ')}, any, or a dotted OID.` },
    policy: {
        type: 'object',
        additionalProperties: false,
        description: 'RFC 5280 §6.1.1 policy inputs.',
        properties: {
            initialPolicySet: { type: 'array', maxItems: 64, items: { type: 'string', pattern: '^\\d+(\\.\\d+)+$' }, description: 'user-initial-policy-set (dotted OIDs); absent = any-policy.' },
            requireExplicitPolicy: { type: 'boolean', default: false, description: 'initial-explicit-policy: every certificate must carry an acceptable policy.' },
            inhibitPolicyMapping: { type: 'boolean', default: false, description: 'initial-policy-mapping-inhibit: policy mappings are refused.' },
            inhibitAnyPolicy: { type: 'boolean', default: false, description: 'initial-any-policy-inhibit: anyPolicy is not a match.' },
        },
    },
} as const;

/** Zod twin of {@link TRUST_INPUT_PROPERTIES}. */
export const TrustShape = {
    trustAnchors: PkiBundleSchema,
    candidates: PkiBundleSchema.optional(),
    crls: PkiBundleSchema.optional(),
    ocspResponses: PkiBundleSchema.optional(),
    at: z.string().min(1).optional(),
    requireRevocation: z.boolean().default(false),
    purposes: z.array(z.string().min(1)).max(16).optional(),
    policy: z.strictObject({
        initialPolicySet: z.array(z.string().regex(/^\d+(\.\d+)+$/)).max(64).optional(),
        requireExplicitPolicy: z.boolean().default(false),
        inhibitPolicyMapping: z.boolean().default(false),
        inhibitAnyPolicy: z.boolean().default(false),
    }).optional(),
};

/** The `policy` members as the engine takes them. */
export function policyOptions(policy: z.infer<z.ZodObject<typeof TrustShape>>['policy']): { initialPolicySet?: readonly string[]; requireExplicitPolicy?: boolean; inhibitPolicyMapping?: boolean; inhibitAnyPolicy?: boolean } {
    if (policy === undefined) return {};
    return {
        ...(policy.initialPolicySet !== undefined ? { initialPolicySet: policy.initialPolicySet } : {}),
        ...(policy.requireExplicitPolicy ? { requireExplicitPolicy: true } : {}),
        ...(policy.inhibitPolicyMapping ? { inhibitPolicyMapping: true } : {}),
        ...(policy.inhibitAnyPolicy ? { inhibitAnyPolicy: true } : {}),
    };
}

/** The `reasons[]` output schema shared by every verdict tool. */
export const REASONS_OUTPUT_PROPERTY = {
    reasons: {
        type: 'array',
        description: 'Why the verdict is negative (empty when valid): the engine PKI_REASON_* codes, each with the standard it cites and the path of the offending element. A reason is returned, never thrown.',
        items: {
            type: 'object',
            additionalProperties: false,
            required: ['code', 'message', 'standard', 'path'],
            properties: {
                code: { type: 'string' },
                message: { type: 'string' },
                standard: { type: 'string' },
                path: { type: 'string' },
                errorCode: { type: 'string', description: 'The PKI_* error the parser would have thrown (PKI_REASON_INPUT_MALFORMED).' },
                limit: { type: 'string', description: 'The limit that fired (PKI_REASON_LIMIT_EXCEEDED).' },
            },
        },
    },
} as const;
