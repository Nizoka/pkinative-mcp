/**
 * Tests for `src/trust.ts` — the TRUST fragment of the verdict tools:
 * purpose resolution, the policy inputs as the engine takes them, and the
 * schema fragments in lock-step with their Zod twins.
 */
import { describe, expect, it } from 'vitest';
import { ANY_EXTENDED_KEY_USAGE, KEY_PURPOSES } from 'pkinative';
import { z } from 'zod';

import { MAX_BUNDLE_ITEMS } from '../src/caps.js';
import { ToolError } from '../src/errors.js';
import { policyOptions, PURPOSE_NAMES, purposeOid, REASONS_OUTPUT_PROPERTY, TRUST_INPUT_PROPERTIES, TrustShape } from '../src/trust.js';
import { fixtureText } from './_pki-fixtures.js';

function thrown(fn: () => unknown): ToolError {
    try {
        fn();
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to throw');
}

describe('purposeOid', () => {
    it('resolves the engine purpose names, any, and dotted OIDs', () => {
        expect(PURPOSE_NAMES).toEqual(['serverAuth', 'clientAuth', 'codeSigning', 'emailProtection', 'timeStamping', 'ocspSigning']);
        for (const name of PURPOSE_NAMES) expect(purposeOid(name, 'purposes[0]'), name).toBe(KEY_PURPOSES[name as keyof typeof KEY_PURPOSES]);
        expect(purposeOid('serverAuth', 'p')).toBe('1.3.6.1.5.5.7.3.1');
        expect(purposeOid('any', 'p')).toBe(ANY_EXTENDED_KEY_USAGE);
        expect(purposeOid('any', 'p')).toBe('2.5.29.37.0');
        expect(purposeOid('1.3.6.1.5.5.7.3.9', 'p')).toBe('1.3.6.1.5.5.7.3.9');
        expect(purposeOid('2.5', 'p')).toBe('2.5');
    });

    it('an unknown purpose is VALIDATION_ERROR naming the path and the choices', () => {
        for (const bad of ['surfing', 'ServerAuth', 'SERVERAUTH', '', '1', '1.2.', 'anyExtendedKeyUsage']) {
            const err = thrown(() => purposeOid(bad, 'purposes[2]'));
            expect(err.code, bad).toBe('VALIDATION_ERROR');
            expect(err.message, bad).toContain(`purposes[2]: unknown purpose "${bad}"`);
            expect(err.message, bad).toContain(PURPOSE_NAMES.join(', '));
            expect(err.data, bad).toEqual({ path: 'purposes[2]' });
        }
    });
});

describe('policyOptions', () => {
    it('returns only the members that are set, as the engine takes them', () => {
        expect(policyOptions(undefined)).toEqual({});
        expect(policyOptions({ requireExplicitPolicy: false, inhibitPolicyMapping: false, inhibitAnyPolicy: false })).toEqual({});
        expect(policyOptions({ initialPolicySet: ['1.2.3'], requireExplicitPolicy: true, inhibitPolicyMapping: false, inhibitAnyPolicy: true })).toEqual({ initialPolicySet: ['1.2.3'], requireExplicitPolicy: true, inhibitAnyPolicy: true });
        expect(policyOptions({ initialPolicySet: [], requireExplicitPolicy: false, inhibitPolicyMapping: true, inhibitAnyPolicy: false })).toEqual({ initialPolicySet: [], inhibitPolicyMapping: true });
        // Through the Zod shape, the booleans default to false.
        const parsed = z.object(TrustShape).parse({ trustAnchors: [{ pem: fixtureText('root.crt.pem') }], policy: { initialPolicySet: ['2.5.29.32.0'] } });
        expect(parsed.policy).toEqual({ initialPolicySet: ['2.5.29.32.0'], requireExplicitPolicy: false, inhibitPolicyMapping: false, inhibitAnyPolicy: false });
        expect(policyOptions(parsed.policy)).toEqual({ initialPolicySet: ['2.5.29.32.0'] });
    });
});

describe('TRUST_INPUT_PROPERTIES / TrustShape', () => {
    it('are in lock-step: the same keys, bundle bounds, purpose cap and policy members', () => {
        expect(Object.keys(TRUST_INPUT_PROPERTIES)).toEqual(Object.keys(TrustShape));
        expect(Object.keys(TRUST_INPUT_PROPERTIES)).toEqual(['trustAnchors', 'candidates', 'crls', 'ocspResponses', 'at', 'requireRevocation', 'purposes', 'policy']);
        for (const bundle of ['trustAnchors', 'candidates', 'crls', 'ocspResponses'] as const) {
            expect(TRUST_INPUT_PROPERTIES[bundle], bundle).toMatchObject({ type: 'array', minItems: 1, maxItems: MAX_BUNDLE_ITEMS });
        }
        expect(TRUST_INPUT_PROPERTIES.trustAnchors['description']).toContain('At least one is required');
        expect(TRUST_INPUT_PROPERTIES.crls['description']).toContain('never fetches');
        expect(TRUST_INPUT_PROPERTIES.at).toMatchObject({ type: 'string', minLength: 1 });
        expect(TRUST_INPUT_PROPERTIES.requireRevocation).toMatchObject({ type: 'boolean', default: false });
        expect(TRUST_INPUT_PROPERTIES.purposes).toMatchObject({ type: 'array', maxItems: 16, items: { type: 'string', minLength: 1 } });
        expect(TRUST_INPUT_PROPERTIES.purposes.description).toContain(PURPOSE_NAMES.join(', '));
        expect(TRUST_INPUT_PROPERTIES.policy).toMatchObject({ type: 'object', additionalProperties: false });
        expect(Object.keys(TRUST_INPUT_PROPERTIES.policy.properties)).toEqual(['initialPolicySet', 'requireExplicitPolicy', 'inhibitPolicyMapping', 'inhibitAnyPolicy']);
        expect(TRUST_INPUT_PROPERTIES.policy.properties.initialPolicySet).toMatchObject({ type: 'array', maxItems: 64, items: { type: 'string', pattern: '^\\d+(\\.\\d+)+$' } });
        const policyShape = TrustShape.policy.unwrap();
        expect(Object.keys(policyShape.shape)).toEqual(Object.keys(TRUST_INPUT_PROPERTIES.policy.properties));
    });

    it('TrustShape validates what the JSON Schema promises', () => {
        const schema = z.object(TrustShape);
        const anchor = { pem: fixtureText('root.crt.pem') };
        expect(schema.safeParse({ trustAnchors: [anchor] }).success).toBe(true);
        expect(schema.safeParse({}).success).toBe(false);
        expect(schema.safeParse({ trustAnchors: [] }).success).toBe(false);
        expect(schema.safeParse({ trustAnchors: [anchor], purposes: Array.from({ length: 17 }, () => 'serverAuth') }).success).toBe(false);
        expect(schema.safeParse({ trustAnchors: [anchor], purposes: [''] }).success).toBe(false);
        expect(schema.safeParse({ trustAnchors: [anchor], policy: { initialPolicySet: ['not-an-oid'] } }).success).toBe(false);
        expect(schema.safeParse({ trustAnchors: [anchor], policy: { bogus: true } }).success).toBe(false);
        expect(schema.safeParse({ trustAnchors: [anchor], at: '' }).success).toBe(false);
        expect(schema.safeParse({ trustAnchors: [anchor], at: 'now', requireRevocation: true }).success).toBe(true);
        const parsed = schema.parse({ trustAnchors: [anchor] });
        expect(parsed.requireRevocation).toBe(false);
        expect(parsed.policy).toBeUndefined();
    });
});

describe('REASONS_OUTPUT_PROPERTY', () => {
    it('describes the reasons[] rows: four required members plus errorCode and limit', () => {
        expect(Object.keys(REASONS_OUTPUT_PROPERTY)).toEqual(['reasons']);
        expect(REASONS_OUTPUT_PROPERTY.reasons.type).toBe('array');
        expect(REASONS_OUTPUT_PROPERTY.reasons.description).toContain('never thrown');
        expect(REASONS_OUTPUT_PROPERTY.reasons.items.required).toEqual(['code', 'message', 'standard', 'path']);
        expect(REASONS_OUTPUT_PROPERTY.reasons.items.additionalProperties).toBe(false);
        expect(Object.keys(REASONS_OUTPUT_PROPERTY.reasons.items.properties)).toEqual(['code', 'message', 'standard', 'path', 'errorCode', 'limit']);
    });
});
