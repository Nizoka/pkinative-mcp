/**
 * Tests for `src/secrets.ts` — password intake (input XOR environment),
 * the SECRET_REQUIRED refusal, redaction and the cache-side secret probe.
 */
import { afterEach, describe, expect, it } from 'vitest';

import { MAX_PASSWORD_BYTES } from '../src/caps.js';
import { ToolError } from '../src/errors.js';
import { carriesSecret, PASSWORD_ENV, PASSWORD_INPUT_PROPERTY, PasswordSchema, redact, resolvePassword, secretRequired } from '../src/secrets.js';
import { PASSWORD } from './_pki-fixtures.js';

function thrown(fn: () => unknown): ToolError {
    try {
        fn();
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to throw');
}

describe('resolvePassword', () => {
    afterEach(() => {
        delete process.env[PASSWORD_ENV];
    });

    it('names the operator variable', () => {
        expect(PASSWORD_ENV).toBe('PKINATIVE_MCP_PASSWORD');
    });

    it('input only, env only, neither', () => {
        expect(resolvePassword('from-input', {})).toBe('from-input');
        expect(resolvePassword(undefined, { [PASSWORD_ENV]: 'from-env' })).toBe('from-env');
        expect(resolvePassword(undefined, {})).toBeUndefined();
        process.env[PASSWORD_ENV] = 'process-env';
        expect(resolvePassword(undefined)).toBe('process-env');
    });

    it('both at once is VALIDATION_ERROR naming the variable, without echoing either value', () => {
        const err = thrown(() => resolvePassword('from-input', { [PASSWORD_ENV]: 'from-env' }));
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.message).toContain(PASSWORD_ENV);
        expect(err.message).not.toContain('from-input');
        expect(err.message).not.toContain('from-env');
        expect(err.data).toEqual({ remedy: `unset ${PASSWORD_ENV} or omit password` });
        process.env[PASSWORD_ENV] = PASSWORD;
        const both = thrown(() => resolvePassword('x'));
        expect(both.code).toBe('VALIDATION_ERROR');
        expect(JSON.stringify({ message: both.message, data: both.data })).not.toContain(PASSWORD);
    });

    it('an empty environment value counts as unset', () => {
        expect(resolvePassword(undefined, { [PASSWORD_ENV]: '' })).toBeUndefined();
        expect(resolvePassword('from-input', { [PASSWORD_ENV]: '' })).toBe('from-input');
    });

    it('an environment value longer than the cap is VALIDATION_ERROR (the value is not echoed); the cap itself passes', () => {
        const long = 'p'.repeat(MAX_PASSWORD_BYTES + 1);
        const err = thrown(() => resolvePassword(undefined, { [PASSWORD_ENV]: long }));
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.message).toContain(PASSWORD_ENV);
        expect(err.message).toContain(String(MAX_PASSWORD_BYTES));
        expect(err.message).not.toContain(long);
        expect(err.data).toBeUndefined();
        expect(resolvePassword(undefined, { [PASSWORD_ENV]: 'p'.repeat(MAX_PASSWORD_BYTES) })).toHaveLength(MAX_PASSWORD_BYTES);
    });
});

describe('secretRequired', () => {
    it('is SECRET_REQUIRED with the password remedy and both channels in the message', () => {
        const err = secretRequired('The key is encrypted and');
        expect(err).toBeInstanceOf(ToolError);
        expect(err.code).toBe('SECRET_REQUIRED');
        expect(err.message).toBe(`The key is encrypted and needs its password: pass the password input, or set ${PASSWORD_ENV} in the server environment.`);
        expect(err.data).toEqual({ remedy: 'password' });
    });
});

describe('redact', () => {
    it('replaces every occurrence of every secret and ignores undefined / empty entries', () => {
        expect(redact('pw=hunter2; again hunter2!', ['hunter2'])).toBe('pw=[REDACTED]; again [REDACTED]!');
        expect(redact('a secret and another', ['secret', 'another'])).toBe('a [REDACTED] and [REDACTED]');
        expect(redact('unchanged text', [undefined, ''])).toBe('unchanged text');
        expect(redact('unchanged text', [])).toBe('unchanged text');
        expect(redact(`error with ${PASSWORD} inside`, [undefined, PASSWORD])).toBe('error with [REDACTED] inside');
        // Regex metacharacters in a secret are literal.
        expect(redact('x.*y and x.*y', ['x.*y'])).toBe('[REDACTED] and [REDACTED]');
        expect(redact('', ['x'])).toBe('');
    });
});

describe('carriesSecret', () => {
    it('sees a password at the top level, and any signer object (key material), nowhere else', () => {
        expect(carriesSecret({ password: 'x' })).toBe(true);
        expect(carriesSecret({ signer: { key: { pem: '-----BEGIN' }, password: 'x' } })).toBe(true);
        // Any object-valued signer carries key material (a plain PKCS#8 key is as secret as a password).
        expect(carriesSecret({ signer: { key: { pem: '-----BEGIN' } } })).toBe(true);
        expect(carriesSecret({ signer: {} })).toBe(true);
        expect(carriesSecret({ password: 123 })).toBe(false);
        expect(carriesSecret({ nested: { password: 'x' } })).toBe(false);
        expect(carriesSecret({ signer: null })).toBe(false);
        expect(carriesSecret({ signer: 'x' })).toBe(false);
        expect(carriesSecret({})).toBe(false);
        expect(carriesSecret(null)).toBe(false);
        expect(carriesSecret('password')).toBe(false);
        expect(carriesSecret(undefined)).toBe(false);
    });
});

describe('PASSWORD_INPUT_PROPERTY / PasswordSchema', () => {
    it('bound the password by MAX_PASSWORD_BYTES and point at the environment alternative', () => {
        expect(Object.keys(PASSWORD_INPUT_PROPERTY)).toEqual(['password']);
        expect(PASSWORD_INPUT_PROPERTY.password).toMatchObject({ type: 'string', minLength: 1, maxLength: MAX_PASSWORD_BYTES });
        expect(PASSWORD_INPUT_PROPERTY.password.description).toContain(PASSWORD_ENV);
        expect(PASSWORD_INPUT_PROPERTY.password.description).toContain('Never echoed');
        expect(PasswordSchema.safeParse('x').success).toBe(true);
        expect(PasswordSchema.safeParse('p'.repeat(MAX_PASSWORD_BYTES)).success).toBe(true);
        expect(PasswordSchema.safeParse('').success).toBe(false);
        expect(PasswordSchema.safeParse('p'.repeat(MAX_PASSWORD_BYTES + 1)).success).toBe(false);
        expect(PasswordSchema.safeParse(42).success).toBe(false);
    });
});
