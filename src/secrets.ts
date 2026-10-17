/**
 * Password intake and redaction.
 *
 * A password reaches a tool through exactly one of two channels:
 *   - the per-call `password` input (plain string; the host's transcript
 *     holds it — the documented trade-off of every MCP secret input), or
 *   - the operator variable `PKINATIVE_MCP_PASSWORD`, which keeps it out of
 *     the model's context entirely.
 * Both at once is a `VALIDATION_ERROR` (as pkinative-cli refuses two sources).
 *
 * The value is never written to stdout, stderr, a message, `ToolError.data`,
 * a cache key or a log; `redact()` is applied to every error message that
 * leaves a handler which held a secret, as a last line of defence.
 */
import { z } from 'zod';

import { MAX_PASSWORD_BYTES } from './caps.js';
import { ToolError } from './errors.js';

/** The operator-side password source. */
export const PASSWORD_ENV = 'PKINATIVE_MCP_PASSWORD';

/** JSON Schema property for the per-call `password` input. */
export const PASSWORD_INPUT_PROPERTY = {
    password: {
        type: 'string',
        minLength: 1,
        maxLength: MAX_PASSWORD_BYTES,
        description: `The password of an encrypted PKCS#8 key or a PKCS#12 file (UTF-8). Never echoed, logged or cached. Alternatively set ${PASSWORD_ENV} in the server environment and omit this input (never both) — the variable keeps the secret out of the model transcript.`,
    },
} as const;

/** Zod twin of {@link PASSWORD_INPUT_PROPERTY}. */
export const PasswordSchema = z.string().min(1).max(MAX_PASSWORD_BYTES);

/**
 * Resolve the password for a call: the input, else the environment, else
 * `undefined`. Two sources at once are refused before anything runs.
 */
export function resolvePassword(input: string | undefined, env: NodeJS.ProcessEnv = process.env): string | undefined {
    const fromEnv = env[PASSWORD_ENV];
    const envSet = fromEnv !== undefined && fromEnv !== '';
    if (input !== undefined && envSet) {
        throw new ToolError('VALIDATION_ERROR', `Give the password once: the password input or ${PASSWORD_ENV}, not both.`, { remedy: `unset ${PASSWORD_ENV} or omit password` });
    }
    if (input !== undefined) return input;
    if (envSet) {
        if (fromEnv.length > MAX_PASSWORD_BYTES) {
            throw new ToolError('VALIDATION_ERROR', `${PASSWORD_ENV} is longer than ${MAX_PASSWORD_BYTES} characters.`);
        }
        return fromEnv;
    }
    return undefined;
}

/** The refusal when a password is needed and none was given. */
export function secretRequired(what: string): ToolError {
    return new ToolError('SECRET_REQUIRED', `${what} needs its password: pass the password input, or set ${PASSWORD_ENV} in the server environment.`, { remedy: 'password' });
}

/**
 * Replace every occurrence of the secrets in `text` with a placeholder. Used
 * on error messages produced while a secret was in scope (an engine message
 * never embeds a password, but the guard costs nothing).
 */
export function redact(text: string, secrets: readonly (string | undefined)[]): string {
    let out = text;
    for (const s of secrets) {
        if (s === undefined || s.length === 0) continue;
        out = out.split(s).join('[REDACTED]');
    }
    return out;
}

/**
 * True when a raw input object carries a secret: a `password` (top level or
 * inside `signer`), or a `signer` at all — a plain PKCS#8 key given inline is
 * a secret even without a password, and such a call must never reach the cache.
 */
export function carriesSecret(input: unknown): boolean {
    if (input === null || typeof input !== 'object') return false;
    const o = input as Record<string, unknown>;
    if (typeof o['password'] === 'string') return true;
    const signer = o['signer'];
    return signer !== null && typeof signer === 'object';
}
