/**
 * Tests for `src/errors.ts` — the three error classes: code, name, message
 * and the machine-readable data.
 */
import { describe, expect, it } from 'vitest';

import { GovernanceError, SecurityError, ToolError } from '../src/errors.js';

describe('ToolError', () => {
    it('carries a code, a message and optional readonly data; it is an Error named ToolError', () => {
        const err = new ToolError('VALIDATION_ERROR', 'bad input', { path: 'certificate', remedy: 'pem' });
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(ToolError);
        expect(err.name).toBe('ToolError');
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.message).toBe('bad input');
        expect(err.data).toEqual({ path: 'certificate', remedy: 'pem' });
        expect(err.stack).toContain('bad input');
        expect(new ToolError('NOT_FOUND', 'x').data).toBeUndefined();
        expect(new ToolError('PKI_ASN1_TRUNCATED', 'engine').code).toBe('PKI_ASN1_TRUNCATED');
    });

    it('is distinguishable from a plain Error with a code member', () => {
        const plain = Object.assign(new Error('x'), { code: 'VALIDATION_ERROR' });
        expect(plain).not.toBeInstanceOf(ToolError);
        expect(new ToolError('X', 'y') instanceof SecurityError).toBe(false);
        expect(new ToolError('X', 'y') instanceof GovernanceError).toBe(false);
    });
});

describe('SecurityError', () => {
    it('is a ToolError with the fixed code SECURITY_VIOLATION and its own name', () => {
        const err = new SecurityError('escapes the sandbox', { remedy: 'inspect_private_key' });
        expect(err).toBeInstanceOf(ToolError);
        expect(err).toBeInstanceOf(SecurityError);
        expect(err).toBeInstanceOf(Error);
        expect(err.name).toBe('SecurityError');
        expect(err.code).toBe('SECURITY_VIOLATION');
        expect(err.message).toBe('escapes the sandbox');
        expect(err.data).toEqual({ remedy: 'inspect_private_key' });
        expect(new SecurityError('x').data).toBeUndefined();
    });
});

describe('GovernanceError', () => {
    it('is a ToolError with the fixed code GOVERNANCE_VIOLATION, no data', () => {
        const err = new GovernanceError('proposes a runtime dependency');
        expect(err).toBeInstanceOf(ToolError);
        expect(err).toBeInstanceOf(GovernanceError);
        expect(err).not.toBeInstanceOf(SecurityError);
        expect(err.name).toBe('GovernanceError');
        expect(err.code).toBe('GOVERNANCE_VIOLATION');
        expect(err.message).toBe('proposes a runtime dependency');
        expect(err.data).toBeUndefined();
    });
});
