/**
 * Custom error type for tool-level failures (returned to the client as
 * `isError: true`). `code` is either one of the wrapper codes documented in
 * docs/AGENT_CONTRACT.md §6 or one of pkinative's 57 frozen `PKI_*` codes
 * carried verbatim (see src/pki-errors.ts). `data` carries machine-readable
 * detail (the limit that fired, the ASN.1 path, the algorithm, the remedy, …)
 * and is surfaced as `_meta.error.data` — never anything secret: a password
 * or a key byte must never reach a message or `data` (src/secrets.ts).
 */
export class ToolError extends Error {
    public override readonly name: string = 'ToolError';
    public readonly code: string;
    public readonly data: Readonly<Record<string, unknown>> | undefined;

    public constructor(code: string, message: string, data?: Readonly<Record<string, unknown>>) {
        super(message);
        this.code = code;
        this.data = data;
    }
}

/**
 * Custom error for security-related violations (path traversal, sandbox
 * escapes, an attempt to dump private-key material).
 */
export class SecurityError extends ToolError {
    public override readonly name: string = 'SecurityError';

    public constructor(message: string, data?: Readonly<Record<string, unknown>>) {
        super('SECURITY_VIOLATION', message, data);
    }
}

/**
 * Custom error for AI-governance / human-in-the-loop policy violations raised
 * by `draft_governance_issue` (code `GOVERNANCE_VIOLATION`).
 *
 * The server never opens GitHub issues; it only produces a local, compliant
 * draft. This error fires when a would-be draft breaks the non-negotiable
 * governance contract (proposing a runtime dependency, missing a local
 * reproduction, or skipping the duplicate search) so the human reviewer is
 * forced to fix the draft before they submit it under their own identity.
 */
export class GovernanceError extends ToolError {
    public override readonly name: string = 'GovernanceError';

    public constructor(message: string) {
        super('GOVERNANCE_VIOLATION', message);
    }
}
