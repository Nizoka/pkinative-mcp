/**
 * Single source of truth for the pkinative-mcp package version.
 *
 * Kept in lock-step with package.json, server.json and CITATION.cff (asserted
 * by tests/metadata.test.ts). Centralised here so both server.ts and the
 * governance tooling reference one constant without importing package.json
 * (the build rootDir is limited to ./src).
 */
export const PKINATIVE_MCP_VERSION = '1.0.0';

/**
 * Per-tool API version used by the opt-in cache key and by `_meta.apiVersion`.
 * Bump when the input or output schema of any tool changes in a way that would
 * make a cached response unsafe to serve. Independent from the package version.
 */
export const TOOL_API_VERSION = '1.0.0';
