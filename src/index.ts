/**
 * Public library entry: re-exports the server factory and type surface so that
 * pkinative-mcp can be embedded in another Node process if desired.
 */
export { createServer, ensureEngineReady, callToolDirect, listToolsPayload, toolNames } from './server.js';
export type { OutputMode, OutputResult, ArtefactEncoding } from './output.js';
export { ToolError, SecurityError, GovernanceError } from './errors.js';
export { PKINATIVE_MCP_VERSION, TOOL_API_VERSION } from './version.js';
