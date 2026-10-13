/**
 * The tool registry, in registration order (= `tools/list` order). Every
 * tool module exports its `ToolDefinition`; this file is the one place that
 * orders them. The catalogue grows with the feature commits.
 */
import type { ToolDefinition } from './_definition.js';

export const TOOLS: readonly ToolDefinition[] = [];
