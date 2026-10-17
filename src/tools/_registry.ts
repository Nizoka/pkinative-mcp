/**
 * The tool registry, in registration order (= `tools/list` order). Every
 * tool module exports its `ToolDefinition`; the group files order them:
 * encodings, certificates and requests, paths / CRLs / OCSP, CMS and
 * time-stamps, keys, meta.
 */
import type { ToolDefinition } from './_definition.js';
import { __setToolCount, DESCRIBE_ENGINE_TOOL } from './describe-engine.js';
import { DRAFT_GOVERNANCE_ISSUE_TOOL } from './draft-governance-issue.js';
import { EXPLAIN_CODE_TOOL } from './explain-code.js';
import { CERTIFICATE_TOOLS } from './_group-certificates.js';
import { CMS_TOOLS } from './_group-cms.js';
import { ENCODING_TOOLS } from './_group-encodings.js';
import { KEY_TOOLS } from './_group-keys.js';
import { PATH_TOOLS } from './_group-paths.js';

export const META_TOOLS: readonly ToolDefinition[] = [DESCRIBE_ENGINE_TOOL, EXPLAIN_CODE_TOOL, DRAFT_GOVERNANCE_ISSUE_TOOL];

export const TOOLS: readonly ToolDefinition[] = [
    ...ENCODING_TOOLS,
    ...CERTIFICATE_TOOLS,
    ...PATH_TOOLS,
    ...CMS_TOOLS,
    ...KEY_TOOLS,
    ...META_TOOLS,
];

__setToolCount(TOOLS.length);
