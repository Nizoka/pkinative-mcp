/** CMS SignedData and RFC 3161 time-stamps group (registration order). */
import type { ToolDefinition } from './_definition.js';
import { AMEND_CMS_TOOL } from './amend-cms.js';
import { CREATE_TIMESTAMP_REQUEST_TOOL } from './create-timestamp-request.js';
import { INSPECT_CMS_TOOL } from './inspect-cms.js';
import { INSPECT_TIMESTAMP_TOOL } from './inspect-timestamp.js';
import { SIGN_CMS_TOOL } from './sign-cms.js';
import { VERIFY_CMS_TOOL } from './verify-cms.js';
import { VERIFY_TIMESTAMP_TOOL } from './verify-timestamp.js';

export const CMS_TOOLS: readonly ToolDefinition[] = [
    SIGN_CMS_TOOL,
    VERIFY_CMS_TOOL,
    INSPECT_CMS_TOOL,
    AMEND_CMS_TOOL,
    CREATE_TIMESTAMP_REQUEST_TOOL,
    INSPECT_TIMESTAMP_TOOL,
    VERIFY_TIMESTAMP_TOOL,
];
