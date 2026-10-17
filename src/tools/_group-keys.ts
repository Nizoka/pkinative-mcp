/** Private keys and PKCS#12 group (registration order): inspect_private_key, inspect_pkcs12, open_pkcs12. */
import type { ToolDefinition } from './_definition.js';
import { INSPECT_PKCS12_TOOL } from './inspect-pkcs12.js';
import { INSPECT_PRIVATE_KEY_TOOL } from './inspect-private-key.js';
import { OPEN_PKCS12_TOOL } from './open-pkcs12.js';

export const KEY_TOOLS: readonly ToolDefinition[] = [INSPECT_PRIVATE_KEY_TOOL, INSPECT_PKCS12_TOOL, OPEN_PKCS12_TOOL];
