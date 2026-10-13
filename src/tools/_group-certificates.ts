/** Certificates and requests group (registration order). */
import type { ToolDefinition } from './_definition.js';
import { CREATE_CERTIFICATE_TOOL } from './create-certificate.js';
import { INSPECT_CERTIFICATE_TOOL } from './inspect-certificate.js';

export const CERTIFICATE_TOOLS: readonly ToolDefinition[] = [
    INSPECT_CERTIFICATE_TOOL,
    CREATE_CERTIFICATE_TOOL,
    // encode_x509_structure, decode_extension, check_certificate_name, check_certificate_purpose, inspect_csr, create_csr
];
