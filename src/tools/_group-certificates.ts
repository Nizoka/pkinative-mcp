/** Certificates and requests group (registration order). */
import type { ToolDefinition } from './_definition.js';
import { CHECK_CERTIFICATE_NAME_TOOL } from './check-certificate-name.js';
import { CHECK_CERTIFICATE_PURPOSE_TOOL } from './check-certificate-purpose.js';
import { CREATE_CERTIFICATE_TOOL } from './create-certificate.js';
import { CREATE_CSR_TOOL } from './create-csr.js';
import { DECODE_EXTENSION_TOOL } from './decode-extension.js';
import { ENCODE_X509_STRUCTURE_TOOL } from './encode-x509-structure.js';
import { INSPECT_CERTIFICATE_TOOL } from './inspect-certificate.js';
import { INSPECT_CSR_TOOL } from './inspect-csr.js';

export const CERTIFICATE_TOOLS: readonly ToolDefinition[] = [
    INSPECT_CERTIFICATE_TOOL,
    CREATE_CERTIFICATE_TOOL,
    ENCODE_X509_STRUCTURE_TOOL,
    DECODE_EXTENSION_TOOL,
    CHECK_CERTIFICATE_NAME_TOOL,
    CHECK_CERTIFICATE_PURPOSE_TOOL,
    INSPECT_CSR_TOOL,
    CREATE_CSR_TOOL,
];
