/** Certification paths, CRLs and OCSP group (registration order). */
import type { ToolDefinition } from './_definition.js';
import { VERIFY_CERTIFICATE_CHAIN_TOOL } from './verify-certificate-chain.js';

export const PATH_TOOLS: readonly ToolDefinition[] = [
    VERIFY_CERTIFICATE_CHAIN_TOOL,
    // build_certificate_path, validate_certificate_path, inspect_crl, check_crl_revocation, create_ocsp_request, inspect_ocsp_response, check_ocsp_status
];
