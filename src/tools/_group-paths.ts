/** Certification paths, CRLs and OCSP group (registration order). */
import type { ToolDefinition } from './_definition.js';
import { BUILD_CERTIFICATE_PATH_TOOL } from './build-certificate-path.js';
import { CHECK_CRL_REVOCATION_TOOL } from './check-crl-revocation.js';
import { CHECK_OCSP_STATUS_TOOL } from './check-ocsp-status.js';
import { CREATE_OCSP_REQUEST_TOOL } from './create-ocsp-request.js';
import { INSPECT_CRL_TOOL } from './inspect-crl.js';
import { INSPECT_OCSP_RESPONSE_TOOL } from './inspect-ocsp-response.js';
import { VALIDATE_CERTIFICATE_PATH_TOOL } from './validate-certificate-path.js';
import { VERIFY_CERTIFICATE_CHAIN_TOOL } from './verify-certificate-chain.js';

export const PATH_TOOLS: readonly ToolDefinition[] = [
    VERIFY_CERTIFICATE_CHAIN_TOOL,
    BUILD_CERTIFICATE_PATH_TOOL,
    VALIDATE_CERTIFICATE_PATH_TOOL,
    INSPECT_CRL_TOOL,
    CHECK_CRL_REVOCATION_TOOL,
    CREATE_OCSP_REQUEST_TOOL,
    INSPECT_OCSP_RESPONSE_TOOL,
    CHECK_OCSP_STATUS_TOOL,
];
