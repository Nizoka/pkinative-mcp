/**
 * The wrapper's own error codes (the server boundary: validation, sandbox,
 * caps, secrets, output), with the one-line meaning and the fix an agent
 * acts on. The 57 `PKI_*` engine codes pass through verbatim (see
 * src/pki-errors.ts). `explain_code` serves this table; tests/error-codes
 * asserts every `ToolError` code in `src/` is listed here.
 */
export interface WrapperCodeEntry {
    readonly code: string;
    readonly meaning: string;
    readonly remedy: string;
}

export const WRAPPER_CODES: readonly WrapperCodeEntry[] = [
    { code: 'VALIDATION_ERROR', meaning: 'The input failed the schema: wrong type / bound / enum, an unknown or misspelt key (top-level or nested — every object is strict), none or several of the exclusive members (pem / derBase64 / path; text / base64 / path; signer.key / signer.p12), a spec member the structure does not define, SHA-1 without allowSha1, a password given twice (input and PKINATIVE_MCP_PASSWORD).', remedy: 'Re-read the field schema (the message names the path); pass exactly one input form.' },
    { code: 'INPUT_TOO_LARGE', meaning: 'A decoded inline input, the sum of inline inputs, or a sandbox file exceeds a cap (the effective maxInputBytes for a PKI object, 128 MiB per call inline, 1 GiB for a content path).', remedy: 'Pass the bytes through a sandbox path, split the input, or raise PKINATIVE_MCP_MAX_INPUT_BYTES for trusted input only.' },
    { code: 'INPUT_NOT_FOUND', meaning: 'A path input does not exist in the sandbox (a dangling link too) or is not a regular file.', remedy: 'Check the relative path (resources/list shows the sandbox); drop the file into PKINATIVE_MCP_OUTPUT_DIR.' },
    { code: 'INVALID_PATH', meaning: 'A path member is empty or not a string.', remedy: 'Pass a non-empty relative path.' },
    { code: 'INVALID_EXTENSION', meaning: 'A path input or outputPath does not end in an allowed extension (PKI inputs: .pem .crt .cer .der .csr .p10 .crl .p7s .p7b .p7c .p7m .cms .p12 .pfx .key .p8 .pub .ocsp .ors .orq .tsq .tsr .tst .bin .asn1; outputs: the same minus the key-bearing ones; .pem for encoding pem; .md .txt .json .pem for text).', remedy: 'Fix the extension (content.path is not subject to it).' },
    { code: 'SECURITY_VIOLATION', meaning: 'File I/O requested with PKINATIVE_MCP_OUTPUT_DIR unset; a path with a NUL byte; an absolute / drive / UNC path; a path escaping the sandbox; a real path (symlink or junction) outside it on a read or a write; an outputPath naming a key-bearing extension; an attempt to extract, dump or serve private-key material (convert_pem extractIndex, decode_asn1, resources/read).', remedy: 'Set PKINATIVE_MCP_OUTPUT_DIR; pass relative paths only; remove the link; open keys with inspect_private_key / inspect_pkcs12 / open_pkcs12 instead.' },
    { code: 'OUTPUT_TOO_LARGE', meaning: 'An inline artefact above 50 MiB, a hex artefact above 64 KiB, a file output above 1 GiB, a resource above the 50 MiB read cap, or a text artefact above 50 MiB.', remedy: "outputMode:'file' with PKINATIVE_MCP_OUTPUT_DIR set; encoding:'der' or 'pem' instead of 'hex'." },
    { code: 'OUTPUT_EXISTS', meaning: 'The target file already exists in the sandbox — the server never overwrites.', remedy: 'Choose another outputPath, or remove the file yourself.' },
    { code: 'MISSING_OUTPUT_PATH', meaning: "outputMode:'file' without outputPath.", remedy: 'Pass a relative outputPath.' },
    { code: 'IO_ERROR', meaning: 'A filesystem operation failed (permissions, disk full, …); the message carries the errno, never an absolute path or an OS message.', remedy: 'Fix the sandbox directory; a partial file was removed.' },
    { code: 'LIMIT_CEILING_EXCEEDED', meaning: 'A limits.* value above its operator ceiling: maxInputBytes above PKINATIVE_MCP_MAX_INPUT_BYTES, maxKdfIterations / maxPkcs12KdfIterations above PKINATIVE_MCP_MAX_KDF_ITERATIONS, maxPathsExplored above PKINATIVE_MCP_MAX_PATHS_EXPLORED (data.env names the variable).', remedy: 'Lower the value (or omit it), or the operator raises the ceiling in the server environment for trusted input only.' },
    { code: 'UNKNOWN_RESOURCE', meaning: 'resources/read with a URI outside pkinative://output/, an empty path, or a file that does not exist — surfaced as JSON-RPC error -32602 (Invalid params).', remedy: 'List URIs with resources/list.' },
    { code: 'GOVERNANCE_VIOLATION', meaning: 'A draft_governance_issue draft breaks the AI-governance contract (proposes a runtime dependency, embeds a private key or a password, has no reproduction code block, or duplicateSearchPerformed:false).', remedy: 'Remove the dependency proposal or the secret, include the reproduction, confirm the duplicate search.' },
    { code: 'SECRET_REQUIRED', meaning: 'An encrypted PKCS#8 key, a PKCS#12 file or a MAC check needs a password and none was given.', remedy: 'Pass the password input, or set PKINATIVE_MCP_PASSWORD in the server environment (never both).' },
    { code: 'KEY_TYPE_REQUIRED', meaning: 'An encrypted PKCS#8 key reveals its type only once decrypted, and neither signer.keyType nor a certificate / public key input names it.', remedy: 'Pass signer.keyType (ec-p256|ec-p384|ec-p521|ed25519|ed448|rsa|rsa-pss), or the matching certificate / subjectPublicKey input.' },
    { code: 'RSA_SCHEME_REQUIRED', meaning: 'An RSA key (PKCS#8 or inside a PKCS#12) was given without rsaScheme: pkinative has no default RSA signature scheme (ADR 0015).', remedy: "rsaScheme:'pkcs1' (RSASSA-PKCS1-v1_5) or 'pss' (RSA-PSS)." },
    { code: 'KEY_MISMATCH', meaning: 'The signing key does not belong to the certificate, the issuer or the subject public key it was paired with (the artefact was verified after signing and refused).', remedy: 'Pair the key with its own certificate / public key.' },
    { code: 'UNSUPPORTED_KEY', meaning: 'A key algorithm Web Crypto cannot sign with on this host (an unknown OID, a non-NIST curve, Ed448 where unsupported).', remedy: 'Use an EC P-256/384/521, RSA, Ed25519 or (where supported) Ed448 key.' },
    { code: 'NOT_FOUND', meaning: 'A named element is absent: an extension kind the certificate lacks, a nodePath step, a signerIndex out of range, an extractIndex past the last block, an unknown code in explain_code.', remedy: 'Inspect the object first (the message names what exists).' },
    { code: 'ENGINE_VERDICT', meaning: 'A one-call engine operation (opening a PKCS#12 to sign) came back negative for a reason that is neither a wrong password nor a scheme or cipher refusal (data.reasons carries the PKI_REASON_* codes).', remedy: 'Read data.reasons; allowUnverifiedIntegrity:true for a file whose origin you trust.' },
    { code: 'ENGINE_ERROR', meaning: 'The engine threw something that is not a PkiError (a bug — data.errorClass: internal).', remedy: 'Report it with a reproduction via draft_governance_issue (targetRepo pkinative).' },
];

export const WRAPPER_CODE_NAMES: readonly string[] = WRAPPER_CODES.map((c) => c.code);
