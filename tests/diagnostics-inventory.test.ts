/**
 * The diagnostic inventory: which of the engine's 97 `PKI_DIAG_*` codes a
 * tool call through this wrapper actually produces, and from what.
 *
 * Part 1 drives every one of the 42 OpenSSL-made fixtures through its
 * reader (and the verdict tools over the fixture combinations) and collects
 * every code that comes back: the fixtures are well-formed, modern PKI, so
 * they reach exactly two codes — the table FIXTURE_ROWS pins each with its
 * tool, severity and path, and the union is asserted exactly, so a changed
 * fixture or engine that produces a new code fails here instead of going
 * unproven. Part 2 reaches 30 more codes with hand-built inputs through
 * `decode_asn1` and `decode_extension` (the two tools that take raw bytes
 * without a surrounding structure). Part 3 lists the 65 codes the fixtures
 * cannot reach, each with the construction that would (honestly: a crafted
 * certificate, CRL, CMS or PKCS#8 object the suite does not build), and the
 * three sets together are asserted to be the whole registry.
 */
import { beforeAll, describe, expect, it } from 'vitest';

import { PKI_DIAGNOSTIC_SEVERITY } from '../src/data/pkinative/code-tables.js';
import { PKI_DIAGNOSTIC_CODES } from '../src/pki-errors.js';
import { callToolDirect, ensureEngineReady } from '../src/server.js';
import { assertResultClean } from './_pki-assert.js';
import { AT, FIXTURE_FILES, fixtureBytes, fixtureInput, PASSWORD } from './_pki-fixtures.js';

interface DiagnosticRow {
    readonly code: string;
    readonly severity: 'warning' | 'info';
    readonly message: string;
    readonly standard: string;
    readonly path: string;
}

type Result = Awaited<ReturnType<typeof callToolDirect>>;
type Args = Record<string, unknown>;

const SEVERITY = PKI_DIAGNOSTIC_SEVERITY as Readonly<Record<string, 'warning' | 'info'>>;
const content = (): { base64: string } => ({ base64: Buffer.from(fixtureBytes('content.txt')).toString('base64') });

function diagnosticsOf(r: Result): DiagnosticRow[] {
    return ((r.structuredContent as { diagnostics?: DiagnosticRow[] } | undefined)?.diagnostics ?? []);
}

/** The reader of a fixture, by name: the tool and the arguments that read it as what it is. */
function readerOf(name: string): Array<[string, Args]> {
    const i = fixtureInput(name);
    if (/\.crt\.(?:pem|der)$/.test(name)) return [['inspect_certificate', { certificate: i }]];
    if (/\.csr\./.test(name)) return [['inspect_csr', { request: i, verify: true }]];
    if (/\.crl\./.test(name)) return [['inspect_crl', { crl: i }]];
    if (/\.ocsp\.der$/.test(name)) return [['inspect_ocsp_response', { response: i }]];
    if (name === 'leaf.ocsp-req.der' || name === 'content.tsq') return [['decode_asn1', { input: i }]];
    if (name === 'attached.p7s') return [['inspect_cms', { signedData: i }]];
    if (name === 'detached.p7s') return [['inspect_cms', { signedData: i, signerCertificate: fixtureInput('leaf.crt.pem'), content: content() }]];
    if (name === 'content.tsr') return [['inspect_timestamp', { input: i, as: 'response' }]];
    if (name === 'content.tst') return [['inspect_timestamp', { input: i, as: 'token' }]];
    if (name.endsWith('.key.enc.pem')) {
        const rsa = name.startsWith('rsa');
        return [
            ['inspect_private_key', { key: i }],
            ['inspect_private_key', { key: i, password: PASSWORD, tryImport: true, keyType: rsa ? 'rsa' : 'ec-p256', ...(rsa ? { rsaScheme: 'pkcs1' } : {}) }],
        ];
    }
    if (/\.key\.(?:pem|der)$/.test(name)) return [['inspect_private_key', { key: i }]];
    if (name === 'leaf.pub.pem') return [['decode_asn1', { input: i }], ['convert_pem', { mode: 'decode', input: i }]];
    if (name.endsWith('.p12')) {
        return [
            ['inspect_pkcs12', { pkcs12: i }],
            ['open_pkcs12', { pkcs12: i, password: PASSWORD, ...(name.startsWith('rsa') ? { rsaScheme: 'pkcs1' } : {}) }],
        ];
    }
    if (name === 'content.txt') return []; // not a PKI object: the content the signatures and time-stamps cover
    throw new Error(`no reader for fixture ${name} — extend readerOf()`);
}

/** The verdict tools over the fixture combinations (the instant pinned inside the validity window). */
const VERDICT_CALLS: ReadonlyArray<[string, string, Args]> = [
    ['chain: leaf', 'verify_certificate_chain', { leaf: fixtureInput('leaf.crt.pem'), candidates: [fixtureInput('inter.crt.pem')], trustAnchors: [fixtureInput('root.crt.pem')], at: AT, crls: [fixtureInput('inter.crl.pem')], serverName: { host: 'example.test' }, purposes: ['serverAuth'] }],
    ['chain: revoked', 'verify_certificate_chain', { leaf: fixtureInput('revoked.crt.pem'), candidates: [fixtureInput('inter.crt.pem')], trustAnchors: [fixtureInput('root.crt.pem')], at: AT, crls: [fixtureInput('inter.crl.pem')] }],
    ['chain: rsa', 'verify_certificate_chain', { leaf: fixtureInput('rsa.crt.pem'), candidates: [fixtureInput('inter.crt.pem')], trustAnchors: [fixtureInput('root.crt.pem')], at: AT }],
    ['chain: ocsp', 'verify_certificate_chain', { leaf: fixtureInput('leaf.crt.pem'), candidates: [fixtureInput('inter.crt.pem'), fixtureInput('ocsp.crt.pem')], trustAnchors: [fixtureInput('root.crt.pem')], at: AT, ocspResponses: [fixtureInput('leaf.ocsp.der')] }],
    ['build path', 'build_certificate_path', { leaf: fixtureInput('leaf.crt.pem'), candidates: [fixtureInput('inter.crt.pem')], trustAnchors: [fixtureInput('root.crt.pem')], at: AT }],
    ['validate path', 'validate_certificate_path', { path: [fixtureInput('leaf.crt.pem'), fixtureInput('inter.crt.pem')], trustAnchors: [fixtureInput('root.crt.pem')], at: AT }],
    ['crl: revoked', 'check_crl_revocation', { certificate: fixtureInput('revoked.crt.pem'), crl: fixtureInput('inter.crl.pem'), issuer: fixtureInput('inter.crt.pem'), at: AT }],
    ['crl: delta', 'check_crl_revocation', { certificate: fixtureInput('ed25519.crt.pem'), crl: fixtureInput('ed25519.crl.der'), delta: fixtureInput('ed25519-delta.crl.der'), issuer: fixtureInput('ed25519.crt.pem'), at: AT }],
    ['ocsp: good', 'check_ocsp_status', { response: fixtureInput('leaf.ocsp.der'), certificate: fixtureInput('leaf.crt.pem'), issuer: fixtureInput('inter.crt.pem'), responder: fixtureInput('ocsp.crt.pem'), at: AT }],
    ['ocsp: revoked', 'check_ocsp_status', { response: fixtureInput('revoked.ocsp.der'), certificate: fixtureInput('revoked.crt.pem'), issuer: fixtureInput('inter.crt.pem'), responder: fixtureInput('ocsp.crt.pem'), at: AT }],
    ['cms: attached', 'verify_cms', { signedData: fixtureInput('attached.p7s'), trustAnchors: [fixtureInput('root.crt.pem')], candidates: [fixtureInput('inter.crt.pem')], at: AT }],
    ['cms: detached', 'verify_cms', { signedData: fixtureInput('detached.p7s'), content: content(), trustAnchors: [fixtureInput('root.crt.pem')], candidates: [fixtureInput('inter.crt.pem')], at: AT }],
    ['tsp: token', 'verify_timestamp', { token: fixtureInput('content.tst'), data: content(), trustAnchors: [fixtureInput('root.crt.pem')], candidates: [fixtureInput('inter.crt.pem'), fixtureInput('tsa.crt.pem')], at: AT }],
    ['tsp: response', 'verify_timestamp', { response: fixtureInput('content.tsr'), request: fixtureInput('content.tsq'), trustAnchors: [fixtureInput('root.crt.pem')], candidates: [fixtureInput('inter.crt.pem'), fixtureInput('tsa.crt.pem')], at: AT }],
    ['name: san', 'check_certificate_name', { certificate: fixtureInput('leaf.crt.pem'), host: 'example.test' }],
    ['name: cn fallback', 'check_certificate_name', { certificate: fixtureInput('revoked.crt.pem'), host: 'revoked.example.test', allowCommonNameFallback: true }],
    ['purpose', 'check_certificate_purpose', { certificate: fixtureInput('leaf.crt.pem'), purpose: 'serverAuth' }],
    ['fingerprint', 'compute_fingerprint', { input: fixtureInput('leaf.crt.pem'), algorithm: 'SHA-256' }],
    ['convert', 'convert_pem', { mode: 'decode', input: fixtureInput('leaf.crt.pem') }],
];

interface FixtureRow {
    readonly code: string;
    readonly fixture: string;
    readonly tool: string;
    readonly path: string;
    readonly args?: Args;
}

/** What the 42 fixtures produce, pinned: code ← fixture through its reader (and the verdict tools that re-read it). */
const FIXTURE_ROWS: readonly FixtureRow[] = [
    // revoked.example.test carries its name in the CN only (no SAN) — the OpenSSL profile of a legacy end entity.
    { code: 'PKI_DIAG_COMMON_NAME_NOT_IN_SAN', fixture: 'revoked.crt.pem', tool: 'inspect_certificate', path: 'tbsCertificate.subject' },
    { code: 'PKI_DIAG_COMMON_NAME_NOT_IN_SAN', fixture: 'revoked.crt.pem', tool: 'verify_certificate_chain', path: 'tbsCertificate.subject', args: { leaf: fixtureInput('revoked.crt.pem'), candidates: [fixtureInput('inter.crt.pem')], trustAnchors: [fixtureInput('root.crt.pem')], at: AT } },
    { code: 'PKI_DIAG_COMMON_NAME_NOT_IN_SAN', fixture: 'revoked.crt.pem', tool: 'check_crl_revocation', path: 'tbsCertificate.subject', args: { certificate: fixtureInput('revoked.crt.pem'), crl: fixtureInput('inter.crl.pem'), issuer: fixtureInput('inter.crt.pem'), at: AT } },
    { code: 'PKI_DIAG_COMMON_NAME_NOT_IN_SAN', fixture: 'revoked.crt.pem', tool: 'check_ocsp_status', path: 'tbsCertificate.subject', args: { response: fixtureInput('revoked.ocsp.der'), certificate: fixtureInput('revoked.crt.pem'), issuer: fixtureInput('inter.crt.pem'), responder: fixtureInput('ocsp.crt.pem'), at: AT } },
    { code: 'PKI_DIAG_COMMON_NAME_NOT_IN_SAN', fixture: 'revoked.crt.pem', tool: 'check_certificate_name', path: 'tbsCertificate.subject', args: { certificate: fixtureInput('revoked.crt.pem'), host: 'revoked.example.test', allowCommonNameFallback: true } },
    // OpenSSL's ts writes the TSA certificate SET OF in file order, not DER order (nothing signed depends on it).
    { code: 'PKI_DIAG_CMS_SET_NOT_SORTED', fixture: 'content.tst', tool: 'inspect_timestamp', path: 'content.certificates' },
    { code: 'PKI_DIAG_CMS_SET_NOT_SORTED', fixture: 'content.tsr', tool: 'inspect_timestamp', path: 'content.certificates' },
    { code: 'PKI_DIAG_CMS_SET_NOT_SORTED', fixture: 'content.tst', tool: 'verify_timestamp', path: 'content.certificates', args: { token: fixtureInput('content.tst'), data: content(), trustAnchors: [fixtureInput('root.crt.pem')], candidates: [fixtureInput('inter.crt.pem'), fixtureInput('tsa.crt.pem')], at: AT } },
];

/** The codes the fixtures reach — the union Part 1 asserts exactly. */
const FIXTURE_REACHABLE: readonly string[] = ['PKI_DIAG_COMMON_NAME_NOT_IN_SAN', 'PKI_DIAG_CMS_SET_NOT_SORTED'];

interface CraftedRow {
    readonly code: string;
    readonly tool: 'decode_asn1' | 'decode_extension';
    readonly args: Args;
}

const b64 = (bytes: readonly number[]): string => Buffer.from(bytes).toString('base64');
const ext = (code: string, oid: string, valueHex: string, critical = false): CraftedRow => ({ code, tool: 'decode_extension', args: { oid, valueHex, critical } });
const pemBody = (name: string): string => fixtureBytes(name) && Buffer.from(fixtureBytes(name)).toString('utf8').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');

/** Codes a hand-built value reaches through the two raw-bytes tools (each verified against the live engine). */
const CRAFTED_ROWS: readonly CraftedRow[] = [
    { code: 'PKI_DIAG_PRINTABLE_STRING_CHARSET', tool: 'decode_asn1', args: { input: { derBase64: b64([0x13, 0x01, 0x40]) }, read: 'string' } },
    { code: 'PKI_DIAG_PEM_LAX_ACCEPTED', tool: 'decode_asn1', args: { input: { pem: `-----BEGIN CERTIFICATE-----\n${pemBody('leaf.crt.pem')}\n-----END CERTIFICATE-----\n` }, pemMode: 'lax' } },
    { code: 'PKI_DIAG_BER_CONSTRUCT_ACCEPTED', tool: 'decode_asn1', args: { input: { derBase64: b64([0x24, 0x04, 0x04, 0x02, 0xaa, 0xbb]) }, encodingRules: 'ber' } },
    ext('PKI_DIAG_BASIC_CONSTRAINTS_NOT_CRITICAL', '2.5.29.19', '30030101ff'),
    ext('PKI_DIAG_PATHLEN_WITHOUT_CA', '2.5.29.19', '3003020100', true),
    ext('PKI_DIAG_DEFAULT_ENCODED', '2.5.29.19', '300601010002010a', true),
    ext('PKI_DIAG_KEY_USAGE_EMPTY', '2.5.29.15', '030100', true),
    ext('PKI_DIAG_KEY_USAGE_NOT_CRITICAL', '2.5.29.15', '03020780'),
    ext('PKI_DIAG_NAMED_BITS_TRAILING_ZERO', '2.5.29.15', '0303078000', true),
    ext('PKI_DIAG_SAN_EMPTY', '2.5.29.17', '3000'),
    ext('PKI_DIAG_ALT_NAME_GENERAL_NAME_EMPTY', '2.5.29.17', '30028200'),
    ext('PKI_DIAG_DNS_NAME_NOT_PREFERRED_SYNTAX', '2.5.29.17', `300b8209${Buffer.from('-bad.test').toString('hex')}`),
    ext('PKI_DIAG_GENERAL_NAME_CONTROL_CHARACTER', '2.5.29.17', `300a8208${Buffer.from('a\u0001b.test').toString('hex')}`),
    ext('PKI_DIAG_ALT_NAME_URI_INVALID', '2.5.29.17', `300e860c${Buffer.from('example.test').toString('hex')}`),
    ext('PKI_DIAG_ALT_NAME_URI_SCHEME_MISSING', '2.5.29.17', `300e860c${Buffer.from('example.test').toString('hex')}`),
    ext('PKI_DIAG_ALT_NAME_URI_HOST_INVALID', '2.5.29.17', `300e860c${Buffer.from('http://-bad.').toString('hex')}`),
    ext('PKI_DIAG_ISSUER_ALT_NAME_CRITICAL', '2.5.29.18', '300e820c6578616d706c652e74657374', true),
    ext('PKI_DIAG_AKI_CRITICAL', '2.5.29.35', '300480020102', true),
    ext('PKI_DIAG_AKI_ISSUER_SERIAL_UNPAIRED', '2.5.29.35', '3010a10e820c6578616d706c652e74657374'),
    ext('PKI_DIAG_SKI_CRITICAL', '2.5.29.14', '04020102', true),
    ext('PKI_DIAG_EKU_ANY_CRITICAL', '2.5.29.37', '30060604551d2500', true),
    ext('PKI_DIAG_AIA_CRITICAL', '1.3.6.1.5.5.7.1.1', '301e301c06082b06010505073002861068747470 3a2f2f6361 2e746573742f78'.replace(/ /g, ''), true),
    ext('PKI_DIAG_CA_ISSUERS_NO_HTTP_OR_LDAP_URI', '1.3.6.1.5.5.7.1.1', '301e301c06082b0601050507300286106674703a2f2f63612e746573742f7878'),
    ext('PKI_DIAG_SIA_CRITICAL', '1.3.6.1.5.5.7.1.11', '301e301c06082b0601050507300586106874 74703a2f2f63612e746573742f78'.replace(/ /g, ''), true),
    ext('PKI_DIAG_INHIBIT_ANY_POLICY_NOT_CRITICAL', '2.5.29.54', '020100'),
    ext('PKI_DIAG_POLICY_CONSTRAINTS_NOT_CRITICAL', '2.5.29.36', '3003800100'),
    ext('PKI_DIAG_POLICY_CONSTRAINTS_EMPTY', '2.5.29.36', '3000', true),
    ext('PKI_DIAG_POLICY_MAPPINGS_NOT_CRITICAL', '2.5.29.33', '300c300a06032a03040603290305'),
    ext('PKI_DIAG_POLICY_DUPLICATE', '2.5.29.32', '300a300306012a300306012a'),
    ext('PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION', '1.2.3.4.5', '0500', true),
];

/**
 * The codes neither the fixtures nor the crafted values reach, with the
 * construction that would. Every reason is what was observed: the fixtures
 * are well-formed, modern, OpenSSL-made objects, and the two raw-bytes tools
 * decode a value without the surrounding structure most of these diagnostics
 * are raised from (a whole certificate, CRL, name, CMS message, OCSP response
 * or PKCS#8 key the suite does not hand-craft).
 */
const NOT_REACHABLE_WITH_FIXTURES: Readonly<Record<string, string>> = {
    PKI_DIAG_SERIAL_TOO_LONG: 'every fixture serial is 1 to 2 octets; needs a certificate with a serial longer than 20 octets',
    PKI_DIAG_SERIAL_NOT_POSITIVE: 'every fixture serial is positive; needs a certificate with a zero or negative serial',
    PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH: 'OpenSSL writes the same algorithm in tbsCertificate.signature and signatureAlgorithm; needs a certificate where they differ',
    PKI_DIAG_RSA_PARAMETERS_NOT_NULL: 'the RSA fixtures carry the NULL parameters; needs an rsaEncryption AlgorithmIdentifier with absent or non-NULL parameters',
    PKI_DIAG_EXTENSIONS_REQUIRE_V3: 'every fixture certificate is v3; needs a v1 / v2 certificate carrying extensions',
    PKI_DIAG_UNIQUE_ID_REQUIRES_V2: 'no fixture carries issuerUniqueID / subjectUniqueID; needs a v1 certificate carrying one',
    PKI_DIAG_UNIQUE_ID_PRESENT: 'no fixture carries a unique identifier; needs a v2 / v3 certificate carrying one',
    PKI_DIAG_GENERALIZED_TIME_BEFORE_2050: 'every fixture validity ends in 2046 (UTCTime); needs a GeneralizedTime instant before 2050',
    PKI_DIAG_GENERALIZED_TIME_FRACTION: 'OpenSSL writes no fractional seconds; needs a GeneralizedTime with a fraction',
    PKI_DIAG_VALIDITY_INVERTED: 'every fixture is valid 2026 → 2046; needs notAfter before notBefore',
    PKI_DIAG_EMPTY_ISSUER: 'every fixture issuer is a non-empty name; needs a certificate with an empty issuer SEQUENCE',
    PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL: 'every fixture subject is non-empty; needs an empty subject with a non-critical SAN',
    PKI_DIAG_SAN_CRITICAL: 'raised while parsing a certificate whose SAN is critical with a non-empty subject (decode_extension sees no subject); no fixture marks the SAN critical',
    PKI_DIAG_RDN_SET_NOT_SORTED: 'OpenSSL writes single-attribute RDNs; needs a multi-valued RDN out of DER order',
    PKI_DIAG_TELETEX_AS_LATIN1: 'every fixture name attribute is PrintableString or UTF8String; needs a TeletexString attribute',
    PKI_DIAG_NAME_ATTRIBUTE_STRING_TYPE: 'every fixture name attribute uses the expected string type; needs an attribute in a type RFC 5280 does not expect (an IA5String CN)',
    PKI_DIAG_COUNTRY_NAME_SIZE: 'the fixture country names are two letters; needs a countryName of another length',
    PKI_DIAG_NAME_COUNTRY_UNKNOWN: 'the fixture country names are ISO 3166 codes; needs an unknown two-letter code',
    PKI_DIAG_NAME_ATTRIBUTE_TOO_LONG: 'every fixture attribute is short; needs an attribute above its RFC 5280 upper bound (a 65-character CN)',
    PKI_DIAG_STRING_SIGNATURE: 'no fixture name attribute carries a leading signature octet; needs a DirectoryString starting with one',
    PKI_DIAG_STRING_ESCAPE_SEQUENCE: 'no fixture name attribute carries an ISO 2022 escape; needs a string with one',
    PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION_IN_CRL: 'not a registry code — placeholder never used',
    PKI_DIAG_NAME_CONSTRAINTS_NOT_CRITICAL: 'no fixture carries nameConstraints; needs a CA certificate with a non-critical nameConstraints (the hand-built value did not decode)',
    PKI_DIAG_NAME_CONSTRAINTS_IN_END_ENTITY: 'no fixture carries nameConstraints; needs an end-entity certificate carrying it',
    PKI_DIAG_NAME_CONSTRAINTS_MIN_MAX: 'no fixture carries nameConstraints; needs a GeneralSubtree with minimum / maximum',
    PKI_DIAG_NAME_CONSTRAINTS_URI_NOT_FQDN: 'no fixture carries nameConstraints; needs a URI subtree that is not a host name',
    PKI_DIAG_KEY_CERT_SIGN_WITHOUT_CA: 'the fixture CAs all carry cA:TRUE; needs keyCertSign on a certificate without basicConstraints cA',
    PKI_DIAG_AKI_MISSING: 'every fixture certificate carries an AKI; needs a certificate (not self-signed) without one',
    PKI_DIAG_SKI_MISSING: 'every fixture CA carries an SKI; needs a CA certificate without one',
    PKI_DIAG_SKI_MISSING_END_ENTITY: 'every fixture end entity carries an SKI; needs an end-entity certificate without one',
    PKI_DIAG_SUBJECT_DIRECTORY_ATTRIBUTES_CRITICAL: 'no fixture carries subjectDirectoryAttributes; needs one marked critical (the hand-built value did not decode)',
    PKI_DIAG_SPKI_RSA_EXPONENT_WEAK: 'the RSA fixture uses e = 65537; needs an RSA public key with a small or even exponent',
    PKI_DIAG_SPKI_EC_PARAMETERS_INVALID: 'the EC fixtures use the named-curve form; needs an EC SPKI with explicit or absent parameters',
    PKI_DIAG_ANY_POLICY_QUALIFIER: 'no fixture carries certificatePolicies; needs anyPolicy with a qualifier other than CPS / userNotice (the hand-built value decoded without it)',
    PKI_DIAG_NOTICE_REF_USED: 'no fixture carries certificatePolicies; needs a userNotice with a noticeRef',
    PKI_DIAG_EXPLICIT_TEXT_STRING_TYPE: 'no fixture carries certificatePolicies; needs an explicitText in a type other than UTF8String',
    PKI_DIAG_EXPLICIT_TEXT_CONTROL_CHARACTER: 'no fixture carries certificatePolicies; needs an explicitText with a control character',
    PKI_DIAG_EXPLICIT_TEXT_NOT_NFC: 'no fixture carries certificatePolicies; needs an explicitText that is not NFC-normalised',
    PKI_DIAG_POLICY_MAPPING_NOT_ASSERTED: 'no fixture carries policyMappings; needs a mapping whose issuer domain policy is not in certificatePolicies',
    PKI_DIAG_CRL_DISTRIBUTION_POINTS_CRITICAL: 'the leaf CRL DP is non-critical; needs a critical cRLDistributionPoints (the hand-built value did not decode)',
    PKI_DIAG_DISTRIBUTION_POINT_WITHOUT_NAME: 'the leaf DP carries a name; needs a DistributionPoint with reasons / cRLIssuer only',
    PKI_DIAG_DISTRIBUTION_POINT_LDAP_URI_INCOMPLETE: 'the leaf DP is an http URI; needs an ldap URI without a DN',
    PKI_DIAG_DISTRIBUTION_POINT_NO_HTTP_OR_LDAP_URI: 'the leaf DP is an http URI; needs a DP whose URIs are neither http nor ldap',
    PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME: 'the leaf DP is a fullName; needs a nameRelativeToCRLIssuer',
    PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME_AMBIGUOUS: 'the leaf DP is a fullName; needs a relative name with several cRLIssuer names',
    PKI_DIAG_FRESHEST_CRL_CRITICAL: 'no fixture carries freshestCRL; needs one marked critical (the hand-built value did not decode)',
    PKI_DIAG_INFO_ACCESS_LDAP_URI_INCOMPLETE: 'the leaf AIA is an http URI; needs an ldap access location without a DN',
    PKI_DIAG_CA_REPOSITORY_NO_HTTP_OR_LDAP_URI: 'no fixture carries subjectInfoAccess caRepository; needs one with a non-http / non-ldap URI',
    PKI_DIAG_CRL_EXTENSION_MALFORMED: 'every fixture CRL extension decodes; needs a CRL carrying an extension whose value does not match its definition',
    PKI_DIAG_CMS_VERSION_MISMATCH: 'OpenSSL writes the version RFC 5652 computes; needs a SignedData whose version disagrees with its content',
    PKI_DIAG_CMS_SIGNED_ATTRIBUTES_NOT_DER: 'OpenSSL writes DER signed attributes; needs a SignerInfo whose signedAttrs SET is not in DER order',
    PKI_DIAG_CMS_DIGEST_ALGORITHM_NOT_LISTED: 'OpenSSL lists every digest algorithm; needs a SignerInfo whose digestAlgorithm is absent from digestAlgorithms',
    PKI_DIAG_CMS_CERTS_ONLY_CONTENT: 'no fixture is a certs-only SignedData with content; needs one (certs-only.p12 is a PKCS#12, not CMS)',
    PKI_DIAG_CMS_COUNTERSIGNATURE_CONTENT_TYPE: 'no fixture carries a countersignature; needs a Countersignature SignerInfo with a contentType attribute',
    PKI_DIAG_CMS_COUNTERSIGNATURE_NO_MESSAGE_DIGEST: 'no fixture carries a countersignature; needs one without a messageDigest attribute',
    PKI_DIAG_CMS_COUNTERSIGNATURE_EMPTY: 'no fixture carries a countersignature; needs an empty Countersignature attribute',
    PKI_DIAG_CMS_SIGNING_TIME_NOT_UTC: 'OpenSSL writes signingTime as UTCTime; needs a GeneralizedTime signingTime before 2050',
    PKI_DIAG_CMS_SIGNING_TIME_FRACTION: 'OpenSSL writes no fraction; needs a signingTime with fractional seconds',
    PKI_DIAG_TSP_CERTREQ_UNMET: 'the fixture TSA honoured certReq; needs a response without the TSA certificate to a certReq request',
    PKI_DIAG_TSP_CERTS_UNREQUESTED: 'the fixture request set certReq; needs certificates in a response to a request without it',
    PKI_DIAG_OCSP_CERTS_EMPTY: 'the fixture responder embeds its certificate; needs a BasicOCSPResponse with an empty certs SEQUENCE',
    PKI_DIAG_OCSP_VERSION_NOT_V1: 'OpenSSL writes v1 responses; needs a ResponseData with another version',
    PKI_DIAG_OCSP_RESPONDER_ID_MISMATCH: 'the fixture responderID matches the embedded certificate; needs one that does not',
    PKI_DIAG_OCSP_SINGLE_RESPONSE_UNREQUESTED: 'raised against a request the response does not answer; check_ocsp_status takes no request input and the fixture pairs match',
    PKI_DIAG_OCSP_NOCHECK_CRITICAL: 'the fixture responder certificate carries no ocspNoCheck; needs one marked critical (decode_extension decoded it without a diagnostic)',
    PKI_DIAG_KEY_KDF_ITERATIONS_LOW: 'the fixture PBES2 / PBMAC1 keys use OpenSSL 3.5 defaults; needs a PBKDF2 iteration count below the engine floor',
};
// A registry code can only be listed once; the placeholder above documents a name that is NOT a code and is dropped here.
delete (NOT_REACHABLE_WITH_FIXTURES as Record<string, string>)['PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION_IN_CRL'];

describe('diagnostics inventory: the 42 fixtures through their readers', () => {
    const produced = new Map<string, Set<string>>();
    const rows = new Map<string, DiagnosticRow[]>();

    beforeAll(async () => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_PASSWORD'];
        await ensureEngineReady();
        const record = (label: string, r: Result): void => {
            for (const d of diagnosticsOf(r)) {
                if (!produced.has(d.code)) produced.set(d.code, new Set());
                produced.get(d.code)!.add(label);
            }
            rows.set(label, diagnosticsOf(r));
        };
        for (const name of FIXTURE_FILES) {
            for (const [tool, args] of readerOf(name)) {
                const r = await callToolDirect(tool, args);
                expect(r.isError, `${name} via ${tool}: ${JSON.stringify(r.content[0])}`).not.toBe(true);
                assertResultClean(r, `${name} via ${tool}`);
                record(`${name}/${tool}`, r);
            }
        }
        for (const [label, tool, args] of VERDICT_CALLS) {
            const r = await callToolDirect(tool, args);
            expect(r.isError, `${label} via ${tool}: ${JSON.stringify(r.content[0])}`).not.toBe(true);
            record(`${label}/${tool}`, r);
        }
    }, 120_000);

    it('every fixture has a reader (content.txt is the only non-PKI file) and the readers accept every fixture', () => {
        expect(FIXTURE_FILES).toHaveLength(42);
        expect(FIXTURE_FILES.filter((f) => readerOf(f).length === 0)).toEqual(['content.txt']);
    });

    for (const row of FIXTURE_ROWS) {
        it(`${row.code} ← ${row.fixture} through ${row.tool}`, async () => {
            const args = row.args ?? readerOf(row.fixture)[0]![1];
            const r = await callToolDirect(row.tool, args);
            expect(r.isError).not.toBe(true);
            const hit = diagnosticsOf(r).find((d) => d.code === row.code);
            expect(hit, `${row.code} in ${JSON.stringify(diagnosticsOf(r).map((d) => d.code))}`).toBeDefined();
            expect(hit?.severity).toBe(SEVERITY[row.code]);
            expect(hit?.path).toBe(row.path);
            expect(typeof hit?.message).toBe('string');
            expect(hit?.message.length).toBeGreaterThan(20);
            expect(typeof hit?.standard).toBe('string');
            const sc = r.structuredContent as { diagnosticCounts: Record<string, number> };
            expect(sc.diagnosticCounts[row.code]).toBeGreaterThanOrEqual(1);
        });
    }

    it('strict:true escalates the first fixture warning to PKI_STRICT_DIAGNOSTIC on the reader', async () => {
        const strict = await callToolDirect('inspect_certificate', { certificate: fixtureInput('revoked.crt.pem'), strict: true });
        expect(strict.isError).toBe(true);
        const err = (strict._meta as { error: { code: string; message: string } }).error;
        expect(err.code).toBe('PKI_STRICT_DIAGNOSTIC');
        expect(err.message).toContain('PKI_DIAG_COMMON_NAME_NOT_IN_SAN');
    });

    it('the union of what the fixtures produce is exactly FIXTURE_REACHABLE (a new code here is a stale table)', () => {
        expect([...produced.keys()].sort()).toEqual([...FIXTURE_REACHABLE].sort());
        for (const code of FIXTURE_REACHABLE) expect(FIXTURE_ROWS.some((r) => r.code === code), code).toBe(true);
        // A reader row is produced by that fixture through that reader; a verdict row by that tool over the fixture combinations.
        for (const row of FIXTURE_ROWS) {
            const from = [...(produced.get(row.code) ?? [])];
            if (row.args === undefined) expect(from, `${row.code} from ${row.fixture}/${row.tool}`).toContain(`${row.fixture}/${row.tool}`);
            else expect(from.some((label) => label.endsWith(`/${row.tool}`)), `${row.code} from ${row.tool}: ${from.join(', ')}`).toBe(true);
        }
    });

    it('every diagnostic row carries code, severity, message, standard and path, and the severity matches the registry', () => {
        for (const [label, list] of rows) {
            for (const d of list) {
                expect(PKI_DIAGNOSTIC_CODES, `${label}: ${d.code}`).toContain(d.code);
                expect(d.severity, `${label}: ${d.code}`).toBe(SEVERITY[d.code]);
                expect(typeof d.path).toBe('string');
                expect(typeof d.standard).toBe('string');
            }
        }
    });
});

describe('diagnostics inventory: hand-built values through decode_asn1 / decode_extension', () => {
    beforeAll(async () => {
        await ensureEngineReady();
    });

    for (const row of CRAFTED_ROWS) {
        it(`${row.code} ← ${row.tool}`, async () => {
            const r = await callToolDirect(row.tool, row.args);
            expect(r.isError, JSON.stringify(r.content[0])).not.toBe(true);
            const hit = diagnosticsOf(r).find((d) => d.code === row.code);
            expect(hit, `${row.code} in ${JSON.stringify(diagnosticsOf(r).map((d) => d.code))}`).toBeDefined();
            expect(hit?.severity).toBe(SEVERITY[row.code]);
            expect(hit?.message.length).toBeGreaterThan(20);
        });
    }

    it('strict:true escalates a crafted warning to PKI_STRICT_DIAGNOSTIC, and never an info', async () => {
        const warning = CRAFTED_ROWS.find((r) => SEVERITY[r.code] === 'warning' && r.tool === 'decode_extension')!;
        const strict = await callToolDirect(warning.tool, { ...warning.args, strict: true });
        expect(strict.isError, warning.code).toBe(true);
        expect((strict._meta as { error: { code: string } }).error.code).toBe('PKI_STRICT_DIAGNOSTIC');
        const info = CRAFTED_ROWS.find((r) => SEVERITY[r.code] === 'info');
        if (info !== undefined) {
            const kept = await callToolDirect(info.tool, { ...info.args, strict: true });
            expect(kept.isError, `${info.code} is info: strict never refuses it`).not.toBe(true);
        }
    });
});

describe('diagnostics inventory: the registry is covered', () => {
    it('fixture-reachable + crafted + NOT_REACHABLE_WITH_FIXTURES = the 97 codes, disjoint, each unreachable one with a reason', () => {
        expect(PKI_DIAGNOSTIC_CODES).toHaveLength(97);
        const crafted = [...new Set(CRAFTED_ROWS.map((r) => r.code))];
        const unreachable = Object.keys(NOT_REACHABLE_WITH_FIXTURES);
        const union = [...FIXTURE_REACHABLE, ...crafted, ...unreachable];
        expect(new Set(union).size, 'a code is listed twice across the three sets').toBe(union.length);
        expect([...union].sort()).toEqual([...PKI_DIAGNOSTIC_CODES].sort());
        for (const [code, reason] of Object.entries(NOT_REACHABLE_WITH_FIXTURES)) {
            expect(PKI_DIAGNOSTIC_CODES, code).toContain(code);
            expect(reason.length, code).toBeGreaterThan(30);
        }
        expect(FIXTURE_REACHABLE).toHaveLength(2);
        expect(crafted).toHaveLength(30);
        expect(unreachable).toHaveLength(65);
    });
});
