/**
 * pkinative-mcp — the OpenSSL interoperability corpus
 * =====================================================
 * One table drives scripts/generate-pki-corpus.ts (`corpus:pki`, writes the
 * artefacts through the BUILT server into test-output/pki/) and
 * scripts/validate-pki.ts (`validate:pki`: level 0 re-reads every artefact
 * through the engine, level 1 hands it to OpenSSL). `docs/data/interop.json`
 * declares the counts (`conformant` / `refused`) and the OpenSSL commands;
 * tests/tools/pki-corpus.test.ts holds the two together.
 *
 * Every entry names the tool that produces it and the arguments as a host
 * would send them, with placeholders:
 *   <fixture:NAME>   the PKI input fragment of tests/fixtures/pki/NAME
 *   <content:NAME>   the CONTENT input fragment ({ base64 }) of a fixture
 *   <corpus:ID>      the input fragment of an EARLIER entry's bytes
 *                    ({ derBase64 }, or { pem } for a `pem` entry)
 *   <password:test-only>   the fixture password
 * so the order matters and execution is sequential. An entry whose tool is
 * not registered at run time — or whose `<corpus:ID>` input was not
 * produced — is SKIPPED with the reason, never failed: the corpus keeps
 * working while the catalogue grows.
 *
 * `deterministic: true` claims the bytes repeat under the pins (serial,
 * nonce, instants, an Ed25519 or RSA PKCS#1 signer); the generator produces
 * such an entry twice and the validator holds the two digests equal. ECDSA
 * and RSA-PSS draw a random per signature and are declared non-deterministic.
 *
 * Negative canaries (`expectRefused`) must be refused with that code: a
 * canary that WRITES bytes is an XPASS and fails the validator — the one way
 * to know the refusals are real and not a validator that accepts everything.
 */

import { createHash } from 'node:crypto';
import { decodeAsn1, parseCertificate, type Asn1Node } from 'pkinative';

import { FIXTURE_PASSWORD, SAMPLE_AT, contentInput, fixtureBytes, fixtureDer, fixtureInput } from '../helpers/io.js';
import type { CommandId } from './interop-tools.js';

export type CorpusKind = 'cert' | 'csr' | 'cms-attached' | 'cms-detached' | 'tsq' | 'ocsp-req' | 'pem';

/** A reference to bytes on disk: an earlier entry or a fixture. */
export type FileRef = `corpus:${string}` | `fixture:${string}`;

export interface RoundTrip {
    readonly tool: string;
    readonly arguments: Readonly<Record<string, unknown>>;
    /**
     * Judge the structured result (the call already succeeded — isError is a
     * failure before this runs). Default: a `valid` member, when present,
     * must be true.
     */
    readonly assert?: (structured: Readonly<Record<string, unknown>>) => string | null;
}

export interface OpensslCheck {
    readonly command: CommandId;
    /** What the classifier must report (documentation; the classifier of the command encodes it). */
    readonly expects: string;
    readonly caFile?: FileRef;
    readonly untrusted?: readonly FileRef[];
    readonly content?: FileRef;
}

/** An OpenSSL release as `major.minor`. */
export type OpensslFloor = `${number}.${number}`;

/**
 * A documented gap of the judge: a check OpenSSL cannot run before a release,
 * with the reason and the proof — the one place such a limit is declared
 * (the engine keeps the same table in pkinative's scripts/lib/interop.ts).
 * An older judge skips the matched checks with the reason on the PASS line
 * instead of failing; level 0 still judges the bytes, and a CI leg that must
 * carry the floors (`PKINATIVE_INTEROP_FLOORS_REQUIRED=1`) fails when its
 * judge is below one. docs/data/interop.json declares the table
 * (`knownGaps`), docs/guides/CONFORMANCE.md documents it, both held by tests.
 */
export interface OpensslGap {
    readonly id: string;
    /** `<entry id>:<command id>` of every check the gap covers. */
    readonly match: readonly `${string}:${CommandId}`[];
    readonly minOpenssl: OpensslFloor;
    readonly reason: string;
    readonly proof: string;
}

export const KNOWN_OPENSSL_GAPS: readonly OpensslGap[] = [
    {
        id: 'cms-eddsa',
        match: ['cms-ed25519-attached:cms-verify-attached'],
        minOpenssl: '3.5',
        reason: 'Ed25519 signs the data, not a digest (RFC 8419). OpenSSL before 3.5.0 refuses every digest for EdDSA in CMS ("eddsa_digest_signverify_init: invalid digest") and can neither sign nor verify an Ed25519 SignedData; 3.5.0 added the signature schemes without a signing digest to CMS.',
        proof: 'The corpus entry verifies with openssl cms -verify on OpenSSL 3.5.5 (Windows, macOS) and fails with that error on OpenSSL 3.0.13 (Ubuntu 24.04) and 3.0.2 (Ubuntu 22.04); the engine round trip (level 0) accepts it on every host.',
    },
];

/** The gap covering one check of one entry, if any. */
export function opensslGapFor(entryId: string, command: CommandId): OpensslGap | undefined {
    return KNOWN_OPENSSL_GAPS.find((gap) => gap.match.includes(`${entryId}:${command}`));
}

/** True when `version` is at or above the `major.minor` floor. */
export function opensslAtLeast(version: { readonly major: number; readonly minor: number }, floor: OpensslFloor): boolean {
    const [major, minor] = floor.split('.').map(Number) as [number, number];
    return version.major > major || (version.major === major && version.minor >= minor);
}

export interface Expectation {
    readonly roundTrip: readonly RoundTrip[];
    readonly openssl: readonly OpensslCheck[];
    readonly deterministic: boolean;
    /** An in-process check over the bytes themselves (the OCSP CertID, the TSP imprint and nonce). */
    readonly engineCheck?: (bytes: Uint8Array) => string | null;
}

export interface CorpusEntry {
    readonly id: string;
    readonly tool: string;
    readonly kind: CorpusKind;
    readonly arguments: Readonly<Record<string, unknown>>;
    /** A conformant entry: what must hold for its bytes. */
    readonly expect?: Expectation;
    /** A negative canary: the code the server must refuse the call with. */
    readonly expectRefused?: string;
}

// ── Placeholders ─────────────────────────────────────────────────────

const FIXTURE_REF = /^fixture:([A-Za-z0-9._-]+)$/;
const CONTENT_REF = /^content:([A-Za-z0-9._-]+)$/;
const CORPUS_REF = /^corpus:([A-Za-z0-9._-]+)$/;
const PASSWORD_REF = 'password:test-only';

/** Every `<…>` token that is a whole string value somewhere in `value`. */
export function placeholdersOf(value: unknown, into: Set<string> = new Set()): Set<string> {
    if (typeof value === 'string') {
        const m = /^<(.+)>$/.exec(value);
        if (m?.[1] !== undefined) into.add(m[1]);
    } else if (Array.isArray(value)) {
        for (const v of value) placeholdersOf(v, into);
    } else if (value !== null && typeof value === 'object') {
        for (const v of Object.values(value)) placeholdersOf(v, into);
    }
    return into;
}

/** The ids of the earlier entries an argument object consumes. */
export function corpusDependencies(value: unknown): string[] {
    return [...placeholdersOf(value)].map((t) => CORPUS_REF.exec(t)?.[1]).filter((id): id is string => id !== undefined);
}

export interface ProducedBytes {
    readonly bytes: Uint8Array;
    readonly kind: CorpusKind;
}

/** Resolve every placeholder of `value` against the fixtures and the produced entries. */
export function resolvePlaceholders(value: unknown, produced: ReadonlyMap<string, ProducedBytes>): unknown {
    const resolve = (token: string): unknown => {
        const fixture = FIXTURE_REF.exec(token)?.[1];
        if (fixture !== undefined) return fixtureInput(fixture);
        const content = CONTENT_REF.exec(token)?.[1];
        if (content !== undefined) return contentInput(content);
        const id = CORPUS_REF.exec(token)?.[1];
        if (id !== undefined) {
            const entry = produced.get(id);
            if (entry === undefined) throw new Error(`corpus order: ${id} is consumed before it is produced`);
            return entry.kind === 'pem' ? { pem: Buffer.from(entry.bytes).toString('utf8') } : { derBase64: Buffer.from(entry.bytes).toString('base64') };
        }
        if (token === PASSWORD_REF) return FIXTURE_PASSWORD;
        throw new Error(`<${token}> is not a corpus placeholder`);
    };
    const walk = (v: unknown): unknown => {
        if (typeof v === 'string') {
            const m = /^<(.+)>$/.exec(v);
            return m?.[1] === undefined ? v : resolve(m[1]);
        }
        if (Array.isArray(v)) return v.map(walk);
        if (v !== null && typeof v === 'object') {
            const out: Record<string, unknown> = {};
            for (const [k, x] of Object.entries(v)) out[k] = walk(x);
            return out;
        }
        return v;
    };
    return walk(value);
}

// ── The engine checks (bytes-level, pkinative readers only) ──────────

const sha256 = (data: Uint8Array): Buffer => createHash('sha256').update(data).digest();
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

/** `SEQUENCE` children of a node, universal tag 16 only. */
function sequences(node: Asn1Node): Asn1Node[] {
    return node.children.filter((c) => c.tagClass === 'universal' && c.tagNumber === 16);
}

/**
 * RFC 6960 §4.1.1: the CertID of the one Request must hash the issuer's
 * subject name and public key with SHA-256 and carry the certificate's
 * serial. Computed here with node:crypto from the fixtures, so the engine's
 * own CertID encoder is judged by an independent reckoning.
 */
export function checkOcspRequest(certificate: string, issuer: string, hashAlgorithmOid: string): (bytes: Uint8Array) => string | null {
    return (bytes) => {
        // The engine's diagnostics (the fixture leaf's CN is not in its SAN) are the tools' business, not this check's.
        const quiet = { onDiagnostic: (): void => undefined };
        const cert = parseCertificate(fixtureDer(certificate), quiet);
        const ca = parseCertificate(fixtureDer(issuer), quiet);
        const root = decodeAsn1(bytes);
        const tbs = root.children[0];
        if (tbs === undefined) return 'OCSPRequest has no tbsRequest';
        const requestList = sequences(tbs)[0];
        const request = requestList?.children[0];
        const certId = request?.children[0];
        if (certId === undefined || certId.children.length !== 4) return 'no CertID in the first Request';
        const [alg, nameHash, keyHash, serial] = certId.children as [Asn1Node, Asn1Node, Asn1Node, Asn1Node];
        const oid = alg.children[0];
        if (oid === undefined || hex(oid.content) !== hashAlgorithmOid) return `CertID hashAlgorithm is ${oid === undefined ? 'absent' : hex(oid.content)}, expected ${hashAlgorithmOid}`;
        const spkiBits = ca.subjectPublicKeyInfo.publicKey.bytes;
        if (hex(nameHash.content) !== hex(sha256(ca.subject.der))) return 'issuerNameHash is not SHA-256(issuer subject)';
        if (hex(keyHash.content) !== hex(sha256(spkiBits))) return 'issuerKeyHash is not SHA-256(issuer public key bits)';
        if (hex(serial.content) !== cert.serialNumber.hex) return `serialNumber is ${hex(serial.content)}, expected ${cert.serialNumber.hex}`;
        return null;
    };
}

/** OID content octets of SHA-256 (2.16.840.1.101.3.4.2.1). */
export const SHA256_OID_HEX = '608648016503040201';
/** OID content octets of SHA-384 (2.16.840.1.101.3.4.2.2). */
export const SHA384_OID_HEX = '608648016503040202';

/**
 * RFC 3161 §2.4.1: the messageImprint must be the named digest of the data
 * and the nonce the integer asked for (42 = 0x2a).
 */
export function checkTimestampRequest(content: string, algorithm: 'sha256' | 'sha384', algorithmOidHex: string, nonceHex: string): (bytes: Uint8Array) => string | null {
    return (bytes) => {
        const root = decodeAsn1(bytes);
        const [version, imprint] = root.children as [Asn1Node | undefined, Asn1Node | undefined];
        if (version === undefined || hex(version.content) !== '01') return 'TimeStampReq version is not 1';
        if (imprint === undefined || imprint.children.length !== 2) return 'no messageImprint';
        const oid = imprint.children[0]?.children[0];
        if (oid === undefined || hex(oid.content) !== algorithmOidHex) return `messageImprint algorithm is ${oid === undefined ? 'absent' : hex(oid.content)}, expected ${algorithmOidHex}`;
        const expected = createHash(algorithm).update(fixtureBytes(content)).digest('hex');
        if (hex(imprint.children[1]?.content ?? new Uint8Array()) !== expected) return `hashedMessage is not ${algorithm}(${content})`;
        const nonce = root.children.find((c, i) => i >= 2 && c.tagClass === 'universal' && c.tagNumber === 2);
        if (nonce === undefined || hex(nonce.content) !== nonceHex) return `nonce is ${nonce === undefined ? 'absent' : hex(nonce.content)}, expected ${nonceHex}`;
        return null;
    };
}

// ── The table ────────────────────────────────────────────────────────

export const CORPUS_ORGANISATION = 'pkinative-mcp corpus';
/** Inside the fixtures' window and inside OpenSSL's wall clock on the day the corpus was written; `-attime` pins it anyway. */
export const CORPUS_NOT_BEFORE = '2026-01-01T00:00:00Z';
/** Epoch seconds of SAMPLE_AT, for `openssl verify -attime`. */
export const CORPUS_ATTIME = Math.floor(Date.parse(SAMPLE_AT) / 1000);

const AT = SAMPLE_AT;
const DER = { encoding: 'der' } as const;
const CA_EXTENSIONS = { basicConstraints: { ca: true, critical: true }, keyUsage: { usages: ['keyCertSign', 'cRLSign'], critical: true } } as const;
const name = (cn: string): Record<string, string> => ({ C: 'FR', O: CORPUS_ORGANISATION, CN: cn });
const ca = (serial: number, cn: string): Record<string, unknown> => ({ serialNumber: serial, subject: name(cn), notBefore: CORPUS_NOT_BEFORE, validityDays: 3650, extensions: CA_EXTENSIONS });
const leaf = (serial: string, host: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({
    serialNumber: serial,
    subject: name(host),
    notBefore: CORPUS_NOT_BEFORE,
    validityDays: 730,
    extensions: {
        basicConstraints: { ca: false, critical: true },
        subjectAltName: { dns: [host], ip: ['192.0.2.9', '2001:db8::9'], email: [`admin@${host}`] },
        extendedKeyUsage: ['serverAuth'],
        keyUsage: { usages: ['digitalSignature'], critical: true },
        ...extra,
    },
});

const ED25519 = { key: '<fixture:ed25519.key.pem>' } as const;
const RSA_PKCS1 = { key: '<fixture:rsa.key.pem>', rsaScheme: 'pkcs1' } as const;
const RSA_PSS = { key: '<fixture:rsa.key.pem>', rsaScheme: 'pss' } as const;
const EC = { key: '<fixture:leaf.key.pem>' } as const;

const signatureValid = (r: Readonly<Record<string, unknown>>): string | null => {
    const sig = r['signature'] as { valid?: unknown } | undefined;
    return sig?.valid === true ? null : `signature.valid is ${JSON.stringify(sig?.valid ?? null)}`;
};

/** inspect_certificate (self or issuer check) + verify_certificate_chain to the anchor. */
function certificateRoundTrip(id: string, anchor: string, options: { readonly issuer?: string; readonly candidates?: readonly string[]; readonly host?: string } = {}): RoundTrip[] {
    const self = options.issuer === undefined;
    return [
        {
            tool: 'inspect_certificate',
            arguments: { certificate: `<corpus:${id}>`, ...(self ? { checkSelfSignature: true } : { issuer: `<corpus:${options.issuer}>` }), verbosity: 'summary' },
            assert: (r) => (r['signatureValid'] === true ? null : `signatureValid is ${JSON.stringify(r['signatureValid'] ?? null)}`),
        },
        {
            tool: 'verify_certificate_chain',
            arguments: {
                leaf: `<corpus:${id}>`,
                trustAnchors: [`<corpus:${anchor}>`],
                ...(options.candidates !== undefined ? { candidates: options.candidates.map((c) => `<corpus:${c}>`) } : {}),
                ...(options.host !== undefined ? { serverName: { host: options.host }, purposes: ['serverAuth'] } : {}),
                at: AT,
            },
        },
    ];
}

export const CORPUS: readonly CorpusEntry[] = [
    // ── Self-signed CAs, one per signature family ──────────────────────
    {
        id: 'ca-ed25519', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: ca(1, 'Corpus Ed25519 CA'), signer: ED25519, ...DER },
        expect: { deterministic: true, roundTrip: certificateRoundTrip('ca-ed25519', 'ca-ed25519'), openssl: [{ command: 'x509-text', expects: 'dump' }, { command: 'verify', expects: 'OK', caFile: 'corpus:ca-ed25519' }] },
    },
    {
        id: 'ca-rsa-pkcs1', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: ca(2, 'Corpus RSA PKCS1 CA'), signer: RSA_PKCS1, ...DER },
        expect: { deterministic: true, roundTrip: certificateRoundTrip('ca-rsa-pkcs1', 'ca-rsa-pkcs1'), openssl: [{ command: 'x509-text', expects: 'dump' }, { command: 'verify', expects: 'OK', caFile: 'corpus:ca-rsa-pkcs1' }] },
    },
    {
        id: 'ca-rsa-pss', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: ca(3, 'Corpus RSA PSS CA'), signer: RSA_PSS, ...DER },
        expect: { deterministic: false, roundTrip: certificateRoundTrip('ca-rsa-pss', 'ca-rsa-pss'), openssl: [{ command: 'x509-text', expects: 'dump' }, { command: 'verify', expects: 'OK', caFile: 'corpus:ca-rsa-pss' }] },
    },
    {
        id: 'ca-ec', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: ca(4, 'Corpus EC P-256 CA'), signer: EC, ...DER },
        expect: { deterministic: false, roundTrip: certificateRoundTrip('ca-ec', 'ca-ec'), openssl: [{ command: 'x509-text', expects: 'dump' }, { command: 'verify', expects: 'OK', caFile: 'corpus:ca-ec' }] },
    },
    // ── Leaves issued by the corpus CAs (the subject key comes from a CSR, a certificate or a PUBLIC KEY) ──
    {
        id: 'leaf-ed25519', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: leaf('0x1001', 'leaf.corpus.example.test'), issuerCertificate: '<corpus:ca-ed25519>', subjectPublicKey: '<fixture:leaf.csr.pem>', signer: ED25519, ...DER },
        expect: {
            deterministic: true,
            roundTrip: certificateRoundTrip('leaf-ed25519', 'ca-ed25519', { issuer: 'ca-ed25519', host: 'leaf.corpus.example.test' }),
            openssl: [{ command: 'x509-text', expects: 'dump' }, { command: 'verify-sslserver', expects: 'OK', caFile: 'corpus:ca-ed25519' }],
        },
    },
    {
        id: 'leaf-rsa-pkcs1', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: leaf('0x1002', 'rsa1.corpus.example.test', { keyUsage: { usages: ['digitalSignature', 'keyEncipherment'], critical: true } }), issuerCertificate: '<corpus:ca-rsa-pkcs1>', subjectPublicKey: '<fixture:leaf.pub.pem>', signer: RSA_PKCS1, ...DER },
        expect: {
            deterministic: true,
            roundTrip: certificateRoundTrip('leaf-rsa-pkcs1', 'ca-rsa-pkcs1', { issuer: 'ca-rsa-pkcs1', host: 'rsa1.corpus.example.test' }),
            openssl: [{ command: 'verify-sslserver', expects: 'OK', caFile: 'corpus:ca-rsa-pkcs1' }],
        },
    },
    {
        id: 'leaf-rsa-pss', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: leaf('0x1003', 'pss.corpus.example.test'), issuerCertificate: '<corpus:ca-rsa-pss>', subjectPublicKey: '<fixture:leaf.pub.pem>', signer: RSA_PSS, ...DER },
        expect: {
            deterministic: false,
            roundTrip: certificateRoundTrip('leaf-rsa-pss', 'ca-rsa-pss', { issuer: 'ca-rsa-pss', host: 'pss.corpus.example.test' }),
            openssl: [{ command: 'verify-sslserver', expects: 'OK', caFile: 'corpus:ca-rsa-pss' }],
        },
    },
    {
        id: 'leaf-ec', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: leaf('0x1004', 'ec.corpus.example.test'), issuerCertificate: '<corpus:ca-ec>', subjectPublicKey: '<fixture:ed25519.crt.pem>', signer: EC, ...DER },
        expect: {
            deterministic: false,
            roundTrip: certificateRoundTrip('leaf-ec', 'ca-ec', { issuer: 'ca-ec', host: 'ec.corpus.example.test' }),
            openssl: [{ command: 'verify-sslserver', expects: 'OK', caFile: 'corpus:ca-ec' }],
        },
    },
    // ── A pathLen-0 intermediate and a leaf under it (a three-certificate path) ──
    {
        id: 'inter-pathlen0', tool: 'create_certificate', kind: 'cert',
        arguments: {
            spec: { serialNumber: '0x2001', subject: name('Corpus Intermediate (pathLen 0)'), notBefore: CORPUS_NOT_BEFORE, validityDays: 1825, extensions: { basicConstraints: { ca: true, pathLen: 0, critical: true }, keyUsage: { usages: ['keyCertSign', 'cRLSign'], critical: true } } },
            issuerCertificate: '<corpus:ca-ed25519>', subjectPublicKey: '<fixture:leaf.pub.pem>', signer: ED25519, ...DER,
        },
        expect: {
            deterministic: true,
            roundTrip: [
                ...certificateRoundTrip('inter-pathlen0', 'ca-ed25519', { issuer: 'ca-ed25519' }),
                { tool: 'inspect_certificate', arguments: { certificate: '<corpus:inter-pathlen0>', extension: 'basicConstraints' }, assert: (r) => ((r['extension'] as { pathLenConstraint?: unknown } | undefined)?.pathLenConstraint === 0 ? null : 'basicConstraints.pathLenConstraint is not 0') },
            ],
            openssl: [{ command: 'x509-text', expects: 'dump' }, { command: 'verify', expects: 'OK', caFile: 'corpus:ca-ed25519' }],
        },
    },
    {
        id: 'leaf-under-inter', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: leaf('0x2002', 'under.corpus.example.test', { keyUsage: { usages: ['digitalSignature', 'keyEncipherment'], critical: true } }), issuerCertificate: '<corpus:inter-pathlen0>', subjectPublicKey: '<fixture:rsa.crt.pem>', signer: EC, ...DER },
        expect: {
            deterministic: false,
            roundTrip: certificateRoundTrip('leaf-under-inter', 'ca-ed25519', { issuer: 'inter-pathlen0', candidates: ['inter-pathlen0'], host: 'under.corpus.example.test' }),
            openssl: [{ command: 'verify-sslserver', expects: 'OK', caFile: 'corpus:ca-ed25519', untrusted: ['corpus:inter-pathlen0'] }],
        },
    },
    // ── Certification requests ─────────────────────────────────────────
    {
        id: 'csr-ec-san', tool: 'create_csr', kind: 'csr',
        arguments: { spec: { subject: name('csr.corpus.example.test'), extensions: { subjectAltName: { dns: ['csr.corpus.example.test', 'alt.corpus.example.test'] }, keyUsage: ['digitalSignature'] } }, signer: EC, ...DER },
        expect: {
            deterministic: false,
            roundTrip: [{ tool: 'inspect_csr', arguments: { request: '<corpus:csr-ec-san>', verify: true }, assert: signatureValid }],
            openssl: [{ command: 'req-verify', expects: 'Certificate request self-signature verify OK' }, { command: 'asn1parse', expects: 'dump' }],
        },
    },
    {
        id: 'csr-rsa-pss', tool: 'create_csr', kind: 'csr',
        arguments: { spec: { subject: name('pss-csr.corpus.example.test') }, signer: RSA_PSS, ...DER },
        expect: {
            deterministic: false,
            roundTrip: [{ tool: 'inspect_csr', arguments: { request: '<corpus:csr-rsa-pss>', verify: true }, assert: signatureValid }],
            openssl: [{ command: 'req-verify', expects: 'Certificate request self-signature verify OK' }],
        },
    },
    {
        id: 'csr-ed25519', tool: 'create_csr', kind: 'csr',
        arguments: { spec: { subject: name('ed-csr.corpus.example.test'), extensions: { subjectAltName: { dns: ['ed-csr.corpus.example.test'] } } }, signer: ED25519, ...DER },
        expect: {
            deterministic: true,
            roundTrip: [{ tool: 'inspect_csr', arguments: { request: '<corpus:csr-ed25519>', verify: true }, assert: signatureValid }],
            openssl: [{ command: 'req-verify', expects: 'Certificate request self-signature verify OK' }],
        },
    },
    // ── CMS SignedData over content.txt ────────────────────────────────
    {
        id: 'cms-attached', tool: 'sign_cms', kind: 'cms-attached',
        arguments: { content: '<content:content.txt>', certificate: '<fixture:leaf.crt.pem>', chain: ['<fixture:inter.crt.pem>'], signer: EC, signingTime: AT, ...DER },
        expect: {
            deterministic: false,
            roundTrip: [{ tool: 'verify_cms', arguments: { signedData: '<corpus:cms-attached>', trustAnchors: ['<fixture:root.crt.pem>'], at: AT, verbosity: 'summary' } }],
            openssl: [{ command: 'cms-verify-attached', expects: 'CMS Verification successful', caFile: 'fixture:root.crt.pem' }],
        },
    },
    {
        id: 'cms-detached', tool: 'sign_cms', kind: 'cms-detached',
        arguments: { content: '<content:content.txt>', detached: true, certificate: '<fixture:leaf.crt.pem>', chain: ['<fixture:inter.crt.pem>'], signer: EC, signingTime: AT, ...DER },
        expect: {
            deterministic: false,
            roundTrip: [{ tool: 'verify_cms', arguments: { signedData: '<corpus:cms-detached>', content: '<content:content.txt>', trustAnchors: ['<fixture:root.crt.pem>'], at: AT, verbosity: 'summary' } }],
            openssl: [{ command: 'cms-verify-detached', expects: 'CMS Verification successful', caFile: 'fixture:root.crt.pem', content: 'fixture:content.txt' }],
        },
    },
    {
        id: 'cms-ed25519-attached', tool: 'sign_cms', kind: 'cms-attached',
        arguments: { content: '<content:content.txt>', certificate: '<fixture:ed25519.crt.pem>', signer: ED25519, signingTime: AT, ...DER },
        expect: {
            deterministic: true,
            roundTrip: [{ tool: 'verify_cms', arguments: { signedData: '<corpus:cms-ed25519-attached>', trustAnchors: ['<fixture:ed25519.crt.pem>'], at: AT, verbosity: 'summary' } }],
            // OpenSSL 3.5+ for this check: KNOWN_OPENSSL_GAPS 'cms-eddsa'.
            openssl: [{ command: 'cms-verify-attached', expects: 'CMS Verification successful', caFile: 'fixture:ed25519.crt.pem' }],
        },
    },
    // ── RFC 3161 requests ──────────────────────────────────────────────
    {
        id: 'tsq-sha256', tool: 'create_timestamp_request', kind: 'tsq',
        arguments: { data: '<content:content.txt>', hashAlgorithm: 'SHA-256', nonce: '42', certReq: true, ...DER },
        expect: {
            deterministic: true,
            roundTrip: [{ tool: 'decode_asn1', arguments: { input: '<corpus:tsq-sha256>', verbosity: 'summary' } }],
            engineCheck: checkTimestampRequest('content.txt', 'sha256', SHA256_OID_HEX, '2a'),
            openssl: [{ command: 'ts-query-text', expects: 'Nonce:' }],
        },
    },
    {
        id: 'tsq-sha384', tool: 'create_timestamp_request', kind: 'tsq',
        arguments: { data: '<content:content.txt>', hashAlgorithm: 'SHA-384', nonce: '42', certReq: true, ...DER },
        expect: {
            deterministic: true,
            roundTrip: [{ tool: 'decode_asn1', arguments: { input: '<corpus:tsq-sha384>', verbosity: 'summary' } }],
            engineCheck: checkTimestampRequest('content.txt', 'sha384', SHA384_OID_HEX, '2a'),
            openssl: [{ command: 'ts-query-text', expects: 'Nonce:' }],
        },
    },
    // ── OCSP requests ──────────────────────────────────────────────────
    {
        id: 'ocsp-req-leaf', tool: 'create_ocsp_request', kind: 'ocsp-req',
        arguments: { certificate: '<fixture:leaf.crt.pem>', issuer: '<fixture:inter.crt.pem>', hashAlgorithm: 'SHA-256', nonce: '0102030405060708090a0b0c0d0e0f10', ...DER },
        expect: {
            deterministic: true,
            roundTrip: [{ tool: 'decode_asn1', arguments: { input: '<corpus:ocsp-req-leaf>', verbosity: 'summary' } }],
            engineCheck: checkOcspRequest('leaf.crt.pem', 'inter.crt.pem', SHA256_OID_HEX),
            openssl: [{ command: 'ocsp-req-text', expects: 'Serial Number:' }],
        },
    },
    {
        id: 'ocsp-req-revoked', tool: 'create_ocsp_request', kind: 'ocsp-req',
        arguments: { certificate: '<fixture:revoked.crt.pem>', issuer: '<fixture:inter.crt.pem>', hashAlgorithm: 'SHA-256', nonce: '0102030405060708090a0b0c0d0e0f10', ...DER },
        expect: {
            deterministic: true,
            roundTrip: [{ tool: 'decode_asn1', arguments: { input: '<corpus:ocsp-req-revoked>', verbosity: 'summary' } }],
            engineCheck: checkOcspRequest('revoked.crt.pem', 'inter.crt.pem', SHA256_OID_HEX),
            openssl: [{ command: 'ocsp-req-text', expects: 'Serial Number:' }],
        },
    },
    // ── PEM encodings of the OpenSSL-made DER fixtures ─────────────────
    {
        id: 'pem-root-cert', tool: 'convert_pem', kind: 'pem',
        arguments: { mode: 'encode', input: '<fixture:root.crt.der>', label: 'CERTIFICATE' },
        expect: {
            deterministic: true,
            roundTrip: [{ tool: 'inspect_certificate', arguments: { certificate: '<corpus:pem-root-cert>', checkSelfSignature: true, verbosity: 'summary' }, assert: (r) => (r['signatureValid'] === true ? null : 'signatureValid is not true') }],
            openssl: [{ command: 'x509-text-pem', expects: 'dump' }],
        },
    },
    {
        id: 'pem-inter-crl', tool: 'convert_pem', kind: 'pem',
        arguments: { mode: 'encode', input: '<fixture:inter.crl.der>', label: 'X509 CRL' },
        expect: {
            deterministic: true,
            roundTrip: [{ tool: 'inspect_crl', arguments: { crl: '<corpus:pem-inter-crl>', issuer: '<fixture:inter.crt.pem>', verbosity: 'summary' } }],
            openssl: [{ command: 'crl-text-pem', expects: 'Certificate Revocation List' }],
        },
    },
    {
        id: 'pem-leaf-csr', tool: 'convert_pem', kind: 'pem',
        arguments: { mode: 'encode', input: '<fixture:leaf.csr.der>', label: 'CERTIFICATE REQUEST' },
        expect: {
            deterministic: true,
            roundTrip: [{ tool: 'inspect_csr', arguments: { request: '<corpus:pem-leaf-csr>', verify: true }, assert: signatureValid }],
            openssl: [{ command: 'req-verify-pem', expects: 'Certificate request self-signature verify OK' }],
        },
    },
    // ── Negative canaries: what the server must refuse, with which code ──
    {
        id: 'refuse-sha1', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: ca(90, 'Corpus SHA-1 canary'), signer: { ...EC, hash: 'SHA-1' }, ...DER },
        expectRefused: 'VALIDATION_ERROR',
    },
    {
        id: 'refuse-legacy-p12', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: ca(91, 'Corpus legacy PKCS#12 canary'), signer: { p12: '<fixture:legacy.p12>', password: '<password:test-only>' }, ...DER },
        expectRefused: 'PKI_KEY_ENCRYPTION_UNSUPPORTED',
    },
    {
        id: 'refuse-rsa-no-scheme', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: ca(92, 'Corpus RSA scheme canary'), signer: { key: '<fixture:rsa.key.pem>' }, ...DER },
        expectRefused: 'RSA_SCHEME_REQUIRED',
    },
    {
        id: 'refuse-notafter-before-notbefore', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: { serialNumber: 93, subject: name('Corpus validity canary'), notBefore: '2027-01-01T00:00:00Z', notAfter: '2026-01-01T00:00:00Z', extensions: CA_EXTENSIONS }, signer: ED25519, ...DER },
        expectRefused: 'VALIDATION_ERROR',
    },
    {
        id: 'refuse-url-member', tool: 'create_certificate', kind: 'cert',
        arguments: { spec: { ...ca(94, 'Corpus unknown-member canary'), url: 'https://example.test/' }, signer: ED25519, ...DER },
        expectRefused: 'VALIDATION_ERROR',
    },
];

export const CONFORMANT = CORPUS.filter((e) => e.expectRefused === undefined);
export const REFUSED = CORPUS.filter((e) => e.expectRefused !== undefined);

/** The distinct OpenSSL command ids the table uses, in table order. */
export function opensslCommandsUsed(): CommandId[] {
    const out: CommandId[] = [];
    for (const e of CORPUS) for (const c of e.expect?.openssl ?? []) if (!out.includes(c.command)) out.push(c.command);
    return out;
}
