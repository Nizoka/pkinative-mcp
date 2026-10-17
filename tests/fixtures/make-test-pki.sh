#!/bin/sh
# Builds the TEST-ONLY PKI under tests/fixtures/pki/ with OpenSSL (>= 3.4 for
# -not_before/-not_after and -pbmac1_pbkdf2). The fixtures have foreign
# provenance: OpenSSL produced them, so a defect in the CLI or in pkinative
# cannot be baked into both a fixture and its reading.
#
# Run ONCE; the outputs are committed and their SHA-256 pinned in
# tests/fixtures/PROVENANCE.md (tests/docs/fixtures.test.ts checks them).
# Re-running produces new keys, i.e. new fixtures: update the table.
#
# Every private key here is public test material. Never trust it.
set -eu
export MSYS_NO_PATHCONV=1

OUT=${1:-tests/fixtures/pki}
PASS=test-only-password
NB=20260101000000Z
NA=20460101000000Z
mkdir -p "$OUT"
cd "$OUT"
# A relative work directory: a native (mingw) OpenSSL cannot open /tmp paths
# once MSYS path conversion is off.
W=.work
mkdir -p "$W"

cat > "$W/ext.cnf" <<'EOF'
[root]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[inter]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth, emailProtection
subjectAltName = DNS:example.test, DNS:*.wild.example.test, IP:192.0.2.1, email:leaf@example.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:http://crl.example.test/inter.crl
authorityInfoAccess = OCSP;URI:http://ocsp.example.test
[rsa]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:rsa.example.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ocsp]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[tsa]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

ec() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

# Keys (PKCS#8 PEM, unencrypted).
ec root.key.pem
ec inter.key.pem
ec leaf.key.pem
ec revoked.key.pem
ec ocsp.key.pem
ec tsa.key.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key.pem
openssl genpkey -algorithm ED25519 -out ed25519.key.pem

# Root, intermediate, leaves.
openssl req -new -x509 -key root.key.pem -subj "/C=FR/O=pkinative-cli test/CN=Test Root CA" \
    -not_before $NB -not_after $NA -set_serial 0x01 -sha256 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -out root.crt.pem

issue() { # key subject issuer-cert issuer-key ext serial out
    openssl req -new -key "$1" -subj "$2" -out "$W/req.csr"
    openssl x509 -req -in "$W/req.csr" -CA "$3" -CAkey "$4" -set_serial "$6" -sha256 \
        -not_before $NB -not_after $NA -extfile "$W/ext.cnf" -extensions "$5" -out "$7"
}
issue inter.key.pem "/C=FR/O=pkinative-cli test/CN=Test Intermediate CA" root.crt.pem root.key.pem inter 0x02 inter.crt.pem
issue leaf.key.pem "/C=FR/O=pkinative-cli test/CN=example.test" inter.crt.pem inter.key.pem leaf 0x1001 leaf.crt.pem
issue revoked.key.pem "/C=FR/O=pkinative-cli test/CN=revoked.example.test" inter.crt.pem inter.key.pem leaf 0x1002 revoked.crt.pem
issue rsa.key.pem "/C=FR/O=pkinative-cli test/CN=rsa.example.test" inter.crt.pem inter.key.pem rsa 0x1003 rsa.crt.pem
issue ocsp.key.pem "/C=FR/O=pkinative-cli test/CN=Test OCSP Responder" inter.crt.pem inter.key.pem ocsp 0x1004 ocsp.crt.pem
issue tsa.key.pem "/C=FR/O=pkinative-cli test/CN=Test TSA" inter.crt.pem inter.key.pem tsa 0x1005 tsa.crt.pem
openssl req -new -x509 -key ed25519.key.pem -subj "/C=FR/O=pkinative-cli test/CN=Test Ed25519 Root" \
    -not_before $NB -not_after $NA -set_serial 0x03 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,digitalSignature" \
    -addext "subjectKeyIdentifier=hash" -out ed25519.crt.pem

# A CSR with a SAN extension request.
openssl req -new -key leaf.key.pem -subj "/C=FR/O=pkinative-cli test/CN=csr.example.test" \
    -addext "subjectAltName=DNS:csr.example.test" -out leaf.csr.pem

# DER forms.
for f in root inter leaf rsa ed25519; do openssl x509 -in $f.crt.pem -outform DER -out $f.crt.der; done
openssl req -in leaf.csr.pem -outform DER -out leaf.csr.der
openssl pkcs8 -topk8 -nocrypt -in leaf.key.pem -outform DER -out leaf.key.der
openssl pkey -in leaf.key.pem -pubout -out leaf.pub.pem

# Encrypted PKCS#8 (PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC).
openssl pkcs8 -topk8 -in leaf.key.pem -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:$PASS -out leaf.key.enc.pem
openssl pkcs8 -topk8 -in rsa.key.pem -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:$PASS -out rsa.key.enc.pem

# PKCS#12: PBES2 for keys and certificates, PBMAC1 (RFC 9579) integrity.
openssl pkcs12 -export -inkey leaf.key.pem -in leaf.crt.pem -certfile inter.crt.pem -name "test leaf" \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -pbmac1_pbkdf2 -passout pass:$PASS -out leaf.p12

# The RSA key as PKCS#12 (PBES2, PBMAC1), and the leaf in the legacy RC2/3DES +
# SHA-1 HMAC form pkinative refuses by doctrine (its ADR 0002).
openssl pkcs12 -export -inkey rsa.key.pem -in rsa.crt.pem -name "test rsa" -keypbe AES-256-CBC -certpbe AES-256-CBC -pbmac1_pbkdf2 -passout pass:$PASS -out rsa.p12
openssl pkcs12 -export -legacy -inkey leaf.key.pem -in leaf.crt.pem -passout pass:$PASS -out legacy.p12
# The Ed25519 key as PKCS#12 (PBES2, PBMAC1): a --p12 signer whose key hashes internally (added for 1.0.0, audit A-12).
openssl pkcs12 -export -inkey ed25519.key.pem -in ed25519.crt.pem -name "test ed25519" -keypbe AES-256-CBC -certpbe AES-256-CBC -pbmac1_pbkdf2 -passout pass:$PASS -out ed25519.p12

# The worst case for a report: an UNENCRYPTED keyBag (plaintext PKCS#8), PBMAC1.
openssl pkcs12 -export -inkey leaf.key.pem -in leaf.crt.pem -keypbe NONE -certpbe NONE -pbmac1_pbkdf2 -passout pass:$PASS -out plain-keybag.p12

# A PKCS#12 file without a MAC and without encryption (certificates only).
openssl pkcs12 -export -in inter.crt.pem -nokeys -certpbe NONE -nomac -passout pass: -out nomac.p12

# A PKCS#12 file with certificates only (no key bag).
openssl pkcs12 -export -nokeys -in inter.crt.pem -certpbe AES-256-CBC -pbmac1_pbkdf2 -passout pass:$PASS -out certs-only.p12

# CA database for the CRL and the OCSP responder: 0x1002 revoked.
cat > "$W/ca.cnf" <<EOF
[ca]
default_ca = test
[test]
database = $W/index.txt
crlnumber = $W/crlnumber
default_md = sha256
default_crl_days = 7300
crl_extensions = crl_ext
[crl_ext]
authorityKeyIdentifier = keyid
EOF
: > "$W/index.txt"
echo 01 > "$W/crlnumber"
echo "V	460101000000Z		1001	unknown	/C=FR/O=pkinative-cli test/CN=example.test" >> "$W/index.txt"
echo "R	460101000000Z	260601000000Z,keyCompromise	1002	unknown	/C=FR/O=pkinative-cli test/CN=revoked.example.test" >> "$W/index.txt"
openssl ca -gencrl -config "$W/ca.cnf" -cert inter.crt.pem -keyfile inter.key.pem -out inter.crl.pem -batch
openssl crl -in inter.crl.pem -outform DER -out inter.crl.der

# A base CRL (number 1, revokes 0x77) and a delta CRL (deltaCRLIndicator 1,
# number 2, adds 0x99) from the Ed25519 CA, whose key the tests keep.
cat > "$W/ed.cnf" <<EOF
[ca]
default_ca = test
[test]
database = $W/ed-index.txt
crlnumber = $W/ed-crlnumber
default_md = default
default_crl_days = 7300
[base_ext]
authorityKeyIdentifier = keyid
[delta_ext]
authorityKeyIdentifier = keyid
2.5.29.27 = critical,DER:020101
EOF
: > "$W/ed-index.txt"
echo 01 > "$W/ed-crlnumber"
printf 'R\t460101000000Z\t260601000000Z,keyCompromise\t77\tunknown\t/CN=base-revoked\n' >> "$W/ed-index.txt"
openssl ca -gencrl -config "$W/ed.cnf" -crlexts base_ext -cert ed25519.crt.pem -keyfile ed25519.key.pem -out "$W/ed-base.pem" -batch
printf 'R\t460101000000Z\t260701000000Z,superseded\t99\tunknown\t/CN=delta-revoked\n' >> "$W/ed-index.txt"
openssl ca -gencrl -config "$W/ed.cnf" -crlexts delta_ext -cert ed25519.crt.pem -keyfile ed25519.key.pem -out "$W/ed-delta.pem" -batch
openssl crl -in "$W/ed-base.pem" -outform DER -out ed25519.crl.der
openssl crl -in "$W/ed-delta.pem" -outform DER -out ed25519-delta.crl.der

# OCSP: request (with nonce) and the responder's answer for the good and the revoked leaf.
openssl ocsp -issuer inter.crt.pem -sha256 -cert leaf.crt.pem -reqout leaf.ocsp-req.der
openssl ocsp -index "$W/index.txt" -rsigner ocsp.crt.pem -rkey ocsp.key.pem -CA inter.crt.pem \
    -reqin leaf.ocsp-req.der -ndays 7300 -respout leaf.ocsp.der
openssl ocsp -issuer inter.crt.pem -sha256 -cert revoked.crt.pem -no_nonce -reqout "$W/rev.req"
openssl ocsp -index "$W/index.txt" -rsigner ocsp.crt.pem -rkey ocsp.key.pem -CA inter.crt.pem \
    -reqin "$W/rev.req" -ndays 7300 -respout revoked.ocsp.der

# CMS SignedData over a fixed content: attached and detached.
printf 'pkinative-cli test content\n' > content.txt
openssl cms -sign -binary -in content.txt -signer leaf.crt.pem -inkey leaf.key.pem -certfile inter.crt.pem \
    -nodetach -outform DER -out attached.p7s
openssl cms -sign -binary -in content.txt -signer leaf.crt.pem -inkey leaf.key.pem -certfile inter.crt.pem \
    -outform DER -out detached.p7s

# RFC 3161: request, response and the token inside it.
cat > "$W/tsa.cnf" <<EOF
[tsa]
default_tsa = t
[t]
serial = $W/tsaserial
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.1
digests = sha256, sha384, sha512
ess_cert_id_alg = sha256
accuracy = secs:1
ordering = no
tsa_name = yes
ess_cert_id_chain = no
EOF
echo 01 > "$W/tsaserial"
openssl ts -query -data content.txt -sha256 -cert -out content.tsq
openssl ts -reply -config "$W/tsa.cnf" -queryfile content.tsq -signer tsa.crt.pem -inkey tsa.key.pem \
    -chain inter.crt.pem -out content.tsr
openssl ts -reply -in content.tsr -token_out -out content.tst

rm -rf "$W"
# A Windows OpenSSL writes CRLF; the repository stores text as LF, so the
# pinned checksums are taken over LF bytes on every host.
for f in *.pem content.txt; do sed -i 's/\r$//' "$f"; done
# The private keys of the CAs and responders are not needed by any test.
rm -f root.key.pem inter.key.pem revoked.key.pem ocsp.key.pem tsa.key.pem
ls -la
