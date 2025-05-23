#!/bin/bash

set -ex

export PATH=/opt/openssl/bin:${PATH}
which openssl
export LD_LIBRARY_PATH=/opt/openssl/lib

# Generating an ML-DSA-65 private key for certificate signing
openssl genpkey -algorithm ML-DSA-65 -out server.key

# Creating an OpenSSL configuration file for the certificate
cat << EOF > openssl.cnf
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
C = US
ST = IL
O = Yahoo
OU = Edge
CN = random.server.com

[v3_req]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = random.server.com
IP.1 = 127.0.0.1
EOF

# Generating a self-signed certificate with ML-DSA-65, valid from May 23, 2025 to ~May 23, 2035
openssl req -x509 -new -nodes -key server.key -days 3652 -out server.pem -config openssl.cnf -set_serial 0x$(openssl rand -hex 8)

# Creating the signer PEM file (copy of server.pem for self-signed certificate)
cp server.pem signer.pem

# Cleaning up the configuration file
rm openssl.cnf

# Verifying the certificate
echo "Verifying the generated certificate:"
openssl x509 -in server.pem -text -noout
echo -e "\nVerifying the signer PEM:"
openssl x509 -in signer.pem -text -noout
