#!/bin/bash
set -e

CERT_DIR="config/certificates"
mkdir -p "$CERT_DIR"

echo "🔐 Generating Campus Security System PKI..."

# Root CA
echo "📜 Creating Root CA..."
openssl req -new -x509 -days 3650 -extensions v3_ca \
  -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
  -subj "/C=EG/ST=Cairo/L=Cairo/O=Campus Security/OU=Security Dept/CN=Campus Root CA" \
  -nodes

make_cert () {
  local name=$1
  local cn=$2

  echo "🔧 Creating certificate for: $name (CN=$cn)"

  openssl genrsa -out "$CERT_DIR/$name.key" 2048
  openssl req -new -key "$CERT_DIR/$name.key" -out "$CERT_DIR/$name.csr" \
    -subj "/C=EG/ST=Cairo/L=Cairo/O=Campus Security/CN=$cn"

  cat > "$CERT_DIR/$name.ext" << EOT
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = $cn
IP.1 = 127.0.0.1
EOT

  openssl x509 -req -in "$CERT_DIR/$name.csr" -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/$name.crt" -days 3650 -extfile "$CERT_DIR/$name.ext"

  rm -f "$CERT_DIR/$name.ext"
}

make_cert "mqtt-broker" "localhost"
make_cert "gateway-agent" "gateway-agent"
make_cert "local-manager" "local-manager"

chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

echo "✅ Certificates generated successfully!"
ls -lh "$CERT_DIR"
