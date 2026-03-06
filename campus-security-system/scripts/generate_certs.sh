#!/bin/bash
# Generates self-signed TLS certs for local development
# Run once from the repo root: bash scripts/generate_certs.sh
set -e
DIR="config/certificates"
mkdir -p "$DIR"

echo "🔐 Generating CA..."
openssl genrsa -out "$DIR/ca.key" 2048
openssl req -new -x509 -days 3650 -key "$DIR/ca.key" -out "$DIR/ca.crt" \
  -subj "/CN=MASS-CA/O=CampusSecurity"

for NAME in mqtt-broker gateway-agent behavioral-agent iot-local-manager pac-eda-agent; do
  echo "🔑 Generating cert: $NAME"
  openssl genrsa -out "$DIR/$NAME.key" 2048
  openssl req -new -key "$DIR/$NAME.key" -out "$DIR/$NAME.csr" \
    -subj "/CN=$NAME/O=CampusSecurity"
  openssl x509 -req -days 3650 -in "$DIR/$NAME.csr" \
    -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
    -out "$DIR/$NAME.crt"
  rm "$DIR/$NAME.csr"
done
echo "✅ Certs in $DIR — add *.key to .gitignore"
