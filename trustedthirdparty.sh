#!/bin/sh

NAME=$1

CNPRE="/CN="
CN="$CNPRE$NAME"

FOLDER="clientkeys/"

KEYSUF="-key.pem"
KEY="$FOLDER$NAME$KEYSUF"

CSRSUF="-csr.pem"
CSR="$FOLDER$NAME$CSRSUF"

CERTSUF="-cert.pem"
CERT="$FOLDER$NAME$CERTSUF"



openssl req -new -key "$KEY" -out "$CSR" -nodes -subj "$CN"

openssl x509 -req -CA ttpkeys/ca-cert.pem -CAkey ttpkeys/ca-key.pem -CAcreateserial \
-in "$CSR" -out "$CERT"
