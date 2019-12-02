#!/bin/sh

VAR1="/CN="
VAR2=$1
VAR3="$VAR1$VAR2"

openssl req -new -key clientkeys/key.pem -out clientkeys/cert-csr.pem -nodes -subj "$VAR3"

openssl x509 -req -CA ttpkeys/ca-cert.pem -CAkey ttpkeys/ca-key.pem -CAcreateserial \
-in clientkeys/cert-csr.pem -out clientkeys/cert.pem
