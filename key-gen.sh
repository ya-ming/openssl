#!/bin/bash

# generate private key and public key
openssl ecparam -genkey -name prime256v1 -noout -out server-private-key.pem
openssl ec -in server-private-key.pem -pubout -out server-public-key.pem

# create the certificate
openssl req -new -x509 -sha256 -key server-private-key.pem -subj "/CN=localhost" -out server-certificate.pem