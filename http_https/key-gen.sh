#!/bin/bash

# Server

# generate private key and public key
openssl ecparam -genkey -name prime256v1 -noout -out server-private-key.pem
openssl ec -in server-private-key.pem -pubout -out server-public-key.pem

# create the certificate
openssl req -new -x509 -sha256 -key server-private-key.pem -subj "/CN=localhost" -out server-certificate.pem

# generate .key file
openssl pkey -in server-private-key.pem -out server-private-key.key

# Client

# generate private key and public key
openssl ecparam -genkey -name prime256v1 -noout -out client-private-key.pem
openssl ec -in client-private-key.pem -pubout -out client-public-key.pem

# create the certificate
openssl req -new -x509 -sha256 -key client-private-key.pem -subj "/CN=localhost" -out client-certificate.pem

# generate .key file
openssl pkey -in client-private-key.pem -out client-private-key.key


# rsa key
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes
openssl pkey -in key.pem -out server.key

openssl req -x509 -newkey rsa:4096 -keyout client-key.pem -out client-cert.pem -days 365 -nodes
openssl pkey -in key.pem -out client.key