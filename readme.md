Generating a self-signed certificate for testing:

`openssl req -x509 -newkey rsa:4096 -keyout self-key.pem -out self-cert.pem -days 365 -nodes`
`openssl pkcs12 -export -out keyStore.p12 -inkey self-key.pem -in self-cert.pem`
