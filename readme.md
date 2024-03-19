Generating a self-signed certificate for testing:

`openssl req -x509 -newkey rsa:4096 -keyout self-key.pem -out self-cert.pem -days 365 -nodes`
`openssl pkcs12 -export -out keyStore.p12 -inkey self-key.pem -in self-cert.pem`

Generate a certificate to be signed by a certificate authority:
```
openssl req -newkey rsa:2048 -keyout private.key -out server.csr
(get the csr signed and get a certificate back)
(save the received certificate as server.pem)
openssl pkcs12 -export -in server.pem -inkey private.key -name ‘test-server’ -out keyStore.p12
openssl pkcs8 -topk8 -in private.key -out server-pkcs8.key
```

Use openssl to query an ocsp responder, validating the root cert, assuming the root cert of the ca is at ~/Downloads/ca.pem
`openssl ocsp -issuer ~/Downloads/ca.pem -cert ~/Downloads/ca.pem -url https://self.uglyoldbob.com:3001/ca/ocsp -resp_text -VAfile ~/Downloads/ca.pem -CAfile ~/Downloads/ca.pem`