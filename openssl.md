Generating a self-signed certificate for testing:

`openssl req -x509 -newkey rsa:4096 -keyout self-key.pem -out self-cert.pem -days 365 -nodes`
`openssl pkcs12 -export -out keyStore.p12 -inkey self-key.pem -in self-cert.pem`

Examine an rsa public key
`openssl rsa -pubin -in ./pubkeytest.pub -text`

Examine a certificate signing request pem format
`openssl req -text -in request.csr`

Examine a certificate signing request der format
`openssl req -text -inform der -in request.csr`


Generate an ecdsa private key
`openssl ecparam -name prime256v1 -genkey -noout -out private.ec.key`

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

Use openssl to show contents of a pkcs12 certificate, the password is required.
`openssl pkcs12 -in ~/Downloads/user-certificate.p12 -info -nodes`

Use openssl to show contents of a public certificate.
`openssl x509 -noout -text -in ./cafiles/certs/2.der`