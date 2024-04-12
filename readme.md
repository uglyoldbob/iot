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

Use openssl to show contents of a pkcs12 certificate, the password is required.
`openssl pkcs12 -in ~/Downloads/user-certificate.p12 -info -nodes`

Use openssl to show contents of a public certificate.
`openssl x509 -noout -text -in ./cafiles/certs/2.der`

List of future changes
- [x] Add more configuration to the client certificate verifier, allowing ca to be something besides self.
- [x] Receive user certs with the SSL_CLIENT_CERT html header for proxy setups.
- [x] Fix ocsp responder.
- [ ] Implement code where todo statements exist.
- [ ] Implement keygen on client side with rust wasm instead of javscript.
- [ ] Allow ca to be intermediate or root.
- [x] Implement pki object containing a vector of ca.
- [x] Allows the https client cert verifier to require a cert, useful for proxied setups.
- [ ] Add links to a privacy page on each content page.
- [ ] Make site look better
- [ ] Make site mobile friendly
- [ ] Verify tpm code works as intended.
- [ ] Fix tpm code on windows.
- [ ] Create indexing program for large proxied setups
- [ ] Add ability to create example reverse proxy setups for common reverse proxies.
- [ ] Feature gate the sqlite backend
- [x] Remove the filesystem backend
- [ ] Add more database backends, feature gated
- [x] Redo how the ca pages are mapped to urls, to allow for proxying in a better fashion once pki is expanded.
- [ ] Add certificate viewer for users.
- [x] Enable using systemd to start the service.