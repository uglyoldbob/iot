function generate_cert() {
  console.log("Starting generate cert");

 // generate a key pair
  console.log('Generating 4096-bit key-pair...');
  var keys = forge.pki.rsa.generateKeyPair(4096);
  console.log('Key-pair created.');

  console.log('Creating certification request (CSR) ...');
  var csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{
    name: 'commonName',
    value: 'example.org'
  }, {
    name: 'countryName',
    value: 'US'
  }, {
    shortName: 'ST',
    value: 'Virginia'
  }, {
    name: 'localityName',
    value: 'Blacksburg'
  }, {
    name: 'organizationName',
    value: 'Test'
  }, {
    shortName: 'OU',
    value: 'Test'
  }]);
  // add optional attributes
  csr.setAttributes([{
    name: 'challengePassword',
    value: 'password'
  }, {
    name: 'unstructuredName',
    value: 'My company'
  }]);

  // sign certification request
  csr.sign(keys.privateKey/*, forge.md.sha256.create()*/);
  console.log('Certification request (CSR) created.');

  // PEM-format keys and csr
  var pem = {
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    publicKey: forge.pki.publicKeyToPem(keys.publicKey),
    csr: forge.pki.certificationRequestToPem(csr)
  };

  console.log('\nKey-Pair:');
  console.log(pem.privateKey);
  console.log(pem.publicKey);

  console.log('\nCertification Request (CSR):');
  console.log(pem.csr);

  // verify certification request
  try {
    if(csr.verify()) {
      console.log('Certification request (CSR) verified.');
    } else {
      throw new Error('Signature not verified.');
    }
  } catch(err) {
    console.log('Certification request (CSR) verification failure: ' +
      JSON.stringify(err, null, 2));
  }

  console.log("Generating download for user");

  const file = new File([pem.privateKey], 'test.bin', {
    type: 'application/octet-stream',
  })

  const link = document.createElement('a')
  const url = URL.createObjectURL(file)

  link.href = url
  link.download = file.name
  document.body.appendChild(link)
  link.click()

  document.body.removeChild(link)
  window.URL.revokeObjectURL(url)

  console.log("Done with generate cert");
}