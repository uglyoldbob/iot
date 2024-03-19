function show_advanced() {
  show(document.getElementsByClassName("advanced"));
  hide(document.getElementsByClassName("regular"));
}

function show_regular() {
  hide(document.getElementsByClassName("advanced"));
  show(document.getElementsByClassName("regular"));
}

function show_loading() {
  show(document.getElementsByClassName("cert_generating"));
  hide(document.getElementsByClassName("cert-gen-stuff"));
}

function hide_loading() {
  hide(document.getElementsByClassName("cert_generating"));
  show(document.getElementsByClassName("cert-gen-stuff"));
}

function hide(elements) {
  elements = elements.length ? elements : [elements];
  for (var index = 0; index < elements.length; index++) {
    elements[index].style.display = 'none';
  }
}

function show (elements, specifiedDisplay) {
  elements = elements.length ? elements : [elements];
  for (var index = 0; index < elements.length; index++) {
    elements[index].style.display = specifiedDisplay || 'block';
  }
}

function do_download(file)
{
  const link = document.createElement('a')
  const url = URL.createObjectURL(file)

  link.href = url
  link.download = file.name
  document.body.appendChild(link)
  link.click()

  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}

function do_csr_submit() {
  let submit = document.getElementById('submit');
  submit.click();
}

function reader_to_blob(stream) {
  return new Promise((resolve, reject) => {
    const chunks = []
    stream
      .on('data', chunk => chunks.push(chunk))
      .once('end', () => {
        const blob = new Blob(chunks);
        resolve(blob)
      })
      .once('error', reject)
  })
}

function cert_work() {
  var subject_stuff = [];
  var subject_good = 0;
  const cname = document.getElementById('cname').value;
  if (cname.length != 0) {
    subject_good = 1;
    subject_stuff.push({name: 'commonName', value: cname});
  }

  const country = document.getElementById('country').value;
  if (country.length != 0) {
    subject_stuff.push({name: 'countryName', value: country});
  }

  const state = document.getElementById('state').value;
  if (state.length != 0) {
    subject_stuff.push({shortName: 'ST', value: state});
  }

  const locality = document.getElementById('locality').value;
  if (locality.length != 0) {
    subject_stuff.push({name: 'localityName', value: locality});
  }

  const organization = document.getElementById('organization').value;
  if (organization.length != 0) {
    subject_stuff.push({name: 'organizationName', value: organization});
  }

  const ou = document.getElementById('organization-unit').value;
  if (ou.length != 0) {
    subject_stuff.push({name: 'OU', value: ou});
  }

  if (subject_good == 0) {
    alert("The certificate subject information is invalid");
    hide_loading();
    return;
  }

  console.log('Creating certification request (CSR) ...');
  var csr = forge.pki.createCertificationRequest();
  csr.setSubject(subject_stuff);
  // add optional attributes
  csr.setAttributes([{
    name: 'challengePassword',
    value: document.getElementById('challenge-pass').value
  }, {
    name: 'unstructuredName',
    value: document.getElementById('challenge-name').value
  }]);

  console.log('Generating 4096-bit key-pair...');
  var keys = forge.pki.rsa.generateKeyPair(4096);
  console.log('Key-pair created.');

  csr.publicKey = keys.publicKey;

  // sign certification request
  csr.sign(keys.privateKey, forge.md.sha256.create());
  console.log('Certification request (CSR) created.');

  var rsaPrivateKey = forge.pki.privateKeyToAsn1(keys.privateKey);
  var privateKeyInfo = forge.pki.wrapRsaPrivateKey(rsaPrivateKey);
  var encryptedPrivateKeyInfo = forge.pki.encryptPrivateKeyInfo(
    privateKeyInfo, document.getElementById('password').value);

  // PEM-format keys and csr
  var pem = {
    privateKey: forge.pki.encryptedPrivateKeyToPem(encryptedPrivateKeyInfo),
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

  do_download(file);

  document.request.csr.value = pem.csr;
  hide_loading();
  setTimeout(do_csr_submit, 1);
}

function generate_cert() {

  var email = document.getElementById('email');
  if (! email.checkValidity())
  {
    email.reportValidity();
    return;
  }

  console.log("Starting generate cert");

  show_loading();

  setTimeout(cert_work, 1);

  console.log("Done with generate cert");
}

function b64toBlob(b64Data, contentType='', sliceSize=512) {
  const byteCharacters = atob(b64Data);
  const byteArrays = [];

  for (let offset = 0; offset < byteCharacters.length; offset += sliceSize) {
    const slice = byteCharacters.slice(offset, offset + sliceSize);

    const byteNumbers = new Array(slice.length);
    for (let i = 0; i < slice.length; i++) {
      byteNumbers[i] = slice.charCodeAt(i);
    }

    const byteArray = new Uint8Array(byteNumbers);
    byteArrays.push(byteArray);
  }
    
  const blob = new Blob(byteArrays, {type: contentType});
  return blob;
}

function b64toFile(b64Data, name, sliceSize=512) {
  const byteCharacters = atob(b64Data);
  const byteArrays = [];

  for (let offset = 0; offset < byteCharacters.length; offset += sliceSize) {
    const slice = byteCharacters.slice(offset, offset + sliceSize);

    const byteNumbers = new Array(slice.length);
    for (let i = 0; i < slice.length; i++) {
      byteNumbers[i] = slice.charCodeAt(i);
    }

    const byteArray = new Uint8Array(byteNumbers);
    byteArrays.push(byteArray);
  }
    
  const file = new File(byteArrays, name, {
    type: 'application/octet-stream',
  });
  
  return file;
}

function build_cert() {
  const fileSelector = document.getElementById('file-selector');
  fileSelector.click();
  fileSelector.addEventListener('change', (event) => {
    const fileList = event.target.files;
    const file = fileList[0];

    const reader = new FileReader();
    reader.addEventListener('load', (event) => {
      const contents = event.target.result;

      if (contents.startsWith("data:application/octet-stream;base64,")) {
        const file = contents.substring(37);
        const pkey = atob(file);

        var pkey3 = forge.pki.decryptRsaPrivateKey(pkey, document.getElementById('password').value);

        var fetchid = document.getElementById('get_request');
        const fetch_url = fetchid.innerText;

        let cfetch = fetch(fetch_url, { method: 'get', mode: 'no-cors', referrerPolicy: 'no-referrer' });
        cfetch.then((response) => {
          return response.text();
        }).then((cpem) => {
          var cert = forge.pki.certificateFromPem(cpem);

          var p12Asn1 = forge.pkcs12.toPkcs12Asn1(
            pkey3, cert, document.getElementById('cert-password').value);

          var p12Der = forge.asn1.toDer(p12Asn1).getBytes();
          var p12b64 = forge.util.encode64(p12Der);

          const blob = b64toFile(p12b64, 'user-certificate.p12');

       
          do_download(blob);
        });
      }
    });
    reader.readAsDataURL(file);
  });
}