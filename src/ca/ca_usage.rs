#[path = "ca_common.rs"]
mod ca_common;

pub use ca_common::*;

impl Ca {
    /// Return a reference to the root cert
    pub fn root_ca_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.root_cert.as_ref()
    }

    /// Return a reference to the ocsp cert
    pub fn ocsp_ca_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.ocsp_signer.as_ref()
    }

    pub fn is_admin(&self, cert: &x509_cert::Certificate) -> bool {
        let admin = self.get_admin_cert().unwrap();
        let admin_x509_cert = {
            use der::Decode;
            x509_cert::Certificate::from_der(&admin.cert).unwrap()
        };
        cert.tbs_certificate.serial_number == admin_x509_cert.tbs_certificate.serial_number
            && cert.tbs_certificate.subject == admin_x509_cert.tbs_certificate.subject
            && cert.tbs_certificate.issuer == admin_x509_cert.tbs_certificate.issuer
    }

    fn get_admin_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.admin.as_ref()
    }

    /// Verify a certificate signing request
    pub async fn verify_request<'a>(
        &mut self,
        csr: &'a x509_cert::request::CertReq,
    ) -> Result<&'a x509_cert::request::CertReq, ()> {
        use der::Encode;
        let info = csr.info.to_der().unwrap();
        let pubkey = &csr.info.public_key;
        let signature = &csr.signature;

        let p = &pubkey.subject_public_key;
        let pder = p.to_der().unwrap();

        let pkey = yasna::parse_der(&pder, |r| {
            let (data, _size) = r.read_bitvec_bytes()?;
            Ok(data)
        })
        .unwrap();

        if let Ok(algo) = csr.algorithm.to_owned().try_into() {
            println!("Checking csr with algo {:?}", algo);
            let csr_cert = InternalPublicKey::create_with(algo, &pkey);
            println!("Cert is {:?}", csr_cert);
            csr_cert
                .verify(&info, signature.as_bytes().unwrap())
                .map_err(|_| ())?;
            //TODO perform more validation of the csr
            return Ok(csr);
        }
        Err(())
    }

    /// Get an iterator for the csr of a ca
    pub fn get_csr_iter(&self) -> CaCsrIter {
        match &self.medium {
            CaCertificateStorage::Nowhere => CaCsrIter::Nowhere,
            CaCertificateStorage::FilesystemDer(p) => {
                let pb = p.join("csr");
                std::fs::create_dir_all(&pb).unwrap();
                let pf = std::fs::read_dir(&pb).unwrap();
                CaCsrIter::FilesystemDer(pf)
            }
        }
    }

    /// Retrieve the specified index of user certificate
    pub async fn get_user_cert(&self, id: usize) -> Option<Vec<u8>> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::FilesystemDer(p) => {
                use tokio::io::AsyncReadExt;
                let pb = p.join("certs");
                let path = pb.join(format!("{}.der", id));
                let mut f = tokio::fs::File::open(path).await.ok()?;
                let mut contents = Vec::with_capacity(f.metadata().await.unwrap().len() as usize);
                f.read_to_end(&mut contents).await.unwrap();
                Some(contents)
            }
        }
    }

    /// Save the user cert of the specified index to storage
    pub async fn save_user_cert(&mut self, id: usize, cert_der: &[u8]) {
        match &self.medium {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::FilesystemDer(p) => {
                use tokio::io::AsyncWriteExt;
                let oldname = p.join("csr").join(format!("{}.toml", id));
                let newpath = p.join("csr-done");
                tokio::fs::create_dir_all(&newpath).await.unwrap();
                let newname = newpath.join(format!("{}.toml", id));
                tokio::fs::rename(oldname, newname).await.unwrap();
                let pb = p.join("certs");
                tokio::fs::create_dir_all(&pb).await.unwrap();
                let path = pb.join(format!("{}.der", id));
                let mut f = tokio::fs::File::create(path).await.ok().unwrap();
                f.write_all(cert_der).await.unwrap();
            }
        }
    }

    /// Retrieve the reason the csr was rejected
    pub async fn get_rejection_reason_by_id(&self, id: usize) -> Option<String> {
        let rejection: Option<CsrRejection> = match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::FilesystemDer(p) => {
                use tokio::io::AsyncReadExt;
                let pb = p.join("csr-reject");
                let path = pb.join(format!("{}.toml", id));
                let mut f = tokio::fs::File::open(path).await.ok()?;
                let mut cert = Vec::with_capacity(f.metadata().await.unwrap().len() as usize);
                f.read_to_end(&mut cert).await.ok().unwrap();
                toml::from_str(std::str::from_utf8(&cert).unwrap()).ok()
            }
        };
        rejection.map(|r| r.rejection)
    }

    /// Reject an existing certificate signing request by id.
    pub async fn reject_csr_by_id(
        &mut self,
        id: usize,
        reason: &String,
    ) -> Result<(), CertificateSigningError> {
        let csr = self.get_csr_by_id(id);
        if csr.is_none() {
            return Err(CertificateSigningError::CsrDoesNotExist);
        }
        let csr = csr.unwrap();
        let reject = CsrRejection::from_csr_with_reason(csr, reason);
        self.store_rejection(&reject).await?;
        self.delete_request_by_id(id).await?;
        Ok(())
    }

    /// Store a rejection struct
    async fn store_rejection(
        &mut self,
        reject: &CsrRejection,
    ) -> Result<(), CertificateSigningError> {
        use tokio::io::AsyncWriteExt;
        match &self.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::FilesystemDer(p) => {
                let pb = p.join("csr-reject");
                tokio::fs::create_dir_all(&pb).await.unwrap();
                let newid = self.get_new_request_id().await;
                if let Some(newid) = newid {
                    let cp = pb.join(format!("{}.toml", newid));
                    let mut cf = tokio::fs::File::create(cp).await.unwrap();
                    let csr_doc = toml::to_string(reject).unwrap();
                    cf.write_all(csr_doc.as_bytes()).await.unwrap();
                }
                Ok(())
            }
        }
    }

    async fn delete_request_by_id(&mut self, id: usize) -> Result<(), CertificateSigningError> {
        match &self.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::FilesystemDer(p) => {
                let pb = p.join("csr");
                let cp = pb.join(format!("{}.toml", id));
                tokio::fs::remove_file(cp)
                    .await
                    .map_err(|_| CertificateSigningError::FailedToDeleteRequest)?;
                Ok(())
            }
        }
    }

    /// Retrieve a certificate signing request by id, if it exists
    pub fn get_csr_by_id(&self, id: usize) -> Option<CsrRequest> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::FilesystemDer(p) => {
                use std::io::Read;
                let pb = p.join("csr");
                let path = pb.join(format!("{}.toml", id));
                let mut f = std::fs::File::open(path).ok()?;
                let mut cert = Vec::with_capacity(f.metadata().unwrap().len() as usize);
                f.read_to_end(&mut cert).ok().unwrap();
                toml::from_str(std::str::from_utf8(&cert).unwrap()).ok()
            }
        }
    }

    pub async fn save_csr(&mut self, csr: &CsrRequest) -> Option<usize> {
        use tokio::io::AsyncWriteExt;
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::FilesystemDer(p) => {
                let pb = p.join("csr");
                tokio::fs::create_dir_all(&pb).await.unwrap();
                let newid = self.get_new_request_id().await;
                if let Some(newid) = newid {
                    let cp = pb.join(format!("{}.toml", newid));
                    let mut cf = tokio::fs::File::create(cp).await.unwrap();
                    let csr_doc = toml::to_string(csr).unwrap();
                    cf.write_all(csr_doc.as_bytes()).await.unwrap();
                }
                newid
            }
        }
    }
}

/// An iterator over the csr of a certificate authority
pub enum CaCsrIter {
    Nowhere,
    FilesystemDer(std::fs::ReadDir),
}

impl Iterator for CaCsrIter {
    type Item = (CsrRequest, usize);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            CaCsrIter::Nowhere => None,
            CaCsrIter::FilesystemDer(rd) => {
                let n = rd.next();
                let a = n.map(|rde| {
                    rde.map(|de| {
                        use std::io::Read;
                        let path = de.path();
                        let fname = path.file_stem().unwrap();
                        let fnint: usize = fname.to_str().unwrap().parse().unwrap();
                        let mut f = std::fs::File::open(path).ok().unwrap();
                        let mut cert = Vec::with_capacity(f.metadata().unwrap().len() as usize);
                        f.read_to_end(&mut cert).unwrap();
                        (
                            toml::from_str(std::str::from_utf8(&cert).unwrap()).unwrap(),
                            fnint,
                        )
                    })
                    .unwrap()
                });
                a
            }
        }
    }
}

#[derive(Debug)]
pub struct InternalPublicKey<'a> {
    key: ring::signature::UnparsedPublicKey<&'a [u8]>,
}

impl<'a> InternalPublicKey<'a> {
    /// Create the public key with the specified algorithm.
    /// # Arguments
    /// * algorithm - The signing algorithm for the public key
    /// * key - The der bytes of the public key. For RSA this is a sequence of two integers.
    pub fn create_with(algorithm: CertificateSigningMethod, key: &'a [u8]) -> Self {
        match algorithm {
            CertificateSigningMethod::RsaSha1 => Self {
                key: ring::signature::UnparsedPublicKey::new(
                    &ring::signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                    key,
                ),
            },
            CertificateSigningMethod::Ecdsa => {
                todo!();
            }
            CertificateSigningMethod::RsaSha256 => Self {
                key: ring::signature::UnparsedPublicKey::new(
                    &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                    key,
                ),
            },
        }
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ()> {
        self.key.verify(data, signature).map_err(|_| ())
    }
}
