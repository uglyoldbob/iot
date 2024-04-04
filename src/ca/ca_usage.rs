#[path = "ca_common.rs"]
mod ca_common;

use async_sqlite::rusqlite::ToSql;
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

    pub async fn is_admin(&self, cert: &x509_cert::Certificate) -> bool {
        let admin = self.retrieve_admin_cert().await.unwrap();
        let admin_x509_cert = {
            use der::Decode;
            x509_cert::Certificate::from_der(&admin.cert).unwrap()
        };
        cert.tbs_certificate.serial_number == admin_x509_cert.tbs_certificate.serial_number
            && cert.tbs_certificate.subject == admin_x509_cert.tbs_certificate.subject
            && cert.tbs_certificate.issuer == admin_x509_cert.tbs_certificate.issuer
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

        //TODO perform more validation of the csr
        return Ok(csr);
    }

    /// Performs an iteration of all certificates, processing them with the given closure.
    pub async fn certificate_processing<'a, F>(&'a self, mut process: F)
    where
        F: FnMut(usize, x509_cert::Certificate, u64) + Send + 'a,
    {
        let (s, mut r) = tokio::sync::mpsc::unbounded_channel();

        let self2_medium = self.medium.to_owned();
        tokio::spawn(async move {
            use der::Decode;
            match self2_medium {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::FilesystemDer(p) => {
                    let pb = p.join("certs");
                    std::fs::create_dir_all(&pb).unwrap();
                    let mut pf = tokio::fs::read_dir(&pb).await.unwrap();
                    let mut index = 0;

                    while let Ok(Some(a)) = pf.next_entry().await {
                        use std::io::Read;
                        let path = a.path();
                        let fname = path.file_stem().unwrap();
                        let fnint: u64 = fname.to_str().unwrap().parse().unwrap();
                        let mut f = std::fs::File::open(path).ok().unwrap();
                        let mut cert = Vec::with_capacity(f.metadata().unwrap().len() as usize);
                        f.read_to_end(&mut cert).unwrap();
                        let cert: x509_cert::Certificate =
                            x509_cert::Certificate::from_der(&cert).unwrap();
                        s.send((index, cert, fnint)).unwrap();
                        index += 1;
                    }
                }
                CaCertificateStorage::Sqlite(p) => {
                    p.conn(move |conn| {
                        let mut stmt = conn.prepare("SELECT * from certs").unwrap();
                        let mut rows = stmt.query([]).unwrap();
                        let mut index = 0;
                        while let Ok(Some(r)) = rows.next() {
                            let id = r.get(0).unwrap();
                            let der: Vec<u8> = r.get(1).unwrap();
                            let cert: x509_cert::Certificate =
                                x509_cert::Certificate::from_der(&der).unwrap();
                            s.send((index, cert, id)).unwrap();
                            index += 1;
                        }
                        Ok(())
                    })
                    .await
                    .unwrap();
                }
            }
        });
        while let Some((index, csr, id)) = r.recv().await {
            process(index, csr, id);
        }
    }

    /// Performs an iteration of all csr that are not done, processing them with the given closure.
    pub async fn csr_processing<'a, F>(&'a self, mut process: F)
    where
        F: FnMut(usize, CsrRequest, u64) + Send + 'a,
    {
        let (s, mut r) = tokio::sync::mpsc::unbounded_channel();

        let self2_medium = self.medium.to_owned();
        tokio::spawn(async move {
            match self2_medium {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::FilesystemDer(p) => {
                    let pb = p.join("csr");
                    std::fs::create_dir_all(&pb).unwrap();
                    let mut pf = tokio::fs::read_dir(&pb).await.unwrap();
                    let mut index = 0;

                    while let Ok(Some(a)) = pf.next_entry().await {
                        use std::io::Read;
                        let path = a.path();
                        let fname = path.file_stem().unwrap();
                        let fnint: u64 = fname.to_str().unwrap().parse().unwrap();
                        let mut f = std::fs::File::open(path).ok().unwrap();
                        let mut cert = Vec::with_capacity(f.metadata().unwrap().len() as usize);
                        f.read_to_end(&mut cert).unwrap();
                        let csr: CsrRequest =
                            toml::from_str(std::str::from_utf8(&cert).unwrap()).unwrap();
                        s.send((index, csr, fnint)).unwrap();
                        index += 1;
                    }
                }
                CaCertificateStorage::Sqlite(p) => {
                    p.conn(move |conn| {
                        let mut stmt = conn.prepare("SELECT * from csr WHERE done='0'").unwrap();
                        let mut rows = stmt.query([]).unwrap();
                        let mut index = 0;
                        while let Ok(Some(r)) = rows.next() {
                            let id = r.get(0).unwrap();
                            let dbentry = CsrRequestDbEntry::new(r);
                            let csr = dbentry.into();
                            s.send((index, csr, id)).unwrap();
                            index += 1;
                        }
                        Ok(())
                    })
                    .await
                    .unwrap();
                }
            }
        });
        while let Some((index, csr, id)) = r.recv().await {
            process(index, csr, id);
        }
    }

    /// Retrieve the specified index of user certificate
    pub async fn get_user_cert(&self, id: u64) -> Option<Vec<u8>> {
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
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<Vec<u8>, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row(
                            &format!("SELECT der FROM certs WHERE id='{}'", id),
                            [],
                            |r| r.get(0),
                        )
                    })
                    .await;
                match cert {
                    Ok(c) => Some(c),
                    Err(_e) => None,
                }
            }
        }
    }

    /// Retrieve the reason the csr was rejected
    pub async fn get_rejection_reason_by_id(&self, id: u64) -> Option<String> {
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
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<CsrRejection, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row(&format!("SELECT * FROM csr WHERE id='{}'", id), [], |r| {
                            let dbentry = CsrRejectionDbEntry::new(r);
                            let csr = dbentry.into();
                            Ok(csr)
                        })
                    })
                    .await;
                cert.ok()
            }
        };
        rejection.map(|r| r.rejection)
    }

    /// Reject an existing certificate signing request by id.
    pub async fn reject_csr_by_id(
        &mut self,
        id: u64,
        reason: &String,
    ) -> Result<(), CertificateSigningError> {
        let csr = self.get_csr_by_id(id).await;
        if csr.is_none() {
            return Err(CertificateSigningError::CsrDoesNotExist);
        }
        let csr = csr.unwrap();
        let reject = CsrRejection::from_csr_with_reason(csr, reason);
        self.store_rejection(&reject).await?;
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
                let pb = p.join("csr");
                let cp = pb.join(format!("{}.toml", reject.id));
                tokio::fs::remove_file(cp)
                    .await
                    .map_err(|_| CertificateSigningError::FailedToDeleteRequest)?;
                let pb = p.join("csr-reject");
                tokio::fs::create_dir_all(&pb).await.unwrap();
                let cp = pb.join(format!("{}.toml", reject.id));
                let mut cf = tokio::fs::File::create(cp).await.unwrap();
                let csr_doc = toml::to_string(reject).unwrap();
                cf.write_all(csr_doc.as_bytes()).await.unwrap();
                Ok(())
            }
            CaCertificateStorage::Sqlite(p) => {
                let rejection = reject.rejection.to_owned();
                let id = reject.id;
                let s = p
                    .conn(move |conn| {
                        let mut stmt = conn
                            .prepare(&format!(
                                "UPDATE csr SET 'rejection' = $1 WHERE id='{}'",
                                id
                            ))
                            .unwrap();
                        stmt.execute([rejection.to_sql().unwrap()])
                    })
                    .await;
                match s {
                    Err(_) => Err(CertificateSigningError::FailedToDeleteRequest),
                    Ok(_) => Ok(()),
                }
            }
        }
    }

    /// Retrieve a certificate signing request by id, if it exists
    pub async fn get_csr_by_id(&self, id: u64) -> Option<CsrRequest> {
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
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<CsrRequest, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row(&format!("SELECT * FROM csr WHERE id='{}'", id), [], |r| {
                            let dbentry = CsrRequestDbEntry::new(r);
                            let csr = dbentry.into();
                            Ok(csr)
                        })
                    })
                    .await;
                match cert {
                    Ok(c) => Some(c.into()),
                    Err(e) => {
                        println!("Error retrieving csr {:?}", e);
                        None
                    }
                }
            }
        }
    }

    pub async fn save_csr(&mut self, csr: &CsrRequest) -> Result<(), ()> {
        use tokio::io::AsyncWriteExt;
        match &self.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::FilesystemDer(p) => {
                let pb = p.join("csr");
                tokio::fs::create_dir_all(&pb).await.unwrap();
                let cp = pb.join(format!("{}.toml", csr.id));
                let mut cf = tokio::fs::File::create(cp).await.unwrap();
                let csr_doc = toml::to_string(csr).unwrap();
                cf.write_all(csr_doc.as_bytes()).await.unwrap();
                Ok(())
            }
            CaCertificateStorage::Sqlite(p) => {
                let csr = csr.to_owned();
                p.conn(move |conn| {
                    let mut stmt = conn.prepare("INSERT INTO csr (id, requestor, email, phone, pem) VALUES (?1, ?2, ?3, ?4, ?5)").expect("Failed to build statement");
                    stmt.execute([
                        csr.id.to_sql().unwrap(),
                        csr.name.to_sql().unwrap(),
                        csr.email.to_sql().unwrap(),
                        csr.phone.to_sql().unwrap(),
                        csr.cert.to_sql().unwrap(),
                    ]).expect("Failed to insert csr");
                    Ok(())
                }).await.expect("Failed to insert csr");
                Ok(())
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
        self.key.verify(data, signature).map_err(|e| {
            println!("Error verifying signature 2 {:?}", e);
            ()
        })
    }
}
