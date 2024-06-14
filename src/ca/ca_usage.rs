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

    /// Returns true if the provided certificate is an admin certificate
    pub async fn is_admin(&self, cert: &x509_cert::Certificate) -> bool {
        let admin = self.retrieve_admin_cert().await.unwrap();
        let admin_x509_cert = admin.x509_cert();
        if let Some(admin_x509_cert) = admin_x509_cert {
            cert.tbs_certificate.serial_number == admin_x509_cert.tbs_certificate.serial_number
                && cert.tbs_certificate.subject == admin_x509_cert.tbs_certificate.subject
                && cert.tbs_certificate.issuer == admin_x509_cert.tbs_certificate.issuer
        } else {
            todo!()
        }
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
                CaCertificateStorage::Sqlite(p) => {
                    p.conn(move |conn| {
                        let mut stmt = conn.prepare("SELECT * from csr WHERE done='0'").unwrap();
                        let mut rows = stmt.query([]).unwrap();
                        let mut index = 0;
                        while let Ok(Some(r)) = rows.next() {
                            let id = r.get(0).unwrap();
                            let dbentry = DbEntry::new(r);
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

    /// Performs an iteration of all ssh request that are not done, processing them with the given closure.
    pub async fn ssh_processing<'a, F>(&'a self, mut process: F)
    where
        F: FnMut(usize, SshRequest, u64) + Send + 'a,
    {
        let (s, mut r) = tokio::sync::mpsc::unbounded_channel();

        let self2_medium = self.medium.to_owned();
        tokio::spawn(async move {
            match self2_medium {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::Sqlite(p) => {
                    p.conn(move |conn| {
                        let mut stmt = conn.prepare("SELECT * from sshr WHERE done='0'").unwrap();
                        let mut rows = stmt.query([]).unwrap();
                        let mut index = 0;
                        while let Ok(Some(r)) = rows.next() {
                            let id = r.get(0).unwrap();
                            let dbentry = DbEntry::new(r);
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
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => match &self.config.sign_method {
                cert_common::CertificateSigningMethod::Https(_) => {
                    let cert: Result<CsrRejection, async_sqlite::Error> = p
                        .conn(move |conn| {
                            conn.query_row(
                                &format!("SELECT * FROM csr WHERE id='{}'", id),
                                [],
                                |r| {
                                    let dbentry = DbEntry::new(r);
                                    let csr = dbentry.into();
                                    Ok(csr)
                                },
                            )
                        })
                        .await;
                    let rejection: Option<CsrRejection> = cert.ok();
                    rejection.map(|r| r.rejection)
                }
                cert_common::CertificateSigningMethod::Ssh(_) => {
                    let cert: Result<SshRejection, async_sqlite::Error> = p
                        .conn(move |conn| {
                            conn.query_row(
                                &format!("SELECT * FROM sshr WHERE id='{}'", id),
                                [],
                                |r| {
                                    let dbentry = DbEntry::new(r);
                                    let csr = dbentry.into();
                                    Ok(csr)
                                },
                            )
                        })
                        .await;
                    let rejection: Option<SshRejection> = cert.ok();
                    rejection.map(|r| r.rejection)
                }
            },
        }
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
        match &self.medium {
            CaCertificateStorage::Nowhere => Ok(()),
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
                self.mark_csr_done(id).await;
                match s {
                    Err(_) => Err(CertificateSigningError::FailedToDeleteRequest),
                    Ok(_) => Ok(()),
                }
            }
        }
    }

    /// Retrieve a https certificate signing request by id, if it exists
    pub async fn get_csr_by_id(&self, id: u64) -> Option<CsrRequest> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<CsrRequest, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row(&format!("SELECT * FROM csr WHERE id='{}'", id), [], |r| {
                            let dbentry = DbEntry::new(r);
                            let csr = dbentry.into();
                            Ok(csr)
                        })
                    })
                    .await;
                match cert {
                    Ok(c) => Some(c),
                    Err(e) => {
                        service::log::error!("Error retrieving csr {:?}", e);
                        None
                    }
                }
            }
        }
    }

    /// Retrieve a ssh certificate signing request by id, if it exists
    pub async fn get_ssh_request_by_id(&self, id: u64) -> Option<SshRequest> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<SshRequest, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row(&format!("SELECT * FROM sshr WHERE id='{}'", id), [], |r| {
                            let dbentry = DbEntry::new(r);
                            let csr = dbentry.into();
                            Ok(csr)
                        })
                    })
                    .await;
                match cert {
                    Ok(c) => Some(c),
                    Err(e) => {
                        service::log::error!("Error retrieving sshr {:?}", e);
                        None
                    }
                }
            }
        }
    }

    /// Save an ssh request to the storage medium
    pub async fn save_ssh_request(&mut self, sshr: &SshRequest) -> Result<(), ()> {
        match &self.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::Sqlite(p) => {
                let csr = sshr.to_owned();
                p.conn(move |conn| {
                    let principals = csr.principals.join("/n");
                    let mut stmt = conn.prepare("INSERT INTO sshr (id, requestor, email, phone, pubkey, principals, comment, usage) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)").expect("Failed to build statement");
                    stmt.execute([
                        csr.id.to_sql().unwrap(),
                        csr.name.to_sql().unwrap(),
                        csr.email.to_sql().unwrap(),
                        csr.phone.to_sql().unwrap(),
                        csr.pubkey.to_sql().unwrap(),
                        principals.to_sql().unwrap(),
                        csr.comment.to_sql().unwrap(),
                        csr.usage.to_sql().unwrap(),
                    ]).expect("Failed to insert ssh request");
                    Ok(())
                }).await.expect("Failed to insert ssh request");
                Ok(())
            }
        }
    }

    /// Save the csr to the storage medium
    pub async fn save_csr(&mut self, csr: &CsrRequest) -> Result<(), ()> {
        match &self.medium {
            CaCertificateStorage::Nowhere => Ok(()),
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
