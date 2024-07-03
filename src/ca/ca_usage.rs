#[path = "ca_common.rs"]
mod ca_common;

use std::sync::Arc;

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
        let mut any_admin = false;
        if let Some(admin) = &self.super_admin {
            any_admin = true;
            let admin_x509_cert = admin.x509_cert();
            if let Ok(admin_x509_cert) = admin_x509_cert {
                if cert.tbs_certificate.serial_number
                    == admin_x509_cert.tbs_certificate.serial_number
                    && cert.tbs_certificate.subject == admin_x509_cert.tbs_certificate.subject
                    && cert.tbs_certificate.issuer == admin_x509_cert.tbs_certificate.issuer
                {
                    return true;
                }
            }
        }
        if let Ok(admin) = &self.admin {
            any_admin = true;
            let admin_x509_cert = admin.x509_cert();
            if let Ok(admin_x509_cert) = admin_x509_cert {
                if cert.tbs_certificate.serial_number
                    == admin_x509_cert.tbs_certificate.serial_number
                    && cert.tbs_certificate.subject == admin_x509_cert.tbs_certificate.subject
                    && cert.tbs_certificate.issuer == admin_x509_cert.tbs_certificate.issuer
                {
                    return true;
                }
            }
        }
        if !any_admin {
            service::log::error!("No admin certificate for admin operations available");
        }
        false
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

use cert_common::oid::*;
use cert_common::CertificateSigningMethod;
use cert_common::HttpsSigningMethod;
use zeroize::Zeroizing;

impl CaCertificateStorage {
    /// Initialize the storage medium
    pub async fn init(&mut self, settings: &crate::ca::CaConfiguration) -> Result<(), ()> {
        let sign_method = settings.sign_method;
        let admin_cert = settings.admin_cert.clone();
        match self {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::Sqlite(p) => {
                p.conn(move |conn| {
                    conn.execute("CREATE TABLE id ( id INTEGER PRIMARY KEY )", [])?;
                    conn.execute("CREATE TABLE serials ( id INTEGER PRIMARY KEY, serial BLOB)", [])?;
                    conn.execute("CREATE TABLE hsm_labels ( id INTEGER PRIMARY KEY, label TEXT)", [])?;
                    if let CertificateType::Soft(_) = admin_cert {
                        conn.execute("CREATE TABLE p12 ( id INTEGER PRIMARY KEY, p12 BLOB)", [])?;
                    }
                    match sign_method {
                        CertificateSigningMethod::Https(_) => {
                            conn.execute(
                                "CREATE TABLE csr ( id INTEGER PRIMARY KEY, requestor TEXT, email TEXT, phone TEXT, pem TEXT, rejection TEXT, done INTEGER DEFAULT 0 )",
                                [],
                            )?;
                        }
                        CertificateSigningMethod::Ssh(_) => {
                            conn.execute(
                                "CREATE TABLE sshr ( id INTEGER PRIMARY KEY, requestor TEXT, email TEXT, phone TEXT, pubkey TEXT, principals TEXT, comment TEXT, usage INTEGER, rejection TEXT, done INTEGER DEFAULT 0 )",
                                [],
                            )?;
                        }
                    }
                    conn.execute(
                        "CREATE TABLE certs ( id INTEGER PRIMARY KEY, der BLOB )",
                        [],
                    )
                })
                .await.map_err(|_|())?;
            }
        }
        Ok(())
    }
}

impl Pki {
    /// Initialize a Pki instance with the specified configuration and options for setting file ownerships (as required).
    #[allow(dead_code)]
    pub async fn init(
        hsm: Arc<crate::hsm2::Hsm>,
        settings: &crate::ca::PkiConfiguration,
        main_config: &crate::main_config::MainConfiguration,
    ) -> Result<Self, PkiLoadError> {
        let mut hm = std::collections::HashMap::new();
        let ca_name = main_config
            .https
            .as_ref()
            .and_then(|h| h.certificate.create_by_ca());
        loop {
            let mut done = true;
            for (name, config) in &settings.local_ca {
                if !hm.contains_key(name) {
                    let config = &config.get_ca(name, main_config);
                    let ca = crate::ca::Ca::init(
                        hsm.clone(),
                        config,
                        config.inferior_to.as_ref().and_then(|n| hm.get_mut(n)),
                    )
                    .await;
                    match ca {
                        Ok(mut ca) => {
                            if let Some(ca_name) = &ca_name {
                                if ca_name == name {
                                    ca.check_https_create(hsm.clone(), main_config)
                                        .await
                                        .map_err(|_| {
                                            PkiLoadError::FailedToLoadCa(
                                                name.to_owned(),
                                                CaLoadError::FailedToInitHttps,
                                            )
                                        })?;
                                }
                            }
                            hm.insert(name.to_owned(), ca);
                        }
                        Err(e) => match e {
                            CaLoadError::SuperiorCaMissing => {
                                done = false;
                            }
                            _ => {
                                return Err(PkiLoadError::FailedToLoadCa(name.to_owned(), e));
                            }
                        },
                    }
                }
            }
            if done {
                break;
            }
        }
        Ok(Self {
            roots: hm,
            super_admin: None,
        })
    }
}

impl PkiInstance {
    /// Init a pki Instance from the given settings
    #[allow(dead_code)]
    pub async fn init(
        hsm: Arc<crate::hsm2::Hsm>,
        settings: &crate::ca::PkiConfigurationEnum,
        main_config: &crate::main_config::MainConfiguration,
    ) -> Result<Self, PkiLoadError> {
        match settings {
            PkiConfigurationEnum::Pki(pki_config) => {
                let pki = crate::ca::Pki::init(hsm, pki_config, main_config).await?;
                Ok(Self::Pki(pki))
            }
            PkiConfigurationEnum::Ca(ca_config) => {
                let ca = ca_config.get_ca(main_config);
                let mut ca = crate::ca::Ca::init(hsm.clone(), &ca, None)
                    .await
                    .map_err(|e| PkiLoadError::FailedToLoadCa("ca".to_string(), e))?; //TODO Use the proper ca superior object instead of None
                if main_config.https.is_some() {
                    ca.check_https_create(hsm.clone(), main_config)
                        .await
                        .map_err(|_| {
                            PkiLoadError::FailedToLoadCa(
                                "ca".to_string(),
                                CaLoadError::FailedToInitHttps,
                            )
                        })?;
                }
                Ok(Self::Ca(ca))
            }
        }
    }
}

impl Ca {
    /// Check to see if the https certifiate should be created
    pub async fn check_https_create(
        &mut self,
        hsm: Arc<crate::hsm2::Hsm>,
        main_config: &crate::main_config::MainConfiguration,
    ) -> Result<(), ()> {
        if let Some(https) = &main_config.https {
            if https.certificate.create_by_ca().is_some() {
                if let Some(pathbuf) = https.certificate.pathbuf() {
                    self.create_https_certificate(
                        hsm.clone(),
                        pathbuf,
                        main_config
                            .public_names
                            .iter()
                            .map(|a| a.to_string())
                            .collect(),
                        https.certificate.password().unwrap(), //assume that the password is valid if the path is valid
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    /// Create the required https certificate
    pub async fn create_https_certificate(
        &mut self,
        _hsm: Arc<crate::hsm2::Hsm>,
        destination: std::path::PathBuf,
        https_names: Vec<String>,
        password: &str,
    ) -> Result<(), ()> {
        service::log::info!("Generating an https certificate for web operations");
        let key_usage_oids = vec![OID_EXTENDED_KEY_USAGE_SERVER_AUTH.to_owned()];
        let extensions = vec![
            cert_common::CsrAttribute::build_extended_key_usage(key_usage_oids)
                .to_custom_extension()
                .unwrap(),
        ];

        let id = self.get_new_request_id().await.unwrap();
        let algorithm = {
            let root_cert = self.root_cert.as_ref().unwrap();
            root_cert.algorithm()
        };
        if let CertificateSigningMethod::Https(m) = algorithm {
            let https_options = SigningRequestParams {
                hsm: None, //TODO put in the hsm object when support is there for using an https certificate with external private key
                smartcard: None,
                t: m,
                name: "https".to_string(),
                common_name: "HTTPS Server".to_string(),
                names: https_names,
                extensions,
                id,
                days_valid: self.config.days, //TODO figure out a method to renew the https certificate automaticcally
            };
            let csr = https_options.generate_request();
            let root_cert = self.root_cert.as_ref().unwrap();
            let mut cert = root_cert
                .sign_csr(csr, self, id, time::Duration::days(self.config.days as i64))
                .unwrap();
            cert.medium = self.medium.clone();
            let (snb, _sn) = CaCertificateToBeSigned::calc_sn(id);
            self.save_user_cert(id, &cert.contents().map_err(|_| ())?, &snb)
                .await;
            let p12 = cert.try_p12(password).unwrap();
            tokio::fs::write(destination, p12).await.unwrap();
        }
        Ok(())
    }

    /// Create a Self from the application configuration
    pub async fn init_from_config(
        settings: &crate::ca::CaConfiguration,
    ) -> Result<Self, CaLoadError> {
        if settings.path.exists().await {
            return Err(CaLoadError::StorageError(
                StorageBuilderError::AlreadyExists,
            ));
        }
        let mut medium = settings
            .path
            .build()
            .await
            .map_err(|e| CaLoadError::StorageError(e))?;
        medium
            .init(settings)
            .await
            .map_err(|_| CaLoadError::StorageError(StorageBuilderError::FailedToInitStorage))?;
        Ok(Self {
            medium,
            root_cert: Err(CertificateLoadingError::DoesNotExist),
            ocsp_signer: Err(CertificateLoadingError::DoesNotExist),
            admin: Err(CertificateLoadingError::DoesNotExist),
            ocsp_urls: Self::get_ocsp_urls(settings),
            admin_access: Zeroizing::new(settings.admin_access_password.to_string()),
            config: settings.to_owned(),
            super_admin: None,
            admin_authorities: Vec::new(),
        })
    }

    /// Initialize a Ca instance with the specified configuration.
    /// superior is used to generate the root certificate for intermediate authorities.
    pub async fn init(
        hsm: Arc<crate::hsm2::Hsm>,
        settings: &crate::ca::CaConfiguration,
        superior: Option<&mut Self>,
    ) -> Result<Self, CaLoadError> {
        service::log::info!("Attempting init for {}", settings.common_name);
        // Unable to to gnerate an intermediate instance without the superior ca reference
        if settings.inferior_to.is_some() && superior.is_none() {
            return Err(CaLoadError::SuperiorCaMissing);
        }

        let mut ca = Self::init_from_config(settings).await?;

        match settings.sign_method {
            CertificateSigningMethod::Https(m) => {
                {
                    service::log::info!("Generating a root certificate for ca operations");

                    let key_pair = hsm
                        .generate_https_keypair(&format!("{}-root", settings.common_name), m, 4096)
                        .unwrap();

                    let san: Vec<String> = settings.san.to_owned();
                    let mut certparams = rcgen::CertificateParams::new(san).unwrap();
                    certparams.distinguished_name = rcgen::DistinguishedName::new();

                    let cn = &settings.common_name;
                    let days = settings.days;
                    let chain_length = settings.chain_length;

                    certparams
                        .distinguished_name
                        .push(rcgen::DnType::CommonName, cn);
                    certparams.not_before = time::OffsetDateTime::now_utc();
                    certparams.not_after =
                        certparams.not_before + time::Duration::days(days as i64);
                    let basic_constraints = rcgen::BasicConstraints::Constrained(chain_length);
                    certparams.is_ca = rcgen::IsCa::Ca(basic_constraints);
                    let rootcert = if settings.inferior_to.is_none() {
                        use crate::hsm2::KeyPairTrait;
                        let cert = certparams.self_signed(&key_pair.keypair()).unwrap();
                        let cert_der = cert.der().to_owned();
                        CaCertificate::from_existing_https(
                            m,
                            ca.medium.clone(),
                            &cert_der,
                            Keypair::Hsm(key_pair),
                            "root".to_string(),
                            0,
                        )
                    } else if let Some(superior) = superior {
                        let id = superior.get_new_request_id().await.unwrap();
                        let key_usage_oids = vec![OID_EXTENDED_KEY_USAGE_SERVER_AUTH.to_owned()];
                        let extensions = vec![cert_common::CsrAttribute::build_extended_key_usage(
                            key_usage_oids,
                        )
                        .to_custom_extension()
                        .unwrap()];
                        let root_options = SigningRequestParams {
                            hsm: Some(hsm.clone()),
                            smartcard: None,
                            t: m,
                            name: format!("{}-root", ca.config.common_name),
                            common_name: ca.config.common_name.clone(),
                            names: ca.config.san.clone(),
                            extensions,
                            id,
                            days_valid: ca.config.days,
                        };
                        let root_csr = root_options.generate_request();
                        let mut root_cert = superior
                            .root_cert
                            .as_ref()
                            .unwrap()
                            .sign_csr(
                                root_csr,
                                &ca,
                                id,
                                time::Duration::days(ca.config.days as i64),
                            )
                            .unwrap();
                        let (snb, _sn) = CaCertificateToBeSigned::calc_sn(id);
                        superior
                            .save_user_cert(
                                id,
                                &root_cert.contents().map_err(|_| {
                                    CaLoadError::FailedToSaveCertificate("root".to_string())
                                })?,
                                &snb,
                            )
                            .await;
                        root_cert.medium = ca.medium.clone();
                        root_cert
                    } else {
                        todo!("Intermediate certificate authority generation not possible");
                    };

                    rootcert.save_to_medium(&mut ca, "").await;
                    ca.root_cert = Ok(rootcert);
                }
                service::log::info!("Generating OCSP responder certificate");
                let key_usage_oids = vec![OID_EXTENDED_KEY_USAGE_OCSP_SIGNING.to_owned()];
                let extensions =
                    vec![
                        cert_common::CsrAttribute::build_extended_key_usage(key_usage_oids)
                            .to_custom_extension()
                            .unwrap(),
                    ];

                let id = ca.get_new_request_id().await.unwrap();
                let ocsp_options = SigningRequestParams {
                    hsm: Some(hsm.clone()),
                    smartcard: None,
                    t: m,
                    name: format!("{}-ocsp", ca.config.common_name),
                    common_name: "OCSP Responder".to_string(),
                    names: ca.ocsp_urls.to_owned(),
                    extensions,
                    id,
                    days_valid: ca.config.days,
                };
                let ocsp_csr = ocsp_options.generate_request();
                let mut ocsp_cert = ca
                    .root_cert
                    .as_ref()
                    .unwrap()
                    .sign_csr(
                        ocsp_csr,
                        &ca,
                        id,
                        time::Duration::days(ca.config.days as i64),
                    )
                    .unwrap();
                ocsp_cert.medium = ca.medium.clone();
                ocsp_cert.save_to_medium(&mut ca, "").await;
                ca.ocsp_signer = Ok(ocsp_cert);

                let key_usage_oids = vec![OID_EXTENDED_KEY_USAGE_CLIENT_AUTH.to_owned()];
                let extensions =
                    vec![
                        cert_common::CsrAttribute::build_extended_key_usage(key_usage_oids)
                            .to_custom_extension()
                            .unwrap(),
                    ];
                service::log::info!("Generating administrator certificate");
                let id = ca.get_new_request_id().await.unwrap();
                let mut options = SigningRequestParams {
                    hsm: None,
                    smartcard: None,
                    t: m,
                    name: format!("{}-admin", ca.config.common_name),
                    common_name: format!("{} Administrator", settings.common_name),
                    names: Vec::new(),
                    extensions,
                    id,
                    days_valid: ca.config.days,
                };
                let admin_cert = match ca.config.admin_cert.clone() {
                    CertificateType::Soft(p) => {
                        let admin_csr = options.generate_request();
                        let mut admin_cert = ca
                            .root_cert
                            .as_ref()
                            .unwrap()
                            .sign_csr(
                                admin_csr,
                                &ca,
                                id,
                                time::Duration::days(ca.config.days as i64),
                            )
                            .unwrap();
                        admin_cert.medium = ca.medium.clone();
                        admin_cert.save_to_medium(&mut ca, &p).await;
                        admin_cert
                    }
                    CertificateType::SmartCard(p) => {
                        let label = format!("{}-admin", ca.config.common_name);
                        let keypair = crate::card::KeyPair::generate_with_smartcard(
                            p.as_bytes().to_vec(),
                            &label,
                        )
                        .ok_or(CaLoadError::FailedToCreateKeypair("admin".to_string()))?;
                        options.smartcard = Some(keypair);
                        let admin_csr = options.generate_request();
                        let mut admin_cert = ca
                            .root_cert
                            .as_ref()
                            .unwrap()
                            .sign_csr(
                                admin_csr,
                                &ca,
                                id,
                                time::Duration::days(ca.config.days as i64),
                            )
                            .unwrap();
                        admin_cert.medium = ca.medium.clone();
                        admin_cert.save_to_medium(&mut ca, &p).await;
                        admin_cert
                    }
                };
                ca.admin = Ok(admin_cert);
            }
            CertificateSigningMethod::Ssh(m) => {
                if settings.inferior_to.is_none() {
                    let key = m.generate_keypair(4096).unwrap();

                    let valid_after = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let valid_before = valid_after + (ca.config.days as u64 * 86400); // e.g. 1 year

                    let mut cert_builder = ssh_key::certificate::Builder::new_with_random_nonce(
                        &mut rand::thread_rng(),
                        key.public_key(),
                        valid_after,
                        valid_before,
                    )
                    .unwrap();
                    cert_builder.serial(0).unwrap();
                    cert_builder.key_id("root").unwrap();
                    cert_builder
                        .cert_type(ssh_key::certificate::CertType::User)
                        .unwrap();
                    cert_builder.valid_principal("invalid").unwrap();
                    cert_builder.comment(ca.config.common_name.clone()).unwrap();
                    let cert = cert_builder.sign(&key).unwrap();
                    let sshc = SshCertificate::new(m, Some(key.key_data().to_owned()), cert);
                    let root = CaCertificate::from_existing_ssh(
                        ca.medium.clone(),
                        sshc,
                        "root".to_string(),
                        0,
                    );
                    root.save_to_medium(&mut ca, "").await;
                    ca.root_cert = Ok(root);
                } else if let Some(_superior) = superior {
                    todo!("Intermediate certificate authority generation not implemented");
                } else {
                    todo!("Intermediate certificate authority generation not possible");
                }
            }
        }
        Ok(ca)
    }
}

/// The options required to build a signing request for a certificate
pub struct SigningRequestParams {
    /// The hsm to used when using the hsm to generate a certificate
    pub hsm: Option<Arc<crate::hsm2::Hsm>>,
    /// The smartcard keypair to use when using a certifcate for a smartcard
    pub smartcard: Option<crate::card::KeyPair>,
    /// The signing method
    pub t: HttpsSigningMethod,
    /// The name of the certificate
    pub name: String,
    /// The common name for the certificate
    pub common_name: String,
    /// The subject alternative names
    pub names: Vec<String>,
    /// Extensions for the certificate
    pub extensions: Vec<rcgen::CustomExtension>,
    /// The id for the certificate
    pub id: u64,
    /// The number of days the certificate should be valid
    pub days_valid: u32,
}

impl SigningRequestParams {
    /// Construct a signing request based on what options are present
    pub fn generate_request(&self) -> CaCertificateToBeSigned {
        let mut extensions = self.extensions.clone();
        let mut params = rcgen::CertificateParams::new(self.names.clone()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, self.common_name.clone());
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = params.not_before + time::Duration::days(self.days_valid as i64);
        params.custom_extensions.append(&mut extensions);
        let mut sn = [0; 20];
        for (i, b) in self.id.to_le_bytes().iter().enumerate() {
            sn[i] = *b;
        }
        if let Some(hsm) = &self.hsm {
            let keypair = hsm
                .generate_https_keypair(&self.name, self.t, 4096)
                .unwrap();
            use crate::hsm2::KeyPairTrait;
            let rckeypair = keypair.keypair();
            let csr = params.serialize_request(&rckeypair).unwrap();
            let csr_der = csr.der();
            let mut csr = rcgen::CertificateSigningRequestParams::from_der(csr_der).unwrap();
            let sn = rcgen::SerialNumber::from_slice(&sn);
            csr.params.serial_number = Some(sn);

            CaCertificateToBeSigned {
                algorithm: self.t,
                medium: CaCertificateStorage::Nowhere,
                csr,
                keypair: Some(Keypair::Hsm(keypair)),
                name: self.name.clone(),
                id: self.id,
            }
        } else if let Some(keypair) = &self.smartcard {
            let csr = params.serialize_request(&keypair.rcgen()).unwrap();
            let csr_der = csr.der();
            let mut csr = rcgen::CertificateSigningRequestParams::from_der(csr_der).unwrap();
            let sn = rcgen::SerialNumber::from_slice(&sn);
            csr.params.serial_number = Some(sn);

            CaCertificateToBeSigned {
                algorithm: self.t,
                medium: CaCertificateStorage::Nowhere,
                csr,
                keypair: Some(Keypair::SmartCard(keypair.clone())),
                name: self.name.clone(),
                id: self.id,
            }
        } else {
            let (keypair, priva) = self.t.generate_keypair(4096).unwrap();
            let csr = params.serialize_request(&keypair).unwrap();
            let csr_der = csr.der();
            let mut csr = rcgen::CertificateSigningRequestParams::from_der(csr_der).unwrap();
            let sn = rcgen::SerialNumber::from_slice(&sn);
            csr.params.serial_number = Some(sn);

            CaCertificateToBeSigned {
                algorithm: self.t,
                medium: CaCertificateStorage::Nowhere,
                csr,
                keypair: Some(Keypair::NotHsm(priva)),
                name: self.name.clone(),
                id: self.id,
            }
        }
    }
}
