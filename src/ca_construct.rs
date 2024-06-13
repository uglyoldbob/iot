#[path = "ca/ca_common.rs"]
mod ca_common;

pub use ca_common::*;
use cert_common::oid::*;
use cert_common::CertificateSigningMethod;
use cert_common::HttpsSigningMethod;
use zeroize::Zeroizing;

impl CaCertificateStorage {
    /// Initialize the storage medium
    pub async fn init(&mut self) {
        match self {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::Sqlite(p) => {
                p.conn(|conn| {
                    conn.execute("CREATE TABLE id ( id INTEGER PRIMARY KEY )", [])?;
                    conn.execute("CREATE TABLE serials ( id INTEGER PRIMARY KEY, serial BLOB)", [])?;
                    conn.execute(
                        "CREATE TABLE p12 ( id INTEGER PRIMARY KEY, name TEXT NOT NULL, der BLOB )",
                        [],
                    )?;
                    conn.execute(
                        "CREATE TABLE csr ( id INTEGER PRIMARY KEY, requestor TEXT, email TEXT, phone TEXT, pem TEXT, rejection TEXT, done INTEGER DEFAULT 0 )",
                        [],
                    )?;
                    conn.execute(
                        "CREATE TABLE certs ( id INTEGER PRIMARY KEY, der BLOB )",
                        [],
                    )
                })
                .await
                .expect("Failed to create table");
            }
        }
    }
}

impl Pki {
    /// Initialize a Pki instance with the specified configuration and options for setting file ownerships (as required).
    #[allow(dead_code)]
    pub async fn init(
        settings: &crate::ca::PkiConfiguration,
        answers: &crate::main_config::MainConfigurationAnswers,
        main_config: &crate::main_config::MainConfiguration,
        options: &OwnerOptions,
    ) -> Self {
        let mut hm = std::collections::HashMap::new();
        let ca_name = answers
            .https
            .as_ref()
            .map(|h| h.certificate.create_by_ca())
            .flatten();
        for (name, config) in settings.local_ca.map() {
            let config = &config.get_ca(name, main_config);
            let mut ca = crate::ca::Ca::init(config, options).await;
            if let Some(ca_name) = &ca_name {
                if ca_name == name {
                    if let Some(https) = &answers.https {
                        if https.certificate.create_by_ca().is_some() {
                            ca.create_https_certificate(
                                https.certificate.pathbuf(),
                                main_config
                                    .public_names
                                    .iter()
                                    .map(|a| a.to_string())
                                    .collect(),
                                https.certpass.to_string().as_str(),
                            )
                            .await;
                        }
                    }
                }
            }
            hm.insert(name.to_owned(), ca);
        }
        Self { roots: hm }
    }
}

impl PkiInstance {
    /// Init a pki Instance from the given settings
    #[allow(dead_code)]
    pub async fn init(
        settings: &crate::ca::PkiConfigurationEnum,
        answers: &crate::main_config::MainConfigurationAnswers,
        main_config: &crate::main_config::MainConfiguration,
        options: &OwnerOptions,
    ) -> Self {
        match settings {
            PkiConfigurationEnum::Pki(pki_config) => {
                let pki = crate::ca::Pki::init(pki_config, answers, main_config, options).await;
                Self::Pki(pki)
            }
            PkiConfigurationEnum::Ca(ca_config) => {
                let ca = ca_config.get_ca(main_config);
                let mut ca = crate::ca::Ca::init(&ca, &options).await;
                if let Some(https) = &answers.https {
                    if https.certificate.create_by_ca().is_some() {
                        ca.create_https_certificate(
                            https.certificate.pathbuf(),
                            main_config
                                .public_names
                                .iter()
                                .map(|a| a.to_string())
                                .collect(),
                            https.certpass.to_string().as_str(),
                        )
                        .await;
                    }
                }
                Self::Ca(ca)
            }
        }
    }
}

impl Ca {
    /// Create the required https certificate
    pub async fn create_https_certificate(
        &mut self,
        destination: std::path::PathBuf,
        https_names: Vec<String>,
        password: &str,
    ) {
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
            let csr = self.generate_signing_request(
                m,
                "https".to_string(),
                "HTTPS Server".to_string(),
                https_names,
                extensions,
                id,
            );
            let root_cert = self.root_cert.as_ref().unwrap();
            let mut cert = root_cert
                .sign_csr(csr, &self, id, time::Duration::days(365))
                .unwrap();
            cert.medium = self.medium.clone();
            let (snb, _sn) = CaCertificateToBeSigned::calc_sn(id);
            self.save_user_cert(id, &cert.contents(), &snb).await;
            let p12 = cert.try_p12(password).unwrap();
            std::fs::write(destination, p12).unwrap();
        }
    }

    /// Create a Self from the application configuration
    pub async fn init_from_config(
        settings: &crate::ca::CaConfiguration,
        options: &OwnerOptions,
    ) -> Self {
        if settings.path.exists().await {
            panic!("Storage medium already exists");
        }
        let mut medium = settings.path.build(Some(options)).await;
        medium.init().await;
        Self {
            medium,
            root_cert: Err(CertificateLoadingError::DoesNotExist),
            ocsp_signer: Err(CertificateLoadingError::DoesNotExist),
            admin: Err(CertificateLoadingError::DoesNotExist),
            ocsp_urls: Self::get_ocsp_urls(settings),
            admin_access: Zeroizing::new(settings.admin_access_password.to_string()),
            config: settings.to_owned(),
        }
    }

    /// Initialize a Ca instance with the specified configuration and options for setting file ownerships (as required).
    pub async fn init(settings: &crate::ca::CaConfiguration, options: &OwnerOptions) -> Self {
        let mut ca = Self::init_from_config(settings, options).await;

        match settings.sign_method {
            CertificateSigningMethod::Https(m) => {
                if settings.root {
                    service::log::info!("Generating a root certificate for ca operations");

                    let (key_pair, _unused) = m.generate_keypair(4096).unwrap();

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

                    let cert = certparams.self_signed(&key_pair).unwrap();
                    let cert_der = cert.der();
                    let key_der = key_pair.serialize_der();

                    let cacert = CaCertificate::from_existing_https(
                        m,
                        ca.medium.clone(),
                        cert_der,
                        Some(Zeroizing::from(key_der)),
                        "root".to_string(),
                        0,
                    );
                    cacert
                        .save_to_medium(&mut ca, &settings.root_password)
                        .await;
                    ca.root_cert = Ok(cacert);
                    service::log::info!("Generating OCSP responder certificate");
                    let key_usage_oids = vec![OID_EXTENDED_KEY_USAGE_OCSP_SIGNING.to_owned()];
                    let extensions =
                        vec![
                            cert_common::CsrAttribute::build_extended_key_usage(key_usage_oids)
                                .to_custom_extension()
                                .unwrap(),
                        ];

                    let id = ca.get_new_request_id().await.unwrap();
                    let ocsp_csr = ca.generate_signing_request(
                        m,
                        "ocsp".to_string(),
                        "OCSP Responder".to_string(),
                        ca.ocsp_urls.to_owned(),
                        extensions,
                        id,
                    );
                    let mut ocsp_cert = ca
                        .root_cert
                        .as_ref()
                        .unwrap()
                        .sign_csr(ocsp_csr, &ca, id, time::Duration::days(365))
                        .unwrap();
                    ocsp_cert.medium = ca.medium.clone();
                    ocsp_cert
                        .save_to_medium(&mut ca, &settings.ocsp_password)
                        .await;
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
                    let admin_csr = ca.generate_signing_request(
                        m,
                        "admin".to_string(),
                        format!("{} Administrator", settings.common_name),
                        Vec::new(),
                        extensions,
                        id,
                    );
                    let mut admin_cert = ca
                        .root_cert
                        .as_ref()
                        .unwrap()
                        .sign_csr(admin_csr, &ca, id, time::Duration::days(365))
                        .unwrap();
                    admin_cert.medium = ca.medium.clone();
                    admin_cert
                        .save_to_medium(&mut ca, &settings.admin_password)
                        .await;
                    ca.admin = Ok(admin_cert);
                } else {
                    todo!("Intermediate certificate authority generation not implemented");
                }
            }
            CertificateSigningMethod::Ssh(m) => {
                if settings.root {
                    let key = m.generate_keypair(4096).unwrap();

                    let valid_after = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let valid_before = valid_after + (365 * 86400); // e.g. 1 year

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
                    root.save_to_medium(&mut ca, &settings.root_password).await;
                    ca.root_cert = Ok(root);
                } else {
                    todo!("Intermediate ssh authority not implemmented");
                }
            }
        }
        ca
    }

    /// Generate a signing request
    /// # Arguments
    /// * t - The signing method for the certificate that will eventually be created
    /// * name - The storage name of the certificate
    /// * common_name - The commonName field for the subject of the certificate
    /// * names - Subject alternate names for the certificate
    /// * extension - The list of extensions to use for the certificate
    pub fn generate_signing_request(
        &mut self,
        t: HttpsSigningMethod,
        name: String,
        common_name: String,
        names: Vec<String>,
        extensions: Vec<rcgen::CustomExtension>,
        id: u64,
    ) -> CaCertificateToBeSigned {
        let mut extensions = extensions.clone();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        let (keypair, pkey) = t.generate_keypair(4096).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = params.not_before + time::Duration::days(365);
        params.custom_extensions.append(&mut extensions);

        let csr = params.serialize_request(&keypair).unwrap();
        let csr_der = csr.der();
        let mut csr = rcgen::CertificateSigningRequestParams::from_der(csr_der).unwrap();

        let mut sn = [0; 20];
        for (i, b) in id.to_le_bytes().iter().enumerate() {
            sn[i] = *b;
        }
        let sn = rcgen::SerialNumber::from_slice(&sn);
        csr.params.serial_number = Some(sn);

        CaCertificateToBeSigned {
            algorithm: t,
            medium: self.medium.clone(),
            csr,
            pkey,
            name,
            id,
        }
    }
}
