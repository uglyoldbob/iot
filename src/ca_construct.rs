#[path = "ca/ca_common.rs"]
mod ca_common;

use crate::oid::*;
pub use ca_common::*;
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
        main_config: &crate::main_config::MainConfiguration,
        options: OwnerOptions,
    ) -> Self {
        let mut hm = std::collections::HashMap::new();
        for (name, config) in settings.local_ca.map() {
            let config = &config.get_ca(name, main_config);
            let ca = crate::ca::Ca::init(config, &options).await;
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
        main_config: &crate::main_config::MainConfiguration,
        options: OwnerOptions,
    ) -> Self {
        match settings {
            PkiConfigurationEnum::Pki(pki_config) => {
                let pki = crate::ca::Pki::init(pki_config, main_config, options).await;
                Self::Pki(pki)
            }
            PkiConfigurationEnum::Ca(ca_config) => {
                let ca = ca_config.get_ca(main_config);
                let ca = crate::ca::Ca::init(&ca, &options).await;
                Self::Ca(ca)
            }
        }
    }
}

impl Ca {
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

        if settings.root {
            println!("Generating a root certificate for ca operations");

            let (key_pair, _unused) = settings.sign_method.generate_keypair().unwrap();

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
            certparams.not_after = certparams.not_before + time::Duration::days(days as i64);
            let basic_constraints = rcgen::BasicConstraints::Constrained(chain_length);
            certparams.is_ca = rcgen::IsCa::Ca(basic_constraints);

            let cert = certparams.self_signed(&key_pair).unwrap();
            let cert_der = cert.der();
            let key_der = key_pair.serialize_der();

            let cacert = CaCertificate::from_existing(
                settings.sign_method,
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
            println!("Generating OCSP responder certificate");
            let key_usage_oids = vec![OID_EXTENDED_KEY_USAGE_OCSP_SIGNING.to_owned()];
            let extensions = vec![CsrAttribute::build_extended_key_usage(key_usage_oids)
                .to_custom_extension()
                .unwrap()];

            let id = ca.get_new_request_id().await.unwrap();
            let ocsp_csr = ca.generate_signing_request(
                settings.sign_method,
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
                .sign_csr(ocsp_csr, &ca)
                .unwrap();
            ocsp_cert.medium = ca.medium.clone();
            ocsp_cert
                .save_to_medium(&mut ca, &settings.ocsp_password)
                .await;
            ca.ocsp_signer = Ok(ocsp_cert);

            let key_usage_oids = vec![OID_EXTENDED_KEY_USAGE_CLIENT_AUTH.to_owned()];
            let extensions = vec![CsrAttribute::build_extended_key_usage(key_usage_oids)
                .to_custom_extension()
                .unwrap()];

            println!("Generating administrator certificate");
            let id = ca.get_new_request_id().await.unwrap();
            let admin_csr = ca.generate_signing_request(
                settings.sign_method,
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
                .sign_csr(admin_csr, &ca)
                .unwrap();
            admin_cert.medium = ca.medium.clone();
            admin_cert
                .save_to_medium(&mut ca, &settings.admin_password)
                .await;
            ca.admin = Ok(admin_cert);
        } else {
            todo!("Intermediate certificate authority generation not implemented");
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
        t: CertificateSigningMethod,
        name: String,
        common_name: String,
        names: Vec<String>,
        extensions: Vec<rcgen::CustomExtension>,
        id: u64,
    ) -> CaCertificateToBeSigned {
        let mut extensions = extensions.clone();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        let (keypair, pkey) = t.generate_keypair().unwrap();
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

impl CertificateSigningMethod {
    /// Generate a keypair
    fn generate_keypair(&self) -> Option<(rcgen::KeyPair, Option<Zeroizing<Vec<u8>>>)> {
        match self {
            Self::RsaSha1 | Self::RsaSha256 => {
                use pkcs8::EncodePrivateKey;
                let mut rng = rand::thread_rng();
                let bits = 4096;
                let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
                let private_key_der = private_key.to_pkcs8_der().unwrap();
                let pkey = Zeroizing::new(private_key_der.as_bytes().to_vec());
                let key_pair = rcgen::KeyPair::try_from(private_key_der.as_bytes()).unwrap();
                Some((key_pair, Some(pkey)))
            }
            Self::EcdsaSha256 => {
                let keypair = rcgen::KeyPair::generate().ok()?;
                Some((keypair, None))
            }
        }
    }
}
