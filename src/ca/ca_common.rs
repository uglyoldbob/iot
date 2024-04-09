use std::path::PathBuf;

use async_sqlite::rusqlite::ToSql;
use x509_cert::ext::pkix::AccessDescription;
use zeroize::Zeroizing;

use crate::{oid::*, pkcs12::BagAttribute};

/// The items used to configure a ca
#[derive(Clone, prompt::Prompting, serde::Deserialize, serde::Serialize)]
pub struct CaConfiguration {
    pub path: CaCertificateStorageBuilder,
    pub generate: bool,
    pub san: Vec<String>,
    pub common_name: String,
    pub days: u32,
    pub chain_length: u8,
    pub admin_access_password: prompt::Password2,
    pub admin_password: prompt::Password2,
    pub ocsp_password: prompt::Password2,
    pub root_password: prompt::Password2,
    pub ocsp_signature: bool,
}

pub struct PkixAuthorityInfoAccess {
    pub der: Vec<u8>,
}

impl PkixAuthorityInfoAccess {
    pub fn new(urls: Vec<String>) -> Self {
        let asn = yasna::construct_der(|w| {
            w.write_sequence_of(|w| {
                for url in urls {
                    w.next().write_sequence(|w| {
                        w.next().write_oid(&OID_OCSP.to_yasna());
                        let d = yasna::models::TaggedDerValue::from_tag_and_bytes(
                            yasna::Tag::context(6),
                            url.as_bytes().to_vec(),
                        );
                        w.next().write_tagged_der(&d);
                    });
                }
            });
        });
        Self { der: asn }
    }
}

/// Errors that can occur when attempting to load a certificate
#[derive(Debug)]
pub enum CertificateLoadingError {
    /// The certificate does not exist
    DoesNotExist,
    /// Cannot open the certificate
    CantOpen,
    /// Other io error
    OtherIo(std::io::Error),
    /// The certificate loaded is invalid
    InvalidCert,
}

/// The method that a certificate uses to sign stuff
#[derive(Debug, Clone)]
pub enum CertificateSigningMethod {
    /// An rsa certificate with sha1
    RsaSha1,
    /// An rsa certificate rsa with sha256
    RsaSha256,
    /// Ecdsa
    Ecdsa,
}

impl<T> TryFrom<x509_cert::spki::AlgorithmIdentifier<T>> for CertificateSigningMethod {
    type Error = ();
    fn try_from(value: x509_cert::spki::AlgorithmIdentifier<T>) -> Result<Self, Self::Error> {
        let oid = value.oid;
        if oid == OID_PKCS1_SHA256_RSA_ENCRYPTION.to_const() {
            Ok(Self::RsaSha256)
        } else if oid == OID_PKCS1_SHA1_RSA_ENCRYPTION.to_const() {
            Ok(Self::RsaSha1)
        } else if oid == OID_ECDSA_P256_SHA256_SIGNING.to_const() {
            Ok(Self::Ecdsa)
        } else {
            println!("The oid to convert is {:?}", value.oid);
            Err(())
        }
    }
}

impl CertificateSigningMethod {
    fn oid(&self) -> crate::oid::Oid {
        match self {
            Self::RsaSha1 => OID_PKCS1_SHA1_RSA_ENCRYPTION.to_owned(),
            Self::RsaSha256 => OID_PKCS1_SHA256_RSA_ENCRYPTION.to_owned(),
            Self::Ecdsa => OID_ECDSA_P256_SHA256_SIGNING.to_owned(),
        }
    }
}

/// The information needed to construct a CaCertificateStorage
#[derive(Clone, prompt::Prompting, serde::Deserialize, serde::Serialize)]
pub enum CaCertificateStorageBuilder {
    /// Certificates are stored nowhere
    Nowhere,
    /// Ca uses a dedicated folder on a filesystem
    Filesystem(PathBuf),
    /// Ca uses a sqlite database on a filesystem
    Sqlite(PathBuf),
}

impl CaCertificateStorageBuilder {
    pub async fn build(&self) -> CaCertificateStorage {
        match self {
            CaCertificateStorageBuilder::Nowhere => CaCertificateStorage::Nowhere,
            CaCertificateStorageBuilder::Filesystem(p) => {
                CaCertificateStorage::FilesystemDer(p.to_owned())
            }
            CaCertificateStorageBuilder::Sqlite(p) => {
                let mut count = 0;
                let mut pool;
                loop {
                    pool = async_sqlite::PoolBuilder::new()
                        .path(p)
                        .journal_mode(async_sqlite::JournalMode::Wal)
                        .open()
                        .await;
                    if pool.is_err() {
                        count += 1;
                        if count > 10 {
                            panic!("Failed to create database");
                        }
                    } else {
                        break;
                    }
                }
                CaCertificateStorage::Sqlite(pool.unwrap())
            }
        }
    }
}

/// Specifies how to access ca certificates on a ca
#[derive(Clone)]
pub enum CaCertificateStorage {
    /// The certificates are stored nowhere. Used for testing.
    Nowhere,
    /// The certificates are stored on a filesystem, in der format, private key and certificate in separate files
    FilesystemDer(PathBuf),
    /// The ca is held in a sqlite database
    Sqlite(async_sqlite::Pool),
}

pub struct CaCertificateToBeSigned {
    /// The algorithm used for the certificate
    pub algorithm: CertificateSigningMethod,
    /// Where the certificate is stored
    pub medium: CaCertificateStorage,
    /// The certificate signing request parameters
    pub csr: rcgen::CertificateSigningRequestParams,
    /// The optional private key in der format
    pub pkey: Option<Zeroizing<Vec<u8>>>,
    /// The certificate name to use for storage
    pub name: String,
    /// The id of the certificate to be signed
    pub id: u64,
}

impl CaCertificateToBeSigned {
    pub fn calc_sn(id: u64) -> ([u8; 20], rcgen::SerialNumber) {
        let mut snb = [0; 20];
        for (i, b) in id.to_le_bytes().iter().enumerate() {
            snb[i] = *b;
        }
        let sn = rcgen::SerialNumber::from_slice(&snb);
        (snb, sn)
    }
}

impl TryFrom<crate::pkcs12::Pkcs12> for CaCertificate {
    type Error = ();
    fn try_from(value: crate::pkcs12::Pkcs12) -> Result<Self, Self::Error> {
        let cert_der = &value.cert;
        let x509_cert = {
            use der::Decode;
            x509_cert::Certificate::from_der(cert_der).unwrap()
        };
        let mut name = "whatever".to_string();
        for a in &value.attributes {
            if let BagAttribute::FriendlyName(n) = a {
                name = n.to_owned();
                break;
            }
        }
        let algorithm = x509_cert.signature_algorithm;
        Ok(Self {
            algorithm: algorithm.try_into().unwrap(),
            medium: CaCertificateStorage::Nowhere,
            cert: cert_der.to_owned(),
            pkey: Some(value.pkey),
            name: name,
            attributes: value.attributes.clone(),
            id: value.id,
        })
    }
}

impl CaCertificateStorage {
    /// Save this certificate to the storage medium
    pub async fn save_to_medium(
        &self,
        name: &str,
        ca: &mut Ca,
        cert: CaCertificate,
        password: &str,
    ) {
        use der::Decode;
        let x509 = x509_cert::Certificate::from_der(&cert.cert).unwrap();
        let snb = x509.tbs_certificate.serial_number.as_bytes().to_vec();
        if cert.pkey.is_some() {
            let p12: crate::pkcs12::Pkcs12 = cert.clone().try_into().unwrap();
            let p12_der = p12.get_pkcs12(password);

            match self {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::FilesystemDer(p) => {
                    tokio::fs::create_dir_all(&p).await.unwrap();
                    use tokio::io::AsyncWriteExt;
                    let cp = p.join(format!("{}_cert.p12", name));
                    let mut cf = tokio::fs::File::create(cp).await.unwrap();
                    cf.write_all(&p12_der).await.unwrap();
                }
                CaCertificateStorage::Sqlite(p) => {
                    println!("Inserting p12 {}", cert.id);
                    let name = name.to_owned();
                    p.conn(move |conn| {
                        let mut stmt = conn
                            .prepare("INSERT INTO p12 (id, name, der) VALUES (?1, ?2, ?3)")
                            .expect("Failed to build prepared statement");
                        stmt.execute([
                            cert.id.to_sql().unwrap(),
                            name.to_sql().unwrap(),
                            p12_der.to_sql().unwrap(),
                        ])
                    })
                    .await
                    .expect("Failed to insert certificate");
                }
            }
        }
        ca.save_user_cert(cert.id, &cert.cert, &snb).await;
    }

    /// Load a certificate from the storage medium
    pub async fn load_from_medium(
        &self,
        name: &str,
    ) -> Result<crate::pkcs12::ProtectedPkcs12, CertificateLoadingError> {
        match self {
            CaCertificateStorage::Nowhere => Err(CertificateLoadingError::DoesNotExist),
            CaCertificateStorage::FilesystemDer(p) => {
                use tokio::io::AsyncReadExt;
                let certp = p.join(format!("{}_cert.p12", name));
                let mut f = tokio::fs::File::open(certp).await?;
                let mut cert = Vec::with_capacity(f.metadata().await.unwrap().len() as usize);
                f.read_to_end(&mut cert).await?;
                let p12 = crate::pkcs12::ProtectedPkcs12 {
                    contents: cert,
                    id: 0,
                };
                Ok(p12)
            }
            CaCertificateStorage::Sqlite(p) => {
                let name = name.to_owned();
                let (id, cert): (u64, Vec<u8>) = p
                    .conn(move |conn| {
                        conn.query_row(
                            &format!("SELECT id,der FROM p12 WHERE name='{}'", name),
                            [],
                            |r| Ok((r.get(0).unwrap(), r.get(1).unwrap())),
                        )
                    })
                    .await
                    .expect("Failed to retrieve cert");
                let p12 = crate::pkcs12::ProtectedPkcs12 { contents: cert, id };
                Ok(p12)
            }
        }
    }
}

/// Represents a certificate that might be able to sign things
#[derive(Clone)]
pub struct CaCertificate {
    /// The algorithm used for the ceertificate
    algorithm: CertificateSigningMethod,
    /// Where the certificate is stored
    pub medium: CaCertificateStorage,
    /// The public certificate in der format
    pub cert: Vec<u8>,
    /// The optional private key in der format
    pub pkey: Option<Zeroizing<Vec<u8>>>,
    /// The certificate name to use for storage
    pub name: String,
    /// The extra attributes for the certificate
    pub attributes: Vec<crate::pkcs12::BagAttribute>,
    /// The id of the certificate
    pub id: u64,
}

impl CaCertificate {
    /// Load a caCertificate instance from der data of the certificate
    pub fn from_existing(
        algorithm: CertificateSigningMethod,
        medium: CaCertificateStorage,
        der: &[u8],
        pkey: Option<Zeroizing<Vec<u8>>>,
        name: String,
        id: u64,
    ) -> Self {
        Self {
            algorithm,
            medium,
            cert: der.to_vec(),
            pkey,
            name: name.clone(),
            attributes: vec![
                BagAttribute::LocalKeyId(vec![42; 16]), //TODO
                BagAttribute::FriendlyName(name),
            ],
            id,
        }
    }

    pub fn get_attributes(&self) -> Vec<crate::pkcs12::BagAttribute> {
        self.attributes.clone()
    }

    pub fn get_name(&self) -> String {
        self.name.to_owned()
    }

    /// Retrieve the private key in der format, if possible
    pub fn pkey_der(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.pkey.clone()
    }

    /// Retrieve the certificate in the native der format
    pub fn certificate_der(&self) -> Vec<u8> {
        self.cert.clone()
    }

    /// Returns the keypair for this certificate
    pub fn keypair(&self) -> rcgen::KeyPair {
        if let Some(pri) = &self.pkey {
            let pkcs8 = rustls_pki_types::PrivatePkcs8KeyDer::from(pri.as_slice());
            let alg =
                rcgen::SignatureAlgorithm::from_oid(&self.algorithm.oid().components()).unwrap();
            rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, alg).unwrap()
        } else {
            todo!("Implement getting keypair from remote keypair");
        }
    }

    /// Retrieve the certificate in the rcgen Certificate format
    pub fn as_certificate(&self) -> rcgen::Certificate {
        let keypair = self.keypair();
        let ca_cert_der = rustls_pki_types::CertificateDer::from(self.cert.clone());
        let p = rcgen::CertificateParams::from_ca_cert_der(&ca_cert_der).unwrap();
        //TODO unsure if this is correct
        p.self_signed(&keypair).unwrap()
    }

    /// Save this certificate to the storage medium
    pub async fn save_to_medium(&self, ca: &mut Ca, password: &str) {
        self.medium
            .save_to_medium(&self.name, ca, self.to_owned(), password)
            .await;
    }

    /// Create a pem version of the public certificate
    pub fn public_pem(&self) -> Result<String, der::Error> {
        use der::Decode;
        let doc: der::Document = der::Document::from_der(&self.cert)?;
        doc.to_pem("CERTIFICATE", pkcs8::LineEnding::CRLF)
    }

    /// Sign a csr with the certificate, if possible
    pub fn sign_csr(&self, mut csr: CaCertificateToBeSigned, ca: &Ca) -> Option<CaCertificate> {
        let the_csr = &mut csr.csr;
        let pkix = PkixAuthorityInfoAccess::new(ca.ocsp_urls.to_owned());
        let ocsp_data = pkix.der;
        let ocsp = rcgen::CustomExtension::from_oid_content(
            &OID_PKIX_AUTHORITY_INFO_ACCESS.components(),
            ocsp_data,
        );
        the_csr.params.custom_extensions.push(ocsp);

        let cert = csr
            .csr
            .signed_by(&self.as_certificate(), &self.keypair())
            .ok()?;
        let cert = cert.der().to_vec();
        Some(CaCertificate {
            algorithm: csr.algorithm,
            medium: CaCertificateStorage::Nowhere,
            cert,
            pkey: csr.pkey,
            name: csr.name.clone(),
            attributes: vec![
                BagAttribute::LocalKeyId(vec![42; 16]), //TODO
                BagAttribute::FriendlyName(csr.name),
            ],
            id: csr.id,
        })
    }

    /// Sign some data with the certificate, if possible
    pub async fn sign(&self, data: &[u8]) -> Option<(crate::oid::Oid, Vec<u8>)> {
        match &self.algorithm {
            CertificateSigningMethod::Ecdsa => {
                if let Some(pkey) = &self.pkey {
                    let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
                    let rng = &ring::rand::SystemRandom::new();
                    let key = ring::signature::EcdsaKeyPair::from_pkcs8(alg, &pkey, rng).unwrap();
                    let signature = key.sign(rng, data).unwrap();
                    Some((self.algorithm.oid(), signature.as_ref().to_vec()))
                } else {
                    todo!("Sign with external method")
                }
            }
            CertificateSigningMethod::RsaSha1 => {
                todo!("Sign with rsa");
            }
            CertificateSigningMethod::RsaSha256 => {
                if let Some(pkey) = &self.pkey {
                    let rng = &ring::rand::SystemRandom::new();
                    let key = ring::signature::RsaKeyPair::from_pkcs8(&pkey).unwrap();
                    let mut signature = vec![0; key.public().modulus_len()];
                    let pad = &ring::signature::RSA_PKCS1_SHA256;
                    key.sign(pad, rng, data, &mut signature).unwrap();
                    Some((self.algorithm.oid(), signature))
                } else {
                    todo!("Sign with external method")
                }
            }
        }
    }
}

/// The actual ca object
pub struct Ca {
    /// Where certificates are stored
    pub medium: CaCertificateStorage,
    /// Represents the root certificate for the ca
    pub root_cert: Result<CaCertificate, CertificateLoadingError>,
    /// Represents the certificate for signing ocsp responses
    pub ocsp_signer: Result<CaCertificate, CertificateLoadingError>,
    /// The administrator certificate
    pub admin: Result<CaCertificate, CertificateLoadingError>,
    /// The urls for the ca
    pub ocsp_urls: Vec<String>,
    /// The access token for the admin certificate
    pub admin_access: zeroize::Zeroizing<String>,
}

impl Ca {
    /// Marks the specified csr as done
    pub async fn mark_csr_done(&mut self, id: u64) {
        match &self.medium {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::FilesystemDer(p) => {
                let oldname = p.join("csr").join(format!("{}.toml", id));
                let newpath = p.join("csr-done");
                tokio::fs::create_dir_all(&newpath).await.unwrap();
                let newname = newpath.join(format!("{}.toml", id));
                tokio::fs::rename(oldname, newname).await.unwrap();
            }
            CaCertificateStorage::Sqlite(p) => {
                p.conn(move |conn| {
                    conn.execute(&format!("UPDATE csr SET done=1 WHERE id='{}'", id), [])
                })
                .await
                .expect("Failed to mark csr as done");
            }
        }
    }

    /// Save the user cert of the specified index to storage
    pub async fn save_user_cert(&mut self, id: u64, der: &[u8], sn: &[u8]) {
        match &self.medium {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::FilesystemDer(p) => {
                use tokio::io::AsyncWriteExt;
                let pb = p.join("certs");
                tokio::fs::create_dir_all(&pb).await.unwrap();
                let path = pb.join(format!("{}.der", id));
                let mut f = tokio::fs::File::create(path).await.ok().unwrap();
                f.write_all(der).await.unwrap();
            }
            CaCertificateStorage::Sqlite(p) => {
                let cert_der = der.to_owned();
                p.conn(move |conn| {
                    let mut stmt = conn
                        .prepare("INSERT INTO certs (id, der) VALUES (?1, ?2)")
                        .expect("Failed to build prepared statement");
                    stmt.execute([id.to_sql().unwrap(), cert_der.to_sql().unwrap()])
                })
                .await
                .expect("Failed to insert certificate");
                let serial = sn.to_owned();
                p.conn(move |conn| {
                    let mut stmt = conn
                        .prepare("INSERT INTO serials (id, serial) VALUES (?1, ?2)")
                        .expect("Failed to build prepared statement");
                    stmt.execute([id.to_sql().unwrap(), serial.to_sql().unwrap()])
                })
                .await
                .expect("Failed to insert serial number for certificate");
            }
        }
    }

    /// Returns the ocsp url, based on the application settings, preferring https over http
    pub fn get_ocsp_urls(settings: &crate::MainConfiguration) -> Vec<String> {
        let mut urls = Vec::new();

        if let Some(table) = &settings.ca {
            for san in &table.san {
                let san: &str = san.as_str();

                let mut url = String::new();
                let mut port_override = None;
                if settings.https.enabled {
                    let default_port = 443;
                    let p = settings.get_https_port();
                    if p != default_port {
                        port_override = Some(p);
                    }
                    url.push_str("https://");
                } else if settings.http.enabled {
                    let default_port = 80;
                    let p = settings.get_http_port();
                    if p != default_port {
                        port_override = Some(p);
                    }
                    url.push_str("http://");
                } else {
                    panic!("Cannot build ocsp responder url");
                }

                url.push_str(san);
                if let Some(p) = port_override {
                    url.push_str(&format!(":{}", p));
                }

                let proxy = &settings.general.proxy;
                url.push_str(proxy.as_str());
                url.push_str("/ca/ocsp");
                urls.push(url);
            }
        }

        urls
    }

    /// Retrieves a certificate, if it is valid, or a reason for it to be invalid
    /// # Arguments
    /// * serial - The serial number of the certificate
    async fn get_cert_by_serial(
        &self,
        serial: &[u8],
    ) -> MaybeError<x509_cert::Certificate, ocsp::response::RevokedInfo> {
        let s_str: Vec<String> = serial.iter().map(|v| format!("{:02X}", v)).collect();
        let s_str = s_str.concat();
        println!("Looking for serial number {}", s_str);
        match &self.medium {
            CaCertificateStorage::Nowhere => MaybeError::None,
            CaCertificateStorage::FilesystemDer(_p) => MaybeError::None,
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<Vec<u8>, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row(
                            &format!("SELECT der FROM certs INNER JOIN serials ON certs.id = serials.id WHERE serial=x'{}'", s_str),
                            [],
                            |r| r.get(0),
                        )
                    })
                    .await;
                match cert {
                    Ok(c) => {
                        use der::Decode;
                        let c = x509_cert::Certificate::from_der(&c).unwrap();
                        println!("Found the cert");
                        MaybeError::Ok(c)
                    }
                    Err(e) => {
                        println!("Did not find the cert {:?}", e);
                        MaybeError::None
                    }
                }
            }
        }
    }

    /// Load ca stuff
    pub async fn load(settings: &crate::MainConfiguration) -> Self {
        let mut ca = Self::from_config(settings).await;

        let table = settings.ca.as_ref().unwrap();

        // These will error when the ca needs to be built
        let _ = ca.load_ocsp_cert(&table.ocsp_password).await;
        let _ = ca.load_admin_cert(&table.admin_password).await;
        let _ = ca.load_root_ca_cert(&table.root_password).await;
        ca
    }

    /// Load the root ca cert from the specified storage media, converting to der as required.
    pub async fn load_root_ca_cert(
        &mut self,
        password: &str,
    ) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.root_cert.is_err() {
            let rc = self.medium.load_from_medium("root").await.unwrap();
            self.root_cert =
                Ok(
                    crate::pkcs12::Pkcs12::load_from_data(&rc.contents, password.as_bytes(), rc.id)
                        .try_into()
                        .unwrap(),
                );
        }
        self.root_cert.as_ref()
    }

    /// Get the protected admin certificate
    pub async fn get_admin_cert(&self) -> Vec<u8> {
        let p = self.medium.load_from_medium("admin").await.unwrap();
        p.contents
    }

    /// Attempt to get the already loaded admin certificate data
    pub async fn retrieve_admin_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.admin.as_ref()
    }

    /// Load the admin signer certificate, loading if required.
    pub async fn load_admin_cert(
        &mut self,
        password: &str,
    ) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.admin.is_err() {
            let rc = self.medium.load_from_medium("admin").await.unwrap();
            let mut cert: CaCertificate =
                crate::pkcs12::Pkcs12::load_from_data(&rc.contents, password.as_bytes(), rc.id)
                    .try_into()
                    .unwrap();
            cert.pkey = None;
            self.admin = Ok(cert);
        }
        self.admin.as_ref()
    }

    /// Load the ocsp signer certificate, loading if required.
    pub async fn load_ocsp_cert(
        &mut self,
        password: &str,
    ) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.ocsp_signer.is_err() {
            let rc = self.medium.load_from_medium("ocsp").await.unwrap();
            self.ocsp_signer =
                Ok(
                    crate::pkcs12::Pkcs12::load_from_data(&rc.contents, password.as_bytes(), rc.id)
                        .try_into()
                        .unwrap(),
                );
        }
        self.ocsp_signer.as_ref()
    }

    /// Create a Self from the application configuration
    pub async fn from_config(settings: &crate::MainConfiguration) -> Self {
        let medium = if let Some(section) = &settings.ca {
            section.path.build().await
        } else {
            CaCertificateStorage::Nowhere
        };
        Self {
            medium,
            root_cert: Err(CertificateLoadingError::DoesNotExist),
            ocsp_signer: Err(CertificateLoadingError::DoesNotExist),
            admin: Err(CertificateLoadingError::DoesNotExist),
            ocsp_urls: Self::get_ocsp_urls(settings),
            admin_access: Zeroizing::new(
                settings
                    .ca
                    .as_ref()
                    .unwrap()
                    .admin_access_password
                    .to_string(),
            ),
        }
    }

    /// Get a new request id, if possible
    pub async fn get_new_request_id(&mut self) -> Option<u64> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::FilesystemDer(p) => {
                use tokio::io::AsyncReadExt;
                let pb = p.join("certs.txt");
                let mut contents = Vec::new();
                let mut cf = tokio::fs::File::open(&pb).await.unwrap();
                cf.read_to_end(&mut contents).await.unwrap();
                if let Ok(cid) = str::parse(std::str::from_utf8(&contents).unwrap()) {
                    use tokio::io::AsyncWriteExt;
                    let new_id = cid + 1;
                    let mut cf = tokio::fs::File::create(pb).await.unwrap();
                    cf.write(format!("{}", new_id).as_bytes()).await.unwrap();
                    Some(cid)
                } else {
                    None
                }
            }
            CaCertificateStorage::Sqlite(p) => {
                let id = p
                    .conn(|conn| {
                        conn.execute("INSERT INTO id VALUES (NULL)", [])?;
                        Ok(conn.last_insert_rowid())
                    })
                    .await
                    .expect("Failed to insert id into table");
                Some(id as u64)
            }
        }
    }

    /// Get the status of the status, part of handling an ocsp request
    /// # Arguments
    /// * root_cert - The root certificate of the ca authority
    /// * certid - The certid from an ocsp request to check
    pub async fn get_cert_status(
        &self,
        root_cert: &x509_cert::Certificate,
        certid: &ocsp::common::asn1::CertId,
    ) -> ocsp::response::CertStatus {
        let oid_der = certid.hash_algo.to_der_raw().unwrap();
        let oid: yasna::models::ObjectIdentifier = yasna::decode_der(&oid_der).unwrap();

        let mut revoke_reason = None;
        let mut status = ocsp::response::CertStatusCode::Unknown;

        let hash = if oid == OID_HASH_SHA1.to_yasna() {
            println!("Using sha1 for hashing");
            HashType::Sha1
        } else {
            println!("Unknown OID for hash is {:?}", oid);
            HashType::Unknown
        };

        let dn = {
            use der::Encode;
            root_cert.tbs_certificate.subject.to_der().unwrap()
        };
        let dnhash = hash.hash(&dn).unwrap();

        println!(
            "Compare {:02X?} and {:02X?}",
            dnhash, certid.issuer_name_hash
        );

        if dnhash == certid.issuer_name_hash {
            let key2 = root_cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            println!("The key to hash is {:02X?}", key2);
            let keyhash = hash.hash(&key2).unwrap();
            println!(
                "Compare {:02X?} and {:02X?}",
                keyhash, certid.issuer_key_hash
            );
            if keyhash == certid.issuer_key_hash {
                let cert = self.get_cert_by_serial(&certid.serial_num).await;
                match cert {
                    MaybeError::Ok(_cert) => {
                        status = ocsp::response::CertStatusCode::Good;
                    }
                    MaybeError::Err(e) => {
                        status = ocsp::response::CertStatusCode::Revoked;
                        revoke_reason = Some(e);
                    }
                    MaybeError::None => {
                        status = ocsp::response::CertStatusCode::Revoked;
                        let reason = ocsp::response::CrlReason::OcspRevokeUnspecified;
                        revoke_reason = Some(ocsp::response::RevokedInfo::new(
                            ocsp::common::asn1::GeneralizedTime::now(),
                            Some(reason),
                        ))
                    }
                }
            }
        }

        ocsp::response::CertStatus::new(status, revoke_reason)
    }
}

#[derive(Debug)]
pub enum ExtendedKeyUsage {
    ClientIdentification,
    ServerIdentification,
    CodeSigning,
    OcspSigning,
    Unrecognized(Oid),
}

impl From<Oid> for ExtendedKeyUsage {
    fn from(value: Oid) -> Self {
        if value == *OID_EXTENDED_KEY_USAGE_CLIENT_AUTH {
            return ExtendedKeyUsage::ClientIdentification;
        } else if value == *OID_EXTENDED_KEY_USAGE_SERVER_AUTH {
            return ExtendedKeyUsage::ServerIdentification;
        } else if value == *OID_EXTENDED_KEY_USAGE_CODE_SIGNING {
            return ExtendedKeyUsage::CodeSigning;
        } else if value == *OID_EXTENDED_KEY_USAGE_OCSP_SIGNING {
            return ExtendedKeyUsage::OcspSigning;
        } else {
            return ExtendedKeyUsage::Unrecognized(value);
        }
    }
}

impl ExtendedKeyUsage {
    fn to_oid(&self) -> Oid {
        match self {
            ExtendedKeyUsage::ClientIdentification => OID_EXTENDED_KEY_USAGE_CLIENT_AUTH.clone(),
            ExtendedKeyUsage::ServerIdentification => OID_EXTENDED_KEY_USAGE_SERVER_AUTH.clone(),
            ExtendedKeyUsage::CodeSigning => OID_EXTENDED_KEY_USAGE_CODE_SIGNING.clone(),
            ExtendedKeyUsage::OcspSigning => OID_EXTENDED_KEY_USAGE_OCSP_SIGNING.clone(),
            ExtendedKeyUsage::Unrecognized(s) => s.clone(),
        }
    }
}

/// The types of attributes that can be present in a csr
#[allow(dead_code)]
pub enum CsrAttribute {
    /// What the certificate can be used for
    ExtendedKeyUsage(Vec<ExtendedKeyUsage>),
    /// The challenge password
    ChallengePassword(String),
    /// The unstructured name
    UnstructuredName(String),
    /// All others
    Unrecognized(Oid, der::Any),
}

impl CsrAttribute {
    #[allow(dead_code)]
    pub fn to_custom_extension(&self) -> rcgen::CustomExtension {
        match self {
            CsrAttribute::ExtendedKeyUsage(oids) => {
                let oid = &OID_CERT_EXTENDED_KEY_USAGE.components();
                let content = yasna::construct_der(|w| {
                    w.write_sequence_of(|w| {
                        for o in oids {
                            w.next().write_oid(&o.to_oid().to_yasna());
                        }
                    });
                });
                rcgen::CustomExtension::from_oid_content(oid, content)
            }
            CsrAttribute::ChallengePassword(_p) => todo!(),
            CsrAttribute::UnstructuredName(_n) => todo!(),
            CsrAttribute::Unrecognized(_oid, _any) => todo!(),
        }
    }

    #[allow(dead_code)]
    pub fn build_extended_key_usage(usage: Vec<Oid>) -> Self {
        let ks = usage.iter().map(|o| o.clone().into()).collect();
        Self::ExtendedKeyUsage(ks)
    }

    #[allow(dead_code)]
    pub fn with_oid_and_any(oid: Oid, any: der::Any) -> Self {
        if oid == *OID_PKCS9_UNSTRUCTURED_NAME {
            let n = any.decode_as().unwrap();
            Self::UnstructuredName(n)
        } else if oid == *OID_PKCS9_CHALLENGE_PASSWORD {
            let n = any.decode_as().unwrap();
            Self::ChallengePassword(n)
        } else if oid == *OID_CERT_EXTENDED_KEY_USAGE {
            let oids: Vec<der::asn1::ObjectIdentifier> = any.decode_as().unwrap();
            let oids = oids.iter().map(|o| Oid::from_const(*o).into()).collect();
            Self::ExtendedKeyUsage(oids)
        } else if oid == *OID_PKCS9_EXTENSION_REQUEST {
            use der::Encode;
            let params = yasna::parse_der(&any.to_der().unwrap(), |r| {
                r.read_sequence(|r| {
                    r.next().read_sequence(|r| {
                        let oid = r.next().read_oid();
                        r.next().read_bytes()
                    })
                })
            })
            .unwrap();
            let oids: Vec<yasna::models::ObjectIdentifier> =
                yasna::parse_der(&params, |r| r.collect_sequence_of(|r| r.read_oid())).unwrap();
            let oids = oids
                .iter()
                .map(|o| Oid::from_yasna(o.clone()).into())
                .collect();
            Self::ExtendedKeyUsage(oids)
        } else {
            Self::Unrecognized(oid, any)
        }
    }
}

/// Errors that can occur when signing a csr
#[allow(dead_code)]
pub enum CertificateSigningError {
    /// The requested csr does not exist
    CsrDoesNotExist,
    /// Unable to delete the request after processing
    FailedToDeleteRequest,
}

/// The types of methods that can be specified by authority info access
#[derive(Debug)]
pub enum AuthorityInfoAccess {
    /// Info is by ocsp provider at the specified url
    Ocsp(String),
    /// Unknown authority info access
    Unknown(String),
}

impl From<&AccessDescription> for AuthorityInfoAccess {
    fn from(value: &AccessDescription) -> Self {
        let s = match &value.access_location {
            x509_cert::ext::pkix::name::GeneralName::OtherName(a) => {
                todo!()
            }
            x509_cert::ext::pkix::name::GeneralName::Rfc822Name(a) => {
                todo!()
            }
            x509_cert::ext::pkix::name::GeneralName::DnsName(a) => {
                let s: &str = a.as_ref();
                s.to_string()
            }
            x509_cert::ext::pkix::name::GeneralName::DirectoryName(a) => {
                todo!()
            }
            x509_cert::ext::pkix::name::GeneralName::EdiPartyName(a) => {
                todo!()
            }
            x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(a) => {
                let s: &str = a.as_ref();
                s.to_string()
            }
            x509_cert::ext::pkix::name::GeneralName::IpAddress(a) => {
                String::from_utf8(a.as_bytes().to_vec()).unwrap()
            }
            x509_cert::ext::pkix::name::GeneralName::RegisteredId(a) => {
                todo!()
            }
        };
        if value.access_method == OID_OCSP.to_const() {
            Self::Ocsp(s)
        } else {
            Self::Unknown(s)
        }
    }
}

/// The types of attributes that can be present in a certificate
#[allow(dead_code)]
pub enum CertAttribute {
    /// The alternate names for the certificate
    SubjectAlternativeName(Vec<String>),
    /// The subject key identifier
    SubjectKeyIdentifier(Vec<u8>),
    /// What the certificate can be used for
    ExtendedKeyUsage(Vec<ExtendedKeyUsage>),
    /// The basic constraints extension
    BasicContraints { ca: bool, path_len: u8 },
    /// Authority info access
    AuthorityInfoAccess(Vec<AuthorityInfoAccess>),
    /// All other types of attributes
    Unrecognized(Oid, der::asn1::OctetString),
}

impl CertAttribute {
    #[allow(dead_code)]
    pub fn with_oid_and_data(oid: Oid, data: der::asn1::OctetString) -> Self {
        if oid == *OID_CERT_EXTENDED_KEY_USAGE {
            let oids: Vec<yasna::models::ObjectIdentifier> =
                yasna::parse_der(data.as_bytes(), |r| r.collect_sequence_of(|r| r.read_oid()))
                    .unwrap();
            let eku = oids
                .iter()
                .map(|o| Oid::from_yasna(o.clone()).into())
                .collect();
            Self::ExtendedKeyUsage(eku)
        } else if oid == *OID_CERT_ALTERNATIVE_NAME {
            let names: Vec<String> = yasna::parse_der(data.as_bytes(), |r| {
                r.collect_sequence_of(|r| {
                    let der = r.read_tagged_der()?;
                    let string = String::from_utf8(der.value().to_vec()).unwrap();
                    Ok(string)
                })
            })
            .unwrap();
            Self::SubjectAlternativeName(names)
        } else if oid == *OID_CERT_SUBJECT_KEY_IDENTIFIER {
            let data: Vec<u8> = yasna::decode_der(data.as_bytes()).unwrap();
            Self::SubjectKeyIdentifier(data)
        } else if oid == *OID_CERT_BASIC_CONSTRAINTS {
            let (ca, len) = yasna::parse_der(data.as_bytes(), |r| {
                r.read_sequence(|r| {
                    let ca = r.next().read_bool()?;
                    let len = r.next().read_u8()?;
                    Ok((ca, len))
                })
            })
            .unwrap();
            Self::BasicContraints { ca, path_len: len }
        } else if oid == *OID_PKIX_AUTHORITY_INFO_ACCESS {
            use der::Decode;
            let aia =
                x509_cert::ext::pkix::AuthorityInfoAccessSyntax::from_der(data.as_bytes()).unwrap();
            let aias: Vec<AuthorityInfoAccess> = aia.0.iter().map(|a| a.into()).collect();
            Self::AuthorityInfoAccess(aias)
        } else {
            Self::Unrecognized(oid, data)
        }
    }
}

pub struct CsrRejectionDbEntry<'a> {
    row_data: &'a async_sqlite::rusqlite::Row<'a>,
}

impl<'a> CsrRejectionDbEntry<'a> {
    #[allow(dead_code)]
    pub fn new(row: &'a async_sqlite::rusqlite::Row<'a>) -> Self {
        Self { row_data: row }
    }
}

impl<'a> Into<CsrRejection> for CsrRejectionDbEntry<'a> {
    fn into(self) -> CsrRejection {
        CsrRejection {
            cert: self.row_data.get(4).unwrap(),
            name: self.row_data.get(1).unwrap(),
            email: self.row_data.get(2).unwrap(),
            phone: self.row_data.get(3).unwrap(),
            rejection: self.row_data.get(5).unwrap(),
            id: self.row_data.get(0).unwrap(),
        }
    }
}

/// Contains a user signing request for a certificate
#[derive(serde::Deserialize, serde::Serialize)]
pub struct CsrRejection {
    /// The actual certificate request in pem format
    cert: String,
    /// The name of the person issuing the request
    name: String,
    /// The email of the person issuing the request
    email: String,
    /// The phone number of the person issuing the request
    phone: String,
    /// The reason for rejection
    pub rejection: String,
    /// The id for the csr
    pub id: u64,
}

impl CsrRejection {
    #[allow(dead_code)]
    pub fn from_csr_with_reason(csr: CsrRequest, reason: &String) -> Self {
        Self {
            cert: csr.cert,
            name: csr.name,
            email: csr.email,
            phone: csr.phone,
            rejection: reason.to_owned(),
            id: csr.id,
        }
    }
}

/// The database form of a CsrRequest
pub struct CsrRequestDbEntry<'a> {
    row_data: &'a async_sqlite::rusqlite::Row<'a>,
}

impl<'a> CsrRequestDbEntry<'a> {
    #[allow(dead_code)]
    pub fn new(row: &'a async_sqlite::rusqlite::Row<'a>) -> Self {
        Self { row_data: row }
    }
}

impl<'a> Into<CsrRequest> for CsrRequestDbEntry<'a> {
    fn into(self) -> CsrRequest {
        CsrRequest {
            cert: self.row_data.get(4).unwrap(),
            name: self.row_data.get(1).unwrap(),
            email: self.row_data.get(2).unwrap(),
            phone: self.row_data.get(3).unwrap(),
            id: self.row_data.get(0).unwrap(),
        }
    }
}

/// Contains a user signing request for a certificate
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct CsrRequest {
    /// The actual certificate request in pem format
    pub cert: String,
    /// The name of the person issuing the request
    pub name: String,
    /// The email of the person issuing the request
    pub email: String,
    /// The phone number of the person issuing the request
    pub phone: String,
    /// The id of the request
    pub id: u64,
}

/// The ways to hash data for the certificate checks
pub enum HashType {
    /// Use the sha1 algorithm
    Sha1,
    /// Unknown algorithm
    Unknown,
}

impl HashType {
    pub fn hash(&self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            HashType::Unknown => None,
            HashType::Sha1 => {
                use sha1::{Digest, Sha1};
                let mut hasher = Sha1::new();
                hasher.update(data);
                Some(hasher.finalize().to_vec())
            }
        }
    }
}

/// Represents a type that can be good, an error, or non-existent.
#[allow(dead_code)]
pub enum MaybeError<T, E> {
    Ok(T),
    Err(E),
    None,
}

impl From<std::io::Error> for CertificateLoadingError {
    fn from(value: std::io::Error) -> Self {
        match value.kind() {
            std::io::ErrorKind::NotFound => CertificateLoadingError::DoesNotExist,
            std::io::ErrorKind::PermissionDenied => CertificateLoadingError::CantOpen,
            _ => CertificateLoadingError::OtherIo(value),
        }
    }
}
