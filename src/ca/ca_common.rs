use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::{oid::*, pkcs12::BagAttribute};

/// The items used to configure a ca
#[derive(Clone, prompt::Prompting, serde::Deserialize, serde::Serialize)]
pub struct CaConfiguration {
    pub path: Option<PathBuf>,
    pub generate: bool,
    pub san: Vec<String>,
    pub common_name: String,
    pub days: u32,
    pub chain_length: u8,
    pub admin_password: String,
    pub ocsp_password: String,
    pub root_password: String,
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

impl CertificateSigningMethod {
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
            Self::Ecdsa => {
                let alg = rcgen::SignatureAlgorithm::from_oid(
                    &OID_ECDSA_P256_SHA256_SIGNING.components(),
                )
                .unwrap();
                let keypair = rcgen::KeyPair::generate(alg).ok()?;
                Some((keypair, None))
            }
        }
    }
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

/// Specifies how to access ca certificates on a ca
#[derive(Clone, Debug)]
pub enum CaCertificateStorage {
    /// The certificates are stored nowhere. Used for testing.
    Nowhere,
    /// The certificates are stored on a filesystem, in der format, private key and certificate in separate files
    FilesystemDer(PathBuf),
}

pub struct CaCertificateToBeSigned {
    /// The algorithm used for the ceertificate
    algorithm: CertificateSigningMethod,
    /// Where the certificate is stored
    medium: CaCertificateStorage,
    /// The certificate signing request
    csr: rcgen::CertificateSigningRequest,
    /// The optional private key in der format
    pkey: Option<Zeroizing<Vec<u8>>>,
    /// The certificate name to use for storage
    name: String,
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
        })
    }
}

impl CaCertificateStorage {
    /// Save this certificate to the storage medium
    pub async fn save_to_medium(&self, name: &str, cert: CaCertificate, password: &str) {
        let p12: crate::pkcs12::Pkcs12 = cert.try_into().unwrap();
        let p12_der = &p12.get_pkcs12(password);

        match self {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::FilesystemDer(p) => {
                tokio::fs::create_dir_all(&p).await;
                use tokio::io::AsyncWriteExt;
                let cp = p.join(format!("{}_cert.p12", name));
                let mut cf = tokio::fs::File::create(cp).await.unwrap();
                cf.write_all(&p12_der).await;
            }
        }
    }

    /// Load a certificate from the storage medium
    pub async fn load_from_medium(
        &self,
        name: &str,
        password: &str,
    ) -> Result<CaCertificate, CertificateLoadingError> {
        match self {
            CaCertificateStorage::Nowhere => Err(CertificateLoadingError::DoesNotExist),
            CaCertificateStorage::FilesystemDer(p) => {
                use tokio::io::AsyncReadExt;
                let certp = p.join(format!("{}_cert.p12", name));
                let mut f = tokio::fs::File::open(certp).await?;
                let mut cert = Vec::with_capacity(f.metadata().await.unwrap().len() as usize);
                f.read_to_end(&mut cert).await?;
                let p12 = crate::pkcs12::Pkcs12::load_from_data(&cert, password.as_bytes());
                Ok(p12.try_into().unwrap())
            }
        }
    }
}

/// Represents a certificate that might be able to sign things
#[derive(Debug, Clone)]
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
}

impl CaCertificate {
    /// Load a caCertificate instance from der data of the certificate
    pub fn from_existing(
        algorithm: CertificateSigningMethod,
        medium: CaCertificateStorage,
        der: &[u8],
        pkey: Option<Zeroizing<Vec<u8>>>,
        name: String,
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

    /// Retrieve the certificate in the rcgen Certificate format
    pub fn as_certificate(&self) -> rcgen::Certificate {
        let keypair = if let Some(kp) = &self.pkey {
            rcgen::KeyPair::from_der(kp).unwrap()
        } else {
            panic!("No keypair - need to implement RemoteKeyPair trait");
        };
        let mut p = rcgen::CertificateParams::from_ca_cert_der(&self.cert, keypair).unwrap();
        rcgen::Certificate::from_params(p).unwrap()
    }

    /// Save this certificate to the storage medium
    pub async fn save_to_medium(&self, password: &str) {
        self.medium
            .save_to_medium(&self.name, self.to_owned(), password)
            .await;
    }

    /// Create a pem version of the public certificate
    pub fn public_pem(&self) -> Result<String, der::Error> {
        use der::Decode;
        let doc: der::Document = der::Document::from_der(&self.cert)?;
        doc.to_pem("CERTIFICATE", pkcs8::LineEnding::CRLF)
    }

    /// Sign a csr with the certificate, if possible
    pub fn sign_csr(&self, csr: CaCertificateToBeSigned) -> Option<CaCertificate> {
        let cert = csr
            .csr
            .serialize_der_with_signer(&self.as_certificate())
            .ok()?;
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
}

impl Ca {
    /// Load ca stuff
    pub async fn load(settings: &crate::MainConfiguration) -> Self {
        let mut ca = Self::from_config(settings);

        let table = settings.ca.as_ref().unwrap();

        ca.load_ocsp_cert(&table.ocsp_password).await;
        ca.load_admin_cert(&table.admin_password).await;
        ca.load_root_ca_cert(&table.root_password).await;
        ca
    }

    /// Load the root ca cert from the specified storage media, converting to der as required.
    pub async fn load_root_ca_cert(
        &mut self,
        password: &str,
    ) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.root_cert.is_err() {
            self.root_cert = self.medium.load_from_medium("root", password).await;
        }
        self.root_cert.as_ref()
    }

    /// Load the admin signer certificate, loading if required.
    pub async fn load_admin_cert(
        &mut self,
        password: &str,
    ) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.admin.is_err() {
            self.admin = self.medium.load_from_medium("admin", password).await;
        }
        self.admin.as_ref()
    }

    /// Load the ocsp signer certificate, loading if required.
    pub async fn load_ocsp_cert(
        &mut self,
        password: &str,
    ) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.ocsp_signer.is_err() {
            self.ocsp_signer = self.medium.load_from_medium("ocsp", password).await;
        }
        self.ocsp_signer.as_ref()
    }

    /// Save the admin certificate to medium
    async fn save_admin(&mut self, p12: &[u8]) {
        match &self.medium {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::FilesystemDer(p) => {
                use tokio::io::AsyncWriteExt;
                let path = p.join("admin.p12");
                let mut f = tokio::fs::File::create(path).await.ok().unwrap();
                f.write_all(p12).await;
            }
        }
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
            let csr_cert = PublicKey::create_with(algo, &pkey);
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
                std::fs::create_dir_all(&pb);
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
                f.read_to_end(&mut contents).await;
                Some(contents)
            }
        }
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
        id: usize,
    ) -> CaCertificateToBeSigned {
        let mut extensions = extensions.clone();
        let mut params = rcgen::CertificateParams::new(names);
        let (keypair, pkey) = t.generate_keypair().unwrap();
        let public_key = keypair.public_key();
        params.key_pair = Some(keypair);
        params.alg =
            rcgen::SignatureAlgorithm::from_oid(&OID_PKCS1_SHA256_RSA_ENCRYPTION.components())
                .unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = params.not_before + time::Duration::days(365);
        params.custom_extensions.append(&mut extensions);

        let mut sn = [0; 20];
        for (i, b) in id.to_le_bytes().iter().enumerate() {
            sn[i] = *b;
        }
        let sn = rcgen::SerialNumber::from_slice(&sn);
        params.serial_number = Some(sn);

        let mut data: Vec<u8> = Vec::new();
        let csr = rcgen::CertificateSigningRequest { params, public_key };
        CaCertificateToBeSigned {
            algorithm: t,
            medium: self.medium.clone(),
            csr,
            pkey,
            name,
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
                tokio::fs::create_dir_all(&newpath).await;
                let newname = newpath.join(format!("{}.toml", id));
                tokio::fs::rename(oldname, newname).await;
                let pb = p.join("certs");
                tokio::fs::create_dir_all(&pb).await;
                let path = pb.join(format!("{}.der", id));
                let mut f = tokio::fs::File::create(path).await.ok().unwrap();
                f.write_all(cert_der).await;
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
                tokio::fs::create_dir_all(&pb).await;
                let newid = self.get_new_request_id().await;
                if let Some(newid) = newid {
                    let cp = pb.join(format!("{}.toml", newid));
                    let mut cf = tokio::fs::File::create(cp).await.unwrap();
                    let csr_doc = toml::to_string(reject).unwrap();
                    cf.write_all(csr_doc.as_bytes()).await;
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
                tokio::fs::create_dir_all(&pb).await;
                let newid = self.get_new_request_id().await;
                if let Some(newid) = newid {
                    let cp = pb.join(format!("{}.toml", newid));
                    let mut cf = tokio::fs::File::create(cp).await.unwrap();
                    let csr_doc = toml::to_string(csr).unwrap();
                    cf.write_all(csr_doc.as_bytes()).await;
                }
                newid
            }
        }
    }

    /// Create a Self from the application configuration
    fn from_config(settings: &crate::MainConfiguration) -> Self {
        let medium = if let Some(section) = &settings.ca {
            if let Some(path) = &section.path {
                CaCertificateStorage::FilesystemDer(path.to_owned())
            } else {
                CaCertificateStorage::Nowhere
            }
        } else {
            CaCertificateStorage::Nowhere
        };
        Self {
            medium,
            root_cert: Err(CertificateLoadingError::DoesNotExist),
            ocsp_signer: Err(CertificateLoadingError::DoesNotExist),
            admin: Err(CertificateLoadingError::DoesNotExist),
        }
    }

    /// Initialize the request id system
    pub async fn init_request_id(&mut self) {
        match &self.medium {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::FilesystemDer(p) => {
                use tokio::io::AsyncWriteExt;
                let pb = p.join("certs.txt");
                let mut cf = tokio::fs::File::create(pb).await.unwrap();
                cf.write(b"1").await;
            }
        }
    }

    /// Get a new request id, if possible
    pub async fn get_new_request_id(&mut self) -> Option<usize> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::FilesystemDer(p) => {
                use tokio::io::AsyncReadExt;
                let pb = p.join("certs.txt");
                let mut contents = Vec::new();
                let mut cf = tokio::fs::File::open(&pb).await.unwrap();
                cf.read_to_end(&mut contents).await;
                if let Ok(cid) = str::parse(std::str::from_utf8(&contents).unwrap()) {
                    use tokio::io::AsyncWriteExt;
                    let new_id = cid + 1;
                    let mut cf = tokio::fs::File::create(pb).await.unwrap();
                    cf.write(format!("{}", new_id).as_bytes()).await;
                    Some(cid)
                } else {
                    None
                }
            }
        }
    }

    /// Return a reference to the root cert
    pub fn root_ca_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.root_cert.as_ref()
    }

    /// Return a reference to the ocsp cert
    pub fn ocsp_ca_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.ocsp_signer.as_ref()
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
        _serial: &[u8],
    ) -> MaybeError<x509_cert::Certificate, ocsp::response::RevokedInfo> {
        match &self.medium {
            CaCertificateStorage::Nowhere => MaybeError::None,
            CaCertificateStorage::FilesystemDer(_p) => MaybeError::None,
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

        if dnhash == certid.issuer_name_hash {
            let key = root_cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .unwrap();
            let keyhash = hash.hash(key).unwrap();
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

/// The types of attributes that can be present in a csr
pub enum CsrAttribute {
    /// What the certificate can be used for
    ExtendedKeyUsage(Vec<Oid>),
    /// The challenge password
    ChallengePassword(String),
    /// The unstructured name
    UnstructuredName(String),
    /// All others
    Unrecognized(Oid, der::Any),
}

impl CsrAttribute {
    pub fn to_custom_extension(&self) -> rcgen::CustomExtension {
        match self {
            CsrAttribute::ExtendedKeyUsage(oids) => {
                let oid = &OID_EXTENDED_KEY_USAGE.components();
                let content = yasna::construct_der(|w| {
                    w.write_sequence_of(|w| {
                        for o in oids {
                            w.next().write_oid(&o.to_yasna());
                        }
                    });
                });
                rcgen::CustomExtension::from_oid_content(oid, content)
            }
            CsrAttribute::ChallengePassword(p) => todo!(),
            CsrAttribute::UnstructuredName(n) => todo!(),
            CsrAttribute::Unrecognized(oid, any) => todo!(),
        }
    }

    pub fn build_extended_key_usage(usage: Vec<Oid>) -> Self {
        Self::ExtendedKeyUsage(usage)
    }

    pub fn with_oid_and_any(oid: Oid, any: der::Any) -> Self {
        if oid == *OID_PKCS9_UNSTRUCTURED_NAME {
            let n = any.decode_as().unwrap();
            Self::UnstructuredName(n)
        } else if oid == *OID_PKCS9_CHALLENGE_PASSWORD {
            let n = any.decode_as().unwrap();
            Self::ChallengePassword(n)
        } else {
            Self::Unrecognized(oid, any)
        }
    }
}

impl std::fmt::Display for CsrAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CsrAttribute::ChallengePassword(s) => f.write_str(&format!("Password: {}", s)),
            CsrAttribute::UnstructuredName(s) => f.write_str(&format!("Unstructured Name: {}", s)),
            CsrAttribute::ExtendedKeyUsage(usages) => {
                for u in usages {
                    f.write_str(&format!("Usage: {:?}", u))?;
                }
                Ok(())
            }
            CsrAttribute::Unrecognized(oid, _a) => f.write_str(&format!("Unrecognized: {:?}", oid)),
        }
    }
}

/// Errors that can occur when signing a csr
pub enum CertificateSigningError {
    /// The requested csr does not exist
    CsrDoesNotExist,
    /// Unable to delete the request after processing
    FailedToDeleteRequest,
}

/// The types of attributes that can be present in a certificate
pub enum CertAttribute {
    /// All other types of attributes
    Unrecognized(Oid, der::asn1::OctetString),
}

impl std::fmt::Display for CertAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertAttribute::Unrecognized(oid, _a) => {
                f.write_str(&format!("Unrecognized: {:?}", oid))
            }
        }
    }
}

impl CertAttribute {
    pub fn with_oid_and_data(oid: Oid, data: der::asn1::OctetString) -> Self {
        {
            Self::Unrecognized(oid, data)
        }
    }
}

/// Contains a user signing request for a certificate
#[derive(serde::Deserialize, serde::Serialize)]
struct CsrRejection {
    /// The actual certificate request in pem format
    cert: String,
    /// The name of the person issuing the request
    name: String,
    /// The email of the person issuing the request
    email: String,
    /// The phone number of the person issuing the request
    phone: String,
    /// The reason for rejection
    rejection: String,
}

impl CsrRejection {
    fn from_csr_with_reason(csr: CsrRequest, reason: &String) -> Self {
        Self {
            cert: csr.cert,
            name: csr.name,
            email: csr.email,
            phone: csr.phone,
            rejection: reason.to_owned(),
        }
    }
}

/// Contains a user signing request for a certificate
#[derive(serde::Deserialize, serde::Serialize)]
pub struct CsrRequest {
    /// The actual certificate request in pem format
    pub cert: String,
    /// The name of the person issuing the request
    pub name: String,
    /// The email of the person issuing the request
    pub email: String,
    /// The phone number of the person issuing the request
    pub phone: String,
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
enum MaybeError<T, E> {
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

#[derive(Debug)]
struct PublicKey<'a> {
    key: ring::signature::UnparsedPublicKey<&'a [u8]>,
}

impl<'a> PublicKey<'a> {
    /// Create the public key with the specified algorithm.
    /// # Arguments
    /// * algorithm - The signing algorithm for the public key
    /// * key - The der bytes of the public key. For RSA this is a sequence of two integers.
    fn create_with(algorithm: CertificateSigningMethod, key: &'a [u8]) -> Self {
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

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ()> {
        self.key.verify(data, signature).map_err(|_| ())
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
