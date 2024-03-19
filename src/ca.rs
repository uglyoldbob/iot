//! Handles certificate authority functionality

use std::path::PathBuf;

use hyper::header::HeaderValue;
use zeroize::Zeroizing;

use crate::{webserver, WebPageContext, WebRouter};

use crate::oid::*;

/// Errors that can occur when signing a csr
enum CertificateSigningError {
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
    fn with_oid_and_data(oid: Oid, data: der::asn1::OctetString) -> Self {
        {
            Self::Unrecognized(oid, data)
        }
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
    fn to_custom_extension(&self) -> rcgen::CustomExtension {
        match self {
            CsrAttribute::ExtendedKeyUsage(oids) => {
                let oid = &OID_EXTENDED_KEY_USAGE.components();
                let content = p12::yasna::construct_der(|w| {
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

    fn build_extended_key_usage(usage: Vec<Oid>) -> Self {
        Self::ExtendedKeyUsage(usage)
    }

    fn with_oid_and_any(oid: Oid, any: der::Any) -> Self {
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
struct CsrRequest {
    /// The actual certificate request in pem format
    cert: String,
    /// The name of the person issuing the request
    name: String,
    /// The email of the person issuing the request
    email: String,
    /// The phone number of the person issuing the request
    phone: String,
}

struct PkixAuthorityInfoAccess {
    der: Vec<u8>,
}

impl PkixAuthorityInfoAccess {
    fn new(urls: Vec<String>) -> Self {
        println!("The ocsp urls are {:?}", urls);
        let asn = p12::yasna::construct_der(|w| {
            w.write_sequence_of(|w| {
                for url in urls {
                    w.next().write_sequence(|w| {
                        w.next().write_oid(&OID_OCSP.to_yasna());
                        let d = p12::yasna::models::TaggedDerValue::from_tag_and_bytes(
                            p12::yasna::Tag::context(6),
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

/// The ways to hash data for the certificate checks
enum HashType {
    /// Use the sha1 algorithm
    Sha1,
    /// Unknown algorithm
    Unknown,
}

impl HashType {
    fn hash(&self, data: &[u8]) -> Option<Vec<u8>> {
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
            CertificateSigningMethod::Rsa_Sha1 => Self {
                key: ring::signature::UnparsedPublicKey::new(
                    &ring::signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                    key,
                ),
            },
            CertificateSigningMethod::Ecdsa => {
                todo!();
            }
            CertificateSigningMethod::Rsa_Sha256 => Self {
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
enum CaCsrIter {
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

/// The actual ca object
pub struct Ca {
    /// Where certificates are stored
    medium: CaCertificateStorage,
    /// Represents the root certificate for the ca
    root_cert: Result<CaCertificate, CertificateLoadingError>,
    /// Represents the certificate for signing ocsp responses
    ocsp_signer: Result<CaCertificate, CertificateLoadingError>,
}

impl Ca {
    /// Verify a certificate signing request
    async fn verify_request<'a>(
        &mut self,
        csr: &'a x509_cert::request::CertReq,
    ) -> Result<&'a x509_cert::request::CertReq, ()> {
        use der::Encode;
        let info = csr.info.to_der().unwrap();
        let pubkey = &csr.info.public_key;
        let signature = &csr.signature;

        let p = &pubkey.subject_public_key;
        let pder = p.to_der().unwrap();

        let pkey = p12::yasna::parse_der(&pder, |r| {
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
    fn get_csr_iter(&self) -> CaCsrIter {
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
    async fn get_user_cert(&self, id: usize) -> Option<Vec<u8>> {
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
    fn generate_signing_request(
        &mut self,
        t: CertificateSigningMethod,
        name: String,
        common_name: String,
        names: Vec<String>,
        extensions: Vec<rcgen::CustomExtension>,
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
    async fn save_user_cert(&mut self, id: usize, cert_der: &[u8]) {
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
    async fn get_rejection_reason_by_id(&self, id: usize) -> Option<String> {
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
    async fn reject_csr_by_id(
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
    fn get_csr_by_id(&self, id: usize) -> Option<CsrRequest> {
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

    async fn save_csr(&mut self, csr: &CsrRequest) -> Option<usize> {
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
            if section.contains_key("path") {
                CaCertificateStorage::FilesystemDer(
                    section.get("path").unwrap().as_str().unwrap().into(),
                )
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

    /// Initialize the ca root certificates if necessary and configured to do so by the configuration
    pub async fn load_and_init(settings: &crate::MainConfiguration) -> Self {
        let mut ca = Self::from_config(settings);
        ca.load_ocsp_cert().await;
        match ca.load_root_ca_cert().await {
            Ok(_cert) => {}
            Err(e) => {
                if let CertificateLoadingError::DoesNotExist = e {
                    if let Some(table) = &settings.ca {
                        if matches!(
                            table
                                .get("generate")
                                .map(|f| f.to_owned())
                                .unwrap_or_else(|| toml::Value::String("no".to_string()))
                                .as_str()
                                .unwrap(),
                            "yes"
                        ) {
                            if let Some(san) = table.get("san").unwrap().as_array() {
                                use pkcs8::EncodePrivateKey;
                                println!("Generating a root certificate for ca operations");

                                let mut rng = rand::thread_rng();
                                let bits = 4096;
                                let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
                                let private_key_der = private_key.to_pkcs8_der().unwrap();
                                let key_pair =
                                    rcgen::KeyPair::try_from(private_key_der.as_bytes()).unwrap();

                                let san: Vec<String> = san
                                    .iter()
                                    .map(|e| e.as_str().unwrap().to_string())
                                    .collect();
                                let mut certparams = rcgen::CertificateParams::new(san);
                                certparams.key_pair = Some(key_pair);
                                certparams.alg = rcgen::SignatureAlgorithm::from_oid(
                                    &OID_PKCS1_SHA256_RSA_ENCRYPTION.components(),
                                )
                                .unwrap();
                                certparams.distinguished_name = rcgen::DistinguishedName::new();

                                let cn = table.get("commonName").unwrap().as_str().unwrap();
                                let days = table.get("days").unwrap().as_integer().unwrap();
                                let chain_length =
                                    table.get("chain_length").unwrap().as_integer().unwrap() as u8;

                                certparams
                                    .distinguished_name
                                    .push(rcgen::DnType::CommonName, cn);
                                certparams.not_before = time::OffsetDateTime::now_utc();
                                certparams.not_after =
                                    certparams.not_before + time::Duration::days(days);
                                let basic_constraints =
                                    rcgen::BasicConstraints::Constrained(chain_length);
                                certparams.is_ca = rcgen::IsCa::Ca(basic_constraints);

                                let pkix =
                                    PkixAuthorityInfoAccess::new(Self::get_ocsp_urls(settings));
                                let ocsp_data = pkix.der;
                                let ocsp = rcgen::CustomExtension::from_oid_content(
                                    &OID_PKIX_AUTHORITY_INFO_ACCESS.components(),
                                    ocsp_data,
                                );
                                certparams.custom_extensions.push(ocsp);
                                let cert = rcgen::Certificate::from_params(certparams).unwrap();
                                let cert_der = cert.serialize_der().unwrap();
                                let key_der = cert.get_key_pair().serialize_der();

                                let cacert = CaCertificate::from_existing(
                                    CertificateSigningMethod::Ecdsa,
                                    ca.medium.clone(),
                                    &cert_der,
                                    Some(Zeroizing::from(key_der)),
                                    "root".to_string(),
                                );
                                cacert.save_to_medium().await;
                                ca.root_cert = Ok(cacert);
                                ca.init_request_id().await;
                                println!("Generating OCSP responder certificate");
                                let ocsp_names = Self::get_ocsp_urls(settings);
                                let mut key_usage_oids = Vec::new();
                                key_usage_oids.push(OID_EXTENDED_KEY_USAGE_OCSP_SIGNING.to_owned());
                                let mut extensions = Vec::new();
                                extensions.push(
                                    CsrAttribute::build_extended_key_usage(key_usage_oids)
                                        .to_custom_extension(),
                                );
                                let ocsp_csr = ca.generate_signing_request(
                                    CertificateSigningMethod::Rsa_Sha256,
                                    "ocsp".to_string(),
                                    "OCSP Responder".to_string(),
                                    ocsp_names,
                                    extensions,
                                );
                                let mut ocsp_cert =
                                    ca.root_cert.as_ref().unwrap().sign_csr(ocsp_csr).unwrap();
                                ocsp_cert.medium = ca.medium.clone();
                                ocsp_cert.save_to_medium().await;
                                ca.ocsp_signer = Ok(ocsp_cert);
                            }
                        }
                    }
                }
            }
        }
        ca
    }

    /// Return a reference to the root cert
    fn root_ca_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.root_cert.as_ref()
    }

    /// Return a reference to the ocsp cert
    fn ocsp_ca_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.ocsp_signer.as_ref()
    }

    /// Load the ocsp signer certificate, loading if required.
    async fn load_ocsp_cert(&mut self) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.ocsp_signer.is_err() {
            self.ocsp_signer = self.medium.load_from_medium("ocsp").await;
        }
        self.ocsp_signer.as_ref()
    }

    /// Load the root ca cert from the specified storage media, converting to der as required.
    async fn load_root_ca_cert(&mut self) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.root_cert.is_err() {
            self.root_cert = self.medium.load_from_medium("root").await;
        }
        self.root_cert.as_ref()
    }

    /// Returns the ocsp url, based on the application settings, preferring https over http
    pub fn get_ocsp_urls(settings: &crate::MainConfiguration) -> Vec<String> {
        let mut urls = Vec::new();

        if let Some(table) = &settings.ca {
            if let Some(sans) = table.get("san").unwrap().as_array() {
                for san in sans {
                    let san: &str = san.as_str().unwrap();

                    let mut url = String::new();
                    let mut port_override = None;
                    if matches!(
                        settings.https.get("enabled").unwrap().as_str().unwrap(),
                        "yes"
                    ) {
                        let default_port = 443;
                        let p = settings.get_https_port();
                        if p != default_port {
                            port_override = Some(p);
                        }
                        url.push_str("https://");
                    } else if matches!(
                        settings.http.get("enabled").unwrap().as_str().unwrap(),
                        "yes"
                    ) {
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

                    let proxy = settings
                        .general
                        .get("proxy")
                        .map(|e| e.to_owned())
                        .unwrap_or(toml::Value::String("".to_string()));
                    url.push_str(proxy.as_str().unwrap());
                    url.push_str("/ca/ocsp");
                    urls.push(url);
                }
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
            CaCertificateStorage::FilesystemDer(p) => MaybeError::None,
        }
    }

    /// Get the status of the status, part of handling an ocsp request
    /// # Arguments
    /// * root_cert - The root certificate of the ca authority
    /// * certid - The certid from an ocsp request to check
    async fn get_cert_status(
        &self,
        root_cert: &x509_cert::Certificate,
        certid: &ocsp::common::asn1::CertId,
    ) -> ocsp::response::CertStatus {
        let oid_der = certid.hash_algo.to_der_raw().unwrap();
        let oid: p12::yasna::models::ObjectIdentifier = p12::yasna::decode_der(&oid_der).unwrap();

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

/// Specifies how to access ca certificates on a ca
#[derive(Clone, Debug)]
pub enum CaCertificateStorage {
    /// The certificates are stored nowhere. Used for testing.
    Nowhere,
    /// The certificates are stored on a filesystem, in der format, private key and certificate in separate files
    FilesystemDer(PathBuf),
}

impl CaCertificateStorage {
    /// Save this certificate to the storage medium
    pub async fn save_to_medium(&self, name: &str, cert: &CaCertificate) {
        match self {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::FilesystemDer(p) => {
                tokio::fs::create_dir_all(&p).await;
                use tokio::io::AsyncWriteExt;
                let cp = p.join(format!("{}_cert.der", name));
                let mut cf = tokio::fs::File::create(cp).await.unwrap();
                cf.write_all(&cert.cert).await;

                if let Some(key) = &cert.pkey {
                    let cp = p.join(format!("{}_key.der", name));
                    let mut cf = tokio::fs::File::create(cp).await.unwrap();
                    cf.write_all(&key).await;
                }
            }
        }
    }

    /// Load a certificate from the storage medium
    pub async fn load_from_medium(
        &self,
        name: &str,
    ) -> Result<CaCertificate, CertificateLoadingError> {
        match self {
            CaCertificateStorage::Nowhere => Err(CertificateLoadingError::DoesNotExist),
            CaCertificateStorage::FilesystemDer(p) => {
                use tokio::io::AsyncReadExt;
                let certp = p.join(format!("{}_cert.der", name));
                let mut f = tokio::fs::File::open(certp).await?;
                let mut cert = Vec::with_capacity(f.metadata().await.unwrap().len() as usize);
                f.read_to_end(&mut cert).await?;

                let keyp = p.join(format!("{}_key.der", name));
                let f2 = tokio::fs::File::open(keyp).await;
                let pkey = if let Ok(mut f2) = f2 {
                    let mut pkey = Zeroizing::new(Vec::with_capacity(
                        f2.metadata().await.unwrap().len() as usize,
                    ));
                    f2.read_to_end(&mut pkey).await?;
                    Some(pkey)
                } else {
                    None
                };

                //TODO actually determine the signing method by parsing the public certificate
                let cert = CaCertificate::from_existing(
                    CertificateSigningMethod::Rsa_Sha256,
                    self.clone(),
                    &cert,
                    pkey,
                    name.to_string(),
                );
                Ok(cert)
            }
        }
    }
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

/// Represents a certificate that might be able to sign things
#[derive(Debug)]
pub struct CaCertificate {
    /// The algorithm used for the ceertificate
    algorithm: CertificateSigningMethod,
    /// Where the certificate is stored
    medium: CaCertificateStorage,
    /// The public certificate in der format
    cert: Vec<u8>,
    /// The optional private key in der format
    pkey: Option<Zeroizing<Vec<u8>>>,
    /// The certificate name to use for storage
    name: String,
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
            name,
        }
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
    pub async fn save_to_medium(&self) {
        self.medium.save_to_medium(&self.name, self).await;
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
            name: csr.name,
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
            CertificateSigningMethod::Rsa_Sha1 => {
                todo!("Sign with rsa");
            }
            CertificateSigningMethod::Rsa_Sha256 => {
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

async fn ca_submit_request(s: WebPageContext) -> webserver::WebResponse {
    let mut ca = s.ca.lock().await;

    let mut valid_csr = false;
    let mut id = None;

    let f = s.post.form();
    if let Some(form) = f {
        use der::DecodePem;
        if let Some(pem) = form.get_first("csr") {
            let cert = x509_cert::request::CertReq::from_pem(pem);
            if let Ok(csr) = cert {
                valid_csr = ca.verify_request(&csr).await.is_ok();
                if valid_csr {
                    use der::EncodePem;
                    let pem = csr.to_pem(pkcs8::LineEnding::CRLF).unwrap();
                    let csrr = CsrRequest {
                        cert: pem,
                        name: form.get_first("name").unwrap().to_string(),
                        email: form.get_first("email").unwrap().to_string(),
                        phone: form.get_first("phone").unwrap().to_string(),
                    };
                    id = ca.save_csr(&csrr).await;
                }
            }
        }
    }

    let mut html = html::root::Html::builder();
    html.head(|h| generic_head(h, &s)).body(|b| {
        if valid_csr {
            b.text("Your request has been submitted").line_break(|f| f);
            b.anchor(|ab| {
                ab.text("View status of request");
                ab.href(format!("/{}ca/view_cert.rs?id={}", s.proxy, id.unwrap()));
                ab
            });
            b.line_break(|lb| lb);
        } else {
            b.text("Your request was considered invalid")
                .line_break(|f| f);
        }
        b
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

async fn ca_request(s: WebPageContext) -> webserver::WebResponse {
    let mut html = html::root::Html::builder();
    html.head(|h| {
        generic_head(h, &s)
            .script(|sb| {
                sb.src(format!("/{}js/forge.min.js", s.proxy));
                sb
            })
            .script(|sb| {
                sb.src(format!("/{}js/certgen.js", s.proxy));
                sb
            })
    })
    .body(|b| {
        b.division(|div| {
            div.class("cert-gen-stuff");
            div.text("This page is used to generate a certificate. The generate button generates a private key and certificate signing request on your local device, protecting the private key with the password specified.").line_break(|a|a);
            div.button(|b| b.text("Generate a certificate").onclick("generate_cert()"));
            div.line_break(|lb| lb);
            div.division(|div| {
                div.class("advanced");
                div.button(|b| b.text("Simple").onclick("show_regular()")).line_break(|a|a);
                div
            });
            div.division(|div| {
                div.class("regular");
                div.button(|b| b.text("Advanced").onclick("show_advanced()")).line_break(|a|a);
                div
            });
            div.division(|div| {
                div.form(|f| {
                    f.name("request");
                    f.action(format!("/{}ca/submit_request.rs", s.proxy));
                    f.method("post");
                    f.text("Your Name")
                        .line_break(|a| a)
                        .input(|i| i.type_("text").id("name").name("name"))
                        .line_break(|a| a);
                    f.text("Email")
                        .line_break(|a| a)
                        .input(|i| i.type_("email").id("email").name("email"))
                        .line_break(|a| a);
                    f.text("Phone Number")
                        .line_break(|a| a)
                        .input(|i| i.type_("tel").id("phone").name("phone"))
                        .line_break(|a| a);
                    f.text("Password for private key")
                        .line_break(|a|a)
                        .input(|i| i.type_("password").id("password"))
                        .line_break(|a|a);
                    f.heading_1(|h| {
                        h.text("Certificate Information").line_break(|a|a)
                    });
                    f.text("Certificate Name")
                        .line_break(|a| a)
                        .input(|i| i.type_("text").id("cname").name("cname"))
                        .line_break(|a| a);
                    f.text("Country")
                        .line_break(|a| a)
                        .input(|i| i.type_("text").id("country").name("country"))
                        .line_break(|a| a);
                    f.text("State")
                        .line_break(|a| a)
                        .input(|i| i.type_("text").id("state").name("state"))
                        .line_break(|a| a);
                    f.text("Locality")
                        .line_break(|a| a)
                        .input(|i| i.type_("text").id("locality").name("locality"))
                        .line_break(|a| a);
                    f.text("Organization Name")
                        .line_break(|a| a)
                        .input(|i| i.type_("text").id("organization").name("organization"))
                        .line_break(|a| a);
                    f.text("Organization Unit")
                        .line_break(|a| a)
                        .input(|i| i.type_("text").id("organization-unit").name("organization-unit"))
                        .line_break(|a| a);
                    f.text("Challenge password")
                        .line_break(|a| a)
                        .input(|i| i.type_("password").id("challenge-pass").name("challenge-pass"))
                        .line_break(|a| a);
                    f.text("Challenge name")
                        .line_break(|a| a)
                        .input(|i| i.type_("text").id("challenge-name").name("challenge-name"))
                        .line_break(|a| a);
                    f.division(|div| {
                        div.class("advanced");
                        div.emphasis(|e| e.text("Advanced")).line_break(|a|a);
                        div.text("CSR")
                            .line_break(|a| a)
                            .text_area(|i| i.id("csr").name("csr"))
                            .line_break(|a| a);
                        div
                    });
                    f.division(|div| {
                        div.class("hidden");
                        div.input(|i| i.type_("submit").id("submit").value("Submit"))
                        .line_break(|a| a);
                        div
                    });
                    f
                });
                div
            });
            div
        });
        b.division(|div| {
            div.class("cert_generating");
            div.text("Generating request...");
            div.line_break(|a| a);
            div
        });
        b
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

///The main landing page for the certificate authority
async fn ca_main_page(s: WebPageContext) -> webserver::WebResponse {
    let mut html = html::root::Html::builder();
    html.head(|h| generic_head(h, &s)).body(|b| {
        b.anchor(|ab| {
            ab.text("Download CA certificate as der");
            ab.href(format!("/{}ca/get_ca.rs?type=der", s.proxy));
            ab.target("_blank");
            ab
        });
        b.line_break(|lb| lb);
        b.anchor(|ab| {
            ab.text("Download CA certificate as pem");
            ab.href(format!("/{}ca/get_ca.rs?type=pem", s.proxy));
            ab.target("_blank");
            ab
        });
        b.line_break(|lb| lb);
        b.anchor(|ab| {
            ab.text("Request a signature on a certificate");
            ab.href(format!("/{}ca/request.rs", s.proxy));
            ab
        });
        b.line_break(|lb| lb);
        b.anchor(|ab| {
            ab.text("List pending requests");
            ab.href(format!("/{}ca/list.rs", s.proxy));
            ab
        });
        b.line_break(|lb| lb);
        b
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

async fn ca_reject_request(s: WebPageContext) -> webserver::WebResponse {
    let mut ca = s.ca.lock().await;

    let mut csr_check = Err(CertificateSigningError::CsrDoesNotExist);
    if let Some(id) = s.get.get("id") {
        let id = str::parse::<usize>(id);
        let reject = s.get.get("rejection").unwrap();
        if let Ok(id) = id {
            csr_check = ca.reject_csr_by_id(id, reject).await;
        }
    }

    let mut html = html::root::Html::builder();

    html.head(|h| generic_head(h, &s)).body(|b| {
        match csr_check {
            Ok(_der) => {
                b.text("The request has been rejected").line_break(|a| a);
            }
            Err(e) => match e {
                CertificateSigningError::CsrDoesNotExist => {
                    b.text("The certificate signing request does not exist")
                        .line_break(|a| a);
                }
                CertificateSigningError::FailedToDeleteRequest => {
                    b.text("Unable to delete request").line_break(|a| a);
                }
            },
        }
        b.anchor(|ab| {
            ab.text("List pending requests");
            ab.href(format!("/{}ca/list.rs", s.proxy));
            ab
        });
        b.line_break(|lb| lb);
        b
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

async fn ca_sign_request(s: WebPageContext) -> webserver::WebResponse {
    let mut ca = s.ca.lock().await;

    let mut csr_check = Err(CertificateSigningError::CsrDoesNotExist);
    if let Some(id) = s.get.get("id") {
        let id = str::parse::<usize>(id);
        if let Ok(id) = id {
            if let Some(csrr) = ca.get_csr_by_id(id) {
                let mut a = rcgen::CertificateSigningRequest::from_pem(&csrr.cert);
                match &mut a {
                    Ok(csr) => {
                        csr.params.not_before = time::OffsetDateTime::now_utc();
                        csr.params.not_after = csr.params.not_before + time::Duration::days(365);
                        println!("Ready to sign the csr");
                        let der = csr
                            .serialize_der_with_signer(
                                &ca.load_root_ca_cert().await.unwrap().as_certificate(),
                            )
                            .unwrap();
                        println!(
                            "got a signed der certificate for the user length {}",
                            der.len()
                        );
                        ca.save_user_cert(id, &der).await;
                        csr_check = Ok(der);
                    }
                    Err(e) => {
                        println!("Error decoding csr to sign: {:?}", e);
                    }
                }
            }
        }
    }

    let mut html = html::root::Html::builder();

    html.head(|h| generic_head(h, &s)).body(|b| {
        match csr_check {
            Ok(_der) => {
                b.text("The request has been signed").line_break(|a| a);
            }
            Err(e) => match e {
                CertificateSigningError::CsrDoesNotExist => {
                    b.text("The certificate signing request does not exist")
                        .line_break(|a| a);
                }
                CertificateSigningError::FailedToDeleteRequest => {
                    b.text("Failed to delete request").line_break(|a| a);
                }
            },
        }
        b.anchor(|ab| {
            ab.text("List pending requests");
            ab.href(format!("/{}ca/list.rs", s.proxy));
            ab
        });
        b.line_break(|lb| lb);
        b
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

async fn ca_list_requests(s: WebPageContext) -> webserver::WebResponse {
    let ca = s.ca.lock().await;

    let mut html = html::root::Html::builder();
    html.head(|h| generic_head(h, &s)).body(|b| {
        if let Some(id) = s.get.get("id") {
            let id = str::parse::<usize>(id);
            if let Ok(id) = id {
                if let Some(csrr) = ca.get_csr_by_id(id) {
                    use der::DecodePem;
                    let csr = x509_cert::request::CertReq::from_pem(&csrr.cert);
                    if let Ok(csr) = csr {
                        let csr_names: Vec<String> = csr
                            .info
                            .subject
                            .0
                            .iter()
                            .map(|n| format!("{}", n))
                            .collect();
                        let t = csr_names.join(", ");
                        b.anchor(|ab| {
                            ab.text("Back to all requests");
                            ab.href(format!("/{}ca/list.rs", s.proxy));
                            ab
                        })
                        .line_break(|a| a);
                        b.text(t).line_break(|a| a);
                        b.text(format!("Name: {}", csrr.name)).line_break(|a| a);
                        b.text(format!("Email: {}", csrr.email)).line_break(|a| a);
                        b.text(format!("Phone: {}", csrr.phone)).line_break(|a| a);
                        for attr in csr.info.attributes.iter() {
                            for p in attr.values.iter() {
                                let pa = CsrAttribute::with_oid_and_any(
                                    Oid::from_const(attr.oid),
                                    p.to_owned(),
                                );
                                b.text(format!("\t{}", pa)).line_break(|a| a);
                            }
                        }
                        b.anchor(|ab| {
                            ab.text("Sign this request");
                            ab.href(format!("/{}ca/request_sign.rs?id={}", s.proxy, id));
                            ab
                        })
                        .line_break(|a| a);
                        b.form(|f| {
                            f.action(format!("/{}ca/request_reject.rs", s.proxy));
                            f.text("Reject reason")
                                .line_break(|a| a)
                                .input(|i| {
                                    i.type_("hidden")
                                        .id("id")
                                        .name("id")
                                        .value(format!("{}", id))
                                })
                                .input(|i| i.type_("text").id("rejection").name("rejection"))
                                .line_break(|a| a);
                            f.input(|i| i.type_("submit").value("Reject this request"))
                                .line_break(|a| a);
                            f
                        });
                    }
                }
            }
        } else {
            b.text("List all pending requests");
            b.line_break(|a| a);
            let mut index_shown = 0;
            for (csrr, id) in ca.get_csr_iter() {
                use der::DecodePem;
                let csr = x509_cert::request::CertReq::from_pem(&csrr.cert);
                if let Ok(csr) = csr {
                    if index_shown > 0 {
                        b.thematic_break(|a| a);
                    }
                    index_shown += 1;
                    let csr_names: Vec<String> = csr
                        .info
                        .subject
                        .0
                        .iter()
                        .map(|n| format!("{}", n))
                        .collect();
                    let t = csr_names.join(", ");
                    b.anchor(|ab| {
                        ab.text("View this request");
                        ab.href(format!("/{}ca/list.rs?id={}", s.proxy, id));
                        ab
                    })
                    .line_break(|a| a);
                    b.text(t).line_break(|a| a);
                    b.text(format!("Name: {}", csrr.name)).line_break(|a| a);
                    b.text(format!("Email: {}", csrr.email)).line_break(|a| a);
                    b.text(format!("Phone: {}", csrr.phone)).line_break(|a| a);
                }
            }
        }
        b
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

/// Runs the page for fetching the user certificate for the certificate authority being run
async fn ca_view_user_cert(s: WebPageContext) -> webserver::WebResponse {
    let ca = s.ca.lock().await;

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;
    let mut csr = None;
    let mut rejection = None;
    let mut myid = 0;

    if let Some(id) = s.get.get("id") {
        let id: Result<usize, std::num::ParseIntError> = str::parse(id.as_str());
        if let Ok(id) = id {
            cert = ca.get_user_cert(id).await;
            if cert.is_none() {
                csr = ca.get_csr_by_id(id);
            }
            if csr.is_none() {
                rejection = Some(ca.get_rejection_reason_by_id(id).await);
            }
            myid = id;
        }
    }

    let mut html = html::root::Html::builder();
    html.head(|h| {
        generic_head(h, &s)
            .script(|sb| {
                sb.src(format!("/{}js/forge.min.js", s.proxy));
                sb
            })
            .script(|sb| {
                sb.src(format!("/{}js/certgen.js", s.proxy));
                sb
            })
    })
    .body(|b| {
        if let Some(cert_der) = cert {
            use der::Decode;
            let cert: Result<x509_cert::certificate::CertificateInner, der::Error> =
                x509_cert::Certificate::from_der(&cert_der);
            match cert {
                Ok(cert) => {
                    let csr_names: Vec<String> = cert
                        .tbs_certificate
                        .subject
                        .0
                        .iter()
                        .map(|n| format!("{}", n))
                        .collect();
                    let t = csr_names.join(", ");
                    b.text(t).line_break(|a| a);
                    if let Some(extensions) = &cert.tbs_certificate.extensions {
                        for e in extensions {
                            let ca = CertAttribute::with_oid_and_data(
                                e.extn_id.into(),
                                e.extn_value.to_owned(),
                            );
                            b.text(format!("\t{}", ca)).line_break(|a| a);
                        }
                    }
                    b.button(|b| b.text("Build certificate").onclick("build_cert()"));
                    b.form(|form| {
                        form.input(|i| i.type_("file").id("file-selector"));
                        form.text("Password for private key").line_break(|a| a);
                        form.input(|i| i.type_("password").id("password"));
                        form.line_break(|a| a);
                        form.text("Password for certificate").line_break(|a| a);
                        form.input(|i| i.type_("password").id("cert-password"));
                        form.line_break(|a| a);
                        form
                    });
                    b.division(|div| {
                        div.class("hidden");
                        div.anchor(|a| {
                            a.id("get_request")
                                .text(format!("/{}ca/get_cert.rs?id={}&type=pem", s.proxy, myid))
                        });
                        div
                    });
                    b.line_break(|lb| lb);
                }
                Err(e) => {
                    println!("Error reading certificate {:?}", e);
                }
            }
        } else if let Some(csr) = csr {
            b.text(format!(
                "Your request is pending at {}",
                time::OffsetDateTime::now_utc()
            ))
            .line_break(|a| a);
        } else if let Some(reason) = rejection {
            match reason {
                Some(reason) => {
                    if reason.is_empty() {
                        b.text("Your request is rejected: No reason given")
                            .line_break(|a| a);
                    } else {
                        b.text(format!("Your request is rejected: {}", reason))
                            .line_break(|a| a);
                    }
                    b.text(format!("{}", time::OffsetDateTime::now_utc()))
                        .line_break(|a| a);
                }
                None => {
                    b.text("Your request is rejected: No reason given")
                        .line_break(|a| a);
                    b.text(format!("{}", time::OffsetDateTime::now_utc()))
                        .line_break(|a| a);
                }
            }
        }
        b.anchor(|ab| {
            ab.text("Back to main page");
            ab.href(format!("/{}ca", s.proxy));
            ab
        });
        b.line_break(|lb| lb);
        b
    });
    let html = html.build();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));

    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

/// Runs the page for fetching the user certificate for the certificate authority being run
async fn ca_get_user_cert(s: WebPageContext) -> webserver::WebResponse {
    let ca = s.ca.lock().await;

    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;

    if let Some(id) = s.get.get("id") {
        let id: Result<usize, std::num::ParseIntError> = str::parse(id.as_str());
        if let Ok(id) = id {
            if let Some(cert_der) = ca.get_user_cert(id).await {
                let ty = if s.get.contains_key("type") {
                    s.get.get("type").unwrap().to_owned()
                } else {
                    "der".to_string()
                };

                match ty.as_str() {
                    "der" => {
                        response.headers.append(
                            "Content-Type",
                            HeaderValue::from_static("application/x509-ca-cert"),
                        );
                        let name = format!("attachment; filename={}.der", id);
                        response
                            .headers
                            .append("Content-Disposition", HeaderValue::from_str(&name).unwrap());
                        cert = Some(cert_der);
                    }
                    "pem" => {
                        use der::Decode;
                        response.headers.append(
                            "Content-Type",
                            HeaderValue::from_static("application/x-pem-file"),
                        );
                        let name = format!("attachment; filename={}.pem", id);
                        response
                            .headers
                            .append("Content-Disposition", HeaderValue::from_str(&name).unwrap());
                        let pem = der::Document::from_der(&cert_der)
                            .unwrap()
                            .to_pem("CERTIFICATE", pkcs8::LineEnding::CRLF)
                            .unwrap();
                        cert = Some(pem.as_bytes().to_vec());
                    }
                    _ => {}
                }
            }
        }
    }

    let body = if let Some(cert) = cert {
        http_body_util::Full::new(hyper::body::Bytes::copy_from_slice(&cert))
    } else {
        http_body_util::Full::new(hyper::body::Bytes::from("missing"))
    };
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

/// Runs the page for fetching the ca certificate for the certificate authority being run
async fn ca_get_cert(s: WebPageContext) -> webserver::WebResponse {
    let ca = s.ca.lock().await;

    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;

    if let Ok(cert_der) = ca.root_ca_cert() {
        let ty = if s.get.contains_key("type") {
            s.get.get("type").unwrap().to_owned()
        } else {
            "der".to_string()
        };

        match ty.as_str() {
            "der" => {
                response.headers.append(
                    "Content-Type",
                    HeaderValue::from_static("application/x509-ca-cert"),
                );
                response.headers.append(
                    "Content-Disposition",
                    HeaderValue::from_static("attachment; filename=ca.cer"),
                );
                cert = Some(cert_der.cert.to_owned());
            }
            "pem" => {
                response.headers.append(
                    "Content-Type",
                    HeaderValue::from_static("application/x-pem-file"),
                );
                response.headers.append(
                    "Content-Disposition",
                    HeaderValue::from_static("attachment; filename=ca.pem"),
                );
                if let Ok(pem) = cert_der.public_pem() {
                    cert = Some(pem.as_bytes().to_vec());
                }
            }
            _ => {}
        }
    }

    let body = if let Some(cert) = cert {
        http_body_util::Full::new(hyper::body::Bytes::copy_from_slice(&cert))
    } else {
        http_body_util::Full::new(hyper::body::Bytes::from("missing"))
    };
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

/// The method that a certificate uses to sign stuff
#[derive(Debug)]
pub enum CertificateSigningMethod {
    /// An rsa certificate with sha1
    Rsa_Sha1,
    /// An rsa certificate rsa with sha256
    Rsa_Sha256,
    /// Ecdsa
    Ecdsa,
}

impl CertificateSigningMethod {
    fn generate_keypair(&self) -> Option<(rcgen::KeyPair, Option<Zeroizing<Vec<u8>>>)> {
        match self {
            Self::Rsa_Sha1 | Self::Rsa_Sha256 => {
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
            Ok(Self::Rsa_Sha256)
        } else if oid == OID_PKCS1_SHA1_RSA_ENCRYPTION.to_const() {
            Ok(Self::Rsa_Sha1)
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
            Self::Rsa_Sha1 => OID_PKCS1_SHA1_RSA_ENCRYPTION.to_owned(),
            Self::Rsa_Sha256 => OID_PKCS1_SHA256_RSA_ENCRYPTION.to_owned(),
            Self::Ecdsa => OID_ECDSA_P256_SHA256_SIGNING.to_owned(),
        }
    }
}

struct OcspRequirements {
    signature: bool,
}

impl OcspRequirements {
    fn new() -> Self {
        Self { signature: false }
    }
}

async fn build_ocsp_response(
    ca: &mut Ca,
    req: ocsp::request::OcspRequest,
) -> ocsp::response::OcspResponse {
    let mut nonce = None;
    let mut crl = None;

    let mut responses = Vec::new();
    let mut extensions = Vec::new();

    let ocsp_cert = ca.ocsp_ca_cert().unwrap();
    let root_cert = ca.root_ca_cert().unwrap();

    let x509_cert = {
        use der::Decode;
        x509_cert::Certificate::from_der(&ocsp_cert.cert).unwrap()
    };

    for r in req.tbs_request.request_list {
        let stat = ca.get_cert_status(&x509_cert, &r.certid).await;
        let resp = ocsp::response::OneResp {
            cid: r.certid,
            cert_status: stat,
            this_update: ocsp::common::asn1::GeneralizedTime::now(),
            next_update: None,
            one_resp_ext: None,
        };
        responses.push(resp);
    }
    if let Some(extensions) = req.tbs_request.request_ext {
        for e in extensions {
            match e.ext {
                ocsp::common::ocsp::OcspExt::Nonce { nonce: n } => nonce = Some(n),
                ocsp::common::ocsp::OcspExt::CrlRef { url, num, time } => {
                    crl = Some((url, num, time));
                }
            }
        }
    }

    let hash = HashType::Sha1
        .hash(
            x509_cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        )
        .unwrap();
    let id = ocsp::response::ResponderId::new_key_hash(&hash);

    if let Some(ndata) = nonce {
        let n = ndata;
        let data = ocsp::common::ocsp::OcspExt::Nonce { nonce: n }
            .to_der()
            .unwrap();
        let datas = p12::yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_der(&data);
            });
        });
        let mut exts = ocsp::common::ocsp::OcspExtI::parse(&datas).unwrap();
        extensions.append(&mut exts);
    }

    if crl.is_some() {
        panic!("Unsure what to do with crl");
    }

    let extensions = if extensions.is_empty() {
        None
    } else {
        Some(extensions)
    };

    let data = ocsp::response::ResponseData::new(
        id,
        ocsp::common::asn1::GeneralizedTime::now(),
        responses,
        extensions,
    );

    let data_der = data.to_der().unwrap();

    let (oid, sign) = ocsp_cert.sign(&data_der).await.unwrap();
    let mut certs = Vec::new();
    certs.push(ocsp_cert.cert.to_owned());
    certs.push(root_cert.cert.to_owned());
    let certs = Some(certs);

    let bresp = ocsp::response::BasicResponse::new(data, oid.to_ocsp(), sign, certs);
    let bytes =
        ocsp::response::ResponseBytes::new_basic(OID_OCSP_RESPONSE_BASIC.to_ocsp(), bresp).unwrap();
    ocsp::response::OcspResponse::new_success(bytes)
}

async fn ca_ocsp_responder(s: WebPageContext) -> webserver::WebResponse {
    let mut ca = s.ca.lock().await;

    let ocsp_request = s.post.ocsp();

    let mut ocsp_requirements = OcspRequirements::new();
    let ocsp_response = if let Some(ocsp) = ocsp_request {
        let ocsp_table = s.settings.ca.as_ref().unwrap().get("ocsp").unwrap();
        if let toml::Value::Table(t) = ocsp_table {
            let require_signature = matches!(t.get("signature").unwrap().as_str().unwrap(), "yes");
            ocsp_requirements.signature = require_signature;
        }

        if ocsp_requirements.signature {
            match ocsp.optional_signature {
                None => ocsp::response::OcspResponse::new_non_success(
                    ocsp::response::OcspRespStatus::SigRequired,
                )
                .unwrap(),
                Some(s) => {
                    println!("Signature is {:?}", s);
                    todo!("Verify signature");
                    build_ocsp_response(&mut ca, ocsp).await
                }
            }
        } else {
            build_ocsp_response(&mut ca, ocsp).await
        }
    } else {
        println!("Did not parse ocsp request");
        ocsp::response::OcspResponse::new_non_success(ocsp::response::OcspRespStatus::MalformedReq)
            .unwrap()
    };

    let der = ocsp_response.to_der().unwrap();

    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    response.headers.append(
        "Content-Type",
        HeaderValue::from_static("application/ocsp-response"),
    );

    let body = http_body_util::Full::new(hyper::body::Bytes::from(der));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

fn generic_head<'a>(
    h: &'a mut html::metadata::builders::HeadBuilder,
    s: &WebPageContext,
) -> &'a mut html::metadata::builders::HeadBuilder {
    h.title(|t| t.text("UglyOldBob Certificate Authority"));
    h.meta(|m| m.charset("UTF-8"));
    h.link(|h| {
        h.href(format!("/{}css/ca.css", s.proxy))
            .rel("stylesheet")
            .media("all")
    });
    h.link(|h| {
        h.href(format!("/{}css/ca-mobile.css", s.proxy))
            .rel("stylesheet")
            .media("screen and (max-width: 640px)")
    });
    h
}

pub fn ca_register(router: &mut WebRouter) {
    router.register("/ca", ca_main_page);
    router.register("/ca/", ca_main_page);
    router.register("/ca/get_ca.rs", ca_get_cert);
    router.register("/ca/view_cert.rs", ca_view_user_cert);
    router.register("/ca/get_cert.rs", ca_get_user_cert);
    router.register("/ca/ocsp", ca_ocsp_responder);
    router.register("/ca/request.rs", ca_request);
    router.register("/ca/submit_request.rs", ca_submit_request);
    router.register("/ca/list.rs", ca_list_requests);
    router.register("/ca/request_sign.rs", ca_sign_request);
    router.register("/ca/request_reject.rs", ca_reject_request);
}
