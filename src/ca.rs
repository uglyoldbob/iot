//! Handles certificate authority functionality

use std::path::PathBuf;

use hyper::header::HeaderValue;
use zeroize::Zeroizing;

use crate::{webserver, WebPageContext, WebRouter};

use crate::oid::*;

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
    fn new(url: String) -> Self {
        let asn = p12::yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_sequence(|w| {
                    w.next().write_oid(&OID_OCSP.to_yasna());
                    let d = p12::yasna::models::TaggedDerValue::from_tag_and_bytes(
                        p12::yasna::Tag::context(6),
                        url.as_bytes().to_vec(),
                    );
                    w.next().write_tagged_der(&d);
                });
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
            CertificateSigningMethod::Rsa_Sha256 => {
                todo!();
            }
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

    fn get_csr_by_id(&self, id: usize) -> Option<CsrRequest> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::FilesystemDer(p) => {
                use std::io::Read;
                let pb = p.join("csr");
                let path = pb.join(format!("{}.toml", id));
                let mut f = std::fs::File::open(path).ok().unwrap();
                let mut cert = Vec::with_capacity(f.metadata().unwrap().len() as usize);
                f.read_to_end(&mut cert).unwrap();
                toml::from_str(std::str::from_utf8(&cert).unwrap()).ok()
            }
        }
    }

    async fn save_csr(&mut self, csr: &CsrRequest) {
        use tokio::io::AsyncWriteExt;
        match &self.medium {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::FilesystemDer(p) => {
                let pb = p.join("csr");
                std::fs::create_dir_all(&pb);
                let pf = std::fs::read_dir(&pb).unwrap();
                let mut highest = 0;
                for f in pf {
                    if let Ok(ent) = f {
                        if ent.file_type().unwrap().is_file() {
                            let name = ent.file_name();
                            let i = str::parse(name.to_str().unwrap()).unwrap();
                            if i > highest {
                                highest = i;
                            }
                        }
                    }
                }
                highest += 1;
                let cp = pb.join(format!("{}.toml", highest));
                let mut cf = tokio::fs::File::create(cp).await.unwrap();
                let csr_doc = toml::to_string(csr).unwrap();
                cf.write_all(csr_doc.as_bytes()).await;
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
        }
    }

    /// Initialize the ca root certificates if necessary and configured to do so by the configuration
    pub async fn load_and_init(settings: &crate::MainConfiguration) -> Self {
        let mut ca = Self::from_config(settings);
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
                                println!("Generating a root certificate for ca operations");
                                let san: Vec<String> = san
                                    .iter()
                                    .map(|e| e.as_str().unwrap().to_string())
                                    .collect();
                                let mut certparams = rcgen::CertificateParams::new(san);
                                certparams.alg = rcgen::SignatureAlgorithm::from_oid(
                                    &OID_ECDSA_P256_SHA256_SIGNING.components(),
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
                                    PkixAuthorityInfoAccess::new(Self::get_ocsp_url(settings));
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
                            }
                        }
                    }
                }
            }
        }
        ca
    }

    /// Return a reference to the root cert
    async fn root_ca_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.root_cert.as_ref()
    }

    /// Load the root ca cert from the specified storage media, converting to der as required.
    async fn load_root_ca_cert(&mut self) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.root_cert.is_err() {
            self.root_cert = self.medium.load_from_medium("root").await;
        }
        self.root_cert.as_ref()
    }

    /// Returns the ocsp url, based on the application settings, preferring https over http
    pub fn get_ocsp_url(settings: &crate::MainConfiguration) -> String {
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

        let n = settings
            .ca
            .as_ref()
            .unwrap()
            .get("ocsp_url")
            .unwrap()
            .as_str()
            .unwrap();
        url.push_str(n);
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

        url
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
                std::fs::create_dir_all(&p);
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
                    CertificateSigningMethod::Ecdsa,
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
                todo!("Sign with rsa-sha256");
            }
        }
    }
}

async fn ca_submit_request(s: WebPageContext) -> webserver::WebResponse {
    let mut ca = s.ca.lock().await;

    let mut valid_csr = false;

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
                    ca.save_csr(&csrr).await;
                }
            }
        }
    }

    let mut html = html::root::Html::builder();
    html.head(|h| generic_head(h, &s)).body(|b| {
        if valid_csr {
            b.text("Your request has been submitted").line_break(|f| f);
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
        b.button(|b| b.text("Generate 2").onclick("generate_cert()"));
        b.line_break(|lb| lb);
        b.division(|div| {
            div.class("hidden");
            div.form(|f| {
                f.name("request");
                f.action(format!("/{}ca/submit_request.rs", s.proxy));
                f.method("post");
                f.text("Name")
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
                f.text("CSR")
                    .line_break(|a| a)
                    .text_area(|i| i.id("csr").name("csr"))
                    .line_break(|a| a);
                f.input(|i| i.type_("submit").id("submit"))
                    .line_break(|a| a);
                f
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
                            ab.text("View this request");
                            ab.href(format!("/{}ca/list.rs?id={}", s.proxy, id));
                            ab
                        })
                        .line_break(|a| a);
                        b.text(t).line_break(|a| a);
                        b.text(format!("Name: {}", csrr.name)).line_break(|a| a);
                        b.text(format!("Email: {}", csrr.email)).line_break(|a| a);
                        b.text(format!("Phone: {}", csrr.phone)).line_break(|a| a);
                        for attr in csr.info.attributes.iter() {
                            b.text(format!("{:?}: ", attr.oid)).line_break(|a| a);
                            for p in attr.values.iter() {
                                b.text(format!("\t{:?}", p)).line_break(|a| a);
                            }
                        }
                    }
                }
            }
        } else {
            b.text("List all pending requests");
            b.line_break(|a| a);
            for (csrr, id) in ca.get_csr_iter() {
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

/// Runs the page for fetching the ca certificate for the certificate authority being run
async fn ca_get_cert(s: WebPageContext) -> webserver::WebResponse {
    let ca = s.ca.lock().await;

    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;

    if let Ok(cert_der) = ca.root_ca_cert().await {
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

    let ca_cert = ca.root_ca_cert().await.unwrap();

    let x509_cert = {
        use der::Decode;
        x509_cert::Certificate::from_der(&ca_cert.cert).unwrap()
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

    let (oid, sign) = ca_cert.sign(&data_der).await.unwrap();
    let cert = Some(ca_cert.cert.to_owned());

    let bresp = ocsp::response::BasicResponse::new(data, oid.to_ocsp(), sign, cert);
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
    router.register("/ca/ocsp", ca_ocsp_responder);
    router.register("/ca/request.rs", ca_request);
    router.register("/ca/submit_request.rs", ca_submit_request);
    router.register("/ca/list.rs", ca_list_requests);
}
