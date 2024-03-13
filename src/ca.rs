//! Handles certificate authority functionality

use std::path::PathBuf;

use hyper::header::HeaderValue;

use crate::{webserver, WebPageContext, WebRouter};

use crate::oid::*;

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
        println!("DER for pkix is following:");
        for b in &asn {
            print!("{:02X} ", b);
        }
        println!("");
        Self { der: asn }
    }
}

/// Specifies how to access ca certificates on a ca
pub enum CaCertificateStorage {
    /// The certificates are stored nowhere. Used for testing.
    Nowhere,
    /// The certificates are stored on a filesystem, in der format, private key and certificate in separate files
    FilesystemDer(PathBuf),
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
enum CertificateLoadingError {
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

impl CaCertificateStorage {
    /// Create a Self from the application configuration
    fn from_config(settings: &crate::MainConfiguration) -> Self {
        if let Some(section) = &settings.ca {
            if section.contains_key("path") {
                return Self::FilesystemDer(section.get("path").unwrap().as_str().unwrap().into());
            }
        }
        Self::Nowhere
    }

    /// Retrieves a certificate, if it is valid, or a reason for it to be invalid
    /// # Arguments
    /// * serial - The serial number of the certificate
    async fn get_cert_by_serial(
        &self,
        _serial: &[u8],
    ) -> MaybeError<x509_cert::Certificate, ocsp::response::RevokedInfo> {
        match self {
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

    /// Save the root certificate to the storage method
    async fn save_root_cert(&self, der: &[u8]) {
        match self {
            Self::Nowhere => {}
            Self::FilesystemDer(p) => {
                use tokio::io::AsyncWriteExt;
                let mut cp = p.clone();
                cp.push("root_cert.der");
                let mut cf = tokio::fs::File::create(cp).await.unwrap();
                cf.write_all(der).await;
            }
        }
    }

    /// Save the root private key to the storage method
    async fn save_root_key(&self, der: &[u8]) {
        match self {
            Self::Nowhere => {}
            Self::FilesystemDer(p) => {
                use tokio::io::AsyncWriteExt;
                let mut cp = p.clone();
                cp.push("root_key.der");
                let mut cf = tokio::fs::File::create(cp).await.unwrap();
                cf.write_all(der).await;
            }
        }
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
            settings.https.get("enabled").unwrap().as_str().unwrap(),
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

    /// Initialize the ca root certificates if necessary and configured to do so by the configuration
    pub async fn load_and_init(settings: &crate::MainConfiguration) -> Self {
        let ca = Self::from_config(settings);
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
                                ca.save_root_cert(&cert_der).await;
                                let key_der = cert.get_key_pair().serialize_der();
                                ca.save_root_key(&key_der).await;
                            }
                        }
                    }
                }
            }
        }
        ca
    }

    /// Load the root ca cert and private key from the specified storage media, converting to der as required.
    async fn load_root_ca_cert(&self) -> Result<der::Document, CertificateLoadingError> {
        match self {
            CaCertificateStorage::Nowhere => Err(CertificateLoadingError::DoesNotExist),
            CaCertificateStorage::FilesystemDer(p) => {
                use der::Decode;
                use tokio::io::AsyncReadExt;
                let mut certp = p.clone();
                certp.push("root_cert.der");
                let mut f = tokio::fs::File::open(certp).await?;
                let mut cert = Vec::with_capacity(f.metadata().await.unwrap().len() as usize);
                f.read_to_end(&mut cert).await?;
                let cert = der::Document::from_der(&cert)
                    .map_err(|_e| CertificateLoadingError::InvalidCert)?;
                Ok(cert)
            }
        }
    }
}

///The main landing page for the certificate authority
async fn ca_main_page(s: WebPageContext) -> webserver::WebResponse {
    let mut html = html::root::Html::builder();
    html.head(|h| h.title(|t| t.text("UglyOldBob Certificate Authority")))
        .body(|b| {
            b.anchor(|ab| {
                ab.text("Download CA certificate as der");
                ab.href("/ca/get_ca.rs?type=der");
                ab.target("_blank");
                ab
            });
            b.line_break(|lb| lb);
            b.anchor(|ab| {
                ab.text("Download CA certificate as pem");
                ab.href("/ca/get_ca.rs?type=pem");
                ab.target("_blank");
                ab
            });
            b.line_break(|lb| lb);
            b.ordered_list(|ol| {
                for name in ["I", "am", "groot"] {
                    ol.list_item(|li| li.text(name));
                }
                ol
            })
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
    let ca = CaCertificateStorage::from_config(&s.settings);

    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;

    if let Ok(cert_der) = ca.load_root_ca_cert().await {
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
                cert = Some(cert_der.to_vec());
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
                if let Ok(pem) = cert_der.to_pem("CERTIFICATE", pkcs8::LineEnding::CRLF) {
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

/// How the signature is generated for an ocsp response
enum OcspResponseDigestMethod {
    /// The digest is sha256 and rsa
    Sha256Rsa,
}

impl OcspResponseDigestMethod {
    fn algorithm(&self) -> ocsp::common::asn1::Oid {
        match self {
            OcspResponseDigestMethod::Sha256Rsa => PKCS1_SHA256_RSA_ENCRYPTED.to_ocsp(),
        }
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            OcspResponseDigestMethod::Sha256Rsa => sha256::digest(data).as_bytes().to_vec(),
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
    ca: CaCertificateStorage,
    req: ocsp::request::OcspRequest,
) -> ocsp::response::OcspResponse {
    let mut nonce = None;
    let mut crl = None;

    let mut responses = Vec::new();
    let mut extensions = Vec::new();

    let ca_cert = ca.load_root_ca_cert().await.unwrap();

    let x509_cert = {
        use der::Decode;
        x509_cert::Certificate::from_der(ca_cert.as_bytes()).unwrap()
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
    let method = OcspResponseDigestMethod::Sha256Rsa;
    let sign = method.sign(&data_der);
    let cert = Some(ca_cert.as_bytes().to_vec());

    let bresp = ocsp::response::BasicResponse::new(data, method.algorithm(), sign, cert);
    let bytes =
        ocsp::response::ResponseBytes::new_basic(OID_OCSP_RESPONSE_BASIC.to_ocsp(), bresp).unwrap();
    ocsp::response::OcspResponse::new_success(bytes)
}

async fn ca_ocsp_responder(s: WebPageContext) -> webserver::WebResponse {
    let ca = CaCertificateStorage::from_config(&s.settings);

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
                    build_ocsp_response(ca, ocsp).await
                }
            }
        } else {
            build_ocsp_response(ca, ocsp).await
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

pub fn ca_register(router: &mut WebRouter) {
    router.register("/ca", ca_main_page);
    router.register("/ca/get_ca.rs", ca_get_cert);
    router.register("/ca/ocsp", ca_ocsp_responder);
}
