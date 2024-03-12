//! Handles certificate authority functionality

use std::default;
use std::path::PathBuf;

use cms::cert;
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
                    w.next().write_oid(&OID_OCSP);
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

/// Errors that can occur when attempting to load a certificate
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
            .get("ocsp")
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
                                    OID_ECDSA_P256_SHA256_SIGNING.components(),
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
                                    OID_PKIX_AUTHORITY_INFO_ACCESS.components(),
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

pub fn ca_register(router: &mut WebRouter) {
    router.register("/ca", ca_main_page);
    router.register("/ca/get_ca.rs", ca_get_cert);
}
