//! Handles certificate authority functionality

use std::path::PathBuf;

use hyper::header::HeaderValue;

use crate::{webserver, WebPageContext, WebRouter};

/// Specifies how to access ca certificates on a ca
enum CaCertificateStorage {
    /// The certificates are stored nowhere. Used for testing.
    Nowhere,
    /// The certificates are stored on a filesystem, in der format, private key and certificate in separate files
    FilesystemDer(PathBuf),
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

    /// Load the root ca cert and private key from the specified storage media, converting to der as required.
    async fn load_root_ca_cert(&self) -> Option<der::Document> {
        match self {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::FilesystemDer(p) => {
                use der::Decode;
                use tokio::io::AsyncReadExt;
                let mut certp = p.clone();
                certp.push("root_cert.der");
                let f = tokio::fs::File::open(certp).await;
                let mut f = f.ok()?;
                let mut cert = Vec::with_capacity(f.metadata().await.unwrap().len() as usize);
                f.read_to_end(&mut cert).await.ok()?;
                let cert = der::Document::from_der(&cert).ok()?;
                Some(cert)
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
                ab.text("Download CA certificate");
                ab.href("/ca/get_ca.rs?type=der");
                ab.target("_blank");
                ab
            });
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

    if let Some(cert_der) = ca.load_root_ca_cert().await {
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
