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
    fn from_config(config: &configparser::ini::Ini) -> Option<Self> {
        None
    }

    /// Load the root ca cert and private key from the specified storage media
    async fn load_root_ca(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        match self {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::FilesystemDer(p) => {
                use tokio::io::AsyncReadExt;
                let mut certp = p.clone();
                certp.push("root_cert.der");
                let mut pkeyp = p.clone();
                pkeyp.push("root_key.der");
                let f = tokio::fs::File::open(certp).await;
                let mut f = f.ok()?;
                let mut cert = Vec::with_capacity(f.metadata().await.unwrap().len() as usize);
                f.read_to_end(&mut cert).await.ok()?;

                let f = tokio::fs::File::open(pkeyp).await;
                let mut f = f.ok()?;
                let mut pkey = Vec::with_capacity(f.metadata().await.unwrap().len() as usize);
                f.read_to_end(&mut pkey).await.ok()?;

                Some((cert, pkey))
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
    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let mut cert: Option<&[u8]> = None;

    println!("GET IS {:?}", s.get);
    if s.get.contains_key("type") {
        let ty = s.get.get("type").unwrap();
        println!("type is {}", ty);
        match ty.as_str() {
            "der" => {
                response.headers.append(
                    "Content-Type",
                    HeaderValue::from_static("application/x509-ca-cert"),
                );
                cert = Some(&[1, 2, 3, 4]);
            }
            "pem" => {
                response.headers.append(
                    "Content-Type",
                    HeaderValue::from_static("application/x-pem-file"),
                );
                cert = Some("asdffdsa".as_bytes());
            }
            _ => {}
        }
    }

    let body = if let Some(cert) = cert {
        http_body_util::Full::new(hyper::body::Bytes::from_static(cert))
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
