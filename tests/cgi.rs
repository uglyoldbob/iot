#![warn(missing_docs)]
#![allow(unused)]

//! Test code for the CGI (common gateway interface) portion of the code

use std::{net::SocketAddr, panic::AssertUnwindSafe, pin::Pin, sync::Arc};

#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/ca/ca_common.rs"]
mod ca;

#[path = "../src/main_config.rs"]
mod main_config;
use cert_common::CertificateSigningMethod;
use futures::{stream::FuturesUnordered, FutureExt};
use main_config::MainConfiguration;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};

use crate::{ca::CaCertificate, webserver::{ExtraContext, UserCerts}};

#[path = "../src/utility.rs"]
mod utility;

#[path = "../src/tpm2.rs"]
mod tpm2;

#[path = "../src/webserver/mod.rs"]
mod webserver;

/// Handle a web request
async fn handle<'a>(
    context: Arc<usize>,
    ec: ExtraContext,
    _addr: SocketAddr,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<http_body_util::Full<hyper::body::Bytes>>, Infallible> {
    let (rparts, body) = req.into_parts();

    let mut post_data: Option<hyper::body::Bytes> = None;

    let reader = BodyHandler { b: body };
    let body = reader.await;
    if let Some(Ok(b)) = body {
        if let Ok(b) = b.into_data() {
            post_data = Some(b);
        }
    }

    let post_data = PostContent::new(post_data, rparts.headers.to_owned());

    let mut get_map = HashMap::new();
    let get_data = rparts.uri.query().unwrap_or("");
    let get_split = get_data.split('&');
    for get_elem in get_split {
        let mut ele_split = get_elem.split('=').take(2);
        let i1 = ele_split.next().unwrap_or_default();
        let i2 = ele_split.next().unwrap_or_default();
        get_map.insert(i1.to_owned(), i2.to_owned());
    }

    let hdrs = rparts.headers;

    let cks_ga = hdrs.get_all("cookie");
    let mut cookiemap = HashMap::new();
    for c in cks_ga.into_iter() {
        if let Ok(c) = c.to_str() {
            for ck in c.split(';') {
                if let Ok(cookie) = Cookie::parse(ck) {
                    let (c1, c2) = cookie.name_value();
                    cookiemap.insert(c1.to_owned(), c2.to_owned());
                }
            }
        }
    }

    let response = Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let ourcookie = if cookiemap.contains_key(&context.cookiename) {
        let value = &cookiemap[&context.cookiename];
        Some(value.to_owned())
    } else {
        None
    };

    let mut user_certs = UserCerts::new();
    if let Some(uc) = ec.user_certs.as_ref() {
        for c in uc {
            user_certs.inner.push(UserCert::HttpsCert(c.to_owned()));
        }
    }

    let ssls = hdrs.get_all("ssl_client_cert");
    for ssl in ssls {
        use der::DecodePem;
        if let Ok(d) = std::str::from_utf8(ssl.as_bytes()) {
            let ssl = url_escape::decode(d);
            if let Ok(x509) = x509_cert::Certificate::from_pem(ssl.as_bytes()) {
                user_certs.inner.push(UserCert::ProxyCert(x509));
            }
        }
    }

    let mysql = context.pool.as_ref().map(|f| f.get_conn().ok()).flatten();
    service::log::debug!("URI IS \"{}\" \"{}\"", rparts.method, rparts.uri);
    let domain = hdrs
        .get("host")
        .map(|h| h.to_str().ok())
        .flatten()
        .unwrap_or_default()
        .to_string();
    service::log::debug!("Domain host is \"{}\"", domain);
    let domain2 = if let Some((a, _b)) = domain.as_str().split_once(':') {
        a.to_string()
    } else {
        domain.clone()
    };
    let path = rparts.uri.path();
    let proxy = if let Some(p) = context.proxy.get(&domain2) {
        p.to_owned()
    } else {
        String::new()
    };
    let fixed_path = path;

    let cookiename = format!("{}{}", proxy, context.cookiename);

    service::log::info!("Lookup {} on {}{}", fixed_path, domain2, proxy);

    let body = if let Some(fun) = context.dirmap.r.get(fixed_path) {
        fun.call(p).await
    } else {
        let response = hyper::Response::new("dummy");
        let (mut response, _) = response.into_parts();
        // lookup the fixed path, if it exists use it, otherwise use the path from the static map
        // This means that the static map is a fallback
        let fixed_path = if let Some(a) = context.static_map.get(fixed_path) {
            if std::path::PathBuf::from(context.root.to_owned() + fixed_path).exists() {
                fixed_path.to_string()
            } else {
                a.to_owned()
            }
        } else {
            fixed_path.to_string()
        };
        let sys_path = std::path::PathBuf::from(context.root.to_owned() + &fixed_path);
        let file = tokio::fs::read(sys_path.clone()).await;
        let body = match file {
            Ok(c) => {
                service::log::debug!("File {} loaded", sys_path.display());
                if let Some(ext) = sys_path.extension() {
                    match ext.to_str() {
                        Some("css") => {
                            response.headers.append(
                                "Content-Type",
                                hyper::header::HeaderValue::from_static("text/css"),
                            );
                        }
                        Some("js") => {
                            response.headers.append(
                                "Content-Type",
                                hyper::header::HeaderValue::from_static("text/javascript"),
                            );
                        }
                        Some("wasm") => {
                            response.headers.append(
                                "Content-Type",
                                hyper::header::HeaderValue::from_static("application/wasm"),
                            );
                        }
                        _ => {}
                    }
                }
                let body = hyper::body::Bytes::copy_from_slice(&c);
                http_body_util::Full::new(body)
            }
            Err(_e) => {
                service::log::debug!("File {} missing", sys_path.display());
                response.status = StatusCode::NOT_FOUND;
                http_body_util::Full::new(hyper::body::Bytes::from("missing"))
            }
        };

        let response = hyper::http::Response::from_parts(response, body);

        WebResponse {
            response,
            cookie: p.logincookie,
        }
    };

    //this section expires the cookie if it needs to be deleted
    //and makes the contents empty
    let sent_cookie = match body.cookie {
        Some(ref x) => {
            let testcookie: cookie::CookieBuilder = cookie::Cookie::build((&cookiename, x))
                .http_only(true)
                .path(proxy)
                .same_site(cookie::SameSite::Strict);
            testcookie
        }
        None => {
            let testcookie: cookie::CookieBuilder = cookie::Cookie::build((&cookiename, ""))
                .http_only(true)
                .path(proxy)
                .expires(time::OffsetDateTime::UNIX_EPOCH)
                .same_site(cookie::SameSite::Strict);
            testcookie
        }
    };

    if let Ok(h) = hyper::http::header::HeaderValue::from_str(&sent_cookie.to_string()) {
        response.headers.append("Set-Cookie", h);
    }
    Ok(body.response)
}

async fn load_certificate(
    https: &ca::HttpsCertificate,
    rcs: Option<RootCertStore>,
    certs: Vec<CaCertificate>,
    require_cert: bool,
) -> Result<Arc<tokio_rustls::rustls::ServerConfig>, Box<dyn std::error::Error + 'static>> {
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    let pkey_der = https
        .get_private()
        .expect("Access to the https private is required right now");
    let pkey = PrivatePkcs8KeyDer::from(pkey_der.to_owned());
    let pkey = PrivateKeyDer::Pkcs8(pkey);
    let cert_der = &https.cert;
    let c1 = CertificateDer::from(cert_der.to_owned());

    let certs = vec![c1];

    let sc: tokio_rustls::rustls::ConfigBuilder<ServerConfig, tokio_rustls::rustls::WantsVerifier> =
        ServerConfig::builder();

    let mut rcs2 = if rcs.is_none() {
        RootCertStore::empty()
    } else {
        rcs.clone().unwrap()
    };

    if rcs.is_none() {
        for cert in certs {
            let cert_der = cert.contents().unwrap(); //TODO remove this unwrap
            rcs2.add(cert_der.into()).unwrap();
        }
    }

    let roots = Arc::new(rcs2);

    let client_verifier = if !require_cert {
        WebPkiClientVerifier::builder(roots)
            .allow_unauthenticated()
            .build()
            .unwrap()
    } else {
        WebPkiClientVerifier::builder(roots).build().unwrap()
    };

    let sc = sc.with_client_cert_verifier(client_verifier);
    let sc = sc.with_single_cert(certs, pkey)?;
    Ok(Arc::new(sc))
}

/// Start the webserver, this is mostly a duplicate of the https_webserver function from the webserver module
async fn start_webserver(
    https: crate::main_config::HttpsSettings,
    https_cert: cert_common::CertificateSigningMethod,
    port: u16,
    tasks: &mut tokio::task::JoinSet<Result<(), webserver::ServiceError>>,
) -> Result<(), webserver::ServiceError> {
    let tls_cert = https.certificate.to_owned();
    let https_cert = tls_cert.get_usable();

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let cert = load_certificate(&https_cert, None, vec![], false).await.map_err(|e| {
        service::log::error!("Error loading https certificate {}", e);
        webserver::ServiceError::Other(e.to_string())
    })?;

    let acc: tokio_rustls::TlsAcceptor = cert.into();
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| webserver::ServiceError::Other(e.to_string()))?;

    let webservice = webserver::WebService::new(Arc::new(42), true, addr, handle);

    tasks.spawn(async move {
        service::log::info!("Rust-iot https server is running");

        let mut f: FuturesUnordered<Pin<Box<dyn futures::Future<Output = ()> + Send>>> =
            FuturesUnordered::new();

        let (t, mut r) = tokio::sync::mpsc::channel(50);

        let acceptor = async {
            loop {
                let la = listener
                    .accept()
                    .await
                    .map_err(|e| webserver::ServiceError::Other(e.to_string()));
                let (stream, addr) = match la {
                    Err(e) => {
                        service::log::error!("Error accepting connection {:?}", e);
                        continue;
                    }
                    Ok(s) => s,
                };

                let stream = acc.accept(stream).await;
                let mut stream = match stream {
                    Err(e) => {
                        service::log::error!("Error accepting tls stream: {:?}", e);
                        continue;
                    }
                    Ok(s) => s,
                };
                let (_a, b) = stream.get_mut();
                let mut svc = webservice.clone();
                svc.addr = addr;
                let cert = b.peer_certificates();
                let sn = b.server_name();
                service::log::info!("Server name is {:?}", sn);
                let certs = cert.map(|cder| {
                    let certs: Vec<x509_cert::certificate::Certificate> = cder
                        .iter()
                        .filter_map(|c| {
                            use der::Decode;
                            x509_cert::Certificate::from_der(c).ok()
                        })
                        .collect();
                    certs
                });
                svc.user_certs = Arc::new(certs);
                let io = webserver::TokioIo::new(stream);
                let _ = t.send((svc, io)).await;
            }
        };

        tokio::pin!(acceptor);

        loop {
            use futures::StreamExt;
            tokio::select! {
                _ = &mut acceptor => { break; }
                Some((svc, io)) = r.recv() => {
                    f.push(Box::pin(async move {
                        if let Err(err) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, svc)
                            .await
                        {
                            service::log::error!("Error serving connection: {:?}", err);
                        }
                    }));
                }
                Ok(Some(_)) = AssertUnwindSafe(f.next()).catch_unwind() => { }
                _ = tokio::signal::ctrl_c() => break,
                else => break,
            }
        }
        Ok(())
    });

    Ok(())
}

#[tokio::test]
async fn cgi_test1() {}
