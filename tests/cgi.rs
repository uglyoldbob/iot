#![warn(missing_docs)]
#![allow(unused)]

//! Test code for the CGI (common gateway interface) portion of the code

use std::{
    collections::HashMap, io::Write, net::SocketAddr, panic::AssertUnwindSafe, pin::Pin,
    process::Stdio, sync::Arc,
};

#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/ca/ca_common.rs"]
mod ca;

#[path = "../src/main_config.rs"]
mod main_config;
use cert_common::CertificateSigningMethod;
use cookie::Cookie;
use futures::Future;
use futures::{stream::FuturesUnordered, FutureExt};
use hyper::{Request, Response};
use main_config::MainConfiguration;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::convert::Infallible;
use tokio::io::{AsyncReadExt, BufReader};
use tokio_rustls::rustls::{server::WebPkiClientVerifier, RootCertStore, ServerConfig};

use crate::{
    ca::CaCertificate,
    main_config::HttpsSettings,
    webserver::{ExtraContext, UserCert, UserCerts, WebHandlerTrait, WebResponse, WebRouter},
};

#[path = "../src/utility.rs"]
mod utility;

#[path = "../src/tpm2.rs"]
mod tpm2;

#[path = "../src/webserver/mod.rs"]
mod webserver;

/// The context necessary to respond to a web request.
struct HttpContext {
    /// The map that is used to route requests to the proper async function.
    pub dirmap: WebRouter<WebRequest>,
}

struct WebRequest {
    data: hyper::body::Bytes,
}

struct CgiCaller {
    name: String,
}

impl CgiCaller {
    fn get_cmd(&self, req: WebRequest) -> tokio::process::Command {
        let mut p = tokio::process::Command::new(&self.name);
        p.stderr(Stdio::piped());
        p.stdin(Stdio::piped());
        p.stdout(Stdio::piped());
        p.env("SERVER_NAME", "127.0.0.1")
            .env("GATEWAY_INTERFACE", "CGI/1.1")
            .env("SERVER_PROTOCOL", "HTTP/1.1")
            .env("SERVER_PORT", "3000")
            .env("REQUEST_METHOD", "GET")
            .env("SCRIPT_NAME", &self.name)
            .env("QUERY_STRING", &self.name)
            .env("REMOTE_ADDR", "11.11.11.11")
            .env("AUTH_TYPE", "")
            .env("REMOTE_USER", "")
            .env("CONTENT_TYPE", "text")
            .env("HTTP_CONTENT_ENCODING", "unknown")
            .env("CONTENT_LENGTH", "0");
        p
    }
}

impl WebHandlerTrait<WebRequest> for CgiCaller {
    fn call(&self, req: WebRequest) -> Pin<Box<dyn Future<Output = WebResponse> + Send + Sync>> {
        let data = req.data.clone();
        let mut cmd = self.get_cmd(req);

        Box::pin(async move {
            match cmd.spawn() {
                Ok(mut c) => {
                    let Some(mut stdin) = c.stdin.as_mut() else {
                        return WebResponse {
                            response: Response::new(http_body_util::Full::new(
                                hyper::body::Bytes::from("no stdin"),
                            )),
                            cookie: None,
                        };
                    };
                    let Some(stdout) = c.stdout.as_mut() else {
                        return WebResponse {
                            response: Response::new(http_body_util::Full::new(
                                hyper::body::Bytes::from("no stdout"),
                            )),
                            cookie: None,
                        };
                    };
                    let Some(mut stderr) = c.stderr.as_mut() else {
                        return WebResponse {
                            response: Response::new(http_body_util::Full::new(
                                hyper::body::Bytes::from("no stderr"),
                            )),
                            cookie: None,
                        };
                    };
                    let mut req_body =
                        tokio_util::io::StreamReader::new(tokio_stream::iter(vec![Ok::<
                            hyper::body::Bytes,
                            std::io::Error,
                        >(
                            data
                        )]));

                    let mut stdout = BufReader::new(stdout);
                    let mut err_output = vec![];
                    let read_stderr = async { stderr.read_to_end(&mut err_output).await };
                    let read_stdout = async {
                        use std::str::FromStr;
                        use tokio::io::AsyncBufReadExt;
                        let mut response = Response::builder();
                        let mut data = vec![];
                        let mut line = String::new();
                        while stdout.read_line(&mut line).await.unwrap_or(0) > 0 {
                            line = line
                                .trim_end_matches("\n")
                                .trim_end_matches("\r")
                                .to_owned();

                            let l: Vec<&str> = line.splitn(2, ": ").collect();
                            if l.len() < 2 {
                                break;
                            }
                            if l[0] == "Status" {
                                response = response.status(
                                    hyper::StatusCode::from_u16(
                                        u16::from_str(l[1].split(" ").next().unwrap_or("500"))
                                            .unwrap_or(500),
                                    )
                                    .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR),
                                );
                            } else {
                                response = response.header(l[0], l[1]);
                            }
                            line = String::new();
                        }
                        stdout.read_to_end(&mut data).await?;
                        response.body(data).map_err(|a| {
                            std::io::Error::new(std::io::ErrorKind::Other, a.to_string())
                        })
                    };
                    let write_stdin = async { tokio::io::copy(&mut req_body, &mut stdin).await };

                    if let Ok((_, _, a)) = tokio::try_join!(write_stdin, read_stderr, read_stdout) {
                        return WebResponse {
                            response: Response::new(http_body_util::Full::new(
                                hyper::body::Bytes::from(a.body().to_vec()),
                            )),
                            cookie: None,
                        };
                    } else {
                        return WebResponse {
                            response: Response::new(http_body_util::Full::new(
                                hyper::body::Bytes::from("failed to read cgi output"),
                            )),
                            cookie: None,
                        };
                    }
                }
                Err(e) => WebResponse {
                    response: Response::new(http_body_util::Full::new(hyper::body::Bytes::from(
                        format!("unknown error 1: {}", e),
                    ))),
                    cookie: None,
                },
            }
        })
    }
}

/// Handle a web request
async fn handle<'a>(
    context: Arc<HttpContext>,
    ec: ExtraContext,
    _addr: SocketAddr,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<http_body_util::Full<hyper::body::Bytes>>, Infallible> {
    let (rparts, body) = req.into_parts();

    let mut post_data: Option<hyper::body::Bytes> = None;

    let reader = webserver::BodyHandler { b: body };
    let body = reader.await;
    if let Some(Ok(b)) = body {
        if let Ok(b) = b.into_data() {
            post_data = Some(b);
        }
    }
    let webrequest_data = post_data.clone().unwrap_or_default();

    let post_data = webserver::PostContent::new(post_data, rparts.headers.to_owned());

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
    let fixed_path = path;

    service::log::info!("Lookup {} on {}", fixed_path, domain2);

    let body = if let Some(fun) = context.dirmap.r.get(fixed_path) {
        fun.call(WebRequest {
            data: webrequest_data,
        })
        .await
    } else {
        let response = hyper::Response::new("dummy");
        let (mut response, _) = response.into_parts();
        let sys_path = std::path::PathBuf::from(&format!("./{}", fixed_path));
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
                response.status = hyper::StatusCode::NOT_FOUND;
                http_body_util::Full::new(hyper::body::Bytes::from("missing"))
            }
        };

        let response = hyper::http::Response::from_parts(response, body);

        WebResponse {
            response,
            cookie: None,
        }
    };

    Ok(body.response)
}

async fn load_certificate(
    https: &ca::HttpsCertificate,
    rcs: Option<RootCertStore>,
    listcerts: Vec<CaCertificate>,
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
        for cert in listcerts {
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
    ca_cert: CaCertificate,
    https_cert: cert_common::CertificateSigningMethod,
    port: u16,
    tasks: &mut tokio::task::JoinSet<Result<(), webserver::ServiceError>>,
    hc: HttpContext,
) -> Result<(), webserver::ServiceError> {
    let tls_cert = https.certificate.to_owned();
    let https_cert = tls_cert.get_usable();

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let cert = load_certificate(&https_cert, None, vec![ca_cert], false)
        .await
        .map_err(|e| {
            service::log::error!("Error loading https certificate {}", e);
            webserver::ServiceError::Other(e.to_string())
        })?;

    let acc: tokio_rustls::TlsAcceptor = cert.into();
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| webserver::ServiceError::Other(e.to_string()))?;

    let webservice = webserver::WebService::new(Arc::new(hc), true, addr, handle);

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

async fn build_https_server() -> (
    HttpsSettings,
    CaCertificate,
    CertificateSigningMethod,
    u16,
    tokio::task::JoinSet<Result<(), webserver::ServiceError>>,
) {
    let port = 3000;

    let (key_pair, pkey) = cert_common::HttpsSigningMethod::RsaSha256
        .generate_keypair(4096)
        .unwrap();
    let mut certparams = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    certparams.distinguished_name = rcgen::DistinguishedName::new();
    certparams
        .distinguished_name
        .push(rcgen::DnType::CommonName, "127.0.0.1");
    certparams.not_before = time::OffsetDateTime::now_utc();
    certparams.not_after = certparams.not_before + time::Duration::days(5i64);
    let basic_constraints = rcgen::BasicConstraints::Constrained(2);
    certparams.is_ca = rcgen::IsCa::Ca(basic_constraints);
    use crate::hsm2::KeyPairTrait;
    let cert = certparams.self_signed(&key_pair).unwrap();
    let cert_der = cert.der().to_owned();

    let cert = CaCertificate::from_existing_https(
        cert_common::HttpsSigningMethod::RsaSha256,
        ca::CaCertificateStorage::Nowhere,
        &cert_der,
        ca::Keypair::NotHsm(pkey),
        "https".to_string(),
        0,
    );
    let password = "whocares";
    let certpath = std::path::PathBuf::from("./https.p12");
    let p12 = cert
        .try_p12(password)
        .expect("Failed to build https p12 cert");
    {
        let mut f = std::fs::File::create(&certpath).unwrap();
        f.write_all(&p12);
    }

    let https = HttpsSettings {
        certificate: main_config::HttpsCertificateLocation::Existing {
            path: certpath,
            password: password.to_string(),
        },
        port,
        require_certificate: false,
    };
    let https_cert = CertificateSigningMethod::Https(cert_common::HttpsSigningMethod::RsaSha256);
    let mut tasks = tokio::task::JoinSet::new();
    (https, cert, https_cert, port, tasks)
}

#[tokio::test]
async fn cgi_test1() {
    let mut dirmap = WebRouter::new();

    dirmap.direct_register(
        "/rust-iot.cgi",
        CgiCaller {
            name: assert_cmd::cargo::cargo_bin!("rust-iot-cgi")
                .display()
                .to_string(),
        },
    );
    let hc = HttpContext { dirmap };
    let (https, cert, https_cert, port, mut tasks) = build_https_server().await;
    let c = cert.contents().unwrap();
    let rcert = reqwest::Certificate::from_der(c.as_ref()).unwrap();
    start_webserver(https, cert, https_cert, port, &mut tasks, hc)
        .await
        .expect("Failed to start webserver");
    let data = reqwest::Client::builder()
        .add_root_certificate(rcert.clone())
        .build()
        .unwrap()
        .get("https://127.0.0.1:3000/rust-iot.cgi")
        .send()
        .await
        .expect("Failed to get main url")
        .bytes()
        .await
        .expect("No content");
    println!("Webserver is ready");
    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
}
