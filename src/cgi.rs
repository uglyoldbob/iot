//! The main cgi application for the pki instance run on a web server

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(unused_extern_crates)]
#![allow(unused)]
//For the html crate
#![recursion_limit = "512"]

mod ca;
mod hsm2;
mod tpm2;
mod utility;
mod webserver;

mod main_config;
use der::DecodePem;
use http_body_util::BodyExt;
pub use main_config::MainConfiguration;

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

use crate::webserver::{PostContent, UserCert};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    cgi::handle_async(async |request: cgi::Request| -> cgi::Response {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("off"))
            .target(env_logger::Target::Stdout)
            .init();
        let Ok(mut config) = std::fs::File::open("./config.bin") else {
            return cgi::html_response(500, "Invalid configuration 1");
        };
        let mut contents = Vec::new();
        if config.read_to_end(&mut contents).is_err() {
            return cgi::html_response(500, "Invalid configuration 2");
        }
        let mut password_combined: Option<Vec<u8>> = None;
        let settings =
            MainConfiguration::load("./".into(), "default", contents, &mut password_combined).await;
        if true {
            service::log::info!("Config is {:#?}<br />\n", settings);
        }

        let post_data = request.body().clone();
        let post_data = hyper::body::Bytes::from(post_data);
        let mut headers = hyper::HeaderMap::new();
        for a in request.headers().iter() {
            headers.insert(a.0, a.1.clone());
        }
        let post_data = PostContent::new(Some(post_data), headers);
        let admin_csr = {
            let f = std::fs::File::open("./admin.csr").ok();
            if let Some(mut f) = f {
                let mut s = String::new();
                let Ok(_a) = f.read_to_string(&mut s) else {
                    return cgi::html_response(500, "FAILED to read admin csr contents");
                };
                Some(s)
            } else {
                return cgi::html_response(
                    500,
                    format!(
                        "FAILED to read open csr contents {}",
                        std::env::current_dir().unwrap().display()
                    ),
                );
            }
        };
        eprintln!("Init hsm");
        let hsm = match settings
            .pki
            .init_hsm(&"./".into(), "default", &settings, admin_csr.as_ref())
            .await
        {
            Ok(h) => h,
            Err(e) => {
                return cgi::html_response(500, format!("FAILED to init hsm {:?}", e));
            }
        };
        eprintln!("Loading pki instance");
        let pki = match ca::PkiInstance::load(hsm.clone(), &settings).await {
            Ok(e) => e,
            Err(e) => return cgi::html_response(500, format!("Failed to load pki - {:?}", e)),
        };
        let pki = Arc::new(futures_util::lock::Mutex::new(pki));

        let get_map = {
            let mut get_map = HashMap::new();
            let get_data = request.headers().get("x-cgi-query-string");
            if let Some(get_data) = get_data {
                if let Ok(get_data) = get_data.to_str() {
                    let get_split = get_data.split('&');
                    for get_elem in get_split {
                        let mut ele_split = get_elem.split('=').take(2);
                        let i1 = ele_split.next().unwrap_or_default();
                        let i2 = ele_split.next().unwrap_or_default();
                        get_map.insert(i1.to_owned(), i2.to_owned());
                    }
                }
            }
            get_map
        };

        let post_map = {
            let mut get_map = HashMap::new();
            if let Some(c) = request.headers().get("x-cgi-content-type") {
                if let Ok(c) = c.to_str() {
                    if "application/x-www-form-urlencoded" == c {
                        let body = request.body();
                        let a: String = String::from_utf8(body.clone()).unwrap_or_default();
                        let get_data = a;
                        let get_data = get_data;
                        let get_split = get_data.split('&');
                        for get_elem in get_split {
                            let mut ele_split = get_elem.split('=').take(2);
                            let i1 = ele_split.next().unwrap_or_default();
                            let i2 = ele_split.next().unwrap_or_default();
                            let s = urlencoding::decode(i2)
                                .unwrap_or_default()
                                .into_owned()
                                .to_string();
                            get_map.insert(i1.to_owned(), s);
                        }
                    }
                }
            }
            get_map
        };

        let mut ucerts = webserver::UserCerts::new();
        if let Ok(cert) = std::env::var("SSL_CLIENT_CERT") {
            if let Ok(c) = x509_cert::Certificate::from_pem(cert) {
                ucerts.inner.push(UserCert::HttpsCert(c));
            }
        }

        let domain = request
            .headers()
            .get("host")
            .map(|h| h.to_str().ok())
            .flatten()
            .unwrap_or_default();

        let p = crate::webserver::WebPageContext {
            delivery: main_config::PageDelivery::Cgi,
            https: true,
            domain: domain.to_string(),
            page: request.uri().to_string().into(),
            post: post_data,
            get: get_map.clone(),
            proxy: String::new(),
            logincookie: None,
            pool: None,
            user_certs: ucerts,
            pki_type: settings.pki.clone().into(),
            pki: pki.clone(),
        };

        match get_map.get("action").map(|a| a.as_str()) {
            Some("download_ca") => {
                let resp = ca::ca_get_cert(p).await;
                let b = resp
                    .response
                    .clone()
                    .into_body()
                    .collect()
                    .await
                    .unwrap_or_default()
                    .to_bytes();
                let mut r = cgi::Response::new(b.to_vec());
                for h in resp.response.headers() {
                    r.headers_mut().append(h.0, h.1.to_owned());
                }
                r
            }
            Some("request_signature") => {
                let resp = ca::ca_request(p).await;
                let b = resp
                    .response
                    .clone()
                    .into_body()
                    .collect()
                    .await
                    .unwrap_or_default()
                    .to_bytes();
                let b = b.as_ref();
                let response: String = String::from_utf8(b.to_vec()).unwrap_or_default();
                cgi::html_response(200, response)
            }
            Some("submit_request") => {
                let resp = ca::ca_submit_request(p).await;
                let b = resp
                    .response
                    .into_body()
                    .collect()
                    .await
                    .unwrap_or_default()
                    .to_bytes();
                let b = b.as_ref();
                let response: String = String::from_utf8(b.to_vec()).unwrap_or_default();
                cgi::html_response(200, response)
            }
            Some("view_cert") => {
                let resp = ca::ca_view_user_https_cert(p).await;
                let b = resp
                    .response
                    .into_body()
                    .collect()
                    .await
                    .unwrap_or_default()
                    .to_bytes();
                let b = b.as_ref();
                let response: String = String::from_utf8(b.to_vec()).unwrap_or_default();
                cgi::html_response(200, response)
            }
            Some("admin") => {
                let resp = ca::ca_get_admin(p).await;
                let b = resp
                    .response
                    .clone()
                    .into_body()
                    .collect()
                    .await
                    .unwrap_or_default()
                    .to_bytes();
                let b = b.as_ref();
                if let Some(ct) = resp.response.headers().get("Content-Type") {
                    let mut r = cgi::Response::new(b.to_vec());
                    for h in resp.response.headers() {
                        r.headers_mut().append(h.0, h.1.to_owned());
                    }
                    r
                } else {
                    let response: String = String::from_utf8(b.to_vec()).unwrap_or_default();
                    cgi::html_response(200, response)
                }
            }
            Some("list_pending_requests") => {
                let resp = ca::ca_list_https_requests(p).await;
                let b = resp
                    .response
                    .into_body()
                    .collect()
                    .await
                    .unwrap_or_default()
                    .to_bytes();
                let b = b.as_ref();
                let response: String = String::from_utf8(b.to_vec()).unwrap_or_default();
                cgi::html_response(200, response)
            }
            Some("request_sign") => {
                let resp = ca::ca_sign_request(p).await;
                let b = resp
                    .response
                    .into_body()
                    .collect()
                    .await
                    .unwrap_or_default()
                    .to_bytes();
                let b = b.as_ref();
                let response: String = String::from_utf8(b.to_vec()).unwrap_or_default();
                cgi::html_response(200, response)
            }
            Some("get_cert") => {
                let resp = ca::ca_get_user_cert(p).await;
                let b = resp
                    .response
                    .clone()
                    .into_body()
                    .collect()
                    .await
                    .unwrap_or_default()
                    .to_bytes();
                let b = b.as_ref();
                if let Some(ct) = resp.response.headers().get("Content-Type") {
                    let mut r = cgi::Response::new(b.to_vec());
                    for h in resp.response.headers() {
                        r.headers_mut().append(h.0, h.1.to_owned());
                    }
                    r
                } else {
                    let response: String = String::from_utf8(b.to_vec()).unwrap_or_default();
                    cgi::html_response(200, response)
                }
            }
            Some("view_all_certs") => {
                let resp = ca::ca_view_all_certs(p).await;
                let b = resp
                    .response
                    .into_body()
                    .collect()
                    .await
                    .unwrap_or_default()
                    .to_bytes();
                let b = b.as_ref();
                let response: String = String::from_utf8(b.to_vec()).unwrap_or_default();
                cgi::html_response(200, response)
            }
            _ => {
                let resp = ca::ca_main_page(p).await;
                let b = resp
                    .response
                    .into_body()
                    .collect()
                    .await
                    .unwrap_or_default()
                    .to_bytes();
                let b = b.as_ref();
                let response: String = String::from_utf8(b.to_vec()).unwrap_or_default();
                cgi::html_response(200, response)
            }
        }
    })
    .await
}
