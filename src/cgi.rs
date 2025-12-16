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
use http_body_util::BodyExt;
pub use main_config::MainConfiguration;

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

use crate::webserver::PostContent;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    cgi::handle_async(async |request: cgi::Request| -> cgi::Response {
        let config = std::fs::File::open("./config.bin");
        if config.is_err() {
            return cgi::html_response(500, "Invalid configuration 1");
        }
        let mut config = config.unwrap();
        let mut contents = Vec::new();
        if config.read_to_end(&mut contents).is_err() {
            return cgi::html_response(500, "Invalid configuration 2");
        }
        let mut password_combined: Option<Vec<u8>> = None;
        let settings =
            MainConfiguration::load("./".into(), "default", contents, &mut password_combined).await;
        if false {
            return cgi::html_response(200, format!("Config is {:#?}<br />\n", settings));
        }
        let hsm: Arc<hsm2::SecurityModule> = settings
            .pki
            .init_hsm(&"./".into(), "default", &settings)
            .await;
        let pki = ca::PkiInstance::load(hsm.clone(), &settings).await.unwrap(); //TODO remove this unwrap?
        let pki = Arc::new(futures_util::lock::Mutex::new(pki));

        let get_map = {
            let mut get_map = HashMap::new();
            let get_data = request.headers().get("x-cgi-query-string");
            if let Some(get_data) = get_data {
                let get_data = get_data.to_str().unwrap();
                let get_split = get_data.split('&');
                for get_elem in get_split {
                    let mut ele_split = get_elem.split('=').take(2);
                    let i1 = ele_split.next().unwrap_or_default();
                    let i2 = ele_split.next().unwrap_or_default();
                    get_map.insert(i1.to_owned(), i2.to_owned());
                }
            }
            get_map
        };

        let post_data = request.body().clone();
        let post_data = hyper::body::Bytes::from(post_data);
        let mut headers = hyper::HeaderMap::new();
        for a in request.headers().iter() {
            headers.insert(a.0, a.1.clone());
        }
        let post_data = PostContent::new(Some(post_data), headers);

        let p = crate::webserver::WebPageContext {
            https: true,
            domain: request
                .headers()
                .get("host")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
            page: request.uri().to_string().into(),
            post: post_data,
            get: get_map,
            proxy: String::new(),
            logincookie: None,
            pool: None,
            user_certs: webserver::UserCerts::new(),
            pki_type: settings.pki.clone().into(),
            pki: pki.clone(),
        };

        let resp = ca::ca_main_page(p).await;
        let b = resp
            .response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let b = b.as_ref();
        let response: String = String::from_utf8(b.to_vec()).unwrap();
        cgi::html_response(200, response)
    })
    .await
}
