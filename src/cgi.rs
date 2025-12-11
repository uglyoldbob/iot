//For the html crate
#![recursion_limit = "512"]

mod ca;
mod hsm2;
mod utility;
mod webserver;

mod main_config;
pub use main_config::MainConfiguration;
use nix::unistd::User;

use std::collections::HashMap;
use std::sync::Arc;
use std::io::Read;

use crate::webserver::PostContent;

/// The main configuration of the cgi page
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct CgiConfiguration {
    /// Is https required?
    https: bool,
    /// The domain
    domain: String,
}

impl CgiConfiguration {
    fn make_web_page_context(&self, request: &cgi::Request) -> crate::webserver::WebPageContext {
        crate::webserver::WebPageContext {
            https: self.https,
            domain: self.domain,
            page: request.uri().path().to_string().into(),
            proxy: String::new(),
            post: PostContent::new(None,
                hyper::header::HeaderMap::new()),
            get: HashMap::new(),
            logincookie: None,
            pool: None,
            user_certs: crate::webserver::UserCerts::new(),
            settings: todo!(),
            pki: Arc::new(todo!()),
        }
    }
}

fn main() {
    cgi::handle(|request: cgi::Request| -> cgi::Response {
        let config = std::fs::File::open("./config.ini");
        if config.is_err() {
            return cgi::html_response(500, "Invalid configuration 1");
        }
        let mut config = config.unwrap();
        let mut contents = String::new();
        if config.read_to_string(&mut contents).is_err() {
            return cgi::html_response(500, "Invalid configuration 2");
        }
        let config = match toml::from_str(&contents) {
            Err(e) => {
                return cgi::html_response(500, "Invalid configuration 3");
            }
            Ok(config) => {
                let config :  CgiConfiguration = config;
                config
            }
        };
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
        let mut html = html::root::Html::builder();
        html.head(|h| h.title(|t| t.text("TEST TITLE"))).body(|b| {
            b.text(format!("{:#?}", config));
            b.text(format!("{:#?}", request));
            b.anchor(|ab| {
                ab.text("List pending requests");
                ab.href("list.rs");
                ab
            });
            b.line_break(|lb| lb);
            b
        });
        let html = html.build();

        let response = hyper::Response::new("dummy");
        let (response, _dummybody) = response.into_parts();
        cgi::html_response(200, html.to_string())
    })
}
