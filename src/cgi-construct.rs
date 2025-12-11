//For the html crate
#![recursion_limit = "512"]

mod ca;
mod tpm2;
mod hsm2;
mod utility;
mod webserver;

mod main_config;
pub use main_config::MainConfiguration;

use std::collections::HashMap;

#[tokio::main]
async fn main() {
    cgi::handle_async(async |request: cgi::Request| -> cgi::Response {
        let mut html = html::root::Html::builder();

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

        let post_map = {
            let mut get_map = HashMap::new();
            let body = request.body();
            let a : String = String::from_utf8(body.clone()).unwrap();
            let get_data = a;
            let get_data = get_data;
            let get_split = get_data.split('&');
            for get_elem in get_split {
                let mut ele_split = get_elem.split('=').take(2);
                let i1 = ele_split.next().unwrap_or_default();
                let i2 = ele_split.next().unwrap_or_default();
                get_map.insert(i1.to_owned(), i2.to_owned());
            }
            get_map
        };

        html.head(|h| h.title(|t| t.text("Configuration Builder"))).body(|b| {
            b.text(format!("{:#?}<br />\n", request));
            b.text(format!("GET IS {:#?}<br />\n", get_map));
            b.text(format!("POST IS {:#?}<br />\n", post_map));
            b.form(|f| {
                f.method("POST");
                f.input(|i| i.type_("hidden").name("config").value("test1"));
                f.button(|b| b.text("Start 1"))
            });
            b.form(|f| {
                f.method("POST");
                f.input(|i| i.type_("hidden").name("config").value("test2"));
                f.button(|b| b.text("Start 2"))
            });
            b.form(|f| {
                f.method("POST");
                f.input(|i| i.type_("hidden").name("config").value("test3"));
                f.button(|b| b.text("Start 3"))
            });
            b.anchor(|ab| {
                ab.text("List pending requests");
                ab.href("list.rs");
                ab
            });
            b.line_break(|lb| lb);
            b
        });
        let html = html.build();
        cgi::html_response(200, html.to_string())
    })
    .await
}
