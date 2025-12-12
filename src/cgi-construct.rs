//For the html crate
#![recursion_limit = "512"]

mod ca;
mod hsm2;
mod tpm2;
mod utility;
mod webserver;

mod main_config;
pub use main_config::MainConfiguration;

use std::collections::HashMap;

use base64::Engine;

fn build_toml_string(doc: &toml::Value) -> String {
    let c = doc.to_string();
    base64::prelude::BASE64_STANDARD_NO_PAD.encode(c)
}

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
            if let Some(c) = request.headers().get("x-cgi-content-type") {
                if let Ok(c) = c.to_str() {
                    if "application/x-www-form-urlencoded" == c {
                        let body = request.body();
                        let a: String = String::from_utf8(body.clone()).unwrap();
                        let get_data = a;
                        let get_data = get_data;
                        let get_split = get_data.split('&');
                        for get_elem in get_split {
                            let mut ele_split = get_elem.split('=').take(2);
                            let i1 = ele_split.next().unwrap_or_default();
                            let i2 = ele_split.next().unwrap_or_default();
                            get_map.insert(i1.to_owned(), i2.to_owned());
                        }
                    }
                }
            }
            get_map
        };

        let toml_plain = post_map
            .get("object")
            .map(|a| base64::prelude::BASE64_STANDARD_NO_PAD.decode(a).ok())
            .unwrap_or(None)
            .map(|t| String::from_utf8(t).ok())
            .flatten();
        let toml_decoded = toml_plain
            .clone()
            .map(|t| toml::from_str::<toml::Value>(&t).ok())
            .flatten();
        let toml_value = match &toml_decoded {
            Some(a) => a.clone(),
            None => {
                let t = toml::Table::new();
                toml::Value::Table(t)
            }
        };
        let mut toml = toml_value;

        let step = post_map
            .get("step")
            .map(|a| a.parse::<u16>().ok())
            .flatten()
            .unwrap_or(0);
        match post_map.get("config").map(|a| a.as_str()) {
            Some("test1") => match step {
                1 => {
                    toml.as_table_mut()
                        .unwrap()
                        .insert("val1".to_string(), toml::Value::String("groot".to_string()));
                    html.head(|h| h.title(|t| t.text("Test1 Builder")))
                        .body(|b| {
                            b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                            b.text(format!("GET IS {:#?}<br />\n", get_map));
                            b.text(format!("POST IS {:#?}<br />\n", post_map));
                            b.form(|f| {
                                f.method("POST");
                                f.input(|i| i.type_("hidden").name("config").value("test1"));
                                f.input(|i| {
                                    i.type_("hidden")
                                        .name("step")
                                        .value(format!("{}", step + 1))
                                });
                                f.input(|i| {
                                    i.type_("hidden")
                                        .name("object")
                                        .value(build_toml_string(&toml))
                                });
                                f.button(|b| b.text("Next"))
                            });
                            b.line_break(|lb| lb);
                            b
                        });
                }
                _ => {
                    toml.as_table_mut().unwrap().insert(
                        "class".to_string(),
                        toml::Value::String("test1".to_string()),
                    );
                    html.head(|h| h.title(|t| t.text("Test1 Builder")))
                        .body(|b| {
                            b.text(format!("{:#?}<br />\n", request));
                            b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                            b.text(format!("GET IS {:#?}<br />\n", get_map));
                            b.text(format!("POST IS {:#?}<br />\n", post_map));
                            b.form(|f| {
                                f.method("POST");
                                f.input(|i| i.type_("hidden").name("config").value("test1"));
                                f.input(|i| {
                                    i.type_("hidden")
                                        .name("step")
                                        .value(format!("{}", step + 1))
                                });
                                f.input(|i| {
                                    i.type_("hidden")
                                        .name("object")
                                        .value(build_toml_string(&toml))
                                });
                                f.button(|b| b.text("Next"))
                            });
                            b.line_break(|lb| lb);
                            b
                        });
                }
            },
            Some("test2") => {
                html.head(|h| h.title(|t| t.text("Test2 Builder")))
                    .body(|b| {
                        b.text(format!("{:#?}<br />\n", request));
                        b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                        b.text(format!("GET IS {:#?}<br />\n", get_map));
                        b.text(format!("POST IS {:#?}<br />\n", post_map));
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| i.type_("hidden").name("config").value("test2"));
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", step + 1))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
            }
            Some("test3") => {
                html.head(|h| h.title(|t| t.text("Test3 Builder")))
                    .body(|b| {
                        b.text(format!("{:#?}<br />\n", request));
                        b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                        b.text(format!("GET IS {:#?}<br />\n", get_map));
                        b.text(format!("POST IS {:#?}<br />\n", post_map));
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| i.type_("hidden").name("config").value("test3"));
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", step + 1))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
            }
            _ => {
                html.head(|h| h.title(|t| t.text("Configuration Builder")))
                    .body(|b| {
                        b.text(format!("{:#?}<br />\n", request));
                        b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                        b.text(format!("GET IS {:#?}<br />\n", get_map));
                        b.text(format!("POST IS {:#?}<br />\n", post_map));
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| i.type_("hidden").name("config").value("test1"));
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.text("Start 1"))
                        });
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| i.type_("hidden").name("config").value("test2"));
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.text("Start 2"))
                        });
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| i.type_("hidden").name("config").value("test3"));
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.text("Start 3"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
            }
        }
        let html = html.build();
        cgi::html_response(200, html.to_string())
    })
    .await
}
