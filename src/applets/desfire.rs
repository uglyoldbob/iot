//! Code for the desfire applet

use crate::ca::Ca;

use super::{AppletTable, AppletTableField, FieldType};

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct Ev1 {
    table_name: String,
}

impl super::AppletTrait for Ev1 {
    fn name(&self) -> &str {
        "desfire_ev1"
    }

    fn admin_groups(&self) -> Vec<&str> {
        vec!["admin"]
    }

    fn groups(&self) -> Vec<&str> {
        vec!["admin", "manager"]
    }

    fn html_form<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        html: &mut html::root::builders::HtmlBuilder,
        fbm: F,
    ) {
        html.body(|b| {
            b.form(|f| {
                f.text("Name of main table");
                f.line_break(|a| a);
                f.input(|i| i.name("table_name"));
                f.line_break(|a| a);
                f.button(|b| b.text("Finish"));
                fbm(f);
                f
            })
        });
    }

    fn apply_form_data(&mut self, data: url_encoded_data::UrlEncodedData) {
        if let Some(t) = data.get_first("table_name") {
            self.table_name = t.to_string();
        }
    }

    fn table_setup(&self) -> Vec<AppletTable> {
        vec![AppletTable {
            name: "applications".to_string(),
            fields: vec![(
                "v1".to_string(),
                AppletTableField {
                    ty: FieldType::Integer,
                    primary_key: false,
                    default: None,
                },
            )],
        }]
    }

    async fn run_applet(
        &mut self,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: usize,
        userid: usize,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
    ) {
        let mut admin = false;
        if ca.is_admin_for_applet(appletid, userid).await {
            admin = true;
        }
        let action = s.get.get("applet_action").map(|a| a.as_str());
        match action {
            Some("asdf") => {
                html.body(|b| {
                    b.text("This is the desvfire ev1 applet sample page");
                    if admin {
                        b.text("You are admin over this applet");
                    }
                    b.line_break(|a| a);

                    b.anchor(|ab| {
                        ab.text("Back to main page");
                        ab.href("?");
                        ab
                    });
                    b
                });
            }
            _ => {
                html.body(|b| {
                    b.text("This is the desvfire ev1 applet");
                    if admin {
                        b.text("You are admin over this applet");
                    }
                    b.line_break(|a| a);

                    b.anchor(|ab| {
                        ab.text("Sample applet link");
                        match s.delivery {
                            crate::main_config::PageDelivery::Cgi => {
                                let mut args = Vec::new();
                                for a in &s.get {
                                    args.push(format!("{}={}", a.0, a.1));
                                }
                                ab.href(format!("?{}&applet_action=asdf", args.join("&")));
                            }
                            crate::main_config::PageDelivery::DedicatedServer => {
                                ab.href(format!("applet.rs?id={}&applet_action=asdf", appletid));
                            }
                        };
                        ab
                    });

                    b.anchor(|ab| {
                        ab.text("Back to main page");
                        ab.href("?");
                        ab
                    });
                    b
                });
            }
        }
    }
}
