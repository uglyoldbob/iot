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
    ) {
        let mut admin = false;
        if ca.is_admin_for_applet(appletid, userid).await {
            admin = true;
        }
        html.body(|b| {
            b.text("This is the desvfire ev1 applet");
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
}
