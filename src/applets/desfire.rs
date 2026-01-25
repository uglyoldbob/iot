//! Code for the desfire applet

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct Ev1 {
    table_name: String,
}

impl super::AppletTrait for Ev1 {
    fn name(&self) -> &str {
        "desfire_ev1"
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
}
