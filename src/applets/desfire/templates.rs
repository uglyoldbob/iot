#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct Counter {}

impl super::FileTemplateTrait for Counter {
    fn html_form<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        b: &mut html::root::builders::BodyBuilder,
        fbm: F,
    ) {
        b.text("Type: Counter");
        b.line_break(|a| a);
    }

    fn apply_form_data(&mut self, data: url_encoded_data::UrlEncodedData) {}

    fn name(&self) -> &str {
        "counter"
    }

    fn generate(&self) -> super::FileGenerator {
        (CounterGenerator {}).into()
    }
}

pub struct CounterGenerator {}

impl super::FileGeneratorTrait for CounterGenerator {
    fn html_form<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        html: &mut html::root::builders::HtmlBuilder,
        fbm: F,
    ) {
        todo!()
    }

    fn apply_form_data(&mut self, data: url_encoded_data::UrlEncodedData) {
        todo!()
    }

    fn generate(&self) -> super::File {
        todo!()
    }
}
