#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct Counter {}

impl super::FileTemplateTrait for Counter {
    fn html_form<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        b: &mut html::root::builders::BodyBuilder,
        fbm: F,
    ) {
        b.text("Type: Counter - no configuration available");
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

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct Bitmap {
    items: Vec<String>,
}

impl super::FileTemplateTrait for Bitmap {
    fn html_form<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        b: &mut html::root::builders::BodyBuilder,
        fbm: F,
    ) {
        b.form(|fb| {
            fb.text("Type: Bitmap");
            fb.line_break(|a| a);
            fb.text("Current entries:").line_break(|a| a);
            for i in &self.items {
                fb.text(i.to_string()).line_break(|a| a);
            }
            fb.text("New entries:");
            fb.line_break(|a| a);
            fb.text_area(|ta| {
                ta.rows(20).cols(50);
                ta.name("file_template_items");
                ta
            });
            fb.line_break(|a| a);
            fbm(fb);
            fb
        });
    }

    fn apply_form_data(&mut self, data: url_encoded_data::UrlEncodedData) {
        if let Some(t) = data.get_first("file_template_items") {
            for line in t.lines() {
                self.items.push(line.to_string());
            }
        }
    }

    fn name(&self) -> &str {
        "bitmap"
    }

    fn generate(&self) -> super::FileGenerator {
        (BitmapGenerator {}).into()
    }
}

pub struct BitmapGenerator {}

impl super::FileGeneratorTrait for BitmapGenerator {
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
