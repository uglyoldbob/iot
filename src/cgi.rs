//For the html crate
#![recursion_limit = "512"]

fn main() {
    cgi::handle(|request: cgi::Request| -> cgi::Response {
        let mut html = html::root::Html::builder();
        let test = request.headers().get("x-cgi-query-string");
        html.head(|h| h.title(|t| t.text("TEST TITLE"))).body(|b| {
            b.text(format!("{:#?}", test));
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
