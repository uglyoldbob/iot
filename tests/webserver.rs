//For the html crate
#![recursion_limit = "512"]

#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/ca/mod.rs"]
mod ca;

#[path = "../src/main_config.rs"]
mod main_config;

pub use main_config::MainConfiguration;

#[path = "../src/utility.rs"]
mod utility;

#[path = "../src/card.rs"]
mod card;

#[path = "../src/webserver/mod.rs"]
mod webserver;

/// A test function that shows some demo content
async fn test_func3(s: webserver::WebPageContext) -> webserver::WebResponse {
    let mut html = html::root::Html::builder();
    html.head(|h| h).body(|b| {
        b.ordered_list(|ol| {
            for name in ["I", "am", "groot"] {
                ol.list_item(|li| li.text(name));
            }
            ol
        })
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

#[test]
fn router() {
    let mut router = webserver::WebRouter::new();
    router.register("/", test_func3);
}
