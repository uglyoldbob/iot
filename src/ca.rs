//! Handles certificate authority functionality

use hyper::header::HeaderValue;

use crate::{webserver, WebPageContext, WebRouter};

use cert_common::{oid::*, CertificateSigningMethod, HttpsSigningMethod};

/// The module for using a certificate authority
pub mod ca_usage;
pub use ca_usage::*;

/// Handle a request submission for a certificate authority
async fn handle_ca_submit_request(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let mut valid_csr = false;
    let mut mycsr_pem = None;
    let mut id = None;

    let f = s.post.form();
    if let Some(form) = f {
        match &ca.config.sign_method {
            CertificateSigningMethod::Https(_) => {
                if let Some(pem) = form.get_first("csr") {
                    mycsr_pem = Some(pem.to_owned());
                    let raw_csr = RawCsrRequest {
                        pem: pem.to_string(),
                    };
                    valid_csr = raw_csr.verify_request().is_ok();
                    if valid_csr {
                        use der::DecodePem;
                        let _cert = x509_cert::request::CertReq::from_pem(pem).unwrap();
                        let newid = ca.get_new_request_id().await;
                        if let Some(newid) = newid {
                            let csrr = CsrRequest {
                                cert: pem.to_string(),
                                name: form.get_first("name").unwrap().to_string(),
                                email: form.get_first("email").unwrap().to_string(),
                                phone: form.get_first("phone").unwrap().to_string(),
                                id: newid,
                            };
                            let _ = ca.save_csr(&csrr).await;
                        }
                        id = newid;
                    }
                }
            }
            CertificateSigningMethod::Ssh(_) => {
                let pub_string = form.get_first("pubkey").unwrap();
                let u: u32 = form.get_first("usage-type").unwrap().parse().unwrap();
                let u: ssh_key::certificate::CertType = u.try_into().unwrap();
                let principals = form
                    .get_first("principals")
                    .unwrap()
                    .lines()
                    .map(|a| a.to_string())
                    .collect();
                let newid = ca.get_new_request_id().await;
                if let Some(newid) = newid {
                    let sshr = SshRequest {
                        pubkey: pub_string.to_string(),
                        principals,
                        usage: u.into(),
                        comment: form.get_first("comment").unwrap().to_string(),
                        name: form.get_first("name").unwrap().to_string(),
                        email: form.get_first("email").unwrap().to_string(),
                        phone: form.get_first("phone").unwrap().to_string(),
                        id: newid,
                    };
                    let _ = ca.save_ssh_request(&sshr).await;
                }
                valid_csr = true;
                id = newid;
            }
        }
    }

    let mut html = html::root::Html::builder();
    html.head(|h| generic_head(h, s, ca).title(|t| t.text(ca.config.common_name.to_owned())))
        .body(|b| {
            if valid_csr {
                b.text("Your request has been submitted").line_break(|f| f);
                b.anchor(|ab| {
                    ab.text("View status of request");
                    ab.href(format!("view_cert.rs?id={}", id.unwrap()));
                    ab
                });
                b.line_break(|lb| lb);
            } else {
                b.text("Your request was considered invalid")
                    .line_break(|f| f);
                if let Some(pem) = mycsr_pem {
                    b.preformatted_text(|c| c.text(pem)).line_break(|a| a);
                }
            }
            b
        });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// The page that allows users to submit a signing request.
async fn ca_submit_request(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_submit_request(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_submit_request(ca, &s).await,
    }
}

/// Page for a user to generate a request for a certificate authority
async fn handle_ca_request(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let pki = ca.config.get_pki_name();
    let mut html = html::root::Html::builder();
    html.head(|h| {
        generic_head(h, s, ca).title(|t| t.text(ca.config.common_name.to_owned()))
            .script(|sb| {
                sb.src(s.get_absolute_url(pki, "js/certgen.js"));
                sb
            })
    })
    .body(|b| {
        b.script(|s| {
            s.text("async function run() {\n")
                .text("await wasm_bindgen();\n")
                .text("}\n")
                .text("run();\n")
        });
        b.division(|div| {
            div.class("cert-gen-stuff");
            div.text("This page is used to generate a certificate. The generate button generates a private key and certificate signing request on your local device, protecting the private key with the password specified.").line_break(|a|a);
            div.anchor(|ab| {
                ab.text("Back to main page");
                ab.href(".");
                ab
            }).line_break(|a|a);
            match ca.config.sign_method {
                CertificateSigningMethod::Https(m) => match m {
                    HttpsSigningMethod::RsaSha256 => {
                        div.button(|b| b.text("Generate a certificate").onclick("wasm_bindgen.generate_csr_rsa_sha256()"));
                    }
                    HttpsSigningMethod::EcdsaSha256 => {
                        div.button(|b| b.text("Generate a certificate").onclick("wasm_bindgen.generate_csr_ecdsa_sha256()"));
                    }
                }
                CertificateSigningMethod::Ssh(m) => {
                    match m {
                        cert_common::SshSigningMethod::Rsa => {
                            div.button(|b| b.text("Generate a certificate").onclick("wasm_bindgen.generate_ssh_rsa()"));
                        }
                        cert_common::SshSigningMethod::Ed25519 => {
                            div.button(|b| b.text("Generate a certificate").onclick("wasm_bindgen.generate_ed25519_rsa()"));
                        }
                    }
                }
            }
            div.line_break(|lb| lb);
            match ca.config.sign_method {
                CertificateSigningMethod::Https(_m) => {
                    div.division(|div| {
                        div.class("advanced");
                        div.button(|b| b.text("Simple").onclick("wasm_bindgen.show_regular()")).line_break(|a|a);
                        div
                    });
                    div.division(|div| {
                        div.class("regular");
                        div.button(|b| b.text("Advanced").onclick("wasm_bindgen.show_advanced()")).line_break(|a|a);
                        div
                    });
                    div.division(|div| {
                        div.form(|f| {
                            f.name("request");
                            f.action("submit_request.rs");
                            f.method("post");
                            f.text("Your Name")
                                .line_break(|a| a)
                                .input(|i| i.type_("text").id("name").name("name"))
                                .line_break(|a| a);
                            f.text("Email")
                                .line_break(|a| a)
                                .input(|i| i.type_("email").id("email").name("email"))
                                .line_break(|a| a);
                            f.text("Phone Number")
                                .line_break(|a| a)
                                .input(|i| i.type_("tel").id("phone").name("phone"))
                                .line_break(|a| a);
                            f.text("Password for private key")
                                .line_break(|a|a)
                                .input(|i| i.type_("password").id("password"))
                                .line_break(|a|a);
                            f.heading_1(|h| {
                                h.text("Certificate Usage").line_break(|a|a)
                            });
                            f.input(|i| { i.type_("checkbox").id("usage-client").name("usage-client").value("client") });
                            f.label(|l| l.for_("usage-client").text("Client certification")).line_break(|a|a);
                            f.input(|i| { i.type_("checkbox").id("usage-code").name("usage-code").value("code") });
                            f.label(|l| l.for_("usage-code").text("Code signing")).line_break(|a|a);
                            f.input(|i| { i.type_("checkbox").id("usage-server").name("usage-server").value("server") });
                            f.label(|l| l.for_("usage-server").text("Server certification")).line_break(|a|a);
                            f.heading_1(|h| {
                                h.text("Certificate Information").line_break(|a|a)
                            });
                            f.text("Certificate Name")
                                .line_break(|a| a)
                                .input(|i| i.type_("text").id("cname").name("cname"))
                                .line_break(|a| a);
                            f.text("Country")
                                .line_break(|a| a)
                                .input(|i| i.type_("text").id("country").name("country"))
                                .line_break(|a| a);
                            f.text("State")
                                .line_break(|a| a)
                                .input(|i| i.type_("text").id("state").name("state"))
                                .line_break(|a| a);
                            f.text("Locality")
                                .line_break(|a| a)
                                .input(|i| i.type_("text").id("locality").name("locality"))
                                .line_break(|a| a);
                            f.text("Organization Name")
                                .line_break(|a| a)
                                .input(|i| i.type_("text").id("organization").name("organization"))
                                .line_break(|a| a);
                            f.text("Organization Unit")
                                .line_break(|a| a)
                                .input(|i| i.type_("text").id("organization-unit").name("organization-unit"))
                                .line_break(|a| a);
                            f.text("Challenge password")
                                .line_break(|a| a)
                                .input(|i| i.type_("password").id("challenge-pass").name("challenge-pass"))
                                .line_break(|a| a);
                            f.text("Challenge name")
                                .line_break(|a| a)
                                .input(|i| i.type_("text").id("challenge-name").name("challenge-name"))
                                .line_break(|a| a);
                            f.division(|div| {
                                div.class("advanced");
                                div.emphasis(|e| e.text("Advanced")).line_break(|a|a);
                                div.text("CSR")
                                    .line_break(|a| a)
                                    .text_area(|i| i.id("csr").name("csr"))
                                    .line_break(|a| a);
                                div
                            });
                            f.division(|div| {
                                div.class("hidden");
                                div.input(|i| i.type_("submit").id("submit").value("Submit"))
                                .line_break(|a| a);
                                div
                            });
                            f
                        });
                        div
                    });
                }
                CertificateSigningMethod::Ssh(_m) => {
                    div.division(|div| {
                        div.text("SSH STUFF").line_break(|a|a);
                        div.form(|f| {
                            f.name("request");
                            f.action("ca/submit_request.rs");
                            f.method("post");
                            f.text("Your Name")
                                .line_break(|a| a)
                                .input(|i| i.type_("text").id("name").name("name"))
                                .line_break(|a| a);
                            f.text("Email")
                                .line_break(|a| a)
                                .input(|i| i.type_("email").id("email").name("email"))
                                .line_break(|a| a);
                            f.text("Phone Number")
                                .line_break(|a| a)
                                .input(|i| i.type_("tel").id("phone").name("phone"))
                                .line_break(|a| a);
                            f.text("Password for private key")
                                .line_break(|a|a)
                                .input(|i| i.type_("password").id("password"))
                                .line_break(|a|a);
                            f.heading_1(|h| {
                                h.text("Certificate Usage").line_break(|a|a)
                            });
                            f.select(|i| {
                                i.name("usage-type").id("usage-type")
                                    .option(|o|o.value("1").text("User"))
                                    .option(|o|o.value("2").text("Host"))
                                }).line_break(|a|a);
                            f.heading_1(|h| {
                                h.text("Certificate Information").line_break(|a|a)
                            });
                            f.text("Principals")
                                    .line_break(|a| a)
                                    .text_area(|i| i.id("principals").name("principals"))
                                    .line_break(|a| a);
                            f.text("Certificate comment")
                                .line_break(|a| a)
                                .input(|i| i.type_("text").id("comment").name("comment"))
                                .line_break(|a| a);
                            f.text("Challenge password")
                                .line_break(|a| a)
                                .input(|i| i.type_("password").id("challenge-pass").name("challenge-pass"))
                                .line_break(|a| a);
                            f.text("Challenge name")
                                .line_break(|a| a)
                                .input(|i| i.type_("text").id("challenge-name").name("challenge-name"))
                                .line_break(|a| a);
                            f.division(|div| {
                                div.class("hidden");
                                div.text_area(|i| i.id("pubkey").name("pubkey"))
                                    .line_break(|a|a)
                                    .input(|i| i.type_("submit").id("submit").value("Submit"))
                                    .line_break(|a| a);
                                div
                            });
                            f
                        });
                        div
                    });
                }
            }
            div
        });
        b.division(|div| {
            div.class("cert_generating");
            div.text("Generating request...");
            div.line_break(|a| a);
            div
        });
        b
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// The page that allows a user to generate a signing request.
async fn ca_request(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_request(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_request(ca, &s).await,
    }
}

/// The main landing page for a pki object
async fn pki_main_page(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    service::log::debug!("Proxy is \"{}\"", s.proxy);
    if let PkiInstance::Pki(pki) = std::ops::DerefMut::deref_mut(&mut pki) {
        let mut html = html::root::Html::builder();
        html.head(|h| {
            h.meta(|m| m.charset("UTF-8"));
            h.link(|h| {
                h.href(format!("{}css/ca.css", s.proxy))
                    .rel("stylesheet")
                    .media("all")
            });
            h.link(|h| {
                h.href(format!("{}css/ca-mobile.css", s.proxy))
                    .rel("stylesheet")
                    .media("screen and (max-width: 640px)")
            });
            h.title(|t| t.text("PKI"))
        })
        .body(|b| {
            b.text("This is the pki page").line_break(|a| a);
            for (name, ca) in &pki.roots {
                service::log::debug!("Root name \"{}\"", name);
                b.thematic_break(|a| a);
                let validity = ca.get_validity();
                if let Some(valid) = validity {
                    b.text(format!(
                        "{}: Valid from {} to {}",
                        name, valid.not_before, valid.not_after
                    ))
                    .line_break(|a| a);
                }
                if let Ok(cert) = ca.root_ca_cert() {
                    b.text(format!("CERT TYPE {:?}", cert.algorithm()))
                        .line_break(|a| a);
                }

                b.anchor(|ab| {
                    ab.text("Visit this CA");
                    ab.href(format!("{}pki/{}/ca", s.proxy, name));
                    ab
                })
                .line_break(|lb| lb);
            }
            b
        });
        let html = html.build();

        let response = hyper::Response::new("dummy");
        let (response, _dummybody) = response.into_parts();
        let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
        webserver::WebResponse {
            response: hyper::http::Response::from_parts(response, body),
            cookie: s.logincookie,
        }
    } else {
        let response = hyper::Response::new("dummy");
        let (response, body) = response.into_parts();
        webserver::WebResponse {
            response: hyper::http::Response::from_parts(response, body.into()),
            cookie: s.logincookie,
        }
    }
}

///The page that redirects to the pki main page without a trailing /
async fn pki_main_page2(s: WebPageContext) -> webserver::WebResponse {
    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    response.status = hyper::http::StatusCode::from_u16(302).unwrap();
    let url = format!("{}/pki", s.proxy);
    service::log::debug!("Redirect to {}", url);
    response
        .headers
        .insert("Location", HeaderValue::from_str(&url).unwrap());

    let body = http_body_util::Full::new(hyper::body::Bytes::from("I am GRooT?"));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

/// The main page for a certificate authority
async fn handle_ca_main_page(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let mut admin = false;
    let cs = s.user_certs.all_certs();
    for cert in cs {
        if ca.is_admin(cert).await {
            admin = true;
        }
    }

    let mut html = html::root::Html::builder();
    html.head(|h| generic_head(h, s, ca).title(|t| t.text(ca.config.common_name.to_owned())))
        .body(|b| {
            if admin {
                b.text("You are admin").line_break(|a| a);
            }
            match &ca.config.sign_method {
                CertificateSigningMethod::Https(_m) => {
                    b.anchor(|ab| {
                        ab.text("Download CA certificate as der");
                        ab.href("ca/get_ca.rs?type=der");
                        ab.target("_blank");
                        ab
                    });
                    b.line_break(|lb| lb);
                    b.anchor(|ab| {
                        ab.text("Download CA certificate as pem");
                        ab.href("ca/get_ca.rs?type=pem");
                        ab.target("_blank");
                        ab
                    });
                    b.line_break(|lb| lb);
                }
                CertificateSigningMethod::Ssh(_m) => {
                    b.anchor(|ab| {
                        ab.text("Download SSH CA certificate");
                        ab.href("ca/get_ca.rs");
                        ab.target("_blank");
                        ab
                    });
                    b.line_break(|lb| lb);
                }
            }
            b.anchor(|ab| {
                ab.text("Request a signature on a certificate");
                ab.href("ca/request.rs");
                ab
            });
            b.line_break(|lb| lb);
            if admin {
                b.anchor(|ab| {
                    ab.text("List pending requests");
                    ab.href("ca/list.rs");
                    ab
                });
                b.line_break(|lb| lb);
                b.anchor(|ab| {
                    ab.text("List all certificates");
                    ab.href("ca/view_all_certs.rs");
                    ab
                });
                b.line_break(|lb| lb);
            }
            b
        });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

///The main landing page for the certificate authority
async fn ca_main_page(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_main_page(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_main_page(ca, &s).await,
    }
}

/// Redirect to the main ca page
async fn handle_ca_main_page2(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let pki = ca.config.get_pki_name();

    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    response.status = hyper::http::StatusCode::from_u16(302).unwrap();
    let url = s.get_absolute_url(pki, "ca");

    service::log::debug!("Redirect to {}", url);
    response
        .headers
        .insert("Location", HeaderValue::from_str(&url).unwrap());

    let body = http_body_util::Full::new(hyper::body::Bytes::from("I am GRooT?"));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

///The page that redirects to the ca main page without a trailing /
async fn ca_main_page2(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_main_page2(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_main_page2(ca, &s).await,
    }
}

/// Reject a specified request for a certificate authority
async fn handle_ca_reject_request(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let pki = ca.config.get_pki_name().to_owned();
    let mut csr_check = Err(CertificateSigningError::CsrDoesNotExist);
    if let Some(id) = s.get.get("id") {
        let id = str::parse::<u64>(id);
        let reject = s.get.get("rejection").unwrap();
        if let Ok(id) = id {
            csr_check = ca.reject_csr_by_id(id, reject).await;
        }
    }

    let mut html = html::root::Html::builder();

    html.head(|h| generic_head(h, s, ca).title(|t| t.text(ca.config.common_name.to_owned())))
        .body(|b| {
            match csr_check {
                Ok(_der) => {
                    b.text("The request has been rejected").line_break(|a| a);
                }
                Err(e) => match e {
                    CertificateSigningError::CsrDoesNotExist => {
                        b.text("The certificate signing request does not exist")
                            .line_break(|a| a);
                    }
                    CertificateSigningError::FailedToDeleteRequest => {
                        b.text("Unable to delete request").line_break(|a| a);
                    }
                    CertificateSigningError::UnableToSign => {
                        b.text("Unable to sign request").line_break(|a| a);
                    }
                    CertificateSigningError::UndecipherableX509Generated => {
                        b.text("The generated certificate was garbage")
                            .line_break(|a| a);
                    }
                },
            }
            b.anchor(|ab| {
                ab.text("List pending requests");
                ab.href(format!("{}{}ca/list.rs", s.proxy, pki));
                ab
            });
            b.line_break(|lb| lb);
            b
        });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// Reject a csr with a specified reason
async fn ca_reject_request(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_reject_request(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_reject_request(ca, &s).await,
    }
}

/// Sign a specified request for a certificate authority
async fn handle_ca_sign_request(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let pki = ca.config.get_pki_name().to_owned();
    let mut admin = false;
    let cs = s.user_certs.all_certs();
    for cert in cs {
        if ca.is_admin(cert).await {
            admin = true;
        }
    }

    let mut csr_check = Err(CertificateSigningError::CsrDoesNotExist);
    if admin {
        if let Some(id) = s.get.get("id") {
            let id = str::parse::<u64>(id);
            if let Ok(id) = id {
                match &ca.config.sign_method {
                    CertificateSigningMethod::Https(_) => {
                        if let Some(csrr) = ca.get_csr_by_id(id).await {
                            use der::Encode;
                            let (_, der) = der::Document::from_pem(&csrr.cert).unwrap();
                            let der = der.to_der().unwrap();
                            let csr_der = rustls_pki_types::CertificateSigningRequestDer::from(der);
                            let a = rcgen::CertificateSigningRequestParams::from_der(&csr_der);
                            match a {
                                Ok(csr) => {
                                    service::log::info!("Ready to sign the csr");
                                    let ca_cert = ca.root_ca_cert().unwrap();
                                    let (snb, _sn) = CaCertificateToBeSigned::calc_sn(id);
                                    if let CertificateSigningMethod::Https(m) =
                                        ca.config.sign_method
                                    {
                                        let cert_to_sign = CaCertificateToBeSigned {
                                            algorithm: m,
                                            medium: ca.medium.clone(),
                                            csr,
                                            keypair: None,
                                            name: "".into(),
                                            id,
                                        };
                                        let cert = ca_cert
                                            .sign_csr(
                                                cert_to_sign,
                                                ca,
                                                id,
                                                time::Duration::days(365),
                                            )
                                            .unwrap();
                                        let der = cert.contents();
                                        if let Ok(der) = der {
                                            ca.mark_csr_done(id).await;
                                            ca.save_user_cert(id, &der, &snb).await;
                                            csr_check = Ok(der);
                                        }
                                    }
                                }
                                Err(e) => {
                                    service::log::error!("Error decoding csr to sign: {:?}", e);
                                }
                            }
                        }
                    }
                    CertificateSigningMethod::Ssh(_) => todo!(),
                }
            }
        }
    }

    let mut html = html::root::Html::builder();

    html.head(|h| generic_head(h, s, ca).title(|t| t.text(ca.config.common_name.to_owned())))
        .body(|b| {
            match csr_check {
                Ok(_der) => {
                    b.text("The request has been signed").line_break(|a| a);
                }
                Err(e) => match e {
                    CertificateSigningError::CsrDoesNotExist => {
                        b.text("The certificate signing request does not exist")
                            .line_break(|a| a);
                    }
                    CertificateSigningError::FailedToDeleteRequest => {
                        b.text("Failed to delete request").line_break(|a| a);
                    }
                    CertificateSigningError::UnableToSign => {
                        b.text("Unable to sign request").line_break(|a| a);
                    }
                    CertificateSigningError::UndecipherableX509Generated => {
                        b.text("The generated certificate was garbage")
                            .line_break(|a| a);
                    }
                },
            }
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
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// A page to sign a single request.
async fn ca_sign_request(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_sign_request(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_sign_request(ca, &s).await,
    }
}

/// Get the pending signing requests for a certificate authority
async fn handle_ca_list_https_requests(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let mut admin = false;
    let cs = s.user_certs.all_certs();
    for cert in cs {
        if ca.is_admin(cert).await {
            admin = true;
        }
    }

    let csrr = if let Some(id) = s.get.get("id") {
        let id = str::parse::<u64>(id);
        if let Ok(id) = id {
            ca.get_csr_by_id(id).await
        } else {
            None
        }
    } else {
        None
    };

    let mut csr_list: Vec<(CsrRequest, u64)> = Vec::new();
    ca.csr_processing(|_index, csr, id| {
        csr_list.push((csr, id));
    })
    .await;

    let mut html = html::root::Html::builder();
    html.head(|h| generic_head(h, s, ca).title(|t| t.text(ca.config.common_name.to_owned())))
        .body(|b| {
            if let Some(id) = s.get.get("id") {
                if let Some(csrr) = csrr {
                    use der::DecodePem;
                    let csr = x509_cert::request::CertReq::from_pem(&csrr.cert);
                    if let Ok(csr) = csr {
                        let csr_names: Vec<String> = csr
                            .info
                            .subject
                            .0
                            .iter()
                            .map(|n| format!("{}", n))
                            .collect();
                        let t = csr_names.join(", ");
                        b.anchor(|ab| {
                            ab.text("Back to all requests");
                            ab.href("list.rs");
                            ab
                        })
                        .line_break(|a| a);
                        b.text(t).line_break(|a| a);
                        b.text(format!("Name: {}", csrr.name)).line_break(|a| a);
                        b.text(format!("Email: {}", csrr.email)).line_break(|a| a);
                        b.text(format!("Phone: {}", csrr.phone)).line_break(|a| a);
                        for attr in csr.info.attributes.iter() {
                            for p in attr.values.iter() {
                                let pa = cert_common::CsrAttribute::with_oid_and_any(
                                    Oid::from_const(attr.oid),
                                    p.to_owned(),
                                );
                                if let Some(pa) = pa {
                                    match pa {
                                        cert_common::CsrAttribute::ExtendedKeyUsage(ek) => {
                                            for key_use in ek {
                                                b.text(format!("\tUsage: {:?}", key_use))
                                                    .line_break(|a| a);
                                            }
                                        }
                                        cert_common::CsrAttribute::ChallengePassword(p) => {
                                            b.text(format!("\tChallenge password: {}", p))
                                                .line_break(|a| a);
                                        }
                                        cert_common::CsrAttribute::UnstructuredName(n) => {
                                            b.text(format!("\tChallenge name: {}", n))
                                                .line_break(|a| a);
                                        }
                                        cert_common::CsrAttribute::Unrecognized(oid, _a) => {
                                            b.text(format!("\tUnrecognized: {:?}", oid))
                                                .line_break(|a| a);
                                        }
                                    }
                                } else {
                                    b.text("Attribute not processed").line_break(|a| a);
                                }
                            }
                        }
                        b.anchor(|ab| {
                            ab.text("Sign this request");
                            ab.href(format!("request_sign.rs?id={}", id));
                            ab
                        })
                        .line_break(|a| a);
                        b.form(|f| {
                            f.action("request_reject.rs");
                            f.text("Reject reason")
                                .line_break(|a| a)
                                .input(|i| {
                                    i.type_("hidden").id("id").name("id").value(id.to_string())
                                })
                                .input(|i| i.type_("text").id("rejection").name("rejection"))
                                .line_break(|a| a);
                            f.input(|i| i.type_("submit").value("Reject this request"))
                                .line_break(|a| a);
                            f
                        });
                    }
                }
            } else if admin {
                b.text("List all pending requests");
                b.line_break(|a| a);
                let mut index_shown = 0;
                for (csrr, id) in csr_list {
                    use der::DecodePem;
                    let csr = x509_cert::request::CertReq::from_pem(&csrr.cert);
                    if let Ok(csr) = csr {
                        if index_shown > 0 {
                            b.thematic_break(|a| a);
                        }
                        index_shown += 1;
                        let csr_names: Vec<String> = csr
                            .info
                            .subject
                            .0
                            .iter()
                            .map(|n| format!("{}", n))
                            .collect();
                        let t = csr_names.join(", ");
                        b.anchor(|ab| {
                            ab.text("View this request");
                            ab.href(format!("list.rs?id={}", id));
                            ab
                        })
                        .line_break(|a| a);
                        b.text(t).line_break(|a| a);
                        b.text(format!("Name: {}", csrr.name)).line_break(|a| a);
                        b.text(format!("Email: {}", csrr.email)).line_break(|a| a);
                        b.text(format!("Phone: {}", csrr.phone)).line_break(|a| a);
                    }
                }
                b.anchor(|ab| {
                    ab.text("Back to main page");
                    ab.href(".");
                    ab
                });
            }
            b
        });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// A page for listing all https requests in the system. It also can enumerate a single request.
async fn ca_list_https_requests(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_list_https_requests(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_list_https_requests(ca, &s).await,
    }
}

/// Get the pending signing requests for a certificate authority
async fn handle_ca_list_ssh_requests(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let pki = ca.config.get_pki_name();
    let mut admin = false;
    let cs = s.user_certs.all_certs();
    for cert in cs {
        if ca.is_admin(cert).await {
            admin = true;
        }
    }

    let csrr = if let Some(id) = s.get.get("id") {
        let id = str::parse::<u64>(id);
        if let Ok(id) = id {
            ca.get_ssh_request_by_id(id).await
        } else {
            None
        }
    } else {
        None
    };

    let mut csr_list: Vec<(SshRequest, u64)> = Vec::new();
    ca.ssh_processing(|_index, csr, id| {
        csr_list.push((csr, id));
    })
    .await;

    let mut html = html::root::Html::builder();
    html.head(|h| generic_head(h, s, ca).title(|t| t.text(ca.config.common_name.to_owned())))
        .body(|b| {
            if let Some(id) = s.get.get("id") {
                if let Some(csrr) = csrr {
                    b.anchor(|ab| {
                        ab.text("Back to all requests");
                        ab.href(format!("{}{}ca/list.rs", s.proxy, pki));
                        ab
                    })
                    .line_break(|a| a);
                    b.text(format!("Name: {}", csrr.name)).line_break(|a| a);
                    b.text(format!("Email: {}", csrr.email)).line_break(|a| a);
                    b.text(format!("Phone: {}", csrr.phone)).line_break(|a| a);
                    if let Ok(u) = csrr.usage.try_into() {
                        let u: ssh_key::certificate::CertType = u;
                        b.text(format!("Certificate Usage: {:?}", u))
                            .line_break(|a| a);
                    } else {
                        b.text("Certificate Usage is invalid!").line_break(|a| a);
                    }
                    for p in &csrr.principals {
                        b.text(format!("Principal: {}", p)).line_break(|a| a);
                    }
                    b.text(format!("Comment: {}", csrr.comment))
                        .line_break(|a| a);
                    b.anchor(|ab| {
                        ab.text("Sign this request");
                        ab.href(format!("{}{}ca/request_sign.rs?id={}", s.proxy, pki, id));
                        ab
                    })
                    .line_break(|a| a);
                    b.form(|f| {
                        f.action(format!("{}{}ca/request_reject.rs", s.proxy, pki));
                        f.text("Reject reason")
                            .line_break(|a| a)
                            .input(|i| i.type_("hidden").id("id").name("id").value(id.to_string()))
                            .input(|i| i.type_("text").id("rejection").name("rejection"))
                            .line_break(|a| a);
                        f.input(|i| i.type_("submit").value("Reject this request"))
                            .line_break(|a| a);
                        f
                    });
                }
            } else if admin {
                b.text("List all pending requests");
                b.line_break(|a| a);
                for (index_shown, (csrr, id)) in csr_list.into_iter().enumerate() {
                    if index_shown > 0 {
                        b.thematic_break(|a| a);
                    }
                    b.anchor(|ab| {
                        ab.text("View this request");
                        ab.href(format!("{}{}ca/list.rs?id={}", s.proxy, pki, id));
                        ab
                    })
                    .line_break(|a| a);
                    b.text(format!("Name: {}", csrr.name)).line_break(|a| a);
                    b.text(format!("Email: {}", csrr.email)).line_break(|a| a);
                    b.text(format!("Phone: {}", csrr.phone)).line_break(|a| a);
                }
                b.anchor(|ab| {
                    ab.text("Back to main page");
                    ab.href(format!("{}{}ca", s.proxy, pki));
                    ab
                });
            }
            b
        });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// A page for listing all https requests in the system. It also can enumerate a single request.
async fn ca_list_ssh_requests(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_list_ssh_requests(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_list_ssh_requests(ca, &s).await,
    }
}

/// View all certificates for a certificate authority
async fn handle_ca_view_all_certs(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let mut admin = false;
    let cs = s.user_certs.all_certs();
    for cert in cs {
        if ca.is_admin(cert).await {
            admin = true;
        }
    }

    let mut csr_list: Vec<(x509_cert::Certificate, u64)> = Vec::new();
    if admin {
        ca.certificate_processing(|_index, cert, id| {
            csr_list.push((cert, id));
        })
        .await;
    }

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();

    let mut html = html::root::Html::builder();
    html.head(|h| generic_head(h, s, ca).title(|t| t.text(ca.config.common_name.to_owned())))
        .body(|b| {
            if admin {
                b.heading_1(|h| h.text("Current Certificates"))
                    .line_break(|a| a);
                for c in csr_list {
                    b.thematic_break(|a| a);
                    b.text(format!("Issued by: {}", c.0.tbs_certificate.issuer))
                        .line_break(|a| a);
                    b.text(format!("Serial #: {}", c.0.tbs_certificate.serial_number))
                        .line_break(|a| a);
                    b.text(format!("Subject: {}", c.0.tbs_certificate.subject))
                        .line_break(|a| a);
                    b.anchor(|ab| {
                        ab.text("View details");
                        ab.href(format!("view_cert.rs?id={}", c.1));
                        ab
                    });
                    b.line_break(|lb| lb);
                }
            }
            b.thematic_break(|a| a);
            b.anchor(|ab| {
                ab.text("Back to main page");
                ab.href(".");
                ab
            });
            b.line_break(|lb| lb);
            b
        });
    let html = html.build();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));

    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// A page for viewing all certificates in the certificate authority
async fn ca_view_all_certs(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_view_all_certs(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_view_all_certs(ca, &s).await,
    }
}

/// View a user certificate for a certificate authority
async fn handle_ca_view_user_https_cert(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let pki = ca.config.get_pki_name();
    let mut admin = false;
    let cs = s.user_certs.all_certs();
    for cert in cs {
        if ca.is_admin(cert).await {
            admin = true;
        }
    }

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;
    let mut csr = None;
    let mut rejection = None;
    let mut myid = 0;

    if let Some(id) = s.get.get("id") {
        let id: Result<u64, std::num::ParseIntError> = str::parse(id.as_str());
        if let Ok(id) = id {
            cert = ca.get_user_cert(id).await;
            if cert.is_none() {
                csr = ca.get_csr_by_id(id).await;
            }
            if csr.is_none() {
                rejection = Some(ca.get_rejection_reason_by_id(id).await);
            }
            myid = id;
        }
    }

    let mut html = html::root::Html::builder();
    html.head(|h| {
        generic_head(h, s, ca)
            .title(|t| t.text(ca.config.common_name.to_owned()))
            .script(|sb| {
                sb.src(s.get_absolute_url(pki, "js/certgen.js"));
                sb
            })
    })
    .body(|b| {
        b.script(|s| {
            s.text("async function run() {\n")
                .text("await wasm_bindgen();\n")
                .text("}\n")
                .text("run();\n")
        });
        if let Some(cert_der) = cert {
            use der::Decode;
            let cert: Result<x509_cert::certificate::CertificateInner, der::Error> =
                x509_cert::Certificate::from_der(&cert_der);
            match cert {
                Ok(cert) => {
                    let csr_names: Vec<String> = cert
                        .tbs_certificate
                        .subject
                        .0
                        .iter()
                        .map(|n| format!("{}", n))
                        .collect();
                    let t = csr_names.join(", ");
                    b.text(t).line_break(|a| a);
                    if admin {
                        b.text(format!(
                            "Valid from {} to {}",
                            cert.tbs_certificate.validity.not_before,
                            cert.tbs_certificate.validity.not_after
                        ))
                        .line_break(|a| a);
                    }
                    if let Some(extensions) = &cert.tbs_certificate.extensions {
                        for e in extensions {
                            let ca = CertAttribute::with_oid_and_data(
                                e.extn_id.into(),
                                e.extn_value.to_owned(),
                            );
                            if let Ok(ca) = ca {
                                match ca {
                                    CertAttribute::ExtendedKeyUsage(ek) => {
                                        for key_use in ek {
                                            b.text(format!("\tUsage: {:?}", key_use))
                                                .line_break(|a| a);
                                        }
                                    }
                                    CertAttribute::Unrecognized(oid, a) => {
                                        b.text(format!("\tUnrecognized: {:?} {:02X?}", oid, a))
                                            .line_break(|a| a);
                                    }
                                    CertAttribute::SubjectAlternativeName(names) => {
                                        b.text(format!("Alternate names: {}", names.join(",")))
                                            .line_break(|a| a);
                                    }
                                    CertAttribute::SubjectKeyIdentifier(i) => {
                                        let p: Vec<String> =
                                            i.iter().map(|a| format!("{:02X}", a)).collect();
                                        b.text(format!("Subject key identifer: {}", p.join(":")))
                                            .line_break(|a| a);
                                    }
                                    CertAttribute::BasicContraints { ca, path_len } => {
                                        b.text(format!(
                                            "Basic Contraints: CA:{}, Path length {}",
                                            ca, path_len
                                        ))
                                        .line_break(|a| a);
                                    }
                                    CertAttribute::AuthorityInfoAccess(aias) => {
                                        for aia in aias {
                                            b.text(format!(
                                                "Authority Information Access: {:?}",
                                                aia
                                            ))
                                            .line_break(|a| a);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    b.button(|b| {
                        b.text("Build certificate")
                            .onclick("wasm_bindgen.build_cert()")
                    });
                    b.form(|form| {
                        form.input(|i| i.type_("file").id("file-selector"))
                            .line_break(|a| a);
                        form.text("Password for private key").line_break(|a| a);
                        form.input(|i| i.type_("password").id("password"));
                        form.line_break(|a| a);
                        form.text("Password for certificate").line_break(|a| a);
                        form.input(|i| i.type_("password").id("cert-password"));
                        form.line_break(|a| a);
                        form
                    });
                    b.division(|div| {
                        div.class("hidden");
                        div.anchor(|a| {
                            a.id("get_request")
                                .text(format!("get_cert.rs?id={}&type=pem", myid))
                        });
                        div
                    });
                    b.line_break(|lb| lb);
                }
                Err(e) => {
                    service::log::error!("Error reading certificate {:?}", e);
                }
            }
        } else if csr.is_some() {
            b.text(format!(
                "Your request is pending at {}",
                time::OffsetDateTime::now_utc()
            ))
            .line_break(|a| a);
        } else if let Some(reason) = rejection {
            match reason {
                Some(reason) => {
                    if reason.is_empty() {
                        b.text("Your request is rejected: No reason given")
                            .line_break(|a| a);
                    } else {
                        b.text(format!("Your request is rejected: {}", reason))
                            .line_break(|a| a);
                    }
                    b.text(format!("{}", time::OffsetDateTime::now_utc()))
                        .line_break(|a| a);
                }
                None => {
                    b.text("Your request is rejected: No reason given")
                        .line_break(|a| a);
                    b.text(format!("{}", time::OffsetDateTime::now_utc()))
                        .line_break(|a| a);
                }
            }
        }
        b.anchor(|ab| {
            ab.text("Back to main page");
            ab.href(".");
            ab
        });
        b.line_break(|lb| lb);
        b
    });
    let html = html.build();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));

    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// Runs the page for fetching the user certificate for the certificate authority being run
async fn ca_view_user_https_cert(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_view_user_https_cert(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_view_user_https_cert(ca, &s).await,
    }
}

/// View a user certificate for a certificate authority
async fn handle_ca_view_user_ssh_cert(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let pki = ca.config.get_pki_name();
    let mut admin = false;
    let cs = s.user_certs.all_certs();
    for cert in cs {
        if ca.is_admin(cert).await {
            admin = true;
        }
    }

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;
    let mut csr = None;
    let mut rejection = None;
    let mut myid = 0;

    if let Some(id) = s.get.get("id") {
        let id: Result<u64, std::num::ParseIntError> = str::parse(id.as_str());
        if let Ok(id) = id {
            cert = ca.get_user_cert(id).await;
            if cert.is_none() {
                csr = ca.get_ssh_request_by_id(id).await;
            }
            if csr.is_none() {
                rejection = Some(ca.get_rejection_reason_by_id(id).await);
            }
            myid = id;
        }
    }

    let mut html = html::root::Html::builder();
    html.head(|h| {
        generic_head(h, s, ca)
            .title(|t| t.text(ca.config.common_name.to_owned()))
            .script(|sb| {
                sb.src(s.get_absolute_url(pki, "js/certgen.js"));
                sb
            })
    })
    .body(|b| {
        b.script(|s| {
            s.text("async function run() {\n")
                .text("await wasm_bindgen();\n")
                .text("}\n")
                .text("run();\n")
        });
        if let Some(cert) = cert {
            if admin {
                b.text(format!("Valid from {} to {}", 42, 43))
                    .line_break(|a| a);
            }
            b.button(|b| {
                b.text("Build certificate")
                    .onclick("wasm_bindgen.build_cert()")
            });
            b.form(|form| {
                form.input(|i| i.type_("file").id("file-selector"))
                    .line_break(|a| a);
                form.text("Password for private key").line_break(|a| a);
                form.input(|i| i.type_("password").id("password"));
                form.line_break(|a| a);
                form.text("Password for certificate").line_break(|a| a);
                form.input(|i| i.type_("password").id("cert-password"));
                form.line_break(|a| a);
                form
            });
            b.division(|div| {
                div.class("hidden");
                div.anchor(|a| {
                    a.id("get_request").text(format!(
                        "{}{}ca/get_cert.rs?id={}&type=pem",
                        s.proxy, pki, myid
                    ))
                });
                div
            });
            b.line_break(|lb| lb);
        } else if csr.is_some() {
            b.text(format!(
                "Your request is pending at {}",
                time::OffsetDateTime::now_utc()
            ))
            .line_break(|a| a);
        } else if let Some(reason) = rejection {
            match reason {
                Some(reason) => {
                    if reason.is_empty() {
                        b.text("Your request is rejected: No reason given")
                            .line_break(|a| a);
                    } else {
                        b.text(format!("Your request is rejected: {}", reason))
                            .line_break(|a| a);
                    }
                    b.text(format!("{}", time::OffsetDateTime::now_utc()))
                        .line_break(|a| a);
                }
                None => {
                    b.text("Your request is rejected: No reason given")
                        .line_break(|a| a);
                    b.text(format!("{}", time::OffsetDateTime::now_utc()))
                        .line_break(|a| a);
                }
            }
        }
        b.anchor(|ab| {
            ab.text("Back to main page");
            ab.href(".");
            ab
        });
        b.line_break(|lb| lb);
        b
    });
    let html = html.build();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));

    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// Runs the page for fetching the user certificate for the certificate authority being run
async fn ca_view_user_ssh_cert(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_view_user_ssh_cert(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_view_user_ssh_cert(ca, &s).await,
    }
}

/// Get a user certificate for a certificate authority
async fn handle_ca_get_user_cert(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;

    if let Some(id) = s.get.get("id") {
        let id: Result<u64, std::num::ParseIntError> = str::parse(id.as_str());
        if let Ok(id) = id {
            if let Some(cert_der) = ca.get_user_cert(id).await {
                let ty = if s.get.contains_key("type") {
                    s.get.get("type").unwrap().to_owned()
                } else {
                    "der".to_string()
                };

                match ty.as_str() {
                    "der" => {
                        response.headers.append(
                            "Content-Type",
                            HeaderValue::from_static("application/x509-ca-cert"),
                        );
                        let name = format!("attachment; filename={}.der", id);
                        response
                            .headers
                            .append("Content-Disposition", HeaderValue::from_str(&name).unwrap());
                        cert = Some(cert_der);
                    }
                    "pem" => {
                        use der::Decode;
                        response.headers.append(
                            "Content-Type",
                            HeaderValue::from_static("application/x-pem-file"),
                        );
                        let name = format!("attachment; filename={}.pem", id);
                        response
                            .headers
                            .append("Content-Disposition", HeaderValue::from_str(&name).unwrap());
                        let pem = der::Document::from_der(&cert_der)
                            .unwrap()
                            .to_pem("CERTIFICATE", pkcs8::LineEnding::CRLF)
                            .unwrap();
                        cert = Some(pem.as_bytes().to_vec());
                    }
                    _ => {}
                }
            }
        }
    }

    let body = if let Some(cert) = cert {
        http_body_util::Full::new(hyper::body::Bytes::copy_from_slice(&cert))
    } else {
        http_body_util::Full::new(hyper::body::Bytes::from("missing"))
    };
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// Runs the page for fetching the user certificate for the certificate authority being run
async fn ca_get_user_cert(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_get_user_cert(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_get_user_cert(ca, &s).await,
    }
}

/// Get the admin certificate for a certificate authority
async fn handle_ca_get_admin(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;

    let p = s.post.form();
    if let Some(p) = p {
        let token = p.get_first("token").unwrap();
        if token == ca.admin_access.as_str() {
            if let Ok(c) = ca.get_admin_cert().await {
                if let CertificateType::Soft(p) = &ca.config.admin_cert {
                    cert = c.try_p12(p);
                    if cert.is_some() {
                        response.headers.append(
                            "Content-Type",
                            HeaderValue::from_static("application/x-pkcs12"),
                        );
                        response.headers.append(
                            "Content-Disposition",
                            HeaderValue::from_static("attachment; filename=admin.p12"),
                        );
                    }
                }
            }
        }
    }

    let body = if let Some(cert) = cert {
        http_body_util::Full::new(hyper::body::Bytes::copy_from_slice(&cert))
    } else {
        let mut html = html::root::Html::builder();
        html.head(|h| generic_head(h, s, ca).title(|t| t.text(ca.config.common_name.to_owned())))
            .body(|b| {
                b.anchor(|ab| {
                    ab.text("Back to main page");
                    ab.href(".");
                    ab
                })
                .line_break(|a| a);
                b.form(|f| {
                    f.method("POST");
                    f.text("Access key for admin certificate")
                        .line_break(|a| a)
                        .input(|i| i.type_("password").name("token").id("token"))
                        .line_break(|a| a);
                    f.input(|i| i.type_("submit")).line_break(|a| a);
                    f
                });
                b
            });
        http_body_util::Full::new(hyper::body::Bytes::from(html.build().to_string()))
    };
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// Runs the page for fetching the ca certificate for the certificate authority being run
async fn ca_get_admin(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_get_admin(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_get_admin(ca, &s).await,
    }
}

/// Get a ca cert for a certificate authrity
async fn handle_ca_get_cert(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;

    if let Ok(cert_der) = ca.root_ca_cert() {
        match &ca.config.sign_method {
            CertificateSigningMethod::Https(_m) => {
                let ty = if s.get.contains_key("type") {
                    s.get.get("type").unwrap().to_owned()
                } else {
                    "der".to_string()
                };

                match ty.as_str() {
                    "der" => {
                        response.headers.append(
                            "Content-Type",
                            HeaderValue::from_static("application/x509-ca-cert"),
                        );
                        response.headers.append(
                            "Content-Disposition",
                            HeaderValue::from_static("attachment; filename=ca.cer"),
                        );
                        cert = cert_der.contents().ok();
                    }
                    "pem" => {
                        response.headers.append(
                            "Content-Type",
                            HeaderValue::from_static("application/x-pem-file"),
                        );
                        response.headers.append(
                            "Content-Disposition",
                            HeaderValue::from_static("attachment; filename=ca.pem"),
                        );
                        if let Some(pem) = cert_der.public_pem() {
                            cert = Some(pem.as_bytes().to_vec());
                        }
                    }
                    _ => {}
                }
            }
            CertificateSigningMethod::Ssh(_m) => {
                response
                    .headers
                    .append("Content-Type", HeaderValue::from_static("text/plain"));
                response.headers.append(
                    "Content-Disposition",
                    HeaderValue::from_static("attachment; filename=ca.txt"),
                );
                if let Some(pem) = cert_der.public_pem() {
                    cert = Some(pem.as_bytes().to_vec());
                }
            }
        }
    }

    let body = if let Some(cert) = cert {
        http_body_util::Full::new(hyper::body::Bytes::copy_from_slice(&cert))
    } else {
        http_body_util::Full::new(hyper::body::Bytes::from("missing"))
    };
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// Runs the page for fetching the ca certificate for the certificate authority being run
async fn ca_get_cert(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_get_cert(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_get_cert(ca, &s).await,
    }
}

/// Ocsp requirements
struct OcspRequirements {
    /// Is a signure required for ocsp requests?
    signature: bool,
}

impl OcspRequirements {
    /// Construct a new Self
    fn new() -> Self {
        Self { signature: false }
    }
}

/// A helper function for building an ocsp response
async fn build_ocsp_response(
    ca: &mut Ca,
    req: ocsp::request::OcspRequest,
) -> ocsp::response::OcspResponse {
    let mut nonce = None;
    let mut crl = None;

    let mut responses = Vec::new();
    let mut extensions = Vec::new();

    let ocsp_cert = ca.ocsp_ca_cert().unwrap();
    let root_cert = ca.root_ca_cert().unwrap();

    let root_x509_cert = root_cert.x509_cert().unwrap();
    let ocsp_x509_cert = ocsp_cert.x509_cert().unwrap();

    for r in req.tbs_request.request_list {
        service::log::info!("Looking up a certificate");
        let stat = ca.get_cert_status(&root_x509_cert, &r.certid).await;
        if let Ok(stat) = stat {
            let resp = ocsp::response::OneResp {
                cid: r.certid,
                cert_status: stat,
                this_update: ocsp::common::asn1::GeneralizedTime::now(),
                next_update: None,
                one_resp_ext: None,
            };
            responses.push(resp);
        } else {
            todo!();
        }
    }
    if let Some(extensions) = req.tbs_request.request_ext {
        for e in extensions {
            match e.ext {
                ocsp::common::ocsp::OcspExt::Nonce { nonce: n } => nonce = Some(n),
                ocsp::common::ocsp::OcspExt::CrlRef { url, num, time } => {
                    crl = Some((url, num, time));
                }
            }
        }
    }

    let hash = HashType::Sha1
        .hash(
            ocsp_x509_cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        )
        .unwrap();
    let id = ocsp::response::ResponderId::new_key_hash(&hash);

    if let Some(ndata) = nonce {
        let n = ndata;
        let data = ocsp::common::ocsp::OcspExt::Nonce { nonce: n }
            .to_der()
            .unwrap();
        let datas = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_der(&data);
            });
        });
        let mut exts = ocsp::common::ocsp::OcspExtI::parse(&datas).unwrap();
        extensions.append(&mut exts);
    }

    if crl.is_some() {
        panic!("Unsure what to do with crl");
    }

    let extensions = if extensions.is_empty() {
        None
    } else {
        Some(extensions)
    };

    let data = ocsp::response::ResponseData::new(
        id,
        ocsp::common::asn1::GeneralizedTime::now(),
        responses,
        extensions,
    );

    let data_der = data.to_der().unwrap();

    let signature = ocsp_cert.sign(&data_der).await.unwrap();
    let certs = vec![ocsp_cert.contents().unwrap(), root_cert.contents().unwrap()]; //TODO remove the unwraps
    let certs = Some(certs);

    let bresp = ocsp::response::BasicResponse::new(
        data,
        signature.oid().unwrap().to_ocsp(),
        signature.signature(),
        certs,
    );
    let bytes =
        ocsp::response::ResponseBytes::new_basic(OID_OCSP_RESPONSE_BASIC.to_ocsp(), bresp).unwrap();
    ocsp::response::OcspResponse::new_success(bytes)
}

/// Run an ocsp response for a ca
async fn handle_ca_ocsp_responder(ca: &mut Ca, s: &WebPageContext) -> webserver::WebResponse {
    let ocsp_request = s.post.ocsp();

    let mut ocsp_requirements = OcspRequirements::new();
    let ocsp_response = if let Some(ocsp) = ocsp_request {
        let config = &ca.config;
        ocsp_requirements.signature = config.ocsp_signature;

        if ocsp_requirements.signature {
            match ocsp.optional_signature {
                None => ocsp::response::OcspResponse::new_non_success(
                    ocsp::response::OcspRespStatus::SigRequired,
                )
                .unwrap(),
                Some(s) => {
                    service::log::info!("Signature is {:?}", s);
                    todo!("Verify signature");
                    //build_ocsp_response(&mut ca, ocsp).await
                }
            }
        } else {
            build_ocsp_response(ca, ocsp).await
        }
    } else {
        service::log::error!("Did not parse ocsp request");
        ocsp::response::OcspResponse::new_non_success(ocsp::response::OcspRespStatus::MalformedReq)
            .unwrap()
    };

    let der = ocsp_response.to_der().unwrap();

    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    response.headers.append(
        "Content-Type",
        HeaderValue::from_static("application/ocsp-response"),
    );

    let body = http_body_util::Full::new(hyper::body::Bytes::from(der));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// Run the ocsp responder
async fn ca_ocsp_responder(s: WebPageContext) -> webserver::WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.roots.get_mut(name).unwrap();
            handle_ca_ocsp_responder(ca, &s).await
        }
        PkiInstance::Ca(ca) => handle_ca_ocsp_responder(ca, &s).await,
    }
}

/// Add elements for a generic header in the ca code.
/// # Arguments
/// * h - The `html::metadata::builders::HeadBuilder` to modify
/// * s - The context for the webpage
/// * Returns - The modified `html::metadata::builders::HeadBuilder`
fn generic_head<'a>(
    h: &'a mut html::metadata::builders::HeadBuilder,
    s: &WebPageContext,
    ca: &Ca,
) -> &'a mut html::metadata::builders::HeadBuilder {
    let pki = ca.config.get_pki_name();
    h.meta(|m| m.charset("UTF-8"));
    h.link(|h| {
        h.href(s.get_absolute_url(pki, "css/ca.css"))
            .rel("stylesheet")
            .media("all")
    });
    h.link(|h| {
        h.href(s.get_absolute_url(pki, "css/ca-mobile.css"))
            .rel("stylesheet")
            .media("screen and (max-width: 640px)")
    });
    h
}

/// Register static file remaps into the specified hashmap
pub fn ca_register_files(
    pki: &PkiInstance,
    static_map: &mut std::collections::HashMap<String, String>,
) {
    match pki {
        PkiInstance::Pki(pki) => {
            service::log::info!("Registering pki static files");
            for name in pki.roots.keys() {
                static_map.insert(
                    format!("/pki/{}/css/ca.css", name),
                    "/css/ca.css".to_string(),
                );
                static_map.insert(
                    format!("/pki/{}/css/ca-mobile.css", name),
                    "/css/ca.css".to_string(),
                );
                static_map.insert(
                    format!("/pki/{}/js/certgen_bg.wasm", name),
                    "/js/certgen_bg.wasm".to_string(),
                );
                static_map.insert(
                    format!("/pki/{}/js/certgen_wasm.js", name),
                    "/js/certgen_wasm.js".to_string(),
                );
                static_map.insert(
                    format!("/pki/{}/js/certgen.js", name),
                    "/js/certgen.js".to_string(),
                );
            }
        }
        PkiInstance::Ca(_ca) => {
            service::log::info!("Registering ca static files");
        }
    }
}

/// Register handlers into the specified webrouter.
pub fn ca_register(pki: &PkiInstance, router: &mut WebRouter) {
    let register = |router: &mut WebRouter, name: &str, ca: &Ca| {
        router.register(&format!("{}/ca", name), ca_main_page);
        router.register(&format!("{}/ca/", name), ca_main_page2);
        router.register(&format!("{}/ca/get_ca.rs", name), ca_get_cert);
        router.register(&format!("{}/ca/request.rs", name), ca_request);
        router.register(&format!("{}/ca/submit_request.rs", name), ca_submit_request);
        router.register(&format!("{}/ca/view_all_certs.rs", name), ca_view_all_certs);
        router.register(&format!("{}/ca/get_cert.rs", name), ca_get_user_cert);
        router.register(&format!("{}/ca/ocsp", name), ca_ocsp_responder);
        router.register(&format!("{}/ca/request_sign.rs", name), ca_sign_request);
        router.register(&format!("{}/ca/request_reject.rs", name), ca_reject_request);
        router.register(&format!("{}/ca/get_admin.rs", name), ca_get_admin);
        match &ca.config.sign_method {
            CertificateSigningMethod::Https(_) => {
                router.register(
                    &format!("{}/ca/view_cert.rs", name),
                    ca_view_user_https_cert,
                );
                router.register(&format!("{}/ca/list.rs", name), ca_list_https_requests);
            }
            CertificateSigningMethod::Ssh(_) => {
                router.register(&format!("{}/ca/view_cert.rs", name), ca_view_user_ssh_cert);
                router.register(&format!("{}/ca/list.rs", name), ca_list_ssh_requests);
            }
        }
    };

    match pki {
        PkiInstance::Pki(pki) => {
            router.register("/pki", pki_main_page);
            router.register("/pki/", pki_main_page2);
            for (name, ca) in &pki.roots {
                register(router, &format!("/pki/{}", name), ca);
            }
        }
        PkiInstance::Ca(ca) => {
            register(router, "", ca);
        }
    }
}
