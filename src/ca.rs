//! Handles certificate authority functionality

use hyper::header::HeaderValue;

use crate::{webserver, WebPageContext, WebRouter};

use crate::oid::*;

pub mod ca_usage;
pub use ca_usage::*;

async fn ca_submit_request(s: WebPageContext) -> webserver::WebResponse {
    let mut ca = s.ca.lock().await;

    let mut valid_csr = false;
    let mut id = None;

    let f = s.post.form();
    if let Some(form) = f {
        use der::DecodePem;
        if let Some(pem) = form.get_first("csr") {
            let cert = x509_cert::request::CertReq::from_pem(pem);
            if let Ok(csr) = cert {
                valid_csr = ca.verify_request(&csr).await.is_ok();
                if valid_csr {
                    use der::EncodePem;
                    let pem = csr.to_pem(pkcs8::LineEnding::CRLF).unwrap();
                    let csrr = CsrRequest {
                        cert: pem,
                        name: form.get_first("name").unwrap().to_string(),
                        email: form.get_first("email").unwrap().to_string(),
                        phone: form.get_first("phone").unwrap().to_string(),
                    };
                    id = ca.save_csr(&csrr).await;
                }
            }
        }
    }

    let mut html = html::root::Html::builder();
    html.head(|h| generic_head(h, &s)).body(|b| {
        if valid_csr {
            b.text("Your request has been submitted").line_break(|f| f);
            b.anchor(|ab| {
                ab.text("View status of request");
                ab.href(format!("/{}ca/view_cert.rs?id={}", s.proxy, id.unwrap()));
                ab
            });
            b.line_break(|lb| lb);
        } else {
            b.text("Your request was considered invalid")
                .line_break(|f| f);
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
}

async fn ca_request(s: WebPageContext) -> webserver::WebResponse {
    let mut html = html::root::Html::builder();
    html.head(|h| {
        generic_head(h, &s)
            .script(|sb| {
                sb.src(format!("/{}js/forge.min.js", s.proxy));
                sb
            })
            .script(|sb| {
                sb.src(format!("/{}js/certgen.js", s.proxy));
                sb
            })
    })
    .body(|b| {
        b.division(|div| {
            div.class("cert-gen-stuff");
            div.text("This page is used to generate a certificate. The generate button generates a private key and certificate signing request on your local device, protecting the private key with the password specified.").line_break(|a|a);
            div.button(|b| b.text("Generate a certificate").onclick("generate_cert()"));
            div.line_break(|lb| lb);
            div.division(|div| {
                div.class("advanced");
                div.button(|b| b.text("Simple").onclick("show_regular()")).line_break(|a|a);
                div
            });
            div.division(|div| {
                div.class("regular");
                div.button(|b| b.text("Advanced").onclick("show_advanced()")).line_break(|a|a);
                div
            });
            div.division(|div| {
                div.form(|f| {
                    f.name("request");
                    f.action(format!("/{}ca/submit_request.rs", s.proxy));
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
        cookie: s.logincookie,
    }
}

///The main landing page for the certificate authority
async fn ca_main_page(s: WebPageContext) -> webserver::WebResponse {
    let ca = s.ca.lock().await;

    let mut admin = false;
    if let Some(cs) = s.user_certs.all_certs() {
        for cert in cs {
            if ca.is_admin(cert) {
                admin = true;
            }
        }
    }

    let mut html = html::root::Html::builder();
    html.head(|h| generic_head(h, &s)).body(|b| {
        if admin {
            b.text("You are admin").line_break(|a| a);
        }
        b.anchor(|ab| {
            ab.text("Download CA certificate as der");
            ab.href(format!("/{}ca/get_ca.rs?type=der", s.proxy));
            ab.target("_blank");
            ab
        });
        b.line_break(|lb| lb);
        b.anchor(|ab| {
            ab.text("Download CA certificate as pem");
            ab.href(format!("/{}ca/get_ca.rs?type=pem", s.proxy));
            ab.target("_blank");
            ab
        });
        b.line_break(|lb| lb);
        b.anchor(|ab| {
            ab.text("Request a signature on a certificate");
            ab.href(format!("/{}ca/request.rs", s.proxy));
            ab
        });
        b.line_break(|lb| lb);
        if admin {
            b.anchor(|ab| {
                ab.text("List pending requests");
                ab.href(format!("/{}ca/list.rs", s.proxy));
                ab
            });
            b.line_break(|lb| lb);
            b.anchor(|ab| {
                ab.text("List all certificates");
                ab.href(format!("/{}ca/view_all_certs.rs", s.proxy));
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
        cookie: s.logincookie,
    }
}

async fn ca_reject_request(s: WebPageContext) -> webserver::WebResponse {
    let mut ca = s.ca.lock().await;

    let mut csr_check = Err(CertificateSigningError::CsrDoesNotExist);
    if let Some(id) = s.get.get("id") {
        let id = str::parse::<usize>(id);
        let reject = s.get.get("rejection").unwrap();
        if let Ok(id) = id {
            csr_check = ca.reject_csr_by_id(id, reject).await;
        }
    }

    let mut html = html::root::Html::builder();

    html.head(|h| generic_head(h, &s)).body(|b| {
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
            },
        }
        b.anchor(|ab| {
            ab.text("List pending requests");
            ab.href(format!("/{}ca/list.rs", s.proxy));
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
        cookie: s.logincookie,
    }
}

async fn ca_sign_request(s: WebPageContext) -> webserver::WebResponse {
    let mut ca = s.ca.lock().await;

    let mut admin = false;
    if let Some(cs) = s.user_certs.all_certs() {
        for cert in cs {
            if ca.is_admin(cert) {
                admin = true;
            }
        }
    }

    let mut csr_check = Err(CertificateSigningError::CsrDoesNotExist);
    if admin {
        if let Some(id) = s.get.get("id") {
            let id = str::parse::<usize>(id);
            if let Ok(id) = id {
                if let Some(csrr) = ca.get_csr_by_id(id) {
                    let mut a = rcgen::CertificateSigningRequest::from_pem(&csrr.cert);
                    match &mut a {
                        Ok(csr) => {
                            csr.params.not_before = time::OffsetDateTime::now_utc();
                            csr.params.not_after =
                                csr.params.not_before + time::Duration::days(365);
                            let mut sn = [0; 20];
                            for (i, b) in id.to_le_bytes().iter().enumerate() {
                                sn[i] = *b;
                            }
                            let sn = rcgen::SerialNumber::from_slice(&sn);
                            csr.params.serial_number = Some(sn);
                            println!("Ready to sign the csr");
                            let der = csr
                                .serialize_der_with_signer(
                                    &ca.root_ca_cert().unwrap().as_certificate(),
                                )
                                .unwrap();
                            println!(
                                "got a signed der certificate for the user length {}",
                                der.len()
                            );
                            ca.mark_csr_done(id).await;
                            ca.save_user_cert(id, &der).await;
                            csr_check = Ok(der);
                        }
                        Err(e) => {
                            println!("Error decoding csr to sign: {:?}", e);
                        }
                    }
                }
            }
        }
    }

    let mut html = html::root::Html::builder();

    html.head(|h| generic_head(h, &s)).body(|b| {
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
            },
        }
        b.anchor(|ab| {
            ab.text("List pending requests");
            ab.href(format!("/{}ca/list.rs", s.proxy));
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
        cookie: s.logincookie,
    }
}

async fn ca_list_requests(s: WebPageContext) -> webserver::WebResponse {
    let ca = s.ca.lock().await;

    let mut admin = false;
    if let Some(cs) = s.user_certs.all_certs() {
        for cert in cs {
            if ca.is_admin(cert) {
                admin = true;
            }
        }
    }

    let mut html = html::root::Html::builder();
    html.head(|h| generic_head(h, &s)).body(|b| {
        if let Some(id) = s.get.get("id") {
            let id = str::parse::<usize>(id);
            if let Ok(id) = id {
                if let Some(csrr) = ca.get_csr_by_id(id) {
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
                            ab.href(format!("/{}ca/list.rs", s.proxy));
                            ab
                        })
                        .line_break(|a| a);
                        b.text(t).line_break(|a| a);
                        b.text(format!("Name: {}", csrr.name)).line_break(|a| a);
                        b.text(format!("Email: {}", csrr.email)).line_break(|a| a);
                        b.text(format!("Phone: {}", csrr.phone)).line_break(|a| a);
                        for attr in csr.info.attributes.iter() {
                            for p in attr.values.iter() {
                                let pa = CsrAttribute::with_oid_and_any(
                                    Oid::from_const(attr.oid),
                                    p.to_owned(),
                                );
                                b.text(format!("\t{}", pa)).line_break(|a| a);
                            }
                        }
                        b.anchor(|ab| {
                            ab.text("Sign this request");
                            ab.href(format!("/{}ca/request_sign.rs?id={}", s.proxy, id));
                            ab
                        })
                        .line_break(|a| a);
                        b.form(|f| {
                            f.action(format!("/{}ca/request_reject.rs", s.proxy));
                            f.text("Reject reason")
                                .line_break(|a| a)
                                .input(|i| {
                                    i.type_("hidden")
                                        .id("id")
                                        .name("id")
                                        .value(format!("{}", id))
                                })
                                .input(|i| i.type_("text").id("rejection").name("rejection"))
                                .line_break(|a| a);
                            f.input(|i| i.type_("submit").value("Reject this request"))
                                .line_break(|a| a);
                            f
                        });
                    }
                }
            }
        } else {
            if admin {
                b.text("List all pending requests");
                b.line_break(|a| a);
                let mut index_shown = 0;
                for (csrr, id) in ca.get_csr_iter() {
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
                            ab.href(format!("/{}ca/list.rs?id={}", s.proxy, id));
                            ab
                        })
                        .line_break(|a| a);
                        b.text(t).line_break(|a| a);
                        b.text(format!("Name: {}", csrr.name)).line_break(|a| a);
                        b.text(format!("Email: {}", csrr.email)).line_break(|a| a);
                        b.text(format!("Phone: {}", csrr.phone)).line_break(|a| a);
                    }
                }
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
        cookie: s.logincookie,
    }
}

async fn ca_view_all_certs(s: WebPageContext) -> webserver::WebResponse {
    let ca = s.ca.lock().await;

    let mut admin = false;
    if let Some(cs) = s.user_certs.all_certs() {
        for cert in cs {
            if ca.is_admin(cert) {
                admin = true;
            }
        }
    }

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();

    let mut html = html::root::Html::builder();
    html.head(|h| {
        generic_head(h, &s)
            .script(|sb| {
                sb.src(format!("/{}js/forge.min.js", s.proxy));
                sb
            })
            .script(|sb| {
                sb.src(format!("/{}js/certgen.js", s.proxy));
                sb
            })
    })
    .body(|b| {
        if admin {
            b.heading_1(|h| h.text("Current Certificates"))
                .line_break(|a| a);
            for c in ca.get_cert_iter() {
                b.thematic_break(|a| a);
                b.text(format!("Issued by: {}", c.0.tbs_certificate.issuer))
                    .line_break(|a| a);
                b.text(format!("Serial #: {}", c.0.tbs_certificate.serial_number))
                    .line_break(|a| a);
                b.text(format!("Subject: {}", c.0.tbs_certificate.subject))
                    .line_break(|a| a);
                b.anchor(|ab| {
                    ab.text("View details");
                    ab.href(format!("/{}ca/view_cert.rs?id={}", s.proxy, c.1));
                    ab
                });
                b.line_break(|lb| lb);
            }
        }
        b.thematic_break(|a| a);
        b.anchor(|ab| {
            ab.text("Back to main page");
            ab.href(format!("/{}ca", s.proxy));
            ab
        });
        b.line_break(|lb| lb);
        b
    });
    let html = html.build();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));

    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

/// Runs the page for fetching the user certificate for the certificate authority being run
async fn ca_view_user_cert(s: WebPageContext) -> webserver::WebResponse {
    let ca = s.ca.lock().await;

    let mut admin = false;
    if let Some(cs) = s.user_certs.all_certs() {
        for cert in cs {
            if ca.is_admin(cert) {
                admin = true;
            }
        }
    }

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;
    let mut csr = None;
    let mut rejection = None;
    let mut myid = 0;

    if let Some(id) = s.get.get("id") {
        let id: Result<usize, std::num::ParseIntError> = str::parse(id.as_str());
        if let Ok(id) = id {
            cert = ca.get_user_cert(id).await;
            if cert.is_none() {
                csr = ca.get_csr_by_id(id);
            }
            if csr.is_none() {
                rejection = Some(ca.get_rejection_reason_by_id(id).await);
            }
            myid = id;
        }
    }

    let mut html = html::root::Html::builder();
    html.head(|h| {
        generic_head(h, &s)
            .script(|sb| {
                sb.src(format!("/{}js/forge.min.js", s.proxy));
                sb
            })
            .script(|sb| {
                sb.src(format!("/{}js/certgen.js", s.proxy));
                sb
            })
    })
    .body(|b| {
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
                            b.text(format!("\t{}", ca)).line_break(|a| a);
                        }
                    }
                    b.button(|b| b.text("Build certificate").onclick("build_cert()"));
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
                                .text(format!("/{}ca/get_cert.rs?id={}&type=pem", s.proxy, myid))
                        });
                        div
                    });
                    b.line_break(|lb| lb);
                }
                Err(e) => {
                    println!("Error reading certificate {:?}", e);
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
            ab.href(format!("/{}ca", s.proxy));
            ab
        });
        b.line_break(|lb| lb);
        b
    });
    let html = html.build();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));

    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

/// Runs the page for fetching the user certificate for the certificate authority being run
async fn ca_get_user_cert(s: WebPageContext) -> webserver::WebResponse {
    let ca = s.ca.lock().await;

    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;

    if let Some(id) = s.get.get("id") {
        let id: Result<usize, std::num::ParseIntError> = str::parse(id.as_str());
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
        cookie: s.logincookie,
    }
}

/// Runs the page for fetching the ca certificate for the certificate authority being run
async fn ca_get_cert(s: WebPageContext) -> webserver::WebResponse {
    let ca = s.ca.lock().await;

    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let mut cert: Option<Vec<u8>> = None;

    if let Ok(cert_der) = ca.root_ca_cert() {
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
                cert = Some(cert_der.cert.to_owned());
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
                if let Ok(pem) = cert_der.public_pem() {
                    cert = Some(pem.as_bytes().to_vec());
                }
            }
            _ => {}
        }
    }

    let body = if let Some(cert) = cert {
        http_body_util::Full::new(hyper::body::Bytes::copy_from_slice(&cert))
    } else {
        http_body_util::Full::new(hyper::body::Bytes::from("missing"))
    };
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

struct OcspRequirements {
    signature: bool,
}

impl OcspRequirements {
    fn new() -> Self {
        Self { signature: false }
    }
}

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

    let x509_cert = {
        use der::Decode;
        x509_cert::Certificate::from_der(&ocsp_cert.cert).unwrap()
    };

    for r in req.tbs_request.request_list {
        let stat = ca.get_cert_status(&x509_cert, &r.certid).await;
        let resp = ocsp::response::OneResp {
            cid: r.certid,
            cert_status: stat,
            this_update: ocsp::common::asn1::GeneralizedTime::now(),
            next_update: None,
            one_resp_ext: None,
        };
        responses.push(resp);
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
            x509_cert
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

    let (oid, sign) = ocsp_cert.sign(&data_der).await.unwrap();
    let mut certs = Vec::new();
    certs.push(ocsp_cert.cert.to_owned());
    certs.push(root_cert.cert.to_owned());
    let certs = Some(certs);

    let bresp = ocsp::response::BasicResponse::new(data, oid.to_ocsp(), sign, certs);
    let bytes =
        ocsp::response::ResponseBytes::new_basic(OID_OCSP_RESPONSE_BASIC.to_ocsp(), bresp).unwrap();
    ocsp::response::OcspResponse::new_success(bytes)
}

async fn ca_ocsp_responder(s: WebPageContext) -> webserver::WebResponse {
    let mut ca = s.ca.lock().await;

    let ocsp_request = s.post.ocsp();

    let mut ocsp_requirements = OcspRequirements::new();
    let ocsp_response = if let Some(ocsp) = ocsp_request {
        let config = s.settings.ca.as_ref().unwrap();
        ocsp_requirements.signature = config.ocsp_signature;

        if ocsp_requirements.signature {
            match ocsp.optional_signature {
                None => ocsp::response::OcspResponse::new_non_success(
                    ocsp::response::OcspRespStatus::SigRequired,
                )
                .unwrap(),
                Some(s) => {
                    println!("Signature is {:?}", s);
                    todo!("Verify signature");
                    //build_ocsp_response(&mut ca, ocsp).await
                }
            }
        } else {
            build_ocsp_response(&mut ca, ocsp).await
        }
    } else {
        println!("Did not parse ocsp request");
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
        cookie: s.logincookie,
    }
}

fn generic_head<'a>(
    h: &'a mut html::metadata::builders::HeadBuilder,
    s: &WebPageContext,
) -> &'a mut html::metadata::builders::HeadBuilder {
    h.title(|t| t.text("UglyOldBob Certificate Authority"));
    h.meta(|m| m.charset("UTF-8"));
    h.link(|h| {
        h.href(format!("/{}css/ca.css", s.proxy))
            .rel("stylesheet")
            .media("all")
    });
    h.link(|h| {
        h.href(format!("/{}css/ca-mobile.css", s.proxy))
            .rel("stylesheet")
            .media("screen and (max-width: 640px)")
    });
    h
}

pub fn ca_register(router: &mut WebRouter) {
    router.register("/ca", ca_main_page);
    router.register("/ca/", ca_main_page);
    router.register("/ca/get_ca.rs", ca_get_cert);
    router.register("/ca/view_cert.rs", ca_view_user_cert);
    router.register("/ca/view_all_certs.rs", ca_view_all_certs);
    router.register("/ca/get_cert.rs", ca_get_user_cert);
    router.register("/ca/ocsp", ca_ocsp_responder);
    router.register("/ca/request.rs", ca_request);
    router.register("/ca/submit_request.rs", ca_submit_request);
    router.register("/ca/list.rs", ca_list_requests);
    router.register("/ca/request_sign.rs", ca_sign_request);
    router.register("/ca/request_reject.rs", ca_reject_request);
}
