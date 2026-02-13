//! Code for the generate csr page

use crate::applets::AppletTrait;
use crate::{
    ca::{Ca, CsrRequest, LocalOrRemoteCa, PkiInstance},
    utility::WebPageContext,
    webserver::WebResponse,
};
use cert_common::{oid::*, CertificateSigningMethod, HttpsSigningMethod};

/// Page for a user to generate a request for a certificate authority
async fn handle_ca_request(ca: &mut Ca, s: &WebPageContext) -> WebResponse {
    let pki = ca.config.get_pki_name();
    let mut html = html::root::Html::builder();
    html.head(|h| {
        super::generic_head(h, s, ca)
            .title(|t| t.text(ca.config.common_name.to_owned()))
            .script(|sb| {
                sb.src(s.get_absolute_url(pki, "js/certgen.js"));
                sb
            })
    });
    html.body(|b| {
        b.script(|s| {
            s.text("async function run() {\n")
                .text("await wasm_bindgen();\n")
                .text("}\n")
                .text("run();\n")
        });
        b.division(|d| {
            d.class("container");
            d.header(|h| {
                h.division(|d2| {
                    d2.class("logo");
                    d2.division(|d3| {
                        d3.class("logo-icon").text("🔐")
                    });
                    d2.division(|d3| {
                        d3.class("logo-text")
                            .heading_1(|h|h.text("Certificate Authority"))
                            .paragraph(|p|p.text("Request Certificate"))
                    });
                    d2
                });
                h.division(|d3| {
                    d3.class("header-actions");
                    d3.anchor(|a|
                        a.href("?")
                            .class("btn btn-secondary")
                            .span(|s|s.text("←"))
                            .text("Back to Main")
                        );
                    d3
                });
                h
            });
            d.division(|d2| {
                d2.class("main-content");
                d2.aside(|a| {
                    a.class("sidebar");
                    a.navigation(|n| {
                        n.division(|d3| {
                            d3.class("nav-section");
                            d3.heading_3(|h|h.text("Actions"));
                            d3.button(|b| {
                                b.text("Generate certificate request");
                                b.class("btn btn-secondary");
                                match ca.config.sign_method {
                                    CertificateSigningMethod::Https(m) => match m {
                                        HttpsSigningMethod::RsaSha256 => {
                                            b.onclick("wasm_bindgen.generate_csr_rsa_sha256()");
                                        }
                                        HttpsSigningMethod::EcdsaSha256 => {
                                            b.onclick("wasm_bindgen.generate_csr_ecdsa_sha256()");
                                        }
                                    }
                                    CertificateSigningMethod::Ssh(m) => {
                                        match m {
                                            cert_common::SshSigningMethod::Rsa => {
                                                b.onclick("wasm_bindgen.generate_ssh_rsa()");
                                            }
                                            cert_common::SshSigningMethod::Ed25519 => {
                                                b.onclick("wasm_bindgen.generate_ed25519_rsa()");
                                            }
                                        }
                                    }
                                }
                                b
                            });
                            d3
                        });
                        n
                    });
                    a
                });
                d2.main(|m| {
                    m.class("content-area");
                    m.division(|d3| {
                        d3.class("page-header");
                        d3.heading_2(|h|h.class("page-title").text("Request New Certificate"));
                        d3
                    });
                    m.division(|d3| {
                        d3.class("info-box");
                        d3.division(|d4| {
                            d4.class("info-box-title");
                            d4.span(|s|s.text("ℹ️"));
                            d4.text("Certificate Request Process");
                            d4
                        });
                        d3.division(|d4| {
                            d4.class("info-box-content");
                            d4.text("Fill out the form below to generate a certificate signing request (CSR). The CSR and private key are generated locally in your browser. ");
                            d4.strong(|s|s.text("Your private key is protected with the password you specify and never leaves your device."));
                            d4
                        });
                        d3
                    });
                    match ca.config.sign_method {
                        CertificateSigningMethod::Https(_m) => {
                            m.form(|f| {
                                match s.delivery {
                                    crate::main_config::PageDelivery::Cgi => f.action("?action=submit_request"),
                                    crate::main_config::PageDelivery::DedicatedServer => f.action("submit_request.rs"),
                                };
                                f.method("post");
                                f.name("request");
                                f.division(|d4| {
                                    d4.class("section-header");
                                    d4.heading_3(|h| h.class("section-title").text("Personal Information"));
                                    d4
                                });
                                f.division(|d4| {
                                    d4.class("form-grid");
                                    d4.division(|d5| {
                                        d5.class("form-group");
                                        d5.label(|l| {
                                            l.for_("name");
                                            l.text("Your Name");
                                            l.span(|s| s.style("color: #e53e3e;").text("*"));
                                            l
                                        });
                                        d5.input(|i| i.name("name").type_("text").id("name").required(""));
                                        d5
                                    });
                                    d4.division(|d5| {
                                        d5.class("form-group");
                                        d5.label(|l| {
                                            l.for_("name");
                                            l.text("Email");
                                            l.span(|s| s.style("color: #e53e3e;").text("*"));
                                            l
                                        });
                                        d5.input(|i| i.name("email").type_("email").id("email").required(""));
                                        d5
                                    });
                                    d4
                                });
                                f.division(|d5| {
                                    d5.class("form-group");
                                    d5.label(|l| {
                                        l.for_("phone");
                                        l.text("Phone Number");
                                        l.span(|s| s.style("color: #e53e3e;").text("*"));
                                        l
                                    });
                                    d5.input(|i| i.name("phone").type_("tel").id("phone").required(""));
                                    d5
                                });
                                f.division(|d5| {
                                    d5.class("form-group");
                                    d5.label(|l| {
                                        l.for_("password");
                                        l.text("Password for private key");
                                        l.span(|s| s.style("color: #e53e3e;").text("*"));
                                        l
                                    });
                                    d5.input(|i| i.name("password").type_("password").id("password").required(""));
                                    d5.side_comment(|s|s.style("color: #718096; font-size: 12px;").text("This password will encrypt your private key for security"));
                                    d5
                                });
                                f.division(|d4| {
                                    d4.class("section-header");
                                    d4.style("margin-top: 32px;");
                                    d4.heading_3(|h| h.class("section-title").text("Certificate Usage"));
                                    d4
                                });
                                f.division(|d4| {
                                    d4.class("form-group");
                                    d4.division(|d5| {
                                        d5.style("display: flex; flex-direction: column; gap: 12px;");
                                        d5.label(|l| {
                                            l.style("display: flex; align-items: center; gap: 12px; cursor: pointer; text-transform: none; letter-spacing: normal;");
                                            l.input(|i| {
                                                i.name("usage-client").type_("checkbox").value("client").id("usage-client").style("width: auto;")
                                            });
                                            l.span(|s| s.text("Client Certification"));
                                            l
                                        });
                                        d5.label(|l| {
                                            l.style("display: flex; align-items: center; gap: 12px; cursor: pointer; text-transform: none; letter-spacing: normal;");
                                            l.input(|i| {
                                                i.name("usage-code").type_("checkbox").value("code").id("usage-code").style("width: auto;")
                                            });
                                            l.span(|s| s.text("Code Signing"));
                                            l
                                        });
                                        d5.label(|l| {
                                            l.style("display: flex; align-items: center; gap: 12px; cursor: pointer; text-transform: none; letter-spacing: normal;");
                                            l.input(|i| {
                                                i.name("usage-server").type_("checkbox").value("server").id("usage-server").style("width: auto;")
                                            });
                                            l.span(|s| s.text("Server Certification"));
                                            l
                                        });
                                        d5
                                    });
                                    d4
                                });
                                f.division(|d4| {
                                    d4.class("section-header");
                                    d4.style("margin-top: 32px;");
                                    d4.heading_3(|h| h.class("section-title").text("Certificate Information"));
                                    d4
                                });
                                f.division(|d5| {
                                    d5.class("form-group");
                                    d5.label(|l| {
                                        l.for_("cname");
                                        l.text("Certificate Name (Common Name) ");
                                        l.span(|s| s.style("color: #e53e3e;").text("*"));
                                        l
                                    });
                                    d5.input(|i| i.name("cname").type_("text").id("cname").placeholder("example.com").required(""));
                                    d5
                                });
                                f.division(|d4| {
                                    d4.class("form-grid");
                                    d4.division(|d5| {
                                        d5.class("form-group");
                                        d5.label(|l| {
                                            l.for_("country");
                                            l.text("Country");
                                            l.span(|s| s.style("color: #e53e3e;").text("*"));
                                            l
                                        });
                                        d5.input(|i| i.name("country").type_("text").id("country").placeholder("US").maxlength("2").required(""));
                                        d5
                                    });
                                    d4.division(|d5| {
                                        d5.class("form-group");
                                        d5.label(|l| {
                                            l.for_("state");
                                            l.text("State/Province");
                                            l.span(|s| s.style("color: #e53e3e;").text("*"));
                                            l
                                        });
                                        d5.input(|i| i.name("state").type_("email").id("state").placeholder("California").required(""));
                                        d5
                                    });
                                    d4
                                });
                                f.division(|d5| {
                                    d5.class("form-group");
                                    d5.label(|l| {
                                        l.for_("organization-unit");
                                        l.text("Organization Unit");
                                        l.span(|s| s.style("color: #e53e3e;").text("*"));
                                        l
                                    });
                                    d5.input(|i| i.name("organization-unit").type_("text").id("organization-unit").placeholder("IT Department").required(""));
                                    d5
                                });
                                f.division(|d4| {
                                    d4.class("form-grid");
                                    d4.division(|d5| {
                                        d5.class("form-group");
                                        d5.label(|l| {
                                            l.for_("challenge-pass");
                                            l.text("Challenge Password");
                                            l.span(|s| s.style("color: #e53e3e;").text("*"));
                                            l
                                        });
                                        d5.input(|i| i.name("challenge-pass").type_("password").id("challenge-pass").required(""));
                                        d5
                                    });
                                    d4.division(|d5| {
                                        d5.class("form-group");
                                        d5.label(|l| {
                                            l.for_("challenge-name");
                                            l.text("Challenge Name");
                                            l.span(|s| s.style("color: #e53e3e;").text("*"));
                                            l
                                        });
                                        d5.input(|i| i.name("challenge-name").type_("text").id("challenge-name").required(""));
                                        d5
                                    });
                                    d4
                                });
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
                                f.division(|d| {
                                    d.button(|b| {
                                        b.text("Generate certificate request");
                                        b.class("btn btn-secondary");
                                        match ca.config.sign_method {
                                            CertificateSigningMethod::Https(m) => match m {
                                                HttpsSigningMethod::RsaSha256 => {
                                                    b.onclick("wasm_bindgen.generate_csr_rsa_sha256()");
                                                }
                                                HttpsSigningMethod::EcdsaSha256 => {
                                                    b.onclick("wasm_bindgen.generate_csr_ecdsa_sha256()");
                                                }
                                            }
                                            CertificateSigningMethod::Ssh(m) => {
                                                match m {
                                                    cert_common::SshSigningMethod::Rsa => {
                                                        b.onclick("wasm_bindgen.generate_ssh_rsa()");
                                                    }
                                                    cert_common::SshSigningMethod::Ed25519 => {
                                                        b.onclick("wasm_bindgen.generate_ed25519_rsa()");
                                                    }
                                                }
                                            }
                                        }
                                        b
                                    })
                                });
                                f
                            });
                        }
                        CertificateSigningMethod::Ssh(_m) => {
                            m.form(|f| {
                                f.name("request");
                                f.action("ca/submit_request.rs"); //TODO change this depending on delivery
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
                        }
                    }
                    m
                });
                d2
            });
            d
        });
        b.division(|div| {
            div.class("cert_generating");
            div.division(|d2| {
                d2.style("text-align: center;");
                d2.division(|d3| {
                    d3.style("margin-bottom: 16px; font-size: 48px;");
                    d3.text("🔄");
                    d3
                });
                d2.division(|d3| {
                    d3.text("Generating Certificate Request...")
                });
                d2.division(|d3| {
                    d3.style("font-size: 16px; font-weight: 400; margin-top: 8px;");
                    d3.text("Please wait while we generate your CSR and private key");
                    d3
                });
                d2
            });
            div
        });
        b
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie.clone(),
    }
}

/// The page that allows a user to generate a signing request.
pub async fn ca_request(s: WebPageContext) -> WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.all_ca.get_mut(name).unwrap();
            if let LocalOrRemoteCa::Local(ca) = ca {
                handle_ca_request(ca, &s).await
            } else {
                todo!("Handle remote ca here")
            }
        }
        PkiInstance::Ca(ca) => handle_ca_request(ca, &s).await,
    }
}
