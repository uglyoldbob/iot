//! Code for the main page

use crate::applets::AppletTrait;
use crate::{
    ca::{Ca, CsrRequest, LocalOrRemoteCa, PkiInstance},
    utility::WebPageContext,
    webserver::WebResponse,
};
use cert_common::{oid::*, CertificateSigningMethod};

fn certificate_info(
    main_content: &mut html::content::builders::MainBuilder,
    s: &WebPageContext,
    ca: &mut Ca,
    issued_certificates: i64,
) {
    main_content.division(|overview| {
        overview
            .class("section-header")
            .style("margin-top: 48px;")
            .id("ca-info")
            .heading_3(|h3| {
                h3.class("section-title")
                    .text("Certificate Authority Information")
            })
    });
    main_content.division(|card| {
        card.class("ca-card");
        card.division(|hdr| {
            hdr.class("ca-header");
            hdr.division(|d| {
                d.division(|d2| {
                    d2.class("ca-name").text("Root CA");
                    d2
                });
                d.division(|d2| {
                    d2.class("ca-type").text("Root Certificate Authority");
                    d2
                });
                d
            });
            hdr.span(|s| s.class("ca-status active").text("ACTIVE"));
            hdr
        });
        card.division(|info| {
            info.class("ca-info");
            let name = ca
                .root_ca_cert()
                .ok()
                .and_then(|r| r.x509_cert().ok())
                .map(|c| {
                    let mut v = Vec::new();
                    for n in &c.tbs_certificate.subject.0 {
                        v.push(n.to_string());
                    }
                    v.join(", ")
                })
                .unwrap_or("Unknown".to_string());
            info.division(|d2| {
                d2.class("ca-info-item");
                d2.division(|d3| d3.class("ca-info-label").text("Subject DN"));
                d2.division(|d3| d3.class("ca-info-value").text(name));
                d2
            });
            let serial = ca
                .root_ca_cert()
                .ok()
                .and_then(|r| r.x509_cert().ok())
                .map(|c| crate::utility::display_hex(c.tbs_certificate.serial_number.as_bytes()))
                .unwrap_or("Unknown".to_string());
            info.division(|d2| {
                d2.class("ca-info-item");
                d2.division(|d3| d3.class("ca-info-label").text("Serial number"));
                d2.division(|d3| d3.class("ca-info-value").text(serial));
                d2
            });
            let valid_until = ca
                .root_ca_cert()
                .ok()
                .and_then(|r| r.x509_cert().ok())
                .map(|c| {
                    c.tbs_certificate
                        .validity
                        .not_after
                        .to_date_time()
                        .to_string()
                })
                .unwrap_or("Unknown".to_string());
            info.division(|d2| {
                d2.class("ca-info-item");
                d2.division(|d3| d3.class("ca-info-label").text("Valid Until"));
                d2.division(|d3| d3.class("ca-info-value").text(valid_until));
                d2
            });
            info.division(|d2| {
                d2.class("ca-info-item");
                d2.division(|d3| d3.class("ca-info-label").text("Certificates issued"));
                d2.division(|d3| {
                    d3.class("ca-info-value")
                        .text(issued_certificates.to_string())
                });
                d2
            });
            info
        });
        card.details(|d| {
            d.summary(|s| s.text("View Additional Details"));
            d.division(|d2| {
                d2.style(
                    "padding: 16px; background: #f7fafc; border-radius: 8px; margin-top: 12px;",
                );
                d2.division(|d3| {
                    d3.style("margin-bottom: 12px;");
                    let key = ca
                        .root_ca_cert()
                        .ok()
                        .and_then(|r| r.x509_cert().ok())
                        .map(|c| {
                            super::public_key_readable(c.tbs_certificate.subject_public_key_info)
                        })
                        .unwrap_or("Unknown".to_string());
                    let fingerprint = ca
                        .root_ca_cert()
                        .ok()
                        .and_then(|r| r.x509_cert().ok())
                        .and_then(|c| {
                            c.tbs_certificate
                                .subject_public_key_info
                                .fingerprint_bytes()
                                .ok()
                        })
                        .map(|d| crate::utility::display_hex(&d))
                        .unwrap_or("Unknown".to_string());
                    let signature = ca
                        .root_ca_cert()
                        .ok()
                        .and_then(|r| r.x509_cert().ok())
                        .map(|c| super::signature_readable(&c.tbs_certificate.signature))
                        .unwrap_or("Unknown".to_string());
                    let issued = ca
                        .root_ca_cert()
                        .ok()
                        .and_then(|r| r.x509_cert().ok())
                        .map(|c| {
                            c.tbs_certificate
                                .validity
                                .not_before
                                .to_date_time()
                                .to_string()
                        })
                        .unwrap_or("Unknown".to_string());
                    d3.strong(|s| s.text("Key Algorithm"))
                        .text(format!(" {key}"))
                        .line_break(|a| a);
                    d3.strong(|s| s.text("Signature Algorithm"))
                        .text(format!(" {signature}"))
                        .line_break(|a| a);
                    d3.strong(|s| s.text("Issued On:"))
                        .text(format!(" {issued}"))
                        .line_break(|a| a);
                    d3.strong(|s| s.text("Fingerprint (SHA-256):"))
                        .text(format!(" {fingerprint}"));
                    d3
                });
                d2
            });
            d
        });
        card.division(|d| {
            d.class("download-section").id("download-certs");
            d.heading_4(|h| h.text("📥 Download CA Certificate"));
            d.division(|d2| {
                d2.class("download-buttons");
                d2.anchor(|a| {
                    match s.delivery {
                        crate::main_config::PageDelivery::Cgi => {
                            a.href("?action=download_ca&type=pem");
                        }
                        crate::main_config::PageDelivery::DedicatedServer => {
                            a.href("ca/get_ca.rs?type=pem");
                        }
                    }
                    a.target("_blank");
                    a.class("btn btn-success")
                        .download("")
                        .text("Download PEM Format");
                    a.span(|s| s.text("📄"));
                    a
                });
                d2.anchor(|a| {
                    match s.delivery {
                        crate::main_config::PageDelivery::Cgi => {
                            a.href("?action=download_ca&type=der");
                        }
                        crate::main_config::PageDelivery::DedicatedServer => {
                            a.href("ca/get_ca.rs?type=der");
                        }
                    }
                    a.target("_blank");
                    a.class("btn btn-success")
                        .download("")
                        .text("Download DER Format");
                    a.span(|s| s.text("📄"));
                    a
                });
                d2.anchor(|a| {
                    match s.delivery {
                        crate::main_config::PageDelivery::Cgi => {
                            a.href("?action=download_ca&type=pem");
                        }
                        crate::main_config::PageDelivery::DedicatedServer => {
                            a.href("ca/get_ca.rs?type=pem");
                        }
                    }
                    a.target("_blank");
                    a.class("btn btn-secondary")
                        .download("")
                        .text("Download Certificate Chain (PEM)");
                    a.span(|s| s.text("🔗"));
                    a
                });
                d2
            });
            d
        });
        card
    });
}

fn android_app_anchor(
    ca: &mut Ca,
    s: &WebPageContext,
    nav_section: &mut html::text_content::builders::DivisionBuilder,
) {
    let name = ca.public_names.first().unwrap();
    let intenturl = match s.delivery {
        crate::main_config::PageDelivery::Cgi => {
            format!("{}{}/rust-iot.cgi", name.domain, name.subdomain)
        }
        crate::main_config::PageDelivery::DedicatedServer => {
            format!("{}{}/register_android.rs", name.domain, name.subdomain)
        }
    };
    nav_section.anchor(|a| {
        let package = "com.uglyoldbob.RustIotNfc";
        let url = "https://play.google.com/store/apps/details?id=com.uglyoldbob.RustIotNfc";
        let url = urlencoding::encode(url);
        let scheme = "registerscheme";
        let others = "action=android.intent.action.VIEW;category=android.intent.category.BROWSABLE;";
        a.href(format!("intent://{intenturl}#Intent;scheme={scheme};package={package};{others}S.browser_fallback_url={url};end"));
        a.class("nav-item");
        a.span(|s|
            s.class("nav-icon").text("📱"));
        a.text("Open in Android App");
        a
    });
}

async fn handle_ca_main_admin_page(
    ca: &mut Ca,
    s: &WebPageContext,
    html: &mut html::root::builders::HtmlBuilder,
) -> WebResponse {
    let mut applets = Vec::new();
    if let Some(a) = ca.medium.retrieve_all_applets().await {
        for applet in a {
            applets.push(applet);
        }
    }

    let quantity_pending_csr = ca.count_pending_csr().await;
    let quantity_approved_csr = ca.count_approved_csr().await;
    let quantity_rejected_csr = ca.count_rejected_csr().await;
    let quantity_total_csr = ca.count_all_csr().await;
    let issued_certificates = ca.count_issued_certs().await;
    let (active_certificates, expiring_in_thrity_days) = ca
        .count_active_and_expiring_soon_certs(std::time::Duration::from_secs(30 * 86400))
        .await;
    let issued_in_last_month = ca
        .count_recently_issued_certs(std::time::Duration::from_secs(30 * 86400))
        .await;

    let mut csr_list: Vec<(CsrRequest, Vec<u8>)> = Vec::new();
    ca.csr_processing(|_index, csr, serial| {
        csr_list.push((csr, serial));
    })
    .await;

    html.body(|b| {
        b.division(|d| {
            d.class("container");
            d.header(|h| {
                h.division(|logo_div| {
                    logo_div.class("logo");
                    logo_div.division(|d| d.class("logo-icon").text("🔐"));
                    logo_div.division(|d| d.class("logo-text")
                        .heading_1(|h|h.text("Certificate Authority"))
                        .paragraph(|p|p.text("Admin Portal")));
                    logo_div
                });
                h.division(|header_actions| {
                    header_actions.class("header-actions");
                    header_actions.division(|user_profile| {
                        user_profile.class("user-profile")
                            .division(|user_avatar| {
                                user_avatar.class("user-avatar").text("AD")
                            })
                            .division(|div| {
                                div.division(|div| div.style("font-weight: 600; font-size: 14px;").text("Admin User"))
                                    .division(|div|div.style("font-size: 12px; color: #718096;").text("Super Admin"))
                            })
                    });
                    header_actions
                });
                h
            });
            d.division(|main_div| {
                main_div.class("main-content");
                main_div.aside(|sidebar| {
                    sidebar.class("sidebar");
                    sidebar.navigation(|nav| {
                        nav.division(|nav_section| {
                            nav_section.class("nav-section")
                                .heading_3(|a| a.text("Dashboard"))
                                .anchor(|a|
                                    a.href("#overview")
                                    .class("nav-item")
                                    .span(|s|
                                        s.class("nav-icon").text("📊"))
                                    .text("Overview"))
                        });
                        nav.division(|nav_section| {
                            nav_section.class("nav-section")
                                .heading_3(|a| a.text("Certificate Operations"));
                            nav_section.anchor(|a|
                                a.href("#csr-queue")
                                .class("nav-item")
                                .span(|s|
                                    s.class("nav-icon").text("📝"))
                                .text("CSR Queue")
                                .span(|s|
                                    s.class("nav-badge").text(quantity_pending_csr.to_string())));
                            nav_section.anchor(|a| {
                                match s.delivery {
                                    crate::main_config::PageDelivery::Cgi => {
                                        a.href("?action=request_signature");
                                    }
                                    crate::main_config::PageDelivery::DedicatedServer => {
                                        a.href("ca/request.rs");
                                    }
                                }
                                a.class("nav-item");
                                a.span(|s|
                                    s.class("nav-icon").text("📝"));
                                a.text("Create a new CSR");
                                a
                            });
                            android_app_anchor(ca, s, nav_section);
                            nav_section
                        });
                        nav.division(|nav_section| {
                            nav_section.class("nav-section")
                                .heading_3(|a| a.text("Certificate Authority"))
                                .anchor(|a|
                                    a.href("#ca-info")
                                    .class("nav-item")
                                    .span(|s|
                                        s.class("nav-icon").text("🏛️"))
                                    .text("CA Information"))
                                .anchor(|a|
                                    a.href("#download-certs")
                                    .class("nav-item")
                                    .span(|s|
                                        s.class("nav-icon").text("⬇️"))
                                    .text("Download Certificates"))
                        });
                        if !applets.is_empty() {
                            nav.division(|nav_section| {
                                nav_section.class("nav-section")
                                    .heading_3(|a| a.text("Applets"));
                                for applet in applets {
                                    nav_section.anchor(|a| {
                                        match s.delivery {
                                            crate::main_config::PageDelivery::Cgi => {
                                                a.href(format!("?action=view_applet&id={}", applet.0));
                                            }
                                            crate::main_config::PageDelivery::DedicatedServer => {
                                                a.href(format!("ca/view_applet.rs?id={}", applet.0));
                                            }
                                        }
                                        a.class("nav-item");
                                        a.text(applet.1.name().to_string());
                                        a
                                    });
                                }
                                nav_section.anchor(|a| {
                                    match s.delivery {
                                        crate::main_config::PageDelivery::Cgi => {
                                            a.href("?action=add_applet");
                                        }
                                        crate::main_config::PageDelivery::DedicatedServer => {
                                            a.href("ca/add_applet.rs");
                                        }
                                    }
                                    a.class("nav-item");
                                    a.span(|s| s.class("nav-icon").text("➕"));
                                    a.text("Add a new applet");
                                    a
                                });
                                nav_section
                            });
                        }
                        nav
                    })
                });
                main_div.main(|main_content| {
                    main_content.class("content-area");
                    main_content.division(|overview| {
                        overview.class("page-header")
                            .heading_2(|h2| h2.class("page-title").text("Dashboard Overview"))
                            .anchor(|a| a.href("#csr-queue").class("btn btn-primary")
                                .span(|s| s.text("📝"))
                                .text("View CSR Queue")
                            )
                    });
                    main_content.division(|dashboard_div| {
                        dashboard_div.class("stats-grid");
                        dashboard_div.anchor(|a| {
                            a.href("#csr-queue");
                            a.division(|grid| {
                                grid.class("stat-card");
                                grid.division(|d| {
                                    d.class("stat-header");
                                    d.division(|div| {
                                        div.division(|div| {
                                            div.class("stat-label").text("Pending CSRs")
                                        });
                                        div.division(|div| {
                                            div.class("stat-value").text(quantity_pending_csr.to_string())
                                        });
                                        if (quantity_pending_csr > 0) {
                                            div.division(|div| {
                                                div.class("stat-trend warning").text("⚠️ Requires action")
                                            });
                                        }
                                        div
                                    });
                                    d.division(|div| div.class("stat-icon").text("📝"));
                                    d
                                });
                                grid
                            });
                            a
                        });
                        dashboard_div.anchor(|a| {
                            match s.delivery {
                                crate::main_config::PageDelivery::Cgi => {
                                    a.href("?action=view_all_certs");
                                }
                                crate::main_config::PageDelivery::DedicatedServer => {
                                    a.href("ca/view_all_certs.rs");
                                }
                            }
                            a.division(|grid| {
                                grid.class("stat-card");
                                grid.division(|d| {
                                    d.class("stat-header");
                                    d.division(|div| {
                                        div.division(|div| {
                                            div.class("stat-label").text("Certificates Issued")
                                        });
                                        div.division(|div| {
                                            div.class("stat-value").text(issued_certificates.to_string())
                                        });
                                        if (issued_in_last_month > 0) {
                                            div.division(|div|
                                                div.class("stat-trend").text(format!("↑ +{issued_in_last_month} this month")));
                                        }
                                        div
                                    });
                                    d.division(|div| div.class("stat-icon").text("✅"));
                                    d
                                });
                                grid
                            });
                            a
                        });
                        dashboard_div.division(|grid| {
                            grid.class("stat-card");
                            grid.division(|d| {
                                d.class("stat-header");
                                d.division(|div| {
                                    div.division(|div| {
                                        div.class("stat-label").text("Active Certificates")
                                    });
                                    div.division(|div| {
                                        div.class("stat-value").text(active_certificates.to_string())
                                    });
                                    div.division(|div|
                                        div.class("stat-trend").text(format!("{:.02}%", 100.0 * active_certificates as f32 / issued_certificates as f32)));
                                    div
                                });
                                d.division(|div| div.class("stat-icon").text("🔒"));
                                d
                            });
                            grid
                        });
                        dashboard_div.division(|grid| {
                            grid.class("stat-card");
                            grid.division(|d| {
                                d.class("stat-header");
                                d.division(|div| {
                                    div.division(|div| {
                                        div.class("stat-label").text("Expiring (30 days)")
                                    });
                                    div.division(|div| {
                                        div.class("stat-value").text(expiring_in_thrity_days.to_string())
                                    });
                                    if (expiring_in_thrity_days > 0) {
                                        div.division(|div|
                                            div.class("stat-trend warning").text("⚠️ Action needed"));
                                    }
                                    div
                                });
                                d.division(|div| div.class("stat-icon").text("⏰"));
                                d
                            });
                            grid
                        });
                        dashboard_div
                    });
                    main_content.division(|overview| {
                        overview.class("section-header").id("csr-queue")
                            .heading_3(|h3| h3.class("section-title").text("Certificate Signing Requests"))
                    });
                    main_content.table(|table| {
                        table.class("data-table");
                        table.table_head(|th| {
                            th.table_row(|tr| {
                                tr.table_header(|th| th.text("CSR ID"));
                                tr.table_header(|th| th.text("Requestor"));
                                tr.table_header(|th| th.text("Certificate Details"));
                                tr.table_header(|th| th.text("Type"));
                                tr.table_header(|th| th.text("Actions"));
                                tr
                            });
                            th
                        });
                        table.table_body(|body| {
                            for csr in csr_list {
                                let sn = {
                                    let asdf : Vec<String> = csr.0.sn.chunks(4).map(|c| {
                                        let serhex: Vec<String> = c.iter().map(|e| format!("{:02x}", e)).collect();
                                        serhex.join(":")
                                    }).collect();
                                    asdf.join("<br >")
                                };
                                body.table_row(|tr| {
                                    tr.table_cell(|c| {
                                        c.division(|d| d.class("request-id").text(sn))
                                    });
                                    tr.table_cell(|c| {
                                        c.division(|d| {
                                            d.class("requestor-info");
                                            d.division(|d| d.class("requestor-name").text(csr.0.name));
                                            d.division(|d| d.class("requestor-email").text(csr.0.email));
                                            d.division(|d| d.class("requestor-email").text(csr.0.phone));
                                            d
                                        });
                                        c
                                    });
                                    let x509 = {
                                        use der::DecodePem;
                                        let csr = x509_cert::request::CertReq::from_pem(&csr.0.cert);
                                        csr
                                    };
                                    eprintln!("X509 cert is {:?}", x509);
                                    let cn_v = x509.as_ref().map(|x| {
                                        let mut v = Some("Unprocessed".to_string());
                                        for a in &x.info.subject.0 {
                                            for attr in a.0.iter() {
                                                let oid: cert_common::oid::Oid = attr.oid.into();
                                                if oid == *cert_common::oid::OID_CERT_COMMON_NAME {
                                                    if let Ok(s) = attr.value.decode_as::<der::asn1::Utf8StringRef>() {
                                                        v = Some(s.to_string());
                                                        break;
                                                    }
                                                    if let Ok(s) = attr.value.decode_as::<der::asn1::PrintableStringRef>() {
                                                        v = Some(s.to_string());
                                                        break;
                                                    }
                                                    v = Some(format!("{:?}", attr.value));
                                                    break;
                                                }
                                            }
                                        }
                                        v
                                    }).ok().flatten().unwrap_or("Invalid x509?".to_string());
                                    let san: String = x509.as_ref().map(|x| {
                                        let mut vr = Vec::new();
                                        for attr in x.info.attributes.iter() {
                                            let oid: cert_common::oid::Oid = attr.oid.into();
                                            if oid == *cert_common::oid::OID_CERT_ALTERNATIVE_NAME {
                                                use der::Decode;
                                                for value in attr.values.iter() {
                                                    if let Ok(s) = value.decode_as::<der::asn1::Utf8StringRef>() {
                                                        vr.push(s.to_string());
                                                    }
                                                    if let Ok(s) = value.decode_as::<der::asn1::PrintableStringRef>() {
                                                        vr.push(s.to_string());
                                                    }
                                                    if let Ok(s) = value.decode_as::<der::asn1::Ia5String>() {
                                                        vr.push(s.to_string());
                                                    }
                                                    if let Ok(s) = value.decode_as::<der::asn1::TeletexString>() {
                                                        vr.push(s.to_string());
                                                    }
                                                }
                                            }
                                        }
                                        vr.join("<br >")
                                    })
                                        .ok()
                                        .unwrap_or(String::new());
                                    let usage = x509.as_ref().map(|x| {
                                        let mut usage = Vec::new();
                                        for attr in x.info.attributes.iter() {
                                            for p in attr.values.iter() {
                                                let pa = cert_common::CsrAttribute::with_oid_and_any(
                                                    Oid::from_const(attr.oid),
                                                    p.to_owned(),
                                                );
                                                if let Some(pa) = pa {
                                                    if let cert_common::CsrAttribute::ExtendedKeyUsage(ek) = pa {
                                                        for key_use in ek {
                                                            usage.push(format!("{:?}", key_use));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        usage.join("<br >")
                                    }).unwrap_or(String::new());

                                    tr.table_cell(|c| {
                                        c.division(|d| {
                                            d.class("cert-details");
                                            d.division(|d| d.class("cert-cn").text(cn_v));
                                            d.division(|d| d.class("cert-san").text(san));
                                            d
                                        });
                                        c
                                    });
                                    tr.table_cell(|c| {
                                        c.text(usage)
                                    });
                                    tr.table_cell(|c| {
                                        c.division(|d| {
                                            d.class("action-buttons");
                                            d.anchor(|a| {
                                                a.class("action-btn");
                                                match s.delivery {
                                                    crate::main_config::PageDelivery::Cgi => a.href(format!(
                                                        "?action=list_pending_requests&serial={}",
                                                        crate::utility::encode_hex(&csr.1)
                                                    )),
                                                    crate::main_config::PageDelivery::DedicatedServer => {
                                                        a.href(format!("list.rs?serial={}", crate::utility::encode_hex(&csr.1)))
                                                    }
                                                };
                                                a.text("Review");
                                                a
                                            });
                                            d.anchor(|a|a.href("#approve-modal").class("action-btn approve").text("Approve"));
                                            d.anchor(|a|a.href("#reject-modal").class("action-btn reject").text("Reject"));
                                            d
                                        });
                                        c
                                    });
                                    tr
                                });
                            }
                            body
                        });
                        table
                    });
                    certificate_info(main_content, s, ca, issued_certificates);
                    main_content
                });
                main_div
            });
            d
        });
            if true {
                match s.delivery {
                    crate::main_config::PageDelivery::Cgi => {
                        b.anchor(|ab| {
                            ab.text("Refresh certificate search");
                            ab.href("?action=refresh_certificate_search");
                            ab
                        });
                    }
                    crate::main_config::PageDelivery::DedicatedServer => {
                        b.anchor(|ab| {
                            ab.text("Refresh certificate search");
                            ab.href("ca/refresh_certificate_search.rs");
                            ab
                        });
                    }
                }
                b.line_break(|lb| lb);
            }
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

async fn handle_ca_main_user_page(
    ca: &mut Ca,
    s: &WebPageContext,
    html: &mut html::root::builders::HtmlBuilder,
    user: Option<String>,
) -> WebResponse {
    let issued_certificates = ca.count_issued_certs().await;
    html.body(|b| {
        b.division(|d| {
            d.class("container");
            d.header(|h| {
                h.division(|logo_div| {
                    logo_div.class("logo");
                    logo_div.division(|d| d.class("logo-icon").text("🔐"));
                    logo_div.division(|d| d.class("logo-text")
                        .heading_1(|h|h.text("Certificate Authority"))
                        .paragraph(|p|p.text("User Portal")));
                    logo_div
                });
                h.division(|header_actions| {
                    header_actions.class("header-actions");
                    header_actions.division(|user_profile| {
                        user_profile.class("user-profile")
                            .division(|user_avatar| {
                                user_avatar.class("user-avatar").text("AD")
                            })
                            .division(|div| {
                                div.division(|div| div.style("font-weight: 600; font-size: 14px;").text("User Name"))
                                    .division(|div|div.style("font-size: 12px; color: #718096;").text("User"))
                            })
                    });
                    header_actions
                });
                h
            });
            d.division(|main_div| {
                main_div.class("main-content");
                main_div.aside(|sidebar| {
                    sidebar.class("sidebar");
                    sidebar.navigation(|nav| {
                        nav.division(|nav_section| {
                            nav_section.class("nav-section")
                                .heading_3(|a| a.text("Certificate Authority"))
                                .anchor(|a|
                                    a.href("#ca-info")
                                    .class("nav-item")
                                    .span(|s|
                                        s.class("nav-icon").text("🏛️"))
                                    .text("CA Information"))
                                .anchor(|a|
                                    a.href("#download-certs")
                                    .class("nav-item")
                                    .span(|s|
                                        s.class("nav-icon").text("⬇️"))
                                    .text("Download Certificates"))
                        });
                        nav
                    })
                });
                main_div.main(|main_content| {
                    main_content.class("content-area");
                    main_content.division(|d| {
                        d.class("welcome-section");
                        d.paragraph(|p|p.text("Request certificates and download CA certificates for your organization"));
                        d.anchor(|a| {
                            match s.delivery {
                                crate::main_config::PageDelivery::Cgi => {
                                    a.href("?action=request_signature");
                                }
                                crate::main_config::PageDelivery::DedicatedServer => {
                                    a.href("ca/request.rs");
                                }
                            }
                            a.class("btn btn-secondary");
                            a.style(|s| s.text("background: white; color: #1e3c72;"));
                            a.span(|s|s.text("➕"));
                            a.text("Request New Certificate");
                            a
                        });
                        d
                    });
                    main_content.division(|d| {
                        d.class("section-header");
                        d.heading_3(|h| h.class("section-title").text("Quick Actions"));
                        d
                    });
                    main_content.division(|d| {
                        d.style("display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 40px;");
                        d.division(|d2| {
                            d2.style("background: white; border-radius: 12px; padding: 24px; border: 2px solid #e2e8f0; transition: all 0.2s ease;");
                            d2.division(|d3| {
                                d3.style("display: flex; align-items: center; gap: 12px; margin-bottom: 16px;");
                                d3.division(|d4| {
                                    d4.style("width: 48px; height: 48px; background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 24px;");
                                    d4.text("📝");
                                    d4
                                });
                                d3.division(|d4| {
                                    d4.style("font-size: 18px; font-weight: 700; color: #1a202c;").text("Request Certificate")
                                });
                                d3
                            });
                            d2.division(|d3| {
                                d3.style("color: #4a5568; font-size: 14px; line-height: 1.6; margin-bottom: 16px;");
                                d3.text("Submit a Certificate Signing Request (CSR) to obtain a new certificate for your domain or service.");
                                d3.line_break(|a|a);
                                d3.anchor(|a| {
                                    match s.delivery {
                                        crate::main_config::PageDelivery::Cgi => {
                                            a.href("?action=request_signature");
                                        }
                                        crate::main_config::PageDelivery::DedicatedServer => {
                                            a.href("ca/request.rs");
                                        }
                                    }
                                    a.class("btn btn-primary").span(|s|s.text("➕")).text("Create CSR")
                                });
                                d3
                            });
                            d2
                        });
                        d.division(|d2| {
                            d2.style("background: white; border-radius: 12px; padding: 24px; border: 2px solid #e2e8f0; transition: all 0.2s ease;");
                            d2.division(|d3| {
                                d3.style("display: flex; align-items: center; gap: 12px; margin-bottom: 16px;");
                                d3.division(|d4| {
                                    d4.style("width: 48px; height: 48px; background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 24px;");
                                    d4.text("📝");
                                    d4
                                });
                                d3.division(|d4| {
                                    d4.style("font-size: 18px; font-weight: 700; color: #1a202c;").text("Register in Android app")
                                });
                                d3
                            });
                            d2.division(|d3| {
                                d3.style("color: #4a5568; font-size: 14px; line-height: 1.6; margin-bottom: 16px;");
                                d3.text("Opens the registration page in the android app so the app can be registered with the Certificate Authority.");
                                d3.line_break(|a|a);
                                android_app_anchor(ca, s, d3);
                                d3
                            });
                            d2
                        });
                        d.division(|d2| {
                            d2.style("background: white; border-radius: 12px; padding: 24px; border: 2px solid #e2e8f0; transition: all 0.2s ease;");
                            d2.division(|d3| {
                                d3.style("display: flex; align-items: center; gap: 12px; margin-bottom: 16px;");
                                d3.division(|d4| {
                                    d4.style("width: 48px; height: 48px; background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 24px;");
                                    d4.text("⬇️");
                                    d4
                                });
                                d3.division(|d4| {
                                    d4.style("font-size: 18px; font-weight: 700; color: #1a202c;").text("Download CA Certificates")
                                });
                                d3
                            });
                            d2.division(|d3| {
                                d3.style("color: #4a5568; font-size: 14px; line-height: 1.6; margin-bottom: 16px;");
                                d3.text("Download the Certificate Authority certificates to install on your systems and establish trust.");
                                d3.line_break(|a|a);
                                d3.anchor(|a| {
                                    a.href("#download-certs").class("btn btn-primary").span(|s|s.text("⬇️")).text("Download")
                                });
                                d3
                            });
                            d2
                        });
                        d.division(|d2| {
                            d2.style("background: white; border-radius: 12px; padding: 24px; border: 2px solid #e2e8f0; transition: all 0.2s ease;");
                            d2.division(|d3| {
                                d3.style("display: flex; align-items: center; gap: 12px; margin-bottom: 16px;");
                                d3.division(|d4| {
                                    d4.style("width: 48px; height: 48px; background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 24px;");
                                    d4.text("📚");
                                    d4
                                });
                                d3.division(|d4| {
                                    d4.style("font-size: 18px; font-weight: 700; color: #1a202c;").text("Download CA Certificates")
                                });
                                d3
                            });
                            d2.division(|d3| {
                                d3.style("color: #4a5568; font-size: 14px; line-height: 1.6; margin-bottom: 16px;");
                                d3.text("Learn how to generate CSRs, install certificates, and troubleshoot common issues.");
                                d3.line_break(|a|a);
                                d3.anchor(|a| {
                                    a.href("#documentation").class("btn btn-primary").span(|s|s.text("📖")).text("View Docs")
                                });
                                d3
                            });
                            d2
                        });
                        d
                    });
                    certificate_info(main_content, s, ca, issued_certificates);
                    main_content.division(|d| {
                        d.class("info-box");
                        d.division(|d2| {
                            d2.class("info-box-title");
                            d2.span(|s|s.text("ℹ️"));
                            d2
                        });
                        d.division(|d2| {
                            d2.class("info-box-content");
                            d2.strong(|s| s.text("Windows: "))
                                .text(" Double-click the certificate file and follow the Certificate Import Wizard. Install to \"Trusted Root Certification Authorities\".")
                                .line_break(|a|a)
                                .line_break(|a|a);
                            d2.strong(|s| s.text("macOS: ")).text(" Double-click the certificate file to open Keychain Access. Add to System keychain and set to \"Always Trust\".")
                                .line_break(|a|a)
                                .line_break(|a|a);
                            d2.strong(|s| s.text("Linux: "))
                                .text(" Copy the certificate to ")
                                .code(|c|c.text("/usr/local/share/ca-certificates/"))
                                .text(" and run ")
                                .code(|c|c.text("sudo update-ca-certificates"))
                                .line_break(|a|a)
                                .line_break(|a|a);
                            d2.text("For detailed instructions, see the ")
                                .anchor(|a|
                                    a.href("#documentation")
                                        .style(|s|s.text("color: #1e3c72; font-weight: 600;"))
                                        .text("documentation")
                                    );
                            d2
                        });
                        d
                    });
                    main_content
                });
                main_div
            });
            d
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

/// The main page for a certificate authority
async fn handle_ca_main_page(ca: &mut Ca, s: &WebPageContext) -> WebResponse {
    use crate::applets::AppletTrait;
    let mut admin = false;
    let mut user = None;
    let cs = s.user_certs.all_certs();
    for cert in cs {
        if user.is_none() {
            let a: Vec<String> = cert
                .tbs_certificate
                .subject
                .0
                .iter()
                .map(|l| l.to_string())
                .collect();
            let a = a.join(",");
            user = Some(a);
        }
        if ca.is_admin(cert).await {
            admin = true;
        }
    }

    let mut html = html::root::Html::builder();
    html.head(|h| {
        super::generic_head(h, s, ca)
            .title(|t| t.text(ca.config.common_name.to_owned()))
            .meta(|m| {
                m.name("viewport")
                    .content("width=device-width, initial-scale=1.0")
            })
    });
    if admin {
        handle_ca_main_admin_page(ca, s, &mut html).await
    } else {
        handle_ca_main_user_page(ca, s, &mut html, user).await
    }
}

///The main landing page for the certificate authority
pub async fn ca_main_page(s: WebPageContext) -> WebResponse {
    let mut pki = s.pki.lock().await;
    match std::ops::DerefMut::deref_mut(&mut pki) {
        PkiInstance::Pki(pki) => {
            let mut pb = s.page.clone();
            pb.pop();
            let name = pb.file_name().unwrap().to_str().unwrap();
            let ca = pki.all_ca.get_mut(name).unwrap();
            if let LocalOrRemoteCa::Local(ca) = ca {
                handle_ca_main_page(ca, &s).await
            } else {
                todo!("Handle remote ca here")
            }
        }
        PkiInstance::Ca(ca) => handle_ca_main_page(ca, &s).await,
    }
}
