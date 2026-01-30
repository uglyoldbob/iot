//! Code for the desfire applet

use std::collections::HashMap;

use crate::ca::{Ca, CertAttribute};

use super::{AppletTable, AppletTableField, FieldType};

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct Ev1 {
    table_name: String,
}

fn backlinks(
    b: &mut html::root::builders::BodyBuilder,
    appletid: i64,
    mut sget: HashMap<String, String>,
    s: &crate::utility::WebPageContext,
) {
    b.anchor(|ab| {
        ab.text("Back to applet home");
        match s.delivery {
            crate::main_config::PageDelivery::Cgi => {
                sget.remove_entry("applet_action");
                sget.remove_entry("step");
                sget.remove_entry("serial");
                sget.remove_entry("applet_data");
                let a = sget
                    .iter()
                    .map(|a| format!("{}={}", a.0, a.1))
                    .collect::<Vec<String>>()
                    .join("&");
                ab.href(format!("?{a}"));
            }
            crate::main_config::PageDelivery::DedicatedServer => {
                ab.href(format!("applet.rs?id={}", appletid));
            }
        };
        ab
    });
    b.line_break(|a| a);

    b.anchor(|ab| {
        ab.text("Back to main page");
        ab.href("?");
        ab
    });
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
        &self,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
    ) {
        const RESULTS_PER_PAGE: i64 = 10;

        let mut admin = false;
        if ca.is_admin_for_applet(appletid, userid).await {
            admin = true;
        }
        let mut sget = s.get.clone();
        let action = s.get.get("applet_action").map(|a| a.as_str());
        match action {
            Some("asdf") => {
                html.body(|b| {
                    b.text("This is the desvfire ev1 applet sample page");
                    b.line_break(|a| a);

                    if admin {
                        b.text("You are admin over this applet");
                        b.line_break(|a| a);
                    }

                    backlinks(b, appletid, sget, s);
                    b
                });
            }
            Some("manage_users") => {
                if admin {
                    let step = s
                        .get
                        .get("step")
                        .map(|a| a.parse::<usize>().ok())
                        .flatten()
                        .unwrap_or(0);
                    match step {
                        1 => {
                            let mut cert: Option<crate::ca::RawCertificateInfo> = None;
                            let mut csr = None;
                            let mut rejection = None;
                            let mut myserial = String::new();

                            if let Some(serialhex) = s.get.get("serial") {
                                let serial: Result<Vec<u8>, std::num::ParseIntError> =
                                    crate::utility::decode_hex(serialhex.as_str());
                                if let Ok(serial) = serial {
                                    cert = ca.get_user_cert(serial.clone()).await;
                                    if cert.is_none() {
                                        csr = ca.get_csr_by_serial(serial.clone()).await;
                                    }
                                    if csr.is_none() {
                                        rejection = Some(
                                            ca.get_rejection_reason_by_serial(serial.clone()).await,
                                        );
                                    }
                                    myserial = crate::utility::encode_hex(&serial);
                                }
                            }

                            html.body(|b| {
                                if let Some(ci) = cert {
                                    let cert_der = ci.cert;
                                    use der::Decode;
                                    let cert: Result<x509_cert::certificate::CertificateInner, der::Error> =
                                        x509_cert::Certificate::from_der(&cert_der);
                                    match cert {
                                        Ok(cert) => {
                                            if let Some(r) = ci.revoked {
                                                b.text("CERTIFICATE IS REVOKED").line_break(|a| a);
                                                crate::ca::do_show_revoked(b, r.data.revocation_reason);
                                                b.text(format!("Revoked at {}", r.revoked.to_rfc2822()))
                                                    .line_break(|a| a);
                                            }
                                            let csr_names: Vec<String> = cert
                                                .tbs_certificate
                                                .subject
                                                .0
                                                .iter()
                                                .map(|n| format!("{}", n))
                                                .collect();
                                            let t = csr_names.join(", ");
                                            b.text(t).line_break(|a| a);
                                            if let Ok(duration) = cert
                                                .tbs_certificate
                                                .validity
                                                .not_after
                                                .to_system_time()
                                                .duration_since(
                                                    cert.tbs_certificate.validity.not_before.to_system_time(),
                                                )
                                            {
                                                b.text(format!(
                                                    "Valid for {} days from {} to {}",
                                                    duration.as_secs() / 86400,
                                                    cert.tbs_certificate.validity.not_before,
                                                    cert.tbs_certificate.validity.not_after
                                                ))
                                                .line_break(|a| a);
                                            } else {
                                                b.text(format!(
                                                    "Valid for ??? days from {} to {}",
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
                                            for group in self.groups() {
                                                b.anchor(|ab| {
                                                    ab.text(format!("Add to the {group} group"));
                                                    match s.delivery {
                                                        crate::main_config::PageDelivery::Cgi => {
                                                            sget.insert("applet_data".to_string(), group.to_string());
                                                            sget.insert("step".to_string(), 2.to_string());
                                                            let a = sget
                                                                .iter()
                                                                .map(|a| format!("{}={}", a.0, a.1))
                                                                .collect::<Vec<String>>()
                                                                .join("&");
                                                            ab.href(format!("?{a}"));
                                                        }
                                                        crate::main_config::PageDelivery::DedicatedServer => {
                                                            ab.href(format!("applet.rs?id={}&action=manage_users&step=2&serial={}&applet_data={}", appletid, myserial, group));
                                                        }
                                                    };
                                                    ab
                                                });
                                                b.line_break(|a|a);
                                            }
                                        }
                                        Err(e) => {

                                        }
                                    }
                                }
                                backlinks(b, appletid, sget, s);
                                b
                            });
                        }
                        2 => {
                            if admin {
                                let mut success = false;
                                if let Some(serialhex) = s.get.get("serial") {
                                    let serial: Result<Vec<u8>, std::num::ParseIntError> =
                                        crate::utility::decode_hex(serialhex.as_str());
                                    if let Ok(serial) = serial {
                                        if let Some(group) = s.get.get("applet_data") {
                                            ca.add_user_by_serial_to_applet_group(
                                                &serial,
                                                appletid,
                                                group.to_string(),
                                            )
                                            .await;
                                            success = true;
                                        }
                                    }
                                }
                                html.body(|b| {
                                    if success {
                                        b.text("Added user to group");
                                    } else {
                                        b.text("Failed to add user to group");
                                    }
                                    b.line_break(|a| a);

                                    backlinks(b, appletid, sget, s);
                                    b
                                });
                            }
                        }
                        3 => {
                            if admin {
                                let mut success = false;

                                let mut myserial = String::new();

                                if let Some(serialhex) = s.get.get("serial") {
                                    let serial: Result<Vec<u8>, std::num::ParseIntError> =
                                        crate::utility::decode_hex(serialhex.as_str());
                                    if let Ok(serial) = serial {
                                        myserial = crate::utility::encode_hex(&serial);
                                        if let Some(group) = s.get.get("applet_data") {
                                            ca.delete_user_by_serial_from_applet_group(
                                                &serial,
                                                appletid,
                                                group.to_string(),
                                            )
                                            .await;
                                            success = true;
                                        }
                                    }
                                }
                                html.body(|b| {
                                    if success {
                                        b.text("Removed user from group");
                                    } else {
                                        b.text("Failed to remove user from group");
                                    }
                                    b.line_break(|a| a);

                                    b.anchor(|ab| {
                                        ab.text(format!("Back to user"));
                                        match s.delivery {
                                            crate::main_config::PageDelivery::Cgi => {
                                                sget.remove("applet_data");
                                                sget.insert("step".to_string(), 1.to_string());
                                                let a = sget
                                                    .iter()
                                                    .map(|a| format!("{}={}", a.0, a.1))
                                                    .collect::<Vec<String>>()
                                                    .join("&");
                                                ab.href(format!("?{a}"));
                                            }
                                            crate::main_config::PageDelivery::DedicatedServer => {
                                                ab.href(format!("applet.rs?id={}&action=manage_users&step=1&serial={}", appletid, myserial));
                                            }
                                        };
                                        ab
                                    });

                                    backlinks(b, appletid, sget, s);
                                    b
                                });
                            }
                        }
                        _ => {
                            let page = if let Some(p) = s.get.get("page") {
                                if let Ok(p) = p.parse::<i64>() {
                                    p
                                } else {
                                    0
                                }
                            } else {
                                0
                            };
                            let offset = page * RESULTS_PER_PAGE;
                            let mut user_list: Vec<crate::ca::CertificateInfo> = Vec::new();
                            let mut user_count = ca
                                .certificate_processing(RESULTS_PER_PAGE, offset, |ci| {
                                    user_list.push(ci);
                                })
                                .await;
                            let mut user_groups = Vec::new();

                            let mut myserial = String::new();

                            if let Some(serialhex) = s.get.get("serial") {
                                let serial: Result<Vec<u8>, std::num::ParseIntError> =
                                    crate::utility::decode_hex(serialhex.as_str());
                                if let Ok(serial) = serial {
                                    myserial = crate::utility::encode_hex(&serial);
                                }
                            }

                            for user in &user_list {
                                let userid = user.id;
                                let mut group_member = Vec::new();
                                for group in
                                    ca.get_groups_for_applet_and_user(appletid, userid).await
                                {
                                    group_member.push(group);
                                }
                                user_groups.push(group_member);
                            }
                            html.body(|b| {
                                b.text("List of users");
                                b.line_break(|a| a);
                                for (index, c) in user_list.iter().enumerate() {
                                    b.thematic_break(|a| a);
                                    b.text(format!("Issued by: {}", c.cert.tbs_certificate.issuer))
                                        .line_break(|a| a);
                                    b.text(format!(
                                        "Serial #: {}",
                                        c.cert.tbs_certificate.serial_number
                                    ))
                                    .line_break(|a| a);
                                    b.text(format!("Subject: {}", c.cert.tbs_certificate.subject))
                                        .line_break(|a| a);
                                    let serial = crate::utility::encode_hex(&c.serial);
                                    b.anchor(|ab| {
                                        ab.text("Modify this user");
                                        match s.delivery {
                                            crate::main_config::PageDelivery::Cgi => {
                                                sget.insert("step".to_string(), 1.to_string());
                                                sget.insert("serial".to_string(), serial);
                                                let a = sget
                                                    .iter()
                                                    .map(|a| format!("{}={}", a.0, a.1))
                                                    .collect::<Vec<String>>()
                                                    .join("&");
                                                ab.href(format!("?{a}"));
                                            }
                                            crate::main_config::PageDelivery::DedicatedServer => {
                                                ab.href(format!("applet.rs?id={}&action=manage_users&step=1&serial={}", appletid, serial));
                                            }
                                        };
                                        ab
                                    });
                                    b.line_break(|lb| lb);
                                    crate::ca::do_show_revoked(b, c.revoked);
                                    b.text(format!(
                                        "{:?}",
                                        crate::ca::CertificateSearchable::try_from(&c.cert)
                                    ))
                                    .line_break(|a| a);
                                    if let Some(usergroups) = user_groups.get(index) {
                                        b.text(format!("Groups are {}", usergroups.join(", ")));
                                        b.line_break(|a|a);
                                        for group in usergroups {
                                            b.anchor(|ab| {
                                                ab.text(format!("Remove from the {group} group"));
                                                match s.delivery {
                                                    crate::main_config::PageDelivery::Cgi => {
                                                        sget.insert("applet_data".to_string(), group.to_string());
                                                        sget.insert("step".to_string(), 3.to_string());
                                                        let a = sget
                                                            .iter()
                                                            .map(|a| format!("{}={}", a.0, a.1))
                                                            .collect::<Vec<String>>()
                                                            .join("&");
                                                        ab.href(format!("?{a}"));
                                                    }
                                                    crate::main_config::PageDelivery::DedicatedServer => {
                                                        ab.href(format!("applet.rs?id={}&action=manage_users&step=3&serial={}&applet_data={}", appletid, myserial, group));
                                                    }
                                                };
                                                ab
                                            });
                                            b.line_break(|a|a);
                                        }
                                    }
                                }
                                b.thematic_break(|a| a);
                                if page > 0 {
                                    match s.delivery {
                                        crate::main_config::PageDelivery::Cgi => {
                                            sget.insert("page".to_string(), (page - 1).to_string());
                                            let a = sget
                                                .iter()
                                                .map(|a| format!("{}={}", a.0, a.1))
                                                .collect::<Vec<String>>()
                                                .join("&");
                                            b.anchor(|ab| {
                                                ab.text("Prev page");
                                                ab.href(format!("?{a}"));
                                                ab
                                            })
                                            .line_break(|a| a);
                                        }
                                        crate::main_config::PageDelivery::DedicatedServer => {
                                            b.anchor(|ab| {
                                                ab.text("Prev page");
                                                ab.href(format!("applet.rs?id={}&action=manage_users&page={}", appletid, page - 1));
                                                ab
                                            })
                                            .line_break(|a| a);
                                        }
                                    };
                                }
                                if ((page + 1) * RESULTS_PER_PAGE) < user_count {
                                    match s.delivery {
                                        crate::main_config::PageDelivery::Cgi => {
                                            sget.insert("page".to_string(), (page + 1).to_string());
                                            let a = sget
                                                .iter()
                                                .map(|a| format!("{}={}", a.0, a.1))
                                                .collect::<Vec<String>>()
                                                .join("&");
                                            b.anchor(|ab| {
                                                ab.text("Next page");
                                                ab.href(format!("?{a}"));
                                                ab
                                            })
                                            .line_break(|a| a);
                                        }
                                        crate::main_config::PageDelivery::DedicatedServer => {
                                            b.anchor(|ab| {
                                                ab.text("Next page");
                                                ab.href(format!("applet.rs?id={}&action=manage_users&page={}", appletid, page + 1));
                                                ab
                                            })
                                            .line_break(|a| a);
                                        }
                                    };
                                }
                                b.line_break(|lb| lb);
                                backlinks(b, appletid, sget, s);
                                b
                            });
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                html.body(|b| {
                    b.text("This is the desvfire ev1 applet");
                    b.line_break(|a| a);

                    if admin {
                        b.text("You are admin over this applet");
                        b.line_break(|a| a);
                        b.anchor(|ab| {
                            ab.text("Modify users");
                            match s.delivery {
                                crate::main_config::PageDelivery::Cgi => {
                                    sget.insert(
                                        "applet_action".to_string(),
                                        "manage_users".to_string(),
                                    );
                                    let a = sget
                                        .iter()
                                        .map(|a| format!("{}={}", a.0, a.1))
                                        .collect::<Vec<String>>()
                                        .join("&");
                                    ab.href(format!("?{a}"));
                                }
                                crate::main_config::PageDelivery::DedicatedServer => {
                                    ab.href(format!(
                                        "applet.rs?id={}&applet_action=manage_users",
                                        appletid
                                    ));
                                }
                            };
                            ab
                        });
                        b.line_break(|a| a);
                    }

                    b.anchor(|ab| {
                        ab.text("Sample applet link");
                        match s.delivery {
                            crate::main_config::PageDelivery::Cgi => {
                                sget.insert("applet_action".to_string(), "asdf".to_string());
                                let a = sget
                                    .iter()
                                    .map(|a| format!("{}={}", a.0, a.1))
                                    .collect::<Vec<String>>()
                                    .join("&");
                                ab.href(format!("?{a}"));
                            }
                            crate::main_config::PageDelivery::DedicatedServer => {
                                ab.href(format!("applet.rs?id={}&applet_action=asdf", appletid));
                            }
                        };
                        ab
                    });
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
    }
}
