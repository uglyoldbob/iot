//! Code for the desfire applet

mod templates;

use std::collections::HashMap;

use rand::RngCore;

use crate::ca::{Ca, CertAttribute, DbEntry};

use super::{AppletTable, AppletTableField, FieldType};

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct Ev1 {
    table_name: String,
}

#[enum_dispatch::enum_dispatch]
trait FileTemplateTrait {
    /// Build the html form for modifying the data
    fn html_form<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        html: &mut html::root::builders::HtmlBuilder,
        fbm: F,
    );
    /// Apply changes from the html form
    fn apply_form_data(&mut self, data: url_encoded_data::UrlEncodedData);
    /// Generate the file
    fn generate(&self) -> FileGenerator;
}

#[derive(Default)]
struct CardApplication {
    aid: [u8; 3],
    name: String,
    key_ids: Vec<(u8, i64)>,
}

impl<'a> TryFrom<DbEntry<'a>> for CardApplication {
    type Error = async_sqlite::rusqlite::Error;
    fn try_from(val: DbEntry<'a>) -> Result<Self, Self::Error> {
        let aid: Vec<u8> = val.row_data.get(0)?;
        let aid = [aid[0], aid[1], aid[2]];
        let key_ids_o: [Option<i64>; 15] = [
            val.row_data.get(2)?,
            val.row_data.get(3)?,
            val.row_data.get(4)?,
            val.row_data.get(5)?,
            val.row_data.get(6)?,
            val.row_data.get(7)?,
            val.row_data.get(8)?,
            val.row_data.get(9)?,
            val.row_data.get(10)?,
            val.row_data.get(11)?,
            val.row_data.get(12)?,
            val.row_data.get(13)?,
            val.row_data.get(14)?,
            val.row_data.get(15)?,
            val.row_data.get(16)?,
        ];
        let mut key_ids = Vec::new();
        for k in key_ids_o.iter().enumerate() {
            if let Some(k2) = k.1 {
                key_ids.push((k.0 as u8, *k2));
            }
        }
        Ok(Self {
            aid,
            name: val.row_data.get(1)?,
            key_ids,
        })
    }
}

#[derive(Default)]
struct CardKey {
    key: Vec<u8>,
    auth: String,
    keytype: String,
    name: String,
}

impl<'a> TryFrom<DbEntry<'a>> for CardKey {
    type Error = async_sqlite::rusqlite::Error;
    fn try_from(val: DbEntry<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            key: val.row_data.get(1)?,
            auth: val.row_data.get(2)?,
            keytype: val.row_data.get(3)?,
            name: val.row_data.get(4)?,
        })
    }
}

#[enum_dispatch::enum_dispatch(FileTemplateTrait)]
enum FileTemplate {
    Counter(templates::Counter),
}

#[enum_dispatch::enum_dispatch]
trait FileGeneratorTrait {
    /// Build the html form for modifying the data
    fn html_form<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        html: &mut html::root::builders::HtmlBuilder,
        fbm: F,
    );
    /// Apply changes from the html form
    fn apply_form_data(&mut self, data: url_encoded_data::UrlEncodedData);
    /// Generate the file
    fn generate(&self) -> File;
}

#[enum_dispatch::enum_dispatch(FileGeneratorTrait)]
enum FileGenerator {
    Counter(templates::CounterGenerator),
}

enum File {}

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

impl Ev1 {
    const RESULTS_PER_PAGE: i64 = 10;

    async fn show_users_list(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
    ) {
        let page = if let Some(p) = s.get.get("page") {
            if let Ok(p) = p.parse::<i64>() {
                p
            } else {
                0
            }
        } else {
            0
        };
        let offset = page * Self::RESULTS_PER_PAGE;
        let mut user_list: Vec<crate::ca::CertificateInfo> = Vec::new();
        let mut user_count = ca
            .certificate_processing(Self::RESULTS_PER_PAGE, offset, |ci| {
                user_list.push(ci);
            })
            .await;
        let mut user_groups = Vec::new();

        for user in &user_list {
            let userid = user.id;
            let mut group_member = Vec::new();
            for group in ca.get_groups_for_applet_and_user(appletid, userid).await {
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
                            sget.insert("serial".to_string(), serial.clone());
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
                                    ab.href(format!("applet.rs?id={}&action=manage_users&step=3&serial={}&applet_data={}", appletid, serial, group));
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
            if ((page + 1) * Self::RESULTS_PER_PAGE) < user_count {
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

    async fn view_specific_user(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
    ) {
        use super::AppletTrait;
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
                    rejection = Some(ca.get_rejection_reason_by_serial(serial.clone()).await);
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

    async fn add_user_to_group(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
    ) {
        if admin {
            let mut success = false;
            if let Some(serialhex) = s.get.get("serial") {
                let serial: Result<Vec<u8>, std::num::ParseIntError> =
                    crate::utility::decode_hex(serialhex.as_str());
                if let Ok(serial) = serial {
                    if let Some(group) = s.get.get("applet_data") {
                        ca.add_user_by_serial_to_applet_group(&serial, appletid, group.to_string())
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

    async fn remove_user_from_group(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
    ) {
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
                            ab.href(format!(
                                "applet.rs?id={}&action=manage_users&step=1&serial={}",
                                appletid, myserial
                            ));
                        }
                    };
                    ab
                });

                backlinks(b, appletid, sget, s);
                b
            });
        }
    }

    async fn manage_users(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
    ) {
        use super::AppletTrait;
        if admin {
            let step = s
                .get
                .get("step")
                .map(|a| a.parse::<usize>().ok())
                .flatten()
                .unwrap_or(0);
            match step {
                1 => {
                    self.view_specific_user(admin, sget, html, appletid, userid, ca, s)
                        .await;
                }
                2 => {
                    self.add_user_to_group(admin, sget, html, appletid, userid, ca, s)
                        .await;
                }
                3 => {
                    self.remove_user_from_group(admin, sget, html, appletid, userid, ca, s)
                        .await;
                }
                _ => {
                    self.show_users_list(admin, sget, html, appletid, userid, ca, s)
                        .await;
                }
                _ => {}
            }
        }
    }

    /// Retrieve a single applet by name
    async fn retrieve_single_application(
        &self,
        medium: &crate::ca::CaCertificateStorage,
        app_table: &str,
        appname: String,
    ) -> Option<CardApplication> {
        let app_table2 = app_table.to_string();
        use crate::ca::CaCertificateStorage;
        match medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => Some(
                p.conn(move |conn| {
                    let mut stmt =
                        conn.prepare(&format!("SELECT * FROM {app_table2} WHERE name=?1 LIMIT 1"))?;
                    let data = stmt.query_row([appname], |row| {
                        let dbentry = DbEntry::new(row);
                        let t: CardApplication = dbentry.try_into()?;
                        Ok(t)
                    })?;
                    Ok(data)
                })
                .await
                .ok()?,
            ),
        }
    }

    /// Retrieve a single applet by name
    async fn retrieve_single_key(
        &self,
        medium: &crate::ca::CaCertificateStorage,
        app_table: &str,
        appname: String,
    ) -> Option<CardKey> {
        let app_table2 = app_table.to_string();
        use crate::ca::CaCertificateStorage;
        match medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => Some(
                p.conn(move |conn| {
                    let mut stmt =
                        conn.prepare(&format!("SELECT * FROM {app_table2} WHERE name=?1 LIMIT 1"))?;
                    let data = stmt.query_row([appname], |row| {
                        let dbentry = DbEntry::new(row);
                        let t: CardKey = dbentry.try_into()?;
                        Ok(t)
                    })?;
                    Ok(data)
                })
                .await
                .ok()?,
            ),
        }
    }

    /// Retrieve all applets
    async fn retrieve_all_card_applications(
        &self,
        medium: &crate::ca::CaCertificateStorage,
        app_table: &str,
    ) -> Option<Vec<CardApplication>> {
        let app_table2 = app_table.to_string();
        use crate::ca::CaCertificateStorage;
        match medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => Some(
                p.conn(move |conn| {
                    let mut stmt = conn.prepare(&format!("SELECT * FROM {app_table2}"))?;
                    let rows = stmt.query_map([], |row| {
                        let dbentry = DbEntry::new(row);
                        let t: CardApplication = dbentry.try_into()?;
                        Ok(t)
                    })?;
                    let mut data = Vec::new();
                    for r in rows {
                        if let Ok(r) = r {
                            data.push(r);
                        }
                    }
                    Ok(data)
                })
                .await
                .ok()?,
            ),
        }
    }

    /// Retrieve all applets
    async fn retrieve_all_keys(
        &self,
        medium: &crate::ca::CaCertificateStorage,
        app_table: &str,
    ) -> Option<Vec<CardKey>> {
        let app_table2 = app_table.to_string();
        use crate::ca::CaCertificateStorage;
        match medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => Some(
                p.conn(move |conn| {
                    let mut stmt = conn.prepare(&format!("SELECT * FROM {app_table2}"))?;
                    let rows = stmt.query_map([], |row| {
                        let dbentry = DbEntry::new(row);
                        let t: CardKey = dbentry.try_into()?;
                        Ok(t)
                    })?;
                    let mut data = Vec::new();
                    for r in rows {
                        if let Ok(r) = r {
                            data.push(r);
                        }
                    }
                    Ok(data)
                })
                .await
                .ok()?,
            ),
        }
    }

    async fn create_application_form<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        app_table: &str,
        fbm: F,
    ) {
        if admin {
            html.body(|b| {
                b.form(|fb| {
                    fb.text("Name of application");
                    fb.line_break(|a| a);
                    fb.input(|i| i.name("application_name"));
                    fb.line_break(|a| a);
                    fb.text("AID of application");
                    fb.line_break(|a| a);
                    fb.input(|i| i.name("aid").type_("number").min("0").max("16777215"));
                    fb.line_break(|a| a);
                    fb.input(|i| {
                        i.type_("hidden")
                            .name("applet_action")
                            .value("manage_applications")
                    });
                    fb.input(|i| i.type_("hidden").name("step").value("3"));
                    fb.line_break(|a| a);
                    fb.button(|b| b.text("Finish"));
                    fbm(fb);
                    fb
                })
            });
        }
    }

    async fn insert_new_application(
        &self,
        ca: &mut Ca,
        appletid: i64,
        app: CardApplication,
    ) -> Result<(), ()> {
        let app_table = ca.get_applet_specific_table_name(appletid, "card_applications");
        use crate::ca::CaCertificateStorage;
        use async_sqlite::rusqlite::ToSql;
        match &ca.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::Sqlite(p) => {
                p.conn(move |conn| {
                    let mut stmt = conn.prepare(&format!(
                        "INSERT INTO {app_table} (aid, name) VALUES (?1, ?2)"
                    ))?;
                    stmt.execute([app.aid.to_sql().unwrap(), app.name.to_sql().unwrap()])?;
                    Ok(())
                })
                .await
                .map_err(|_| ())?;
                Ok(())
            }
        }
    }

    async fn submit_new_application_form(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        app_table: &str,
    ) {
        if admin {
            if let Some(form) = s.post.form() {
                if let Some(app_name) = form.get_first("application_name") {
                    if let Some(app_aid) = form.get_first("aid") {
                        let app_aid = if let Ok(a) = app_aid.parse::<u32>() {
                            let aid_full = a.to_le_bytes();
                            Some([aid_full[2], aid_full[1], aid_full[0]])
                        } else {
                            None
                        };
                        if let Some(app_aid) = app_aid {
                            let mut app = CardApplication::default();
                            app.name = app_name.to_string();
                            app.aid = app_aid;
                            if self.insert_new_application(ca, appletid, app).await.is_ok() {
                                html.body(|b| {
                                    b.text("Applicaiton created");
                                    backlinks(b, appletid, sget, s);
                                    b
                                });
                            } else {
                                html.body(|b| {
                                    b.text("Failed to create applicaiton");
                                    backlinks(b, appletid, sget, s);
                                    b
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    async fn view_specific_application(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        app_table: &str,
    ) {
        if admin {
            if let Some(appname) = s.get.get("applet_data") {
                if let Some(app) = self
                    .retrieve_single_application(&ca.medium, app_table, appname.to_owned())
                    .await
                {
                    let key_table = ca.get_applet_specific_table_name(appletid, "card_keys");
                    let keys = self.retrieve_all_keys(&ca.medium, &key_table).await;
                    html.body(|b| {
                        b.text(format!("NAME: {}", app.name));
                        b.line_break(|a| a);
                        b.text(format!("AID: {:X?}", app.aid));
                        b.line_break(|a| a);
                        if let Some(keys) = keys {
                            for akey in app.key_ids.iter().enumerate() {
                                b.thematic_break(|a| a);
                                if let Some(key) = keys.get(akey.0 as usize) {
                                    b.text(format!("KEY {} - {}", akey.0, key.name));
                                    b.line_break(|a| a);
                                    b.text(format!("AUTH {}", key.auth));
                                    b.line_break(|a| a);
                                    b.text(format!("KEYTYPE {}", key.keytype));
                                    b.line_break(|a| a);
                                } else {
                                    b.text(format!("INVALID KEY {}", akey.0));
                                    b.line_break(|a| a);
                                }
                            }
                            b.thematic_break(|a| a);
                        }
                        backlinks(b, appletid, sget, s);
                        b
                    });
                }
            }
        }
    }

    async fn show_applications_list(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        app_table: &str,
    ) {
        if admin {
            let list = self
                .retrieve_all_card_applications(&ca.medium, app_table)
                .await;
            html.body(|b| {
                if let Some(list) = list {
                    for app in list {
                        b.thematic_break(|a| a);
                        b.anchor(|ab| {
                            ab.text(format!("{} application", app.name));
                            match s.delivery {
                                crate::main_config::PageDelivery::Cgi => {
                                    sget.insert("applet_data".to_string(), app.name.clone());
                                    sget.insert("step".to_string(), 1.to_string());
                                    let a = sget
                                        .iter()
                                        .map(|a| format!("{}={}", a.0, a.1))
                                        .collect::<Vec<String>>()
                                        .join("&");
                                    ab.href(format!("?{a}"));
                                }
                                crate::main_config::PageDelivery::DedicatedServer => {
                                    ab.href(format!("applet.rs?id={}&action=manage_applications&step=3&applet_data={}", appletid, app.name));
                                }
                            };
                            ab
                        });
                        b.line_break(|a|a);
                    }
                    b.thematic_break(|a| a);
                    b.anchor(|ab| {
                        ab.text(format!("Create new application"));
                        match s.delivery {
                            crate::main_config::PageDelivery::Cgi => {
                                sget.insert("step".to_string(), 2.to_string());
                                let a = sget
                                    .iter()
                                    .map(|a| format!("{}={}", a.0, a.1))
                                    .collect::<Vec<String>>()
                                    .join("&");
                                ab.href(format!("?{a}"));
                            }
                            crate::main_config::PageDelivery::DedicatedServer => {
                                ab.href(format!("applet.rs?id={}&action=manage_applications&step=2", appletid));
                            }
                        };
                        ab
                    });
                    b.line_break(|a|a);
                }
                backlinks(b, appletid, sget, s);
                b
            });
        }
    }

    async fn manage_applications<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        fbm: F,
    ) {
        let steps = s
            .post
            .form()
            .and_then(|f| f.get_first("step").map(|a| a.to_string()))
            .or(s.get.get("step").map(|a| a.clone()));
        let step = steps
            .map(|a| a.parse::<usize>().ok())
            .flatten()
            .unwrap_or(0);
        let app_table = ca.get_applet_specific_table_name(appletid, "card_applications");
        match step {
            1 => {
                self.view_specific_application(
                    admin, sget, html, appletid, userid, ca, s, &app_table,
                )
                .await;
            }
            2 => {
                self.create_application_form(
                    admin, sget, html, appletid, userid, ca, s, &app_table, fbm,
                )
                .await;
            }
            3 => {
                self.submit_new_application_form(
                    admin, sget, html, appletid, userid, ca, s, &app_table,
                )
                .await;
            }
            _ => {
                self.show_applications_list(admin, sget, html, appletid, userid, ca, s, &app_table)
                    .await;
            }
        }
    }

    async fn create_key_form<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        app_table: &str,
        fbm: F,
    ) {
        if admin {
            html.body(|b| {
                b.form(|fb| {
                    fb.text("Name of key");
                    fb.line_break(|a| a);
                    fb.input(|i| i.name("key_name"));
                    fb.line_break(|a| a);
                    fb.text("Key auth method");
                    fb.line_break(|a| a);
                    fb.input(|i| i.name("key_auth"));
                    fb.line_break(|a| a);
                    fb.text("Key type");
                    fb.line_break(|a| a);
                    fb.input(|i| i.name("key_type"));
                    fb.line_break(|a| a);
                    fb.input(|i| i.type_("hidden").name("applet_action").value("manage_keys"));
                    fb.line_break(|a| a);
                    fb.input(|i| i.type_("hidden").name("step").value("3"));
                    fb.line_break(|a| a);
                    fb.button(|b| b.text("Finish"));
                    fbm(fb);
                    fb
                })
            });
        }
    }

    async fn insert_new_key(&self, ca: &mut Ca, appletid: i64, app: CardKey) -> Result<(), ()> {
        let app_table = ca.get_applet_specific_table_name(appletid, "card_keys");
        use crate::ca::CaCertificateStorage;
        use async_sqlite::rusqlite::ToSql;
        match &ca.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::Sqlite(p) => {
                p.conn(move |conn| {
                    let mut stmt = conn.prepare(&format!(
                        "INSERT INTO {app_table} (name, key, keytype, auth) VALUES (?1, ?2, ?3, ?4)"
                    ))?;
                    stmt.execute([
                        app.name.to_sql().unwrap(),
                        app.key.to_sql().unwrap(),
                        app.keytype.to_sql().unwrap(),
                        app.auth.to_sql().unwrap(),
                    ])?;
                    Ok(())
                })
                .await
                .map_err(|_| ())?;
                Ok(())
            }
        }
    }

    async fn submit_new_key_form(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        app_table: &str,
    ) {
        if admin {
            if let Some(form) = s.post.form() {
                if let Some(app_name) = form.get_first("key_name") {
                    if let Some(key_auth) = form.get_first("key_auth") {
                        if let Some(key_type) = form.get_first("key_type") {
                            let mut app = CardKey::default();
                            let mut rng = rand::thread_rng();
                            app.key = match key_type {
                                "DES" => {
                                    let mut key: [u8; 8] = [0; 8];
                                    rng.fill_bytes(&mut key);
                                    key.to_vec()
                                }
                                "TDES" | "AES" | "TWO_KEY_THREEDES" => {
                                    let mut key: [u8; 16] = [0; 16];
                                    rng.fill_bytes(&mut key);
                                    key.to_vec()
                                }
                                "TKTDES" => {
                                    let mut key: [u8; 24] = [0; 24];
                                    rng.fill_bytes(&mut key);
                                    key.to_vec()
                                }
                                _ => Vec::new(),
                            };
                            app.name = app_name.to_string();
                            app.keytype = key_type.to_string();
                            app.auth = key_auth.to_string();

                            if self.insert_new_key(ca, appletid, app).await.is_ok() {
                                html.body(|b| {
                                    b.text("Key created");
                                    backlinks(b, appletid, sget, s);
                                    b
                                });
                            } else {
                                html.body(|b| {
                                    b.text("Failed to create key");
                                    backlinks(b, appletid, sget, s);
                                    b
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    async fn view_specific_key(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        key_table: &str,
    ) {
        if admin {
            if let Some(appname) = s.get.get("applet_data") {
                if let Some(app) = self
                    .retrieve_single_key(&ca.medium, key_table, appname.to_owned())
                    .await
                {
                    let key_table = ca.get_applet_specific_table_name(appletid, "card_keys");
                    let keys = self.retrieve_all_keys(&ca.medium, &key_table).await;
                    html.body(|b| {
                        b.text(format!("NAME: {}", app.name));
                        b.line_break(|a| a);
                        b.text(format!("AUTH: {}", app.auth));
                        b.line_break(|a| a);
                        b.text(format!("KEYTYPE: {}", app.keytype));
                        b.line_break(|a| a);
                        backlinks(b, appletid, sget, s);
                        b
                    });
                }
            }
        }
    }

    async fn show_keys_list(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        key_table: &str,
    ) {
        if admin {
            let list = self.retrieve_all_keys(&ca.medium, key_table).await;
            html.body(|b| {
                if let Some(list) = list {
                    for app in list {
                        b.thematic_break(|a| a);
                        b.anchor(|ab| {
                            ab.text(format!("{} key", app.name));
                            match s.delivery {
                                crate::main_config::PageDelivery::Cgi => {
                                    sget.insert("applet_data".to_string(), app.name.clone());
                                    sget.insert("step".to_string(), 1.to_string());
                                    let a = sget
                                        .iter()
                                        .map(|a| format!("{}={}", a.0, a.1))
                                        .collect::<Vec<String>>()
                                        .join("&");
                                    ab.href(format!("?{a}"));
                                }
                                crate::main_config::PageDelivery::DedicatedServer => {
                                    ab.href(format!(
                                        "applet.rs?id={}&action=manage_keys&step=3&applet_data={}",
                                        appletid, app.name
                                    ));
                                }
                            };
                            ab
                        });
                        b.line_break(|a| a);
                    }
                    b.thematic_break(|a| a);
                    b.anchor(|ab| {
                        ab.text(format!("Create new key"));
                        match s.delivery {
                            crate::main_config::PageDelivery::Cgi => {
                                sget.insert("step".to_string(), 2.to_string());
                                let a = sget
                                    .iter()
                                    .map(|a| format!("{}={}", a.0, a.1))
                                    .collect::<Vec<String>>()
                                    .join("&");
                                ab.href(format!("?{a}"));
                            }
                            crate::main_config::PageDelivery::DedicatedServer => {
                                ab.href(format!(
                                    "applet.rs?id={}&action=manage_keys&step=2",
                                    appletid
                                ));
                            }
                        };
                        ab
                    });
                    b.line_break(|a| a);
                }
                backlinks(b, appletid, sget, s);
                b
            });
        }
    }

    async fn manage_keys<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        fbm: F,
    ) {
        let steps = s
            .post
            .form()
            .and_then(|f| f.get_first("step").map(|a| a.to_string()))
            .or(s.get.get("step").map(|a| a.clone()));
        let step = steps
            .map(|a| a.parse::<usize>().ok())
            .flatten()
            .unwrap_or(0);
        let key_table = ca.get_applet_specific_table_name(appletid, "card_keys");
        match step {
            1 => {
                self.view_specific_key(admin, sget, html, appletid, userid, ca, s, &key_table)
                    .await;
            }
            2 => {
                self.create_key_form(admin, sget, html, appletid, userid, ca, s, &key_table, fbm)
                    .await;
            }
            3 => {
                self.submit_new_key_form(admin, sget, html, appletid, userid, ca, s, &key_table)
                    .await;
            }
            _ => {
                self.show_keys_list(admin, sget, html, appletid, userid, ca, s, &key_table)
                    .await;
            }
        }
    }
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
        vec![
            AppletTable {
                name: "applications".to_string(),
                fields: vec![(
                    "v1".to_string(),
                    AppletTableField {
                        ty: FieldType::Integer,
                        primary_key: false,
                        default: None,
                    },
                )],
            },
            AppletTable {
                name: "file_templates".to_string(),
                fields: vec![
                    (
                        "id".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: true,
                            default: None,
                        },
                    ),
                    (
                        "name".to_string(),
                        AppletTableField {
                            ty: FieldType::Text,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "definition".to_string(),
                        AppletTableField {
                            ty: FieldType::Text,
                            primary_key: false,
                            default: None,
                        },
                    ),
                ],
            },
            AppletTable {
                name: "card_keys".to_string(),
                fields: vec![
                    (
                        "id".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: true,
                            default: None,
                        },
                    ),
                    (
                        "key".to_string(),
                        AppletTableField {
                            ty: FieldType::Blob,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "auth".to_string(),
                        AppletTableField {
                            ty: FieldType::Text,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "keytype".to_string(),
                        AppletTableField {
                            ty: FieldType::Text,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "name".to_string(),
                        AppletTableField {
                            ty: FieldType::Text,
                            primary_key: false,
                            default: None,
                        },
                    ),
                ],
            },
            AppletTable {
                name: "card_applications".to_string(),
                fields: vec![
                    (
                        "aid".to_string(),
                        AppletTableField {
                            ty: FieldType::Blob,
                            primary_key: true,
                            default: None,
                        },
                    ),
                    (
                        "name".to_string(),
                        AppletTableField {
                            ty: FieldType::Text,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key0".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key1".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key2".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key3".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key4".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key5".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key6".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key7".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key8".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key9".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key10".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key11".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key12".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key13".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "key14".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                ],
            },
        ]
    }

    fn api_calls(&self) -> cert_common::api::AppletCalls {
        cert_common::api::AppletCalls {
            calls: vec!["test".to_string()],
        }
    }

    async fn api_call(
        &self,
        call: &str,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
    ) -> String {
        let mut admin = false;
        if ca.is_admin_for_applet(appletid, userid).await {
            admin = true;
        }
        match call {
            "test" => String::new(),
            _ => String::new(),
        }
    }

    async fn run_applet<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        fbm: F,
    ) {
        let mut admin = false;
        if ca.is_admin_for_applet(appletid, userid).await {
            admin = true;
        }
        let mut sget = s.get.clone();
        let action = s.get.get("applet_action").map(|a| a.clone()).or(s
            .post
            .form()
            .and_then(|f| f.get_first("applet_action").map(|a| a.to_string())));
        match action.as_deref() {
            Some("manage_users") => {
                self.manage_users(admin, sget, html, appletid, userid, ca, s)
                    .await;
            }
            Some("manage_applications") => {
                self.manage_applications(admin, sget, html, appletid, userid, ca, s, fbm)
                    .await;
            }
            Some("manage_keys") => {
                self.manage_keys(admin, sget, html, appletid, userid, ca, s, fbm)
                    .await;
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
                        b.anchor(|ab| {
                            ab.text("Modify applications");
                            match s.delivery {
                                crate::main_config::PageDelivery::Cgi => {
                                    sget.insert(
                                        "applet_action".to_string(),
                                        "manage_applications".to_string(),
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
                                        "applet.rs?id={}&applet_action=manage_applications",
                                        appletid
                                    ));
                                }
                            };
                            ab
                        });
                        b.line_break(|a| a);
                        b.anchor(|ab| {
                            ab.text("Modify application keys");
                            match s.delivery {
                                crate::main_config::PageDelivery::Cgi => {
                                    sget.insert(
                                        "applet_action".to_string(),
                                        "manage_keys".to_string(),
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
                                        "applet.rs?id={}&applet_action=manage_keys",
                                        appletid
                                    ));
                                }
                            };
                            ab
                        });
                        b.line_break(|a| a);
                    }
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
