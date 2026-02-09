//! Code for the desfire applet

mod templates;

use std::collections::HashMap;

use async_sqlite::rusqlite::ToSql;
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
        b: &mut html::root::builders::BodyBuilder,
        fbm: F,
    );
    /// Apply changes from the html form
    fn apply_form_data(&mut self, data: url_encoded_data::UrlEncodedData);
    /// Show the name of the template
    fn name(&self) -> &str;
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

struct ApplicationBuilder {
    id: i64,
    name: String,
    card_app_aid: Vec<u8>,
}

impl<'a> TryFrom<DbEntry<'a>> for ApplicationBuilder {
    type Error = async_sqlite::rusqlite::Error;
    fn try_from(val: DbEntry<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            id: val.row_data.get(0)?,
            name: val.row_data.get(1)?,
            card_app_aid: val.row_data.get(2)?,
        })
    }
}

struct ApplicationReference {
    id: i64,
    name: String,
    app: CardApplication,
    files: HashMap<u8, FileGenerator>,
}

struct ApplicationBuilderFile {
    id: i64,
    file_number: u8,
    file_template_id: i64,
}

impl<'a> TryFrom<DbEntry<'a>> for ApplicationBuilderFile {
    type Error = async_sqlite::rusqlite::Error;
    fn try_from(val: DbEntry<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            id: val.row_data.get(0)?,
            file_number: val.row_data.get(2)?,
            file_template_id: val.row_data.get(3)?,
        })
    }
}

impl ApplicationBuilder {
    async fn get_file_builders(
        &self,
        appletid: i64,
        app_builder_id: i64,
        ca: &mut Ca,
        ev1: &Ev1,
    ) -> Option<HashMap<u8, FileGenerator>> {
        let tablename = ca.get_applet_specific_table_name(appletid, "application_builder_files");
        use crate::ca::CaCertificateStorage;
        let id = self.id;
        let mut hm = HashMap::new();
        if let Some(abfs) = match &ca.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => Some(
                p.conn(move |conn| {
                    let mut stmt = conn.prepare(&format!(
                        "SELECT * FROM {tablename} WHERE application_instance_id=?1"
                    ))?;
                    let rows = stmt.query_map([app_builder_id.to_sql().unwrap()], |row| {
                        let dbentry = DbEntry::new(row);
                        let t: ApplicationBuilderFile = dbentry.try_into()?;
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
        } {
            for abf in abfs {
                let ftid = abf.file_template_id;
                let ft_table_name = ca.get_applet_specific_table_name(appletid, "file_templates");
                if let Some(ftempd) = ev1
                    .retrieve_specific_file_template(&ca.medium, &ft_table_name, ftid)
                    .await
                {
                    if let Ok(ftemp) = toml::from_str(&ftempd.definition) {
                        let ftemp: FileTemplate = ftemp;
                        let a = ftemp.generate();
                        hm.insert(abf.file_number, a);
                    }
                }
            }
        }
        Some(hm)
    }
}

#[derive(Default)]
struct CardKey {
    id: i64,
    key: Vec<u8>,
    auth: String,
    keytype: String,
    name: String,
}

impl<'a> TryFrom<DbEntry<'a>> for CardKey {
    type Error = async_sqlite::rusqlite::Error;
    fn try_from(val: DbEntry<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            id: val.row_data.get(0)?,
            key: val.row_data.get(1)?,
            auth: val.row_data.get(2)?,
            keytype: val.row_data.get(3)?,
            name: val.row_data.get(4)?,
        })
    }
}

#[enum_dispatch::enum_dispatch(FileTemplateTrait)]
#[derive(strum::EnumIter, serde::Serialize, serde::Deserialize)]
enum FileTemplate {
    Counter(templates::Counter),
    Bitmap(templates::Bitmap),
}

struct FileTemplateEntry {
    id: i64,
    name: String,
    definition: String,
}

impl<'a> TryFrom<DbEntry<'a>> for FileTemplateEntry {
    type Error = async_sqlite::rusqlite::Error;
    fn try_from(val: DbEntry<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            id: val.row_data.get(0)?,
            name: val.row_data.get(1)?,
            definition: val.row_data.get(2)?,
        })
    }
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
    /// User readable description
    fn description(&self) -> String;
}

#[enum_dispatch::enum_dispatch(FileGeneratorTrait)]
enum FileGenerator {
    Counter(templates::CounterGenerator),
    Bitmap(templates::BitmapGenerator),
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
    async fn retrieve_single_application_by_aid(
        &self,
        medium: &crate::ca::CaCertificateStorage,
        app_table: &str,
        aid: Vec<u8>,
    ) -> Option<CardApplication> {
        let app_table2 = app_table.to_string();
        use crate::ca::CaCertificateStorage;
        match medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => p
                .conn(move |conn| {
                    let query = format!(
                        "SELECT * FROM {} WHERE aid=x'{}' LIMIT 1",
                        app_table2,
                        crate::utility::encode_hex(&aid)
                    );
                    conn.query_row(&query, [], |row| {
                        let dbentry = DbEntry::new(row);
                        let t: CardApplication = dbentry.try_into()?;
                        Ok(t)
                    })
                })
                .await
                .ok(),
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

    /// Retrieve a specific file template
    async fn retrieve_specific_file_template(
        &self,
        medium: &crate::ca::CaCertificateStorage,
        app_table: &str,
        id: i64,
    ) -> Option<FileTemplateEntry> {
        let app_table2 = app_table.to_string();
        use crate::ca::CaCertificateStorage;
        match medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => Some(
                p.conn(move |conn| {
                    let mut stmt =
                        conn.prepare(&format!("SELECT * FROM {app_table2} WHERE id=?1 LIMIT 1"))?;
                    let data = stmt.query_row([id], |row| {
                        let dbentry = DbEntry::new(row);
                        let t: FileTemplateEntry = dbentry.try_into()?;
                        Ok(t)
                    })?;
                    Ok(data)
                })
                .await
                .ok()?,
            ),
        }
    }

    /// Retrieve all file templates
    async fn retrieve_all_file_templates(
        &self,
        medium: &crate::ca::CaCertificateStorage,
        app_table: &str,
    ) -> Option<Vec<FileTemplateEntry>> {
        let app_table2 = app_table.to_string();
        use crate::ca::CaCertificateStorage;
        match medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => Some(
                p.conn(move |conn| {
                    let mut stmt = conn.prepare(&format!("SELECT * FROM {app_table2}"))?;
                    let rows = stmt.query_map([], |row| {
                        let dbentry = DbEntry::new(row);
                        let t: FileTemplateEntry = dbentry.try_into()?;
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
        fbm: F,
    ) {
        if admin {
            let keys = self
                .retrieve_all_keys(
                    &ca.medium,
                    &ca.get_applet_specific_table_name(appletid, "card_keys"),
                )
                .await;
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

                    if let Some(keys) = keys {
                        for i in 0..15 {
                            fb.thematic_break(|a| a);
                            fb.text(format!("Key {i}"));
                            fb.select(|sb| {
                                sb.name(format!("key{i}"));
                                sb.option(|ob| ob.value("NULL").text("None"));
                                for key in &keys {
                                    sb.option(|ob| {
                                        ob.value(format!("{}", key.id)).text(key.name.clone())
                                    });
                                }
                                sb
                            });
                            fb.line_break(|a| a);
                        }
                        fb.thematic_break(|a| a);
                    }

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
                });
                backlinks(b, appletid, sget, s);
                b
            });
        }
    }

    async fn modify_application_form<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        application: &CardApplication,
        fbm: F,
    ) {
        if admin {
            let keys = self
                .retrieve_all_keys(
                    &ca.medium,
                    &ca.get_applet_specific_table_name(appletid, "card_keys"),
                )
                .await;
            html.body(|b| {
                b.form(|fb| {
                    fb.text(format!("NAME: {}", application.name));
                    fb.line_break(|a| a);
                    fb.text(format!("AID: {:X?}", application.aid));
                    fb.line_break(|a| a);

                    if let Some(keys) = keys {
                        for i in 0..15 {
                            fb.thematic_break(|a| a);
                            fb.text(format!("Key {i}"));
                            fb.select(|sb| {
                                sb.name(format!("key{i}"));
                                sb.id(format!("key{i}"));
                                sb.option(|ob| ob.value("NULL").text("None"));
                                for key in &keys {
                                    sb.option(|ob| {
                                        ob.value(format!("{}", key.id)).text(key.name.clone());
                                        for ak in &application.key_ids {
                                            if ak.0 == i && ak.1 == key.id {
                                                ob.selected(true);
                                                break;
                                            }
                                        }
                                        ob
                                    });
                                }
                                sb
                            });
                            fb.line_break(|a| a);
                        }
                        fb.thematic_break(|a| a);
                    }
                    fb.input(|i| {
                        i.type_("hidden")
                            .name("application_name")
                            .value(application.name.clone())
                    });
                    fb.input(|i| {
                        i.type_("hidden")
                            .name("applet_action")
                            .value("manage_applications")
                    });
                    fb.input(|i| i.type_("hidden").name("step").value("4"));
                    fb.line_break(|a| a);
                    fb.button(|b| b.text("Update"));
                    fbm(fb);
                    fb
                });
                backlinks(b, appletid, sget, s);
                b
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
                    for key in &app.key_ids {
                        let mut stmt = conn.prepare(&format!(
                            "UPDATE {} SET key{} = ?1 WHERE name=?2",
                            app_table, key.0
                        ))?;
                        stmt.execute([key.1.to_sql().unwrap(), app.name.to_sql().unwrap()])?;
                    }
                    Ok(())
                })
                .await
                .map_err(|_| ())?;
                Ok(())
            }
        }
    }

    async fn modify_application(
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
                            "UPDATE {} SET key0=NULL, key1=NULL, key2=NULL, key3=NULL, key4=NULL, key5=NULL, key6=NULL, key7=NULL, key8=NULL, key9=NULL, key10=NULL, key11=NULL, key12=NULL, key13=NULL, key14=NULL WHERE name=?1",
                        app_table
                    ))?;
                    stmt.execute([app.name.to_sql().unwrap()])?;
                    for key in &app.key_ids {
                        let mut stmt = conn.prepare(&format!(
                            "UPDATE {} SET key{} = ?1 WHERE name=?2",
                            app_table, key.0
                        ))?;
                        stmt.execute([key.1.to_sql().unwrap(), app.name.to_sql().unwrap()])?;
                    }
                    Ok(())
                })
                .await
                .map_err(|_| ())?;
                Ok(())
            }
        }
    }

    async fn update_existing_application(
        &self,
        admin: bool,
        mut sget: HashMap<String, String>,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
        mut application: CardApplication,
    ) {
        if admin {
            if let Some(form) = s.post.form() {
                if let Some(app_name) = form.get_first("application_name") {
                    let mut keys = Vec::new();
                    for i in 0..15 {
                        if let Some(v) = form.get_first(&format!("key{i}")) {
                            if let Ok(v) = v.parse::<i64>() {
                                keys.push((i, v));
                            }
                        }
                    }

                    application.key_ids = keys;
                    if self
                        .modify_application(ca, appletid, application)
                        .await
                        .is_ok()
                    {
                        html.body(|b| {
                            b.text("Application updated");
                            b.line_break(|a| a);
                            backlinks(b, appletid, sget, s);
                            b
                        });
                    } else {
                        html.body(|b| {
                            b.text("Failed to update application");
                            b.line_break(|a| a);
                            backlinks(b, appletid, sget, s);
                            b
                        });
                    }
                }
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

                        let mut keys = Vec::new();
                        for i in 0..15 {
                            if let Some(v) = form.get_first(&format!("key{i}")) {
                                if let Ok(v) = v.parse::<i64>() {
                                    keys.push((i, v));
                                }
                            }
                        }

                        if let Some(app_aid) = app_aid {
                            let mut app = CardApplication::default();
                            app.name = app_name.to_string();
                            app.aid = app_aid;
                            app.key_ids = keys;
                            if self.insert_new_application(ca, appletid, app).await.is_ok() {
                                html.body(|b| {
                                    b.text("Application created");
                                    b.line_break(|a| a);
                                    backlinks(b, appletid, sget, s);
                                    b
                                });
                            } else {
                                html.body(|b| {
                                    b.text("Failed to create application");
                                    b.line_break(|a| a);
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
                if let Some(appname) = s.get.get("applet_data") {
                    if let Some(app) = self
                        .retrieve_single_application(&ca.medium, &app_table, appname.to_owned())
                        .await
                    {
                        self.modify_application_form(
                            admin, sget, html, appletid, userid, ca, s, &app, fbm,
                        )
                        .await;
                    }
                }
            }
            2 => {
                self.create_application_form(admin, sget, html, appletid, userid, ca, s, fbm)
                    .await;
            }
            3 => {
                self.submit_new_application_form(admin, sget, html, appletid, userid, ca, s)
                    .await;
            }
            4 => {
                if let Some(appname) = s.get.get("applet_data") {
                    if let Some(app) = self
                        .retrieve_single_application(&ca.medium, &app_table, appname.to_owned())
                        .await
                    {
                        self.update_existing_application(
                            admin, sget, html, appletid, userid, ca, s, app,
                        )
                        .await;
                    }
                }
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
                    fb.select(|sb| {
                        sb.name("key_auth");
                        sb.option(|ob| ob.value("Native").text("Native desfire authentication"));
                        sb.option(|ob| ob.value("ISO").text("ISO 7816-4 authentication"));
                        sb
                    });
                    fb.line_break(|a| a);
                    fb.text("Key type");
                    fb.line_break(|a| a);
                    fb.select(|sb| {
                        sb.name("key_type");
                        sb.option(|ob| ob.value("DES").text("DES (legacy)"));
                        sb.option(|ob| ob.value("TWO_KEY_THREEDES").text("Two-key triple DES"));
                        sb.option(|ob| ob.value("TKTDES").text("Three-key triple DES"));
                        sb.option(|ob| ob.value("AES").text("AES-128"));
                        sb
                    });
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
                                    b.line_break(|a| a);
                                    backlinks(b, appletid, sget, s);
                                    b
                                });
                            } else {
                                html.body(|b| {
                                    b.text("Failed to create key");
                                    b.line_break(|a| a);
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

    async fn view_specific_file_template<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
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
        if admin {
            if let Some(template_id) = s.get.get("applet_data") {
                if let Ok(id) = template_id.parse::<i64>() {
                    let key_table = ca.get_applet_specific_table_name(appletid, "file_templates");
                    if let Some(template) = self
                        .retrieve_specific_file_template(&ca.medium, &key_table, id)
                        .await
                    {
                        html.body(|b| {
                            b.text(format!("NAME: {}", template.name));
                            b.line_break(|a| a);
                            if let Ok(temp) = toml::from_str(&template.definition) {
                                let temp: FileTemplate = temp;
                                temp.html_form(b, |fb| {
                                    fb.input(|i| {
                                        i.type_("hidden")
                                            .name("applet_action")
                                            .value("manage_file_templates")
                                    });
                                    fb.input(|i| {
                                        i.type_("hidden")
                                            .name("template_id")
                                            .value(format!("{}", id))
                                    });
                                    fb.input(|i| i.type_("hidden").name("step").value("4"));
                                    fb.button(|b| b.text("Update"));
                                    fbm(fb);
                                });
                            }
                            backlinks(b, appletid, sget, s);
                            b
                        });
                    }
                }
            }
        }
    }

    async fn insert_new_file_template(
        &self,
        ca: &mut Ca,
        appletid: i64,
        name: String,
        template: FileTemplate,
    ) -> Result<(), ()> {
        let table = ca.get_applet_specific_table_name(appletid, "file_templates");
        use crate::ca::CaCertificateStorage;
        use async_sqlite::rusqlite::ToSql;
        match &ca.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::Sqlite(p) => {
                p.conn(move |conn| {
                    let mut stmt = conn.prepare(&format!(
                        "INSERT INTO {table} (name, definition) VALUES (?1, ?2)"
                    ))?;
                    stmt.execute([
                        name.to_sql().unwrap(),
                        toml::to_string(&template).unwrap().to_sql().unwrap(),
                    ])?;
                    Ok(())
                })
                .await
                .map_err(|_| ())?;
                Ok(())
            }
        }
    }

    async fn update_file_template(
        &self,
        ca: &mut Ca,
        appletid: i64,
        name: String,
        template: FileTemplate,
        templateid: i64,
    ) -> Result<(), ()> {
        let table = ca.get_applet_specific_table_name(appletid, "file_templates");
        use crate::ca::CaCertificateStorage;
        use async_sqlite::rusqlite::ToSql;
        match &ca.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::Sqlite(p) => {
                p.conn(move |conn| {
                    let mut stmt = conn.prepare(&format!(
                        "REPLACE INTO {table} (id, name, definition) VALUES (?1, ?2, ?3)"
                    ))?;
                    stmt.execute([
                        templateid.to_sql().unwrap(),
                        name.to_sql().unwrap(),
                        toml::to_string(&template).unwrap().to_sql().unwrap(),
                    ])?;
                    Ok(())
                })
                .await
                .map_err(|_| ())?;
                Ok(())
            }
        }
    }

    async fn create_file_template_form<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
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
        if admin {
            html.body(|b| {
                b.form(|fb| {
                    fb.text("Name of file template");
                    fb.line_break(|a| a);
                    fb.input(|i| i.name("template_name"));
                    fb.line_break(|a| a);
                    fb.select(|sb| {
                        sb.name("definition");
                        use strum::IntoEnumIterator;
                        for f in FileTemplate::iter() {
                            let encoded = crate::utility::build_toml_string(&f);
                            sb.option(|ob| ob.value(encoded).text(f.name().to_string()));
                        }
                        sb
                    });
                    fb.line_break(|a| a);
                    fb.input(|i| {
                        i.type_("hidden")
                            .name("applet_action")
                            .value("manage_file_templates")
                    });
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

    async fn submit_new_file_template_form(
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
            if let Some(form) = s.post.form() {
                if let Some(name) = form.get_first("template_name") {
                    if let Some(definition) = form.get_first("definition") {
                        if let Some(template) = crate::utility::decode_toml_string(definition) {
                            let template: FileTemplate = template;
                            if self
                                .insert_new_file_template(ca, appletid, name.to_string(), template)
                                .await
                                .is_ok()
                            {
                                html.body(|b| {
                                    b.text("File template created");
                                    b.line_break(|a| a);
                                    backlinks(b, appletid, sget, s);
                                    b
                                });
                            } else {
                                html.body(|b| {
                                    b.text("Failed to create file template");
                                    b.line_break(|a| a);
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

    async fn show_file_templates_list(
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
            let key_table = ca.get_applet_specific_table_name(appletid, "file_templates");
            let list = self
                .retrieve_all_file_templates(&ca.medium, &key_table)
                .await;
            html.body(|b| {
                if let Some(list) = list {
                    for app in list {
                        if let Ok(ft) = toml::from_str(&app.definition) {
                            let ft: FileTemplate = ft;
                            b.thematic_break(|a| a);
                            b.anchor(|ab| {
                                ab.text(format!("{} template", app.name.clone()));
                                match s.delivery {
                                    crate::main_config::PageDelivery::Cgi => {
                                        sget.insert("applet_data".to_string(), format!("{}", app.id));
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
                                            "applet.rs?id={}&action=manage_file_templates&step=3&applet_data={}",
                                            appletid, app.id
                                        ));
                                    }
                                };
                                ab
                            });
                            b.line_break(|a| a);
                        }
                    }
                    b.thematic_break(|a| a);
                    b.anchor(|ab| {
                        ab.text(format!("Create new file template"));
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
                                    "applet.rs?id={}&action=manage_file_templates&step=2",
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

    async fn manage_file_templates<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
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
        match step {
            1 => {
                self.view_specific_file_template(admin, sget, html, appletid, userid, ca, s, fbm)
                    .await;
            }
            2 => {
                self.create_file_template_form(admin, sget, html, appletid, userid, ca, s, fbm)
                    .await;
            }
            3 => {
                self.submit_new_file_template_form(admin, sget, html, appletid, userid, ca, s)
                    .await;
            }
            4 => {
                if admin {
                    if let Some(form) = s.post.form() {
                        if let Some(templateid_str) = form.get_first("template_id") {
                            if let Ok(templateid) = templateid_str.parse::<i64>() {
                                let tablename =
                                    ca.get_applet_specific_table_name(appletid, "file_templates");
                                if let Some(template) = self
                                    .retrieve_specific_file_template(
                                        &ca.medium, &tablename, templateid,
                                    )
                                    .await
                                {
                                    if let Ok(ftemplate) = toml::from_str(&template.definition) {
                                        let mut ftemplate: FileTemplate = ftemplate;
                                        ftemplate.apply_form_data(form);
                                        if self
                                            .update_file_template(
                                                ca,
                                                appletid,
                                                template.name.clone(),
                                                ftemplate,
                                                templateid,
                                            )
                                            .await
                                            .is_ok()
                                        {
                                            html.body(|b| {
                                                b.text("File template updated");
                                                b.line_break(|a| a);
                                                backlinks(b, appletid, sget, s);
                                                b
                                            });
                                        } else {
                                            html.body(|b| {
                                                b.text("Failed to update file template");
                                                b.line_break(|a| a);
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
            }
            _ => {
                self.show_file_templates_list(admin, sget, html, appletid, userid, ca, s)
                    .await;
            }
        }
    }

    /// Retrieve a specific file template
    async fn retrieve_specific_application_instance(
        &self,
        medium: &crate::ca::CaCertificateStorage,
        app_table: &str,
        id: i64,
    ) -> Option<ApplicationBuilder> {
        let app_table2 = app_table.to_string();
        use crate::ca::CaCertificateStorage;
        match medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => Some(
                p.conn(move |conn| {
                    let mut stmt =
                        conn.prepare(&format!("SELECT * FROM {app_table2} WHERE id=?1 LIMIT 1"))?;
                    let data = stmt.query_row([id], |row| {
                        let dbentry = DbEntry::new(row);
                        let t: ApplicationBuilder = dbentry.try_into()?;
                        Ok(t)
                    })?;
                    Ok(data)
                })
                .await
                .ok()?,
            ),
        }
    }

    /// Retrieve all file templates
    async fn retrieve_all_application_instances(
        &self,
        medium: &crate::ca::CaCertificateStorage,
        app_table: &str,
    ) -> Option<Vec<ApplicationBuilder>> {
        let app_table2 = app_table.to_string();
        use crate::ca::CaCertificateStorage;
        match medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => Some(
                p.conn(move |conn| {
                    let mut stmt = conn.prepare(&format!("SELECT * FROM {app_table2}"))?;
                    let rows = stmt.query_map([], |row| {
                        let dbentry = DbEntry::new(row);
                        let t: ApplicationBuilder = dbentry.try_into()?;
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

    async fn view_specific_application_instance<
        F: FnOnce(&mut html::forms::builders::FormBuilder),
    >(
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
        if admin {
            if let Some(template_id) = s.get.get("applet_data") {
                if let Ok(template_id) = template_id.parse::<i64>() {
                    let tablename =
                        ca.get_applet_specific_table_name(appletid, "application_builder");
                    if let Some(template) = self
                        .retrieve_specific_application_instance(&ca.medium, &tablename, template_id)
                        .await
                    {
                        let apptablename =
                            ca.get_applet_specific_table_name(appletid, "card_applications");
                        if let Some(card_app) = self
                            .retrieve_single_application_by_aid(
                                &ca.medium,
                                &apptablename,
                                template.card_app_aid.clone(),
                            )
                            .await
                        {
                            let mut files = Vec::new();
                            if let Some(f) = template
                                .get_file_builders(appletid, template_id, ca, self)
                                .await
                            {
                                let mut v: Vec<_> = f.into_iter().collect();
                                v.sort_by(|x, y| x.0.cmp(&y.0));
                                files = v;
                            }
                            let mut expected = 0;
                            for num in &files {
                                if num.0 == expected {
                                    expected += 1;
                                } else if num.0 > expected {
                                    break;
                                }
                            }
                            let next_id = expected;
                            html.body(|b| {
                                b.text(format!("NAME: {}", template.name));
                                b.line_break(|a| a);
                                b.text(format!("Application {}", card_app.name));
                                b.line_break(|a| a);
                                for f in files {
                                    b.thematic_break(|a|a );
                                    b.text(format!("File {}: {}", f.0, f.1.description()));
                                }
                                b.thematic_break(|a|a );
                                b.anchor(|ab| {
                                    ab.text(format!("Add a file"));
                                    match s.delivery {
                                        crate::main_config::PageDelivery::Cgi => {
                                            sget.insert("step".to_string(), 4.to_string());
                                            sget.insert("new_file_number".to_string(), next_id.to_string());
                                            let a = sget
                                                .iter()
                                                .map(|a| format!("{}={}", a.0, a.1))
                                                .collect::<Vec<String>>()
                                                .join("&");
                                            ab.href(format!("?{a}"));
                                        }
                                        crate::main_config::PageDelivery::DedicatedServer => {
                                            ab.href(format!(
                                                "applet.rs?id={}&action=manage_file_templates&step=4",
                                                appletid
                                            ));
                                        }
                                    };
                                    ab
                                });
                                b.line_break(|a| a);
                                backlinks(b, appletid, sget, s);
                                b
                            });
                        }
                    }
                }
            }
        }
    }

    async fn create_application_instance_form<
        F: FnOnce(&mut html::forms::builders::FormBuilder),
    >(
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
        if admin {
            let app_table = ca.get_applet_specific_table_name(appletid, "card_applications");
            let file_number = s
                .get
                .get("new_file_number")
                .map(|a| a.to_owned())
                .unwrap_or(0.to_string());
            let mut applications = Vec::new();
            if let Some(a) = self
                .retrieve_all_card_applications(&ca.medium, &app_table)
                .await
            {
                applications = a;
            }
            html.body(|b| {
                b.form(|fb| {
                    fb.text("Name of application instance");
                    fb.line_break(|a| a);
                    fb.input(|i| i.name("instance_name"));
                    fb.line_break(|a| a);
                    fb.select(|sb| {
                        sb.name("application");
                        for f in &applications {
                            sb.option(|ob| {
                                ob.value(crate::utility::encode_hex(&f.aid))
                                    .text(f.name.clone())
                            });
                        }
                        sb
                    });
                    fb.line_break(|a| a);
                    fb.input(|i| i.type_("hidden").name("new_file_number").value(file_number));
                    fb.line_break(|a| a);
                    fb.input(|i| {
                        i.type_("hidden")
                            .name("applet_action")
                            .value("manage_application_instances")
                    });
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

    async fn insert_new_application_instance(
        &self,
        ca: &mut Ca,
        appletid: i64,
        name: String,
        aid: Vec<u8>,
    ) -> Result<(), ()> {
        let table = ca.get_applet_specific_table_name(appletid, "application_builder");
        use crate::ca::CaCertificateStorage;
        use async_sqlite::rusqlite::ToSql;
        match &ca.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::Sqlite(p) => {
                p.conn(move |conn| {
                    let mut stmt = conn.prepare(&format!(
                        "INSERT INTO {table} (name, card_application_aid) VALUES (?1, ?2)"
                    ))?;
                    stmt.execute([name.to_sql().unwrap(), aid.to_sql().unwrap()])?;
                    Ok(())
                })
                .await
                .map_err(|_| ())?;
                Ok(())
            }
        }
    }

    async fn submit_new_application_instance_form(
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
            if let Some(form) = s.post.form() {
                if let Some(name) = form.get_first("instance_name") {
                    if let Some(application) = form.get_first("application") {
                        if let Ok(aid) = crate::utility::decode_hex(application) {
                            if self
                                .insert_new_application_instance(
                                    ca,
                                    appletid,
                                    name.to_string(),
                                    aid,
                                )
                                .await
                                .is_ok()
                            {
                                html.body(|b| {
                                    b.text("Application instance created");
                                    b.line_break(|a| a);
                                    backlinks(b, appletid, sget, s);
                                    b
                                });
                            } else {
                                html.body(|b| {
                                    b.text("Failed to create application instance");
                                    b.line_break(|a| a);
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

    async fn show_application_instance_list(
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
            let key_table = ca.get_applet_specific_table_name(appletid, "application_builder");
            let list = self
                .retrieve_all_application_instances(&ca.medium, &key_table)
                .await;
            let mut full_app_instance_list = Vec::new();
            if let Some(list) = list {
                let app_table = ca.get_applet_specific_table_name(appletid, "card_applications");
                for app in list {
                    if let Some(application) = self
                        .retrieve_single_application_by_aid(
                            &ca.medium,
                            &app_table,
                            app.card_app_aid.clone(),
                        )
                        .await
                    {
                        if let Some(fb) = app.get_file_builders(appletid, app.id, ca, self).await {
                            let a = ApplicationReference {
                                id: app.id,
                                name: app.name.clone(),
                                app: application,
                                files: fb,
                            };
                            full_app_instance_list.push(a);
                        }
                    }
                }
            }
            html.body(|b| {
                for item in full_app_instance_list {
                    b.thematic_break(|a| a);
                    b.text(format!("Instance {}", item.name));
                    b.line_break(|a|a);
                    b.text(format!("Uses application {}", item.app.name));
                    b.line_break(|a|a);
                    for f in &item.files {
                        b.text(format!("File {}", f.0));
                        b.line_break(|a|a);
                    }
                    b.anchor(|ab| {
                        ab.text("Modify");
                        for f in &item.files {
                            ab.text(format!("File {}", f.0));
                            ab.line_break(|a|a);
                        }
                        match s.delivery {
                            crate::main_config::PageDelivery::Cgi => {
                                sget.insert("applet_data".to_string(), format!("{}", item.id));
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
                                    "applet.rs?id={}&action=manage_application_instances&step=1&applet_data={}",
                                    appletid, item.id
                                ));
                            }
                        };
                        ab
                    });
                    b.line_break(|a| a);
                }
                b.thematic_break(|a| a);
                b.anchor(|ab| {
                    ab.text(format!("Create new application instance"));
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
                            ab.href(format!("applet.rs?id={}&action=manage_application_instances&step=2", appletid));
                        }
                    };
                    ab
                });
                b.line_break(|a|a);
                backlinks(b, appletid, sget, s);
                b
            });
        }
    }

    async fn application_instance_new_file_form<
        F: FnOnce(&mut html::forms::builders::FormBuilder),
    >(
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
        if admin {
            let table = ca.get_applet_specific_table_name(appletid, "file_templates");
            let mut files = Vec::new();
            let tfiles = self.retrieve_all_file_templates(&ca.medium, &table).await;
            if let Some(f) = tfiles {
                files = f;
            }
            html.body(|b| {
                b.form(|fb| {
                    fb.select(|sb| {
                        sb.name("file");
                        for f in &files {
                            sb.option(|ob| ob.value(f.name.clone()).text(f.name.clone()));
                        }
                        sb
                    });
                    fb.line_break(|a| a);
                    fb.input(|i| {
                        i.type_("hidden")
                            .name("applet_action")
                            .value("manage_application_instances")
                    });
                    fb.line_break(|a| a);
                    fb.input(|i| i.type_("hidden").name("step").value("5"));
                    fb.line_break(|a| a);
                    fb.button(|b| b.text("Save"));
                    fbm(fb);
                    fb
                })
            });
        }
    }

    async fn application_instance_insert_new_file<
        F: FnOnce(&mut html::forms::builders::FormBuilder),
    >(
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
        if admin {
            if let Some(form) = s.post.form() {
                if let Some(file) = form.get_first("file") {}
            }
        }
    }

    async fn manage_application_instances<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
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
        match step {
            1 => {
                self.view_specific_application_instance(
                    admin, sget, html, appletid, userid, ca, s, fbm,
                )
                .await;
            }
            2 => {
                self.create_application_instance_form(
                    admin, sget, html, appletid, userid, ca, s, fbm,
                )
                .await;
            }
            3 => {
                self.submit_new_application_instance_form(
                    admin, sget, html, appletid, userid, ca, s,
                )
                .await;
            }
            4 => {
                self.application_instance_new_file_form(
                    admin, sget, html, appletid, userid, ca, s, fbm,
                )
                .await;
            }
            5 => {
                self.application_instance_insert_new_file(
                    admin, sget, html, appletid, userid, ca, s, fbm,
                )
                .await;
            }
            _ => {
                self.show_application_instance_list(admin, sget, html, appletid, userid, ca, s)
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
                name: "application_builder".to_string(),
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
                        "card_application_aid".to_string(),
                        AppletTableField {
                            ty: FieldType::Blob,
                            primary_key: false,
                            default: None,
                        },
                    ),
                ],
            },
            AppletTable {
                name: "application_builder_files".to_string(),
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
                        "application_instance_id".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "file_number".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                    (
                        "file_template".to_string(),
                        AppletTableField {
                            ty: FieldType::Integer,
                            primary_key: false,
                            default: None,
                        },
                    ),
                ],
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
            Some("manage_file_templates") => {
                self.manage_file_templates(admin, sget, html, appletid, userid, ca, s, fbm)
                    .await;
            }
            Some("manage_application_instances") => {
                self.manage_application_instances(admin, sget, html, appletid, userid, ca, s, fbm)
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
                        b.anchor(|ab| {
                            ab.text("Modify file templates");
                            match s.delivery {
                                crate::main_config::PageDelivery::Cgi => {
                                    sget.insert(
                                        "applet_action".to_string(),
                                        "manage_file_templates".to_string(),
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
                                        "applet.rs?id={}&applet_action=manage_file_templates",
                                        appletid
                                    ));
                                }
                            };
                            ab
                        });
                        b.line_break(|a| a);
                        b.anchor(|ab| {
                            ab.text("Modify application instances");
                            match s.delivery {
                                crate::main_config::PageDelivery::Cgi => {
                                    sget.insert(
                                        "applet_action".to_string(),
                                        "manage_application_instances".to_string(),
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
                                        "applet.rs?id={}&applet_action=manage_application_instances",
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
