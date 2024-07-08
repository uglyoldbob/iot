//! Common code for a certificate authority, used from both using the certificate authority and constructing a certificate authority.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use async_sqlite::rusqlite::ToSql;
use cert_common::oid::*;
use cert_common::pkcs12::ProtectedPkcs12;
use cert_common::CertificateSigningMethod;
use cert_common::HttpsSigningMethod;
use cert_common::SshSigningMethod;
use der::asn1::UtcTime;
use rcgen::RemoteKeyPair;
use x509_cert::ext::pkix::AccessDescription;
use zeroize::Zeroizing;

use crate::hsm2::KeyPairTrait;
use crate::MainConfiguration;
use cert_common::pkcs12::BagAttribute;

/// Hash and convert to der format
pub fn rsa_sha256(hash: &[u8]) -> Vec<u8> {
    let mut hash = hash.to_vec();
    // convert to der format, indicating sha-256 hash present
    let mut der_hash = vec![
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    der_hash.append(&mut hash);
    der_hash
}

/// apply pkcs1.5 padding to pkcs1 hash, suitable for signing
pub fn pkcs15_sha256(total_size: usize, hash: &[u8]) -> Vec<u8> {
    // convert to der format, indicating sha-256 hash present
    let mut der_hash = rsa_sha256(hash);

    let plen = total_size - der_hash.len() - 3;
    let mut p = vec![0xff; plen];

    let mut total = Vec::new();
    total.append(&mut vec![0, 1]);
    total.append(&mut p);
    total.push(0);
    total.append(&mut der_hash);
    total
}

/// Get the list of sqlite files from the base filename for a sqlite database
pub fn get_sqlite_paths(p: &std::path::PathBuf) -> Vec<std::path::PathBuf> {
    let name = p.file_name().unwrap().to_owned();
    let mut p2 = p.clone();
    p2.pop();
    vec![
        p.to_owned(),
        p2.join(format!("{}-shm", name.to_str().unwrap())),
        p2.join(format!("{}-wal", name.to_str().unwrap())),
    ]
}

/// A type that allows the user to enter a smart card pin, twice for verification
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct SmartCardPin2(String, String);

impl userprompt::EguiPrompting for SmartCardPin2 {
    fn build_gui(&mut self, ui: &mut egui::Ui, name: Option<&str>) -> Result<(), String> {
        if let Some(n) = name {
            ui.label(n);
        }
        let p: &mut String = &mut self.0;
        let pe = egui::TextEdit::singleline(p).password(true);
        ui.add(pe);
        let p: &mut String = &mut self.1;
        let pe = egui::TextEdit::singleline(p).password(true);
        ui.add(pe);
        if !self.0.is_empty() && self.0 == self.1 {
            let pinlen = self.0.chars().count();
            if pinlen < 6 {
                return Err(format!("{} pin is too short", name.unwrap_or("")));
            }
            if pinlen > 8 {
                return Err(format!("{} pin is too long", name.unwrap_or("")));
            }
            for c in self.0.chars() {
                if !c.is_numeric() {
                    return Err(format!("{} pin is invalid", name.unwrap_or("")));
                }
            }
            Ok(())
        } else {
            Err(format!("{} password does not match", name.unwrap_or("")))
        }
    }
}

impl userprompt::Prompting for SmartCardPin2 {
    fn prompt(name: Option<&str>) -> Result<Self, userprompt::Error> {
        use std::io::Write;
        let mut buffer;
        'prompt: loop {
            if let Some(n) = name {
                print!("{}:Enter pin (6-8 nummbers):", n);
            } else {
                print!("Enter pin (6-8 nummbers):");
            }
            std::io::stdout().flush().unwrap();
            buffer = rpassword::read_password().unwrap();
            for c in buffer.chars() {
                if !c.is_numeric() {
                    println!("Not a valid pin");
                    continue 'prompt;
                }
            }
            let pinlen = buffer.chars().count();
            if pinlen < 6 {
                println!("Pin is too short");
                continue 'prompt;
            }
            if pinlen > 8 {
                println!("Pin is too long");
                continue 'prompt;
            }
            if let Some(n) = name {
                print!("{}: Enter pin again:", n);
            } else {
                print!("Enter pin again: ");
            }
            std::io::stdout().flush().unwrap();
            let buf2 = rpassword::read_password().unwrap();
            if buffer == buf2 {
                break;
            }
            println!("Pins do not match, try again");
        }
        Ok(Self(buffer.clone(), buffer))
    }
}

impl From<SmartCardPin2> for String {
    fn from(value: SmartCardPin2) -> Self {
        value.0
    }
}

impl SmartCardPin2 {
    /// Get a string
    pub fn to_string(&self) -> String {
        self.0.to_owned()
    }
}

/// The kinds of tokens that can exist for certificates generated
#[derive(
    Clone,
    Debug,
    userprompt::Prompting,
    userprompt::EguiPrompting,
    serde::Deserialize,
    serde::Serialize,
)]
pub enum CertificateTypeAnswers {
    /// A certificate represented by a regular protected p12 document, secured by a passwor
    Soft(userprompt::Password2),
    /// A certificate stored in a smart card, protected by a pin
    SmartCard(SmartCardPin2),
}

impl Default for CertificateTypeAnswers {
    fn default() -> Self {
        Self::Soft(userprompt::Password2::default())
    }
}

/// The kinds of tokens that can exist for certificates generated
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum CertificateType {
    /// A certificate represented by a regular protected p12 document, secured by a password
    Soft(String),
    /// A certificate stored in a smart card, protected by a pin
    SmartCard(String),
}

impl From<CertificateTypeAnswers> for CertificateType {
    fn from(value: CertificateTypeAnswers) -> Self {
        match value {
            CertificateTypeAnswers::Soft(a) => Self::Soft(a.to_string()),
            CertificateTypeAnswers::SmartCard(a) => Self::SmartCard(a.0),
        }
    }
}

/// The items used to configure a standalone certificate authority, typically used as part of a large pki installation.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct StandaloneCaConfiguration {
    /// The signing method for the certificate authority
    pub sign_method: CertificateSigningMethod,
    /// Where to store the certificate authority
    pub path: CaCertificateStorageBuilder,
    /// Does this authority have a superior authority?
    pub inferior_to: Option<String>,
    /// The common name of the certificate authority
    pub common_name: String,
    /// The number of days the certificate authority should be good for.
    pub days: u32,
    /// The maximum chain length for a chain of certificate authorities.
    pub chain_length: u8,
    /// The password required in order to download the admin certificate over the web
    pub admin_access_password: String,
    /// The certificate type for the admin cert
    pub admin_cert: CertificateType,
    /// Is a signature required for ocsp requests?
    pub ocsp_signature: bool,
    /// The name of the ca instance
    pub name: String,
}

impl From<Box<StandaloneCaConfigurationAnswers>> for Box<StandaloneCaConfiguration> {
    fn from(value: Box<StandaloneCaConfigurationAnswers>) -> Self {
        let a: &StandaloneCaConfigurationAnswers = &value;
        Box::new(a.to_owned().into())
    }
}

impl From<StandaloneCaConfigurationAnswers> for StandaloneCaConfiguration {
    fn from(value: StandaloneCaConfigurationAnswers) -> Self {
        Self {
            sign_method: value.sign_method,
            path: value.path,
            inferior_to: value.inferior_to,
            common_name: value.common_name,
            days: value.days,
            chain_length: value.chain_length,
            admin_access_password: value.admin_access_password.to_string(),
            admin_cert: value.admin_cert.into(),
            ocsp_signature: value.ocsp_signature,
            name: value.name.clone(),
        }
    }
}

impl StandaloneCaConfiguration {
    ///Get a CaConfiguration from a LocalCaConfiguration
    /// #Arguments
    /// * name - The name of the ca for pki purposes
    /// * settings - The application settings
    pub fn get_ca(&self, settings: &MainConfiguration) -> CaConfiguration {
        let mut full_name = self.name.clone();
        if !full_name.ends_with('/') && !full_name.is_empty() {
            full_name.push('/');
        }
        let san: Vec<String> = settings
            .public_names
            .iter()
            .map(|n| n.domain.clone())
            .collect();
        let http_port = settings
            .proxy_config
            .as_ref()
            .and_then(|a| a.http_port)
            .or_else(|| settings.get_http_port());
        let https_port = settings
            .proxy_config
            .as_ref()
            .and_then(|a| a.https_port)
            .or_else(|| settings.get_https_port());
        let proxy = if !settings.public_names.is_empty() {
            Some(settings.public_names[0].subdomain.to_owned())
        } else {
            None
        };
        CaConfiguration {
            sign_method: self.sign_method,
            path: self.path.clone(),
            inferior_to: self.inferior_to.clone(),
            san,
            common_name: self.common_name.clone(),
            days: self.days,
            chain_length: self.chain_length,
            admin_access_password: self.admin_access_password.clone(),
            admin_cert: self.admin_cert.clone(),
            ocsp_signature: self.ocsp_signature,
            http_port,
            https_port,
            proxy,
            pki_name: Some(format!("pki/{}", full_name)),
        }
    }
}

/// The items used to configure a standalone certificate authority, typically used as part of a large pki installation.
#[derive(
    Clone,
    Debug,
    userprompt::Prompting,
    userprompt::EguiPrompting,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct StandaloneCaConfigurationAnswers {
    /// The signing method for the certificate authority
    pub sign_method: CertificateSigningMethod,
    /// Where to store the certificate authority
    pub path: CaCertificateStorageBuilder,
    /// Does this authority have a superior authority?
    pub inferior_to: Option<String>,
    /// The common name of the certificate authority
    pub common_name: String,
    /// The number of days the certificate authority should be good for.
    pub days: u32,
    /// The maximum chain length for a chain of certificate authorities.
    pub chain_length: u8,
    /// The password required in order to download the admin certificate over the web
    pub admin_access_password: userprompt::Password2,
    /// The certificate type for the admin cert
    pub admin_cert: CertificateTypeAnswers,
    /// Is a signature required for ocsp requests?
    pub ocsp_signature: bool,
    /// The name of the ca instance
    pub name: String,
}

impl Default for StandaloneCaConfigurationAnswers {
    fn default() -> Self {
        Self::new()
    }
}

impl StandaloneCaConfigurationAnswers {
    /// Construct a blank Self.
    pub fn new() -> Self {
        Self {
            sign_method: CertificateSigningMethod::Https(HttpsSigningMethod::RsaSha256),
            path: CaCertificateStorageBuilder::Nowhere,
            inferior_to: None,
            common_name: "".to_string(),
            days: 1,
            chain_length: 0,
            admin_access_password: userprompt::Password2::new("".to_string()),
            admin_cert: Default::default(),
            ocsp_signature: false,
            name: String::new(),
        }
    }

    ///Get a Caconfiguration for editing
    pub fn get_editable_ca(&self) -> CaConfigurationAnswers {
        CaConfigurationAnswers {
            sign_method: self.sign_method,
            path: self.path.clone(),
            inferior_to: self.inferior_to.clone(),
            san: Vec::new(),
            common_name: self.common_name.clone(),
            days: self.days,
            chain_length: self.chain_length,
            admin_access_password: self.admin_access_password.clone(),
            admin_cert: self.admin_cert.clone(),
            ocsp_signature: self.ocsp_signature,
            http_port: None,
            https_port: None,
            proxy: None,
            pki_name: None,
        }
    }

    ///Get a CaConfiguration from a LocalCaConfiguration
    /// #Arguments
    /// * name - The name of the ca for pki purposes
    /// * settings - The application settings
    pub fn get_ca(&self, settings: &MainConfiguration) -> CaConfigurationAnswers {
        let mut full_name = self.name.clone();
        if !full_name.ends_with('/') && !full_name.is_empty() {
            full_name.push('/');
        }
        let san: Vec<String> = settings
            .public_names
            .iter()
            .map(|n| n.domain.clone())
            .collect();
        let http_port = settings
            .proxy_config
            .as_ref()
            .and_then(|a| a.http_port)
            .or_else(|| settings.get_http_port());
        let https_port = settings
            .proxy_config
            .as_ref()
            .and_then(|a| a.https_port)
            .or_else(|| settings.get_https_port());
        CaConfigurationAnswers {
            sign_method: self.sign_method,
            path: self.path.clone(),
            inferior_to: self.inferior_to.clone(),
            san,
            common_name: self.common_name.clone(),
            days: self.days,
            chain_length: self.chain_length,
            admin_access_password: self.admin_access_password.clone(),
            admin_cert: self.admin_cert.clone(),
            ocsp_signature: self.ocsp_signature,
            http_port,
            https_port,
            proxy: Some(settings.public_names[0].subdomain.to_owned()),
            pki_name: Some(format!("pki/{}", full_name)),
        }
    }
}

/// The items used to configure a local certificate authority in a pki configuration
#[derive(
    Clone,
    Debug,
    userprompt::Prompting,
    userprompt::EguiPrompting,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct LocalCaConfigurationAnswers {
    /// The signing method for the certificate authority
    pub sign_method: CertificateSigningMethod,
    /// Where to store the certificate authority
    pub path: CaCertificateStorageBuilder,
    /// Does this authority have a superior authority?
    pub inferior_to: Option<String>,
    /// The common name of the certificate authority
    pub common_name: String,
    /// The number of days the certificate authority should be good for.
    pub days: u32,
    /// The maximum chain length for a chain of certificate authorities.
    pub chain_length: u8,
    /// The password required in order to download the admin certificate over the web
    pub admin_access_password: userprompt::Password2,
    /// The certificate type for the admin cert
    pub admin_cert: CertificateTypeAnswers,
    /// Is a signature required for ocsp requests?
    pub ocsp_signature: bool,
}

impl Default for LocalCaConfigurationAnswers {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalCaConfigurationAnswers {
    /// Construct a blank Self.
    pub fn new() -> Self {
        Self {
            sign_method: CertificateSigningMethod::Https(HttpsSigningMethod::RsaSha256),
            path: CaCertificateStorageBuilder::Nowhere,
            inferior_to: None,
            common_name: "".to_string(),
            days: 1,
            chain_length: 0,
            admin_access_password: userprompt::Password2::new("".to_string()),
            admin_cert: Default::default(),
            ocsp_signature: false,
        }
    }

    ///Get a Caconfiguration for editing
    pub fn get_editable_ca(&self) -> CaConfigurationAnswers {
        CaConfigurationAnswers {
            sign_method: self.sign_method,
            path: self.path.clone(),
            inferior_to: self.inferior_to.clone(),
            san: Vec::new(),
            common_name: self.common_name.clone(),
            days: self.days,
            chain_length: self.chain_length,
            admin_access_password: self.admin_access_password.clone(),
            admin_cert: self.admin_cert.clone(),
            ocsp_signature: self.ocsp_signature,
            http_port: None,
            https_port: None,
            proxy: None,
            pki_name: None,
        }
    }
}

/// The items used to configure a local certificate authority in a pki configuration
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalCaConfiguration {
    /// The signing method for the certificate authority
    pub sign_method: CertificateSigningMethod,
    /// Where to store the certificate authority
    pub path: CaCertificateStorageBuilder,
    /// Does this authority have a superior authority?
    pub inferior_to: Option<String>,
    /// The common name of the certificate authority
    pub common_name: String,
    /// The number of days the certificate authority should be good for.
    pub days: u32,
    /// The maximum chain length for a chain of certificate authorities.
    pub chain_length: u8,
    /// The password required in order to download the admin certificate over the web
    pub admin_access_password: String,
    /// The certificate type for the admin cert
    pub admin_cert: CertificateType,
    /// The password to protect the ocsp p12 certificate document.
    pub ocsp_password: String,
    /// The password to protect the root p12 certificate document.
    pub root_password: String,
    /// Is a signature required for ocsp requests?
    pub ocsp_signature: bool,
}

impl From<LocalCaConfigurationAnswers> for LocalCaConfiguration {
    fn from(value: LocalCaConfigurationAnswers) -> Self {
        Self {
            sign_method: value.sign_method,
            path: value.path,
            inferior_to: value.inferior_to,
            common_name: value.common_name,
            days: value.days,
            chain_length: value.chain_length,
            admin_access_password: value.admin_access_password.to_string(),
            admin_cert: value.admin_cert.into(),
            ocsp_password: crate::utility::generate_password(32),
            root_password: crate::utility::generate_password(32),
            ocsp_signature: value.ocsp_signature,
        }
    }
}

impl LocalCaConfiguration {
    ///Get a CaConfiguration from a LocalCaConfiguration
    /// #Arguments
    /// * name - The name of the ca for pki purposes
    /// * settings - The application settings
    pub fn get_ca(&self, name: &str, settings: &MainConfiguration) -> CaConfiguration {
        let mut full_name = name.to_string();
        if !full_name.ends_with('/') && !full_name.is_empty() {
            full_name.push('/');
        }
        let san: Vec<String> = settings
            .public_names
            .iter()
            .map(|n| n.domain.clone())
            .collect();
        let http_port = settings
            .proxy_config
            .as_ref()
            .and_then(|a| a.http_port)
            .or_else(|| settings.get_http_port());
        let https_port = settings
            .proxy_config
            .as_ref()
            .and_then(|a| a.https_port)
            .or_else(|| settings.get_https_port());
        CaConfiguration {
            sign_method: self.sign_method,
            path: self.path.clone(),
            inferior_to: self.inferior_to.clone(),
            san,
            common_name: self.common_name.clone(),
            days: self.days,
            chain_length: self.chain_length,
            admin_access_password: self.admin_access_password.clone(),
            admin_cert: self.admin_cert.clone(),
            ocsp_signature: self.ocsp_signature,
            http_port,
            https_port,
            proxy: Some(settings.public_names[0].subdomain.to_owned()),
            pki_name: Some(format!("pki/{}", full_name)),
        }
    }
}

/// The items used to configure a certificate authority
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CaConfiguration {
    /// The signing method for the certificate authority
    pub sign_method: CertificateSigningMethod,
    /// Where to store the certificate authority
    pub path: CaCertificateStorageBuilder,
    /// Does this authority have a superior authority?
    pub inferior_to: Option<String>,
    /// The subject alternate names for the certificate authority.
    pub san: Vec<String>,
    /// The common name of the certificate authority
    pub common_name: String,
    /// The number of days the certificate authority should be good for.
    pub days: u32,
    /// The maximum chain length for a chain of certificate authorities.
    pub chain_length: u8,
    /// The password required in order to download the admin certificate over the web
    pub admin_access_password: String,
    /// The certificate type for the admin cert
    pub admin_cert: CertificateType,
    /// Is a signature required for ocsp requests?
    pub ocsp_signature: bool,
    /// The externally accessible https port, if accessible by https
    pub https_port: Option<u16>,
    /// The externally accessible http port, if accessible by http
    pub http_port: Option<u16>,
    /// The proxy configuration for this authority
    pub proxy: Option<String>,
    /// The pki name for the authority, used when operating a pki
    pub pki_name: Option<String>,
}

impl CaConfiguration {
    /// Get the pki name for the configuration
    pub fn get_pki_name(&self) -> &str {
        if let Some(p) = &self.pki_name {
            p
        } else {
            ""
        }
    }

    /// Destroy the backend storage
    pub async fn destroy_backend(&self) {
        match &self.path {
            CaCertificateStorageBuilder::Nowhere => {}
            CaCertificateStorageBuilder::Sqlite(p) => {
                for p in get_sqlite_paths(p) {
                    let _e = std::fs::remove_file(p);
                }
            }
        }
    }
}

/// The items used to configure a certificate authority
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CaConfigurationAnswers {
    /// The signing method for the certificate authority
    pub sign_method: CertificateSigningMethod,
    /// Where to store the certificate authority
    pub path: CaCertificateStorageBuilder,
    /// Does this authority have a superior authority?
    pub inferior_to: Option<String>,
    /// The subject alternate names for the certificate authority.
    pub san: Vec<String>,
    /// The common name of the certificate authority
    pub common_name: String,
    /// The number of days the certificate authority should be good for.
    pub days: u32,
    /// The maximum chain length for a chain of certificate authorities.
    pub chain_length: u8,
    /// The password required in order to download the admin certificate over the web
    pub admin_access_password: userprompt::Password2,
    /// The certificate type for the admin cert
    pub admin_cert: CertificateTypeAnswers,
    /// Is a signature required for ocsp requests?
    pub ocsp_signature: bool,
    /// The externally accessible https port, if accessible by https
    pub https_port: Option<u16>,
    /// The externally accessible http port, if accessible by http
    pub http_port: Option<u16>,
    /// The proxy configuration for this authority
    pub proxy: Option<String>,
    /// The pki name for the authority, used when operating a pki
    pub pki_name: Option<String>,
}

impl Default for CaConfigurationAnswers {
    fn default() -> Self {
        Self::new()
    }
}

impl CaConfigurationAnswers {
    /// Get a local ca configuration
    pub fn get_local(&self) -> LocalCaConfigurationAnswers {
        LocalCaConfigurationAnswers {
            sign_method: self.sign_method,
            path: self.path.clone(),
            inferior_to: self.inferior_to.clone(),
            common_name: self.common_name.clone(),
            days: self.days,
            chain_length: self.chain_length,
            admin_access_password: self.admin_access_password.clone(),
            admin_cert: self.admin_cert.clone(),
            ocsp_signature: self.ocsp_signature,
        }
    }

    /// Get the pki name for the configuration
    pub fn get_pki_name(&self) -> &str {
        if let Some(p) = &self.pki_name {
            p
        } else {
            ""
        }
    }

    /// Construct a blank Self.
    pub fn new() -> Self {
        Self {
            sign_method: CertificateSigningMethod::Https(HttpsSigningMethod::RsaSha256),
            path: CaCertificateStorageBuilder::Nowhere,
            inferior_to: None,
            san: Vec::new(),
            common_name: "".to_string(),
            days: 1,
            chain_length: 0,
            admin_access_password: userprompt::Password2::new("".to_string()),
            admin_cert: Default::default(),
            ocsp_signature: false,
            http_port: None,
            https_port: None,
            proxy: None,
            pki_name: None,
        }
    }
}

/// The Authority Info Access for specifying certification validators.
pub struct PkixAuthorityInfoAccess {
    /// The der representation
    pub der: Vec<u8>,
}

impl PkixAuthorityInfoAccess {
    /// Create a new Self with the given list of urls, all assumed to be ocsp access urls.
    pub fn new(urls: Vec<String>) -> Self {
        let asn = yasna::construct_der(|w| {
            w.write_sequence_of(|w| {
                for url in urls {
                    w.next().write_sequence(|w| {
                        w.next().write_oid(&OID_OCSP.to_yasna());
                        let d = yasna::models::TaggedDerValue::from_tag_and_bytes(
                            yasna::Tag::context(6),
                            url.as_bytes().to_vec(),
                        );
                        w.next().write_tagged_der(&d);
                    });
                }
            });
        });
        Self { der: asn }
    }
}

/// Errors that can occur when attempting to load a certificate
#[derive(Clone, Debug)]
pub enum CertificateLoadingError {
    /// The certificate does not exist
    DoesNotExist,
    /// Cannot open the certificate
    CantOpen,
    /// Other io error
    OtherIo(String),
    /// The certificate loaded is invalid
    InvalidCert,
    /// There is no algorithm detected
    NoAlgorithm,
}

use egui_multiwin::egui;

/// The information needed to construct a CaCertificateStorage
#[derive(
    Clone,
    Debug,
    userprompt::Prompting,
    userprompt::EguiPrompting,
    serde::Deserialize,
    serde::Serialize,
    strum::EnumIter,
)]
pub enum CaCertificateStorageBuilder {
    /// Certificates are stored nowhere
    Nowhere,
    /// Ca uses a sqlite database on a filesystem
    Sqlite(userprompt::FileCreate),
}

impl CaCertificateStorageBuilder {
    /// Remove relative paths, path might need to exist for this to succeed
    pub async fn remove_relative_paths(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Nowhere => {}
            Self::Sqlite(p) => {
                if p.is_relative() {
                    use tokio::io::AsyncWriteExt;
                    let p2: std::path::PathBuf = p.to_path_buf();
                    let mut f = tokio::fs::File::create(p2).await?;
                    f.write_all(" ".as_bytes()).await?;
                    **p = p.canonicalize()?;
                }
            }
        }
        Ok(())
    }

    /// Returns true if the item already exists
    pub async fn exists(&self) -> bool {
        match self {
            Self::Nowhere => false,
            Self::Sqlite(p) => p.exists(),
        }
    }

    /// The gui friendly name for the type
    pub fn display(&self) -> &str {
        match self {
            Self::Nowhere => "Nowhere",
            Self::Sqlite(_) => "Sqlite Database",
        }
    }
}

/// Contains the options for setting ownership in a generic way
pub struct OwnerOptions {
    #[cfg(target_family = "unix")]
    /// The unix based user id
    uid: u32,
    #[cfg(target_family = "windows")]
    raw_sid: Vec<winapi::shared::minwindef::BYTE>,
    #[cfg(target_family = "windows")]
    tpo: windows_privilege::TokenPrivilegesEnabled,
}

#[cfg(target_family = "windows")]
mod windows_privilege;

impl OwnerOptions {
    /// Construct a new Self
    #[cfg(target_family = "unix")]
    pub fn new(uid: u32) -> Self {
        Self { uid }
    }

    #[cfg(target_family = "windows")]
    pub fn new(username: &str) -> Self {
        service::log::debug!("Trying to lookup {}", username);
        let sid = windows_acl::helper::name_to_sid(username, None).unwrap(); //TODO remove this unwrap
        service::log::debug!("Lookup returned {:02X?}", sid);

        let luid = windows_privilege::Luid::new(None, "SeRestorePrivilege").unwrap(); //TODO remove this unwrap
        let tp = windows_privilege::TokenPrivileges::enable(luid);

        let token =
            windows_privilege::Token::new_thread(winapi::um::winnt::TOKEN_ADJUST_PRIVILEGES);
        let token = if let Ok(t) = token {
            t
        } else {
            windows_privilege::Token::new_process(winapi::um::winnt::TOKEN_ADJUST_PRIVILEGES)
                .unwrap() //TODO remove this unwrap
        };
        service::log::debug!("Token is obtained");
        let tpo = windows_privilege::TokenPrivilegesEnabled::new(token, tp).unwrap(); //TODO remove this unwrap
        service::log::debug!("token privileges obtained");

        Self { raw_sid: sid, tpo }
    }

    /// Set the owner of a single file
    #[cfg(target_family = "unix")]
    pub fn set_owner(&self, p: &PathBuf, permissions: u32) -> Result<(), std::io::Error> {
        if p.exists() {
            service::log::info!("Setting ownership of {}", p.display());
            std::os::unix::fs::chown(p, Some(self.uid), None)?;
            let mut perms = std::fs::metadata(p)?.permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perms, permissions);
            std::fs::set_permissions(p, perms)?;
            Ok(())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }

    #[cfg(target_family = "windows")]
    fn get_utf16(value: &str) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    #[cfg(target_family = "windows")]
    pub fn set_owner(&self, p: &PathBuf, permissions: u32) {
        service::log::debug!("Set owner of {}", p.display());
        let (ox, ow, or) = (
            ((permissions & 1) != 0),
            ((permissions & 2) != 0),
            ((permissions & 4) != 0),
        );
        let (gx, gw, gr) = (
            ((permissions & 0x8) != 0),
            ((permissions & 0x10) != 0),
            ((permissions & 0x20) != 0),
        );
        let (ux, uw, ur) = (
            ((permissions & 0x40) != 0),
            ((permissions & 0x80) != 0),
            ((permissions & 0x100) != 0),
        );

        let mut sid = self.raw_sid.clone();
        let owner = sid.as_mut_ptr() as winapi::um::winnt::PSID;

        let asdf = unsafe {
            winapi::um::aclapi::SetNamedSecurityInfoW(
                Self::get_utf16(p.as_os_str().to_str().unwrap()).as_mut_ptr(),
                winapi::um::accctrl::SE_FILE_OBJECT,
                winapi::um::winnt::OWNER_SECURITY_INFORMATION,
                owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        service::log::debug!("Set named security info returned {}", asdf);

        let mut perms = std::fs::metadata(p).unwrap().permissions(); //TODO remove the unwrap here?
        service::log::debug!("Read only {}", !uw);
        perms.set_readonly(!uw);
        std::fs::set_permissions(p, perms).unwrap(); //TODO remove this unwrap
    }
}

/// Errors that can occur building a certificate storage
#[derive(Debug)]
pub enum StorageBuilderError {
    /// Unable to create the storage
    FailedToCreateStorage,
    /// Unable to initialize the storage
    FailedToInitStorage,
    /// The storage already exists
    AlreadyExists,
}

impl CaCertificateStorageBuilder {
    /// Build the CaCertificateStorage from self
    /// # Arguments
    pub async fn build(&self) -> Result<CaCertificateStorage, StorageBuilderError> {
        match self {
            CaCertificateStorageBuilder::Nowhere => Ok(CaCertificateStorage::Nowhere),
            CaCertificateStorageBuilder::Sqlite(p) => {
                service::log::info!("Building sqlite with {}", p.display());
                let mut count = 0;
                let mut pool;
                loop {
                    let p: &std::path::PathBuf = p;
                    let mode = async_sqlite::JournalMode::Wal;
                    pool = async_sqlite::PoolBuilder::new()
                        .path(p)
                        .journal_mode(mode)
                        .open()
                        .await;
                    if pool.is_err() {
                        count += 1;
                        if count > 10 {
                            return Err(StorageBuilderError::FailedToCreateStorage);
                        }
                    } else {
                        break;
                    }
                }
                Ok(CaCertificateStorage::Sqlite(
                    pool.map_err(|_| StorageBuilderError::FailedToCreateStorage)?,
                ))
            }
        }
    }
}

/// Specifies how to access ca certificates on a ca
#[derive(Clone)]
pub enum CaCertificateStorage {
    /// The certificates are stored nowhere. Used for testing.
    Nowhere,
    /// The ca is held in a sqlite database
    Sqlite(async_sqlite::Pool),
}

impl std::fmt::Debug for CaCertificateStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nowhere => write!(f, "Nowhere"),
            Self::Sqlite(arg0) => write!(f, "Sqlite"),
        }
    }
}

/// Represents a certificate that has not been signed yet.
pub struct CaCertificateToBeSigned {
    /// The algorithm used for the certificate
    pub algorithm: HttpsSigningMethod,
    /// Where the certificate is stored
    pub medium: CaCertificateStorage,
    /// The certificate signing request parameters
    pub csr: rcgen::CertificateSigningRequestParams,
    /// The optional key pair
    pub keypair: Option<Keypair>,
    /// The certificate name to use for storage
    pub name: String,
    /// The id of the certificate to be signed
    pub id: u64,
}

impl CaCertificateToBeSigned {
    /// Calculate a serial for a certificate from an id.
    pub fn calc_sn(id: u64) -> ([u8; 20], rcgen::SerialNumber) {
        let mut snb = [0; 20];
        for (i, b) in id.to_le_bytes().iter().enumerate() {
            snb[i] = *b;
        }
        let sn = rcgen::SerialNumber::from_slice(&snb);
        (snb, sn)
    }
}

/// The errors that can occur when importing a p12 (pkcs12) certificate.
#[derive(Debug)]
pub enum Pkcs12ImportError {
    /// The signing method is not supported
    InvalidSigningMethod,
    /// The certificate type is invalid or not supported
    InvalidCertificate,
    /// The keypair is invalid
    InvalidKeypair,
}

impl TryFrom<cert_common::pkcs12::Pkcs12> for CaCertificate {
    type Error = Pkcs12ImportError;
    fn try_from(value: cert_common::pkcs12::Pkcs12) -> Result<Self, Self::Error> {
        let cert_der = value.cert;
        let cert = {
            use der::Decode;
            x509_cert::Certificate::from_der(&cert_der)
        };
        if let Ok(x509_cert) = cert {
            let mut name = "whatever".to_string();
            for a in &value.attributes {
                if let BagAttribute::FriendlyName(n) = a {
                    n.clone_into(&mut name);
                    break;
                }
            }
            let algorithm = x509_cert.signature_algorithm;
            return Ok(Self {
                medium: CaCertificateStorage::Nowhere,
                data: CertificateData::Https(HttpsCertificate {
                    algorithm: algorithm.try_into().unwrap(),
                    cert: cert_der.to_owned(),
                    keypair: Some(Keypair::NotHsm(value.pkey)),
                    attributes: value.attributes.clone(),
                }),
                name,
                id: value.id,
            });
        }
        use ssh_encoding::Decode;
        let cert = ssh_key::Certificate::from_bytes(&cert_der);
        if let Ok(cert) = cert {
            let private = value.pkey;
            let mut pk = private.as_ref();
            let keypair = ssh_key::private::KeypairData::decode(&mut pk)
                .map_err(|_| Pkcs12ImportError::InvalidKeypair)?;
            let t = match &keypair {
                ssh_key::private::KeypairData::Ed25519(_) => SshSigningMethod::Ed25519,
                ssh_key::private::KeypairData::Rsa(_) => SshSigningMethod::Rsa,
                _ => return Err(Pkcs12ImportError::InvalidSigningMethod),
            };
            return Ok(Self {
                medium: CaCertificateStorage::Nowhere,
                data: CertificateData::Ssh(SshCertificate {
                    algorithm: t,
                    keypair: Some(keypair),
                    cert,
                }),
                name: "whatever".to_string(),
                id: value.id,
            });
        }
        Err(Pkcs12ImportError::InvalidCertificate)
    }
}

/// Errors that can occur when saving a certificate
pub enum CertificateSaveError {
    /// Unable to save for some reason
    FailedToSave,
    /// The certificate being saved is invalid
    FailedToParseCertificate,
}

impl CaCertificateStorage {
    /// Initialize the storage medium
    pub async fn init(&mut self, settings: &crate::ca::CaConfiguration) -> Result<(), ()> {
        let sign_method = settings.sign_method;
        let admin_cert = settings.admin_cert.clone();
        match self {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::Sqlite(p) => {
                p.conn(move |conn| {
                    conn.execute("CREATE TABLE id ( id INTEGER PRIMARY KEY )", [])?;
                    conn.execute("CREATE TABLE serials ( id INTEGER PRIMARY KEY, serial BLOB)", [])?;
                    conn.execute("CREATE TABLE hsm_labels ( id INTEGER PRIMARY KEY, label TEXT)", [])?;
                    if let CertificateType::Soft(_) = admin_cert {
                        conn.execute("CREATE TABLE p12 ( id INTEGER PRIMARY KEY, p12 BLOB)", [])?;
                    }
                    match sign_method {
                        CertificateSigningMethod::Https(_) => {
                            conn.execute(
                                "CREATE TABLE csr ( id INTEGER PRIMARY KEY, requestor TEXT, email TEXT, phone TEXT, pem TEXT, rejection TEXT, done INTEGER DEFAULT 0 )",
                                [],
                            )?;
                        }
                        CertificateSigningMethod::Ssh(_) => {
                            conn.execute(
                                "CREATE TABLE sshr ( id INTEGER PRIMARY KEY, requestor TEXT, email TEXT, phone TEXT, pubkey TEXT, principals TEXT, comment TEXT, usage INTEGER, rejection TEXT, done INTEGER DEFAULT 0 )",
                                [],
                            )?;
                        }
                    }
                    conn.execute(
                        "CREATE TABLE certs ( id INTEGER PRIMARY KEY, der BLOB )",
                        [],
                    )
                })
                .await.map_err(|_|())?;
            }
        }
        Ok(())
    }

    /// Save this certificate to the storage medium
    /// TODO Return a Result with an error
    pub async fn save_to_medium(
        &self,
        ca: &mut Ca,
        cert: CaCertificate,
        password: &str,
    ) -> Result<(), CertificateSaveError> {
        let cert_der = &cert
            .contents()
            .map_err(|_| CertificateSaveError::FailedToParseCertificate)?;
        if let Some(card) = cert.smartcard() {
            let _ = card.save_cert_to_card(cert_der);
        }
        ca.save_user_cert(
            cert.id,
            cert_der,
            &cert
                .get_snb()
                .map_err(|_| CertificateSaveError::FailedToParseCertificate)?,
        )
        .await;
        if let Some(label) = cert.data.hsm_label() {
            match self {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::Sqlite(p) => {
                    service::log::info!("Inserting hsm data for {}", cert.id);
                    p.conn(move |conn| {
                        let mut stmt = conn
                            .prepare("INSERT INTO hsm_labels (id, label) VALUES (?1, ?2)")
                            .expect("Failed to build prepared statement");
                        stmt.execute([cert.id.to_sql().unwrap(), label.to_sql().unwrap()])
                    })
                    .await
                    .map_err(|_| CertificateSaveError::FailedToSave)?;
                }
            }
        } else if let Some(p12) = cert.try_p12(password) {
            service::log::info!("Inserting p12 data for {}", cert.id);
            match self {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::Sqlite(p) => {
                    p.conn(move |conn| {
                        let mut stmt = conn
                            .prepare("INSERT INTO p12 (id, pem) VALUES (?1, ?2)")
                            .expect("Failed to build prepared statement");
                        stmt.execute([cert.id.to_sql().unwrap(), p12.to_sql().unwrap()])
                    })
                    .await
                    .map_err(|_| CertificateSaveError::FailedToSave)?;
                }
            }
        }
        Ok(())
    }

    /// Load a certificate from the storage medium
    pub async fn load_hsm_from_medium(
        &self,
        hsm: Arc<crate::hsm2::Hsm>,
        name: &str,
    ) -> Result<CaCertificate, CertificateLoadingError> {
        match self {
            CaCertificateStorage::Nowhere => Err(CertificateLoadingError::DoesNotExist),
            CaCertificateStorage::Sqlite(p) => {
                let name = name.to_owned();
                let name2 = name.to_owned();
                let id = p
                    .conn(move |conn| {
                        conn.query_row(
                            &format!("SELECT id FROM hsm_labels WHERE label='{}'", name2),
                            [],
                            |r| Ok(r.get(0).unwrap()),
                        )
                    })
                    .await
                    .map_err(|_| {
                        service::log::debug!("Cannot load cert {}", name);
                        CertificateLoadingError::DoesNotExist
                    })?;
                let cert = p
                    .conn(move |conn| {
                        conn.query_row(
                            &format!("SELECT der FROM certs WHERE id='{}'", id),
                            [],
                            |r| Ok(r.get(0).unwrap()),
                        )
                    })
                    .await
                    .map_err(|_| {
                        service::log::debug!("Cannot load cert {}", name);
                        CertificateLoadingError::DoesNotExist
                    })?;
                let hsm_cert = crate::hsm2::KeyPair::load_with_label(hsm, &name);
                let kp = hsm_cert
                    .as_ref()
                    .ok_or(CertificateLoadingError::NoAlgorithm)?;
                let alg = kp
                    .https_algorithm()
                    .ok_or(CertificateLoadingError::NoAlgorithm)?;
                let hsm_cert = hsm_cert.map(Keypair::Hsm);
                //TODO dynamically pick the correct certificate type here
                let hcert = HttpsCertificate {
                    algorithm: alg,
                    cert,
                    keypair: hsm_cert,
                    attributes: Vec::new(),
                };
                let cert = CaCertificate {
                    medium: self.clone(),
                    data: CertificateData::Https(hcert),
                    name: name.to_owned(),
                    id,
                };
                Ok(cert)
            }
        }
    }

    /// Load a certificate from the storage medium
    pub async fn load_p12_from_medium(
        &self,
        label: &str,
    ) -> Result<ProtectedPkcs12, CertificateLoadingError> {
        match self {
            CaCertificateStorage::Nowhere => Err(CertificateLoadingError::DoesNotExist),
            CaCertificateStorage::Sqlite(p) => {
                let label = label.to_owned();
                let label2 = label.to_owned();
                let id = p
                    .conn(move |conn| {
                        conn.query_row(
                            &format!("SELECT id FROM hsm_labels WHERE label='{}'", label),
                            [],
                            |r| Ok(r.get(0).unwrap()),
                        )
                    })
                    .await
                    .map_err(|e| {
                        service::log::debug!("Cannot load cert {} - {:?}", label2, e);
                        CertificateLoadingError::DoesNotExist
                    })?;
                let cert: Result<Vec<u8>, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row("SELECT der FROM certs WHERE id=?1", [id], |r| r.get(0))
                    })
                    .await;
                let p12 = cert_common::pkcs12::ProtectedPkcs12 {
                    contents: cert.map_err(|_e| CertificateLoadingError::DoesNotExist)?,
                    id,
                };
                Ok(p12)
            }
        }
    }
}

/// A keypair that can be in the hsm or not
#[derive(Clone, Debug)]
pub enum Keypair {
    /// A keypair contained in the hsm
    Hsm(crate::hsm2::KeyPair),
    /// A keypair contained in a smartcard
    SmartCard(crate::card::KeyPair),
    /// A keypair not contained in the hsm
    NotHsm(Zeroizing<Vec<u8>>),
}

impl Keypair {
    /// Get the contents of the cert if it is stored in a smart card
    fn smartcard(&self) -> Option<&crate::card::KeyPair> {
        if let Keypair::SmartCard(sc) = self {
            Some(sc)
        } else {
            None
        }
    }

    /// Get the private key if possible
    pub fn private(&self) -> Option<&Zeroizing<Vec<u8>>> {
        if let Keypair::NotHsm(a) = self {
            Some(a)
        } else {
            None
        }
    }

    /// Erase the private key of the certificate
    pub fn erase_private(&mut self) {
        match self {
            Self::SmartCard(_) | Self::Hsm(_) => {}
            Self::NotHsm(k) => {
                *k = Zeroizing::new(Vec::new());
            }
        }
    }

    /// Get the hsm keypair, if possible
    pub fn hsm_keypair(&self) -> Option<&crate::hsm2::KeyPair> {
        match self {
            Keypair::Hsm(k) => Some(k),
            Keypair::SmartCard(_) | Keypair::NotHsm(_) => None,
        }
    }

    /// Sign a chunk of data
    pub fn sign(&self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Keypair::Hsm(k) => k.sign(data).ok(),
            Keypair::SmartCard(k) => k.sign_with_pin(data).ok(),
            Keypair::NotHsm(_k) => {
                todo!();
            }
        }
    }
}

/// An https certificate
#[derive(Clone, Debug)]
pub struct HttpsCertificate {
    /// The algorithm used for the certificate
    pub algorithm: HttpsSigningMethod,
    /// The public certificate in der format
    pub cert: Vec<u8>,
    /// The keypair or a private key
    pub keypair: Option<Keypair>,
    /// The extra attributes for the certificate
    pub attributes: Vec<cert_common::pkcs12::BagAttribute>,
}

impl CertificateDataTrait for HttpsCertificate {
    fn smartcard(&self) -> Option<&crate::card::KeyPair> {
        self.keypair.as_ref().and_then(|kp| kp.smartcard())
    }

    fn hsm_label(&self) -> Option<String> {
        self.keypair.as_ref().and_then(|kp| {
            let keypair = kp.hsm_keypair();
            let label = keypair.map(|kp| {
                use crate::hsm2::KeyPairTrait;
                kp.label()
            });
            let kps = kp.smartcard();
            let label2 = kps.map(|a| a.label());
            label.or(label2.or(None))
        })
    }

    fn erase_private_key(&mut self) {
        if let Some(c) = self.keypair.as_mut() {
            c.erase_private();
        }
    }

    fn public_pem(&self) -> Option<String> {
        use der::Decode;
        let doc: der::Document = der::Document::from_der(&self.cert).ok()?;
        doc.to_pem("CERTIFICATE", pkcs8::LineEnding::CRLF).ok()
    }

    fn sign_csr(
        &self,
        csr: CaCertificateToBeSigned,
    ) -> Result<CaCertificate, CertificateSigningError> {
        let (issuer, issuer_key) = &self
            .get_rcgen_cert_and_keypair()
            .ok_or(CertificateSigningError::UnableToSign)?;
        let rc_cert = csr
            .csr
            .signed_by(issuer, issuer_key)
            .map_err(|_| CertificateSigningError::UnableToSign)?;
        let der = rc_cert.der().to_vec();
        use der::Decode;
        let x509 = x509_cert::Certificate::from_der(&der)
            .map_err(|_| CertificateSigningError::UndecipherableX509Generated)?;
        let local_key_id = x509.tbs_certificate.serial_number.as_bytes().to_vec();
        Ok(CaCertificate {
            medium: CaCertificateStorage::Nowhere,
            data: CertificateData::Https(HttpsCertificate {
                algorithm: csr.algorithm,
                cert: der,
                keypair: csr.keypair,
                attributes: vec![
                    BagAttribute::LocalKeyId(local_key_id),
                    BagAttribute::FriendlyName(csr.name.clone()),
                ],
            }),
            name: csr.name.clone(),
            id: csr.id,
        })
    }

    fn get_attributes(&self) -> Vec<cert_common::pkcs12::BagAttribute> {
        self.attributes.clone()
    }

    fn try_p12(&self, id: u64, password: &str) -> Option<Vec<u8>> {
        self.keypair.as_ref().and_then(|kp| {
            let keypair = kp.private();
            keypair.map(|kp| {
                let p12: cert_common::pkcs12::Pkcs12 = cert_common::pkcs12::Pkcs12 {
                    cert: self.cert.clone(),
                    pkey: kp.to_owned(),
                    attributes: self.attributes.clone(),
                    id,
                };
                p12.get_pkcs12(password)
            })
        })
    }

    fn algorithm(&self) -> CertificateSigningMethod {
        CertificateSigningMethod::Https(self.algorithm)
    }

    fn get_snb(&self, _id: u64) -> Result<Vec<u8>, der::Error> {
        let x509 = self.x509_cert()?;
        Ok(x509.tbs_certificate.serial_number.as_bytes().to_vec())
    }

    fn contents(&self) -> Result<Vec<u8>, ()> {
        Ok(self.cert.to_owned())
    }

    fn sign(&self, data: &[u8]) -> Option<Signature> {
        let sig = self.keypair.as_ref()?.sign(data)?;
        Some(Signature::OidSignature(self.algorithm.oid(), sig))
    }

    fn x509_cert(&self) -> Result<x509_cert::Certificate, der::Error> {
        use der::Decode;
        x509_cert::Certificate::from_der(&self.cert)
    }
}

impl HttpsCertificate {
    /// Build a Self from an x509 certificate
    fn from_x509(x509: x509_cert::Certificate) -> Result<Self, CertificateLoadingError> {
        use der::Encode;
        Ok(Self {
            algorithm: x509
                .signature_algorithm
                .clone()
                .try_into()
                .map_err(|_e| CertificateLoadingError::InvalidCert)?,
            cert: x509
                .to_der()
                .map_err(|_e| CertificateLoadingError::InvalidCert)?,
            keypair: None,
            attributes: Vec::new(),
        })
    }

    /// Get the rcgen certificate and keypair at the same time
    pub fn get_rcgen_cert_and_keypair(&self) -> Option<(rcgen::Certificate, rcgen::KeyPair)> {
        if let Some(keypair) = self.keypair() {
            let ca_cert_der = rustls_pki_types::CertificateDer::from(self.cert.clone());
            let p = rcgen::CertificateParams::from_ca_cert_der(&ca_cert_der).ok()?;
            //TODO unsure if this is correct
            let rc_cert = p.self_signed(&keypair).ok()?;
            Some((rc_cert, keypair))
        } else {
            None
        }
    }

    /// Returns the keypair for this certificate
    pub fn keypair(&self) -> Option<rcgen::KeyPair> {
        use crate::hsm2::KeyPairTrait;
        self.keypair.as_ref().and_then(|a| {
            if let Keypair::Hsm(a) = a {
                Some(a.keypair())
            } else {
                todo!()
            }
        })
    }

    /// Attempt to get the private key
    pub fn get_private(&self) -> Option<&[u8]> {
        self.keypair.as_ref().and_then(|a| {
            if let Keypair::NotHsm(a) = a {
                Some(a.as_ref())
            } else {
                None
            }
        })
    }
}

/// An ssh certificate
#[derive(Clone, Debug)]
pub struct SshCertificate {
    /// The algorithm used for the certificate
    algorithm: SshSigningMethod,
    /// The keypair for the certificate
    keypair: Option<ssh_key::private::KeypairData>,
    /// The actual certificate
    cert: ssh_key::certificate::Certificate,
}

impl CertificateDataTrait for SshCertificate {
    fn smartcard(&self) -> Option<&crate::card::KeyPair> {
        todo!()
    }

    fn hsm_label(&self) -> Option<String> {
        todo!()
    }

    fn erase_private_key(&mut self) {
        self.keypair.take();
    }

    fn public_pem(&self) -> Option<String> {
        self.cert.to_openssh().ok()
    }

    fn sign_csr(
        &self,
        csr: CaCertificateToBeSigned,
    ) -> Result<CaCertificate, CertificateSigningError> {
        todo!()
    }

    fn get_attributes(&self) -> Vec<cert_common::pkcs12::BagAttribute> {
        todo!()
    }

    fn try_p12(&self, id: u64, password: &str) -> Option<Vec<u8>> {
        use ssh_encoding::Encode;
        let public_contents = self.cert.to_bytes().unwrap();
        if let Some(keypair) = &self.keypair {
            let mut con = Vec::new();
            keypair.encode(&mut con).ok()?;
            let p12: cert_common::pkcs12::Pkcs12 = cert_common::pkcs12::Pkcs12 {
                cert: public_contents,
                pkey: Zeroizing::new(con),
                attributes: Vec::new(),
                id,
            };
            let p12_der = p12.get_pkcs12(password);
            Some(p12_der)
        } else {
            None
        }
    }

    fn algorithm(&self) -> CertificateSigningMethod {
        CertificateSigningMethod::Ssh(self.algorithm)
    }

    fn get_snb(&self, id: u64) -> Result<Vec<u8>, der::Error> {
        Ok(u64::to_le_bytes(id).to_vec())
    }

    fn contents(&self) -> Result<Vec<u8>, ()> {
        Ok(self.cert.to_openssh().map_err(|_| ())?.as_bytes().to_vec())
    }

    fn sign(&self, data: &[u8]) -> Option<Signature> {
        todo!()
    }

    fn x509_cert(&self) -> Result<x509_cert::Certificate, der::Error> {
        todo!()
    }
}

impl SshCertificate {
    /// Construct a certificate
    pub fn new(
        algorithm: SshSigningMethod,
        keypair: Option<ssh_key::private::KeypairData>,
        cert: ssh_key::certificate::Certificate,
    ) -> Self {
        Self {
            algorithm,
            keypair,
            cert,
        }
    }
}

/// Represents a signature of a certificate
pub enum Signature {
    /// A signature with an oid
    OidSignature(Oid, Vec<u8>),
    /// Some other signature
    Other(Vec<u8>),
}

impl Signature {
    /// Get the oid, if applicable
    pub fn oid(&self) -> Option<Oid> {
        if let Signature::OidSignature(a, _b) = self {
            Some(a.to_owned())
        } else {
            None
        }
    }

    /// Get the signature value
    pub fn signature(&self) -> Vec<u8> {
        match self {
            Self::Other(o) => o.clone(),
            Self::OidSignature(_a, sig) => sig.clone(),
        }
    }
}

/// The trait commmon to all certificate data
#[enum_dispatch::enum_dispatch]
pub trait CertificateDataTrait {
    /// Get the contents of the cert if it is stored in a smart card
    fn smartcard(&self) -> Option<&crate::card::KeyPair>;
    /// Try to get the hsm handle for the certificate
    fn hsm_label(&self) -> Option<String>;
    /// Erase the private key from the certificate
    fn erase_private_key(&mut self);
    /// Retrieve the certificate in pem format
    fn public_pem(&self) -> Option<String>;
    ///sign a certificate
    fn sign_csr(
        &self,
        csr: CaCertificateToBeSigned,
    ) -> Result<CaCertificate, CertificateSigningError>;
    /// Get the list of bag attributes for the certificate data
    fn get_attributes(&self) -> Vec<cert_common::pkcs12::BagAttribute>;
    /// Attempt to build a p12 document
    fn try_p12(&self, id: u64, password: &str) -> Option<Vec<u8>>;
    /// Get the algorithm
    fn algorithm(&self) -> CertificateSigningMethod;
    /// Retrieve the serial number as a vector
    fn get_snb(&self, id: u64) -> Result<Vec<u8>, der::Error>;
    /// Retrieve the contents of the certificate data in a storable format
    fn contents(&self) -> Result<Vec<u8>, ()>;
    /// Attempt to sign the specified data
    fn sign(&self, data: &[u8]) -> Option<Signature>;
    /// attempt to get an x509_cert object
    fn x509_cert(&self) -> Result<x509_cert::Certificate, der::Error>;
}

/// The kinds of certificates that can exist
#[derive(Clone, Debug)]
#[enum_dispatch::enum_dispatch(CertificateDataTrait)]
pub enum CertificateData {
    /// Data required for an https certificate
    Https(HttpsCertificate),
    /// Data required for an ssh certificate
    Ssh(SshCertificate),
}

impl CertificateData {
    /// Build a Self from an x509 certificate
    pub fn from_x509(x509: x509_cert::Certificate) -> Result<Self, CertificateLoadingError> {
        //TODO handle ssh certificates somehow
        let cert = HttpsCertificate::from_x509(x509)?;
        let cac = Self::Https(cert);
        Ok(cac)
    }
}

/// Represents a certificate that might be able to sign things
#[derive(Clone, Debug)]
pub struct CaCertificate {
    /// Where the certificate is stored
    pub medium: CaCertificateStorage,
    /// The certificate data
    data: CertificateData,
    /// The certificate name to use for storage
    pub name: String,
    /// The id of the certificate
    pub id: u64,
}

impl CaCertificate {
    /// Get the contents of the cert if it is stored in a smart card
    fn smartcard(&self) -> Option<&crate::card::KeyPair> {
        self.data.smartcard()
    }

    /// Erase the private key from the certificate
    pub fn erase_private_key(&mut self) {
        self.data.erase_private_key();
    }

    /// Try to get an x509 certificate
    pub fn x509_cert(&self) -> Result<x509_cert::Certificate, der::Error> {
        self.data.x509_cert()
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> CertificateSigningMethod {
        self.data.algorithm()
    }

    /// Retrieve the certificate serial number
    pub fn get_snb(&self) -> Result<Vec<u8>, der::Error> {
        self.data.get_snb(self.id)
    }

    /// Retrieve the contents of the certificate data in a storable format
    pub fn contents(&self) -> Result<Vec<u8>, ()> {
        self.data.contents()
    }

    /// Attempt to build a p12 document
    pub fn try_p12(&self, password: &str) -> Option<Vec<u8>> {
        self.data.try_p12(self.id, password)
    }

    /// Load an ssh certificate
    pub fn from_existing_ssh(
        medium: CaCertificateStorage,
        cert: SshCertificate,
        name: String,
        id: u64,
    ) -> Self {
        Self {
            medium,
            data: CertificateData::Ssh(cert),
            name,
            id,
        }
    }

    /// Load a caCertificate instance from der data of the certificate
    pub fn from_existing_https(
        algorithm: HttpsSigningMethod,
        medium: CaCertificateStorage,
        der: &[u8],
        keypair: Keypair,
        name: String,
        id: u64,
    ) -> Self {
        use der::Decode;
        let x509 = x509_cert::Certificate::from_der(der).unwrap();
        Self {
            medium,
            data: CertificateData::Https(HttpsCertificate {
                algorithm,
                cert: der.to_vec(),
                keypair: Some(keypair),
                attributes: vec![
                    BagAttribute::LocalKeyId(
                        x509.tbs_certificate.serial_number.as_bytes().to_vec(),
                    ),
                    BagAttribute::FriendlyName(name.clone()),
                ],
            }),
            name: name.clone(),
            id,
        }
    }

    /// Get the list of attributes
    pub fn get_attributes(&self) -> Vec<cert_common::pkcs12::BagAttribute> {
        self.data.get_attributes()
    }

    /// Get the name of the certificate
    pub fn get_name(&self) -> String {
        self.name.to_owned()
    }

    /// Retrieve the certificate in pem format
    pub fn public_pem(&self) -> Option<String> {
        self.data.public_pem()
    }

    /// Save this certificate to the storage medium
    pub async fn save_to_medium(&self, ca: &mut Ca, password: &str) {
        self.medium
            .save_to_medium(ca, self.to_owned(), password)
            .await;
    }

    /// Sign a csr with the certificate, if possible
    pub fn sign_csr(
        &self,
        mut csr: CaCertificateToBeSigned,
        ca: &Ca,
        id: u64,
        duration: time::Duration,
    ) -> Option<CaCertificate> {
        let the_csr = &mut csr.csr;
        let pkix = PkixAuthorityInfoAccess::new(ca.ocsp_urls.to_owned());
        let ocsp_data = pkix.der;
        let ocsp = rcgen::CustomExtension::from_oid_content(
            &OID_PKIX_AUTHORITY_INFO_ACCESS.components(),
            ocsp_data,
        );
        the_csr.params.custom_extensions.push(ocsp);

        the_csr.params.not_before = time::OffsetDateTime::now_utc();
        the_csr.params.not_after = the_csr.params.not_before + duration;
        let (_snb, sn) = CaCertificateToBeSigned::calc_sn(id);
        the_csr.params.serial_number = Some(sn);

        self.data.sign_csr(csr).ok()
    }

    /// Sign some data with the certificate, if possible
    pub async fn sign(&self, data: &[u8]) -> Option<Signature> {
        self.data.sign(data)
    }
}

/// Represents a domain and a subdomain for proxying
#[derive(
    Clone,
    Debug,
    Default,
    userprompt::Prompting,
    userprompt::EguiPrompting,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct ComplexName {
    /// The domain name, such as example.com
    pub domain: String,
    /// The subdomain, such as / or /asdf
    pub subdomain: String,
}

impl core::fmt::Display for ComplexName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.domain)?;
        f.write_str(&self.subdomain)
    }
}

impl std::str::FromStr for ComplexName {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = if let Some((a, b)) = s.split_once('/') {
            ComplexName {
                domain: a.to_string(),
                subdomain: format!("/{}", b),
            }
        } else {
            ComplexName {
                domain: s.to_string(),
                subdomain: "/".to_string(),
            }
        };
        Ok(s)
    }
}

/// The options for setting up a reverse proxy that points to a server
/// This redirects http://example.com/asdf/pki to https://server_name/pki
#[derive(
    Clone,
    Debug,
    Default,
    userprompt::Prompting,
    userprompt::EguiPrompting,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct ProxyConfig {
    /// The public port number for http, 80 for the example (the default port for http)
    pub http_port: Option<u16>,
    /// The public port number for https, 443 for the example (the default port for https)
    pub https_port: Option<u16>,
}

/// The configuration of a general pki instance.
#[derive(
    Clone,
    Debug,
    Default,
    userprompt::Prompting,
    userprompt::EguiPrompting,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct PkiConfigurationAnswers {
    /// List of local ca
    pub local_ca: userprompt::SelectedHashMap<LocalCaConfigurationAnswers>,
    /// The provider for the super-admin key
    super_admin: Option<String>,
}

/// The configuration of a general pki instance.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct PkiConfiguration {
    /// List of local ca
    pub local_ca: std::collections::HashMap<String, LocalCaConfiguration>,
    /// The super-admin certificate provider
    pub super_admin: Option<String>,
}

impl From<PkiConfigurationAnswers> for PkiConfiguration {
    fn from(value: PkiConfigurationAnswers) -> Self {
        let map = value.local_ca.map().clone();
        let map2 = map
            .iter()
            .map(|(s, v)| {
                let v: LocalCaConfiguration = v.to_owned().into();
                (s.to_owned(), v.to_owned())
            })
            .collect();
        Self {
            local_ca: map2,
            super_admin: value.super_admin.clone(),
        }
    }
}

///A generic configuration for a pki or certificate authority.
#[derive(
    Clone,
    Debug,
    userprompt::Prompting,
    userprompt::EguiPrompting,
    serde::Deserialize,
    serde::Serialize,
    strum::EnumIter,
)]
pub enum PkiConfigurationEnumAnswers {
    /// A generic Pki configuration
    Pki(PkiConfigurationAnswers),
    /// A standard certificate authority configuration
    Ca(Box<StandaloneCaConfigurationAnswers>),
}

impl Default for PkiConfigurationEnumAnswers {
    fn default() -> Self {
        Self::new()
    }
}

impl PkiConfigurationEnumAnswers {
    /// Construct a new ca, defaulting to a Ca configuration
    pub fn new() -> Self {
        Self::Ca(Box::new(StandaloneCaConfigurationAnswers::new()))
    }
}

///A generic configuration for a pki or certificate authority.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum PkiConfigurationEnum {
    /// A generic Pki configuration
    Pki(PkiConfiguration),
    /// A standard certificate authority configuration
    Ca(Box<StandaloneCaConfiguration>),
}

impl From<PkiConfigurationEnumAnswers> for PkiConfigurationEnum {
    fn from(value: PkiConfigurationEnumAnswers) -> Self {
        match value {
            PkiConfigurationEnumAnswers::Pki(pki) => Self::Pki(pki.into()),
            PkiConfigurationEnumAnswers::Ca(ca) => Self::Ca(ca.into()),
        }
    }
}

impl PkiConfigurationEnum {
    /// Remove relative pathnames from all paths specified
    pub async fn remove_relative_paths(&mut self) {
        match self {
            PkiConfigurationEnum::Pki(pki) => {
                for (_k, a) in pki.local_ca.iter_mut() {
                    a.path.remove_relative_paths().await;
                }
            }
            PkiConfigurationEnum::Ca(ca) => {
                ca.path.remove_relative_paths().await;
            }
        }
    }

    /// Build an nginx reverse proxy config
    fn nginx_reverse(
        &self,
        proxy: &ProxyConfig,
        config: &MainConfiguration,
        ca: Option<&StandaloneCaConfiguration>,
    ) -> String {
        let mut contents = String::new();
        contents.push_str("#nginx reverse proxy settings\n");
        let location_name = if let Some(ca) = ca {
            format!("pki/{}", ca.name)
        } else {
            "".to_string()
        };
        if let Some(http) = proxy.http_port {
            for complex_name in &config.public_names {
                contents.push_str("server {\n");
                contents.push_str(&format!("\tlisten {};\n", http));
                contents.push_str(&format!("\tserver_name {};\n", complex_name.domain));
                contents.push_str(&format!(
                    "\tlocation {}{} {{\n",
                    complex_name.subdomain, location_name
                ));
                if let Some(https) = &config.https {
                    if https.port == 443 {
                        contents.push_str("\t\tproxy_pass https://127.0.0.1/;\n");
                    } else {
                        contents.push_str(&format!(
                            "\t\tproxy_pass https://127.0.0.1:{}/;\n",
                            https.port
                        ));
                    }
                    if https.require_certificate {
                        contents.push_str("\t\tproxy_ssl_certificate /put/location/here;\n");
                        contents.push_str("\t\tproxy_ssl_certificate_key /put/location/here;\n");
                    }
                } else if let Some(http) = &config.http {
                    if http.port == 80 {
                        contents.push_str("\t\tproxy_pass http://127.0.0.1/;\n");
                    } else {
                        contents.push_str(&format!(
                            "\t\tproxy_pass http://127.0.0.1:{}/;\n",
                            http.port
                        ));
                    }
                }
                contents.push_str("\t}\n}\n\n");
            }
        }
        if let Some(https) = proxy.https_port {
            for complex_name in &config.public_names {
                contents.push_str("server {\n");
                contents.push_str(&format!("\tlisten {} ssl;\n", https));
                contents.push_str(&format!("\tserver_name {};\n", complex_name.domain));
                contents.push_str("\tssl_certificate /put/location/here;\n");
                contents.push_str("\tssl_certificate_key /put/location/here;\n");
                contents.push_str("\tssl_verify_client optional;\n");
                contents.push_str(&format!(
                    "\tlocation {}{} {{\n",
                    complex_name.subdomain, location_name
                ));
                contents
                    .push_str("\t\tproxy_set_header SSL_CLIENT_CERT $ssl_client_escaped_cert;\n");
                if let Some(https) = &config.https {
                    if https.port == 443 {
                        contents.push_str("\t\tproxy_pass https://127.0.0.1/;\n");
                    } else {
                        contents.push_str(&format!(
                            "\t\tproxy_pass https://127.0.0.1:{}/;\n",
                            https.port
                        ));
                    }
                    if https.require_certificate {
                        contents.push_str("\t\tproxy_ssl_certificate /put/location/here;\n");
                        contents.push_str("\t\tproxy_ssl_certificate_key /put/location/here;\n");
                    }
                } else if let Some(http) = &config.http {
                    if http.port == 80 {
                        contents.push_str("\t\tproxy_pass http://127.0.0.1/;\n");
                    } else {
                        contents.push_str(&format!(
                            "\t\tproxy_pass http://127.0.0.1:{}/;\n",
                            http.port
                        ));
                    }
                }
                contents.push_str("\t}\n}\n\n");
            }
        }
        contents
    }

    /// Build a example config for reverse proxy if applicable
    pub fn reverse_proxy(&self, config: &MainConfiguration) -> Option<String> {
        if let Some(proxy) = &config.proxy_config {
            match self {
                PkiConfigurationEnum::Pki(_) => {
                    let mut contents = String::new();
                    contents.push_str(&self.nginx_reverse(proxy, config, None));
                    Some(contents)
                }
                PkiConfigurationEnum::Ca(ca) => {
                    let mut contents = String::new();
                    contents.push_str(&self.nginx_reverse(proxy, config, Some(ca.as_ref())));
                    Some(contents)
                }
            }
        } else {
            None
        }
    }

    /// The display name of the item for gui purposes
    pub fn display(&self) -> &str {
        match self {
            Self::Pki(_) => "Pki",
            Self::Ca(_) => "Certificate Authority",
        }
    }
}

/// A normal pki object, containing one or more Certificate authorities
#[derive(Debug)]
pub struct Pki {
    /// All of the root certificate authorities
    pub roots: HashMap<String, Ca>,
    /// The super-admin certificate
    pub super_admin: Option<CaCertificate>,
}

/// Potential errors when loading a pki object
#[derive(Debug)]
pub enum PkiLoadError {
    /// An individual ca failed to load with the config data specified
    FailedToLoadCa(String, CaLoadError),
    /// A ca cannot be superior to itself
    CannotBeOwnSuperior(String),
}

/// Potential errors when loading a specific ca object
#[derive(Debug)]
pub enum CaLoadError {
    /// Error building the storage for the ca
    StorageError(StorageBuilderError),
    /// Error when loading certificates for the ca
    CertificateLoadingError(CertificateLoadingError),
    /// Superior ca is missing and is required
    SuperiorCaMissing,
    /// Failed to initialize the https certificate
    FailedToInitHttps,
    /// Failed to save a certificate
    FailedToSaveCertificate(String),
    /// Failed to create a needed keypair
    FailedToCreateKeypair(String),
    /// Failed to build ocsp responder url
    FailedToBuildOcspUrl,
}

impl From<&CertificateLoadingError> for CaLoadError {
    fn from(value: &CertificateLoadingError) -> Self {
        Self::CertificateLoadingError(value.to_owned())
    }
}

impl Pki {
    /// Initialize a Pki instance with the specified configuration and options for setting file ownerships (as required).
    #[allow(dead_code)]
    pub async fn init(
        hsm: Arc<crate::hsm2::Hsm>,
        settings: &crate::ca::PkiConfiguration,
        main_config: &crate::main_config::MainConfiguration,
    ) -> Result<Self, PkiLoadError> {
        let mut hm = std::collections::HashMap::new();
        let ca_name = main_config
            .https
            .as_ref()
            .and_then(|h| h.certificate.create_by_ca());
        loop {
            let mut done = true;
            for (name, config) in &settings.local_ca {
                if !hm.contains_key(name) {
                    let config = &config.get_ca(name, main_config);
                    let ca = crate::ca::Ca::init(
                        hsm.clone(),
                        config,
                        config.inferior_to.as_ref().and_then(|n| hm.get_mut(n)),
                    )
                    .await;
                    match ca {
                        Ok(mut ca) => {
                            if let Some(ca_name) = &ca_name {
                                if ca_name == name {
                                    ca.check_https_create(hsm.clone(), main_config)
                                        .await
                                        .map_err(|_| {
                                            PkiLoadError::FailedToLoadCa(
                                                name.to_owned(),
                                                CaLoadError::FailedToInitHttps,
                                            )
                                        })?;
                                }
                            }
                            hm.insert(name.to_owned(), ca);
                        }
                        Err(e) => match e {
                            CaLoadError::SuperiorCaMissing => {
                                done = false;
                            }
                            _ => {
                                return Err(PkiLoadError::FailedToLoadCa(name.to_owned(), e));
                            }
                        },
                    }
                }
            }
            if done {
                break;
            }
        }
        Ok(Self {
            roots: hm,
            super_admin: None,
        })
    }

    /// Load pki stuff
    #[allow(dead_code)]
    pub async fn load(
        hsm: Arc<crate::hsm2::Hsm>,
        settings: &crate::ca::PkiConfiguration,
        main_config: &MainConfiguration,
    ) -> Result<Self, PkiLoadError> {
        let mut hm = HashMap::new();
        for (name, config) in &settings.local_ca {
            let config = &config.get_ca(name, main_config);
            let ca = crate::ca::Ca::load(hsm.clone(), config)
                .await
                .map_err(|e| PkiLoadError::FailedToLoadCa(name.to_owned(), e))?;
            hm.insert(name.to_owned(), ca);
        }
        let super_admin: Option<CaCertificate> = if let Some(sa) = &settings.super_admin {
            if let Some(ca) = hm.get_mut(sa) {
                let p = ca.admin_access.to_string();
                Some(
                    ca.load_admin_cert(hsm.clone(), &p)
                        .await
                        .map(|a| a.to_owned())
                        .map_err(|e| {
                            PkiLoadError::FailedToLoadCa(
                                sa.to_owned(),
                                CaLoadError::CertificateLoadingError(e.to_owned()),
                            )
                        })?,
                )
            } else {
                None
            }
        } else {
            None
        };
        if let Some(sa) = &super_admin {
            for ca in hm.values_mut() {
                ca.insert_super_admin(sa.to_owned());
            }
        }
        let mut s: HashSet<String> = HashSet::new();
        //Add root authorities to the list first
        for (name, a) in settings.local_ca.iter() {
            if a.inferior_to.is_none() {
                s.insert(name.to_owned());
            }
        }
        let mut iter_count = 0;
        loop {
            service::log::info!(
                "Adding admin certificate for inferior certificates round {}",
                iter_count + 1
            );
            let mut iter_done = true;
            for (name, a) in settings.local_ca.iter() {
                if let Some(superior) = &a.inferior_to {
                    if superior == name {
                        service::log::error!("An authority cannot be superior to itself");
                        return Err(PkiLoadError::CannotBeOwnSuperior(name.to_owned()));
                    }
                    if s.contains(superior) {
                        let mut superiors = Vec::new();
                        let mut admin = None;
                        if let Some(sca) = hm.get(superior) {
                            superiors = sca.get_superior_admin();
                            admin = sca.admin.as_ref().ok().cloned();
                        }
                        if let Some(current_ca) = hm.get_mut(name) {
                            service::log::info!("..{}", name);
                            for s in superiors {
                                current_ca.add_superior_admin(s);
                            }
                            if let Some(admin) = admin {
                                current_ca.add_superior_admin(admin.to_owned());
                            }
                            s.insert(name.to_owned());
                        }
                    } else {
                        iter_done = false;
                    }
                }
            }
            iter_count += 1;
            if iter_done {
                break;
            }
        }
        service::log::info!("Adding admin certificate for inferior certificates done");
        Ok(Self {
            roots: hm,
            super_admin,
        })
    }

    /// Retrieve the certificate authorities associated with verifying client certificates
    #[allow(dead_code)]
    pub async fn get_client_certifiers(&self) -> std::collections::hash_map::Values<String, Ca> {
        self.roots.values()
    }
}

/// An instance of either a pki or ca.
pub enum PkiInstance {
    /// A generic pki instance
    Pki(Pki),
    /// A single certificate authority instance
    Ca(Ca),
}

impl PkiInstance {
    /// Init a pki Instance from the given settings
    #[allow(dead_code)]
    pub async fn init(
        hsm: Arc<crate::hsm2::Hsm>,
        settings: &crate::ca::PkiConfigurationEnum,
        main_config: &crate::main_config::MainConfiguration,
    ) -> Result<Self, PkiLoadError> {
        match settings {
            PkiConfigurationEnum::Pki(pki_config) => {
                let pki = crate::ca::Pki::init(hsm, pki_config, main_config).await?;
                Ok(Self::Pki(pki))
            }
            PkiConfigurationEnum::Ca(ca_config) => {
                let ca = ca_config.get_ca(main_config);
                let mut ca = crate::ca::Ca::init(hsm.clone(), &ca, None)
                    .await
                    .map_err(|e| PkiLoadError::FailedToLoadCa("ca".to_string(), e))?; //TODO Use the proper ca superior object instead of None
                if main_config.https.is_some() {
                    ca.check_https_create(hsm.clone(), main_config)
                        .await
                        .map_err(|_| {
                            PkiLoadError::FailedToLoadCa(
                                "ca".to_string(),
                                CaLoadError::FailedToInitHttps,
                            )
                        })?;
                }
                Ok(Self::Ca(ca))
            }
        }
    }

    /// Load an instance of self from the settings.
    #[allow(dead_code)]
    pub async fn load(
        hsm: Arc<crate::hsm2::Hsm>,
        settings: &crate::MainConfiguration,
    ) -> Result<Self, PkiLoadError> {
        match &settings.pki {
            PkiConfigurationEnum::Pki(pki_config) => {
                let pki = crate::ca::Pki::load(hsm, pki_config, settings).await?;
                Ok(Self::Pki(pki))
            }
            PkiConfigurationEnum::Ca(ca_config) => {
                let ca_config = &ca_config.get_ca(settings);
                let ca = Ca::load(hsm, ca_config)
                    .await
                    .map_err(|e| PkiLoadError::FailedToLoadCa("ca".to_string(), e))?;
                Ok(Self::Ca(ca))
            }
        }
    }
}

/// The actual ca object
#[derive(Debug)]
pub struct Ca {
    /// Where certificates are stored
    pub medium: CaCertificateStorage,
    /// Represents the root certificate for the ca
    pub root_cert: Result<CaCertificate, CertificateLoadingError>,
    /// Represents the certificate for signing ocsp responses
    pub ocsp_signer: Result<CaCertificate, CertificateLoadingError>,
    /// The administrator certificate
    pub admin: Result<CaCertificate, CertificateLoadingError>,
    /// The super-admin certificate
    pub super_admin: Option<CaCertificate>,
    /// Admin certificates for superior authorities
    pub admin_authorities: Vec<CaCertificate>,
    /// The urls for the ca
    pub ocsp_urls: Vec<String>,
    /// The access token for the admin certificate
    pub admin_access: zeroize::Zeroizing<String>,
    /// The configuration used to create this ca
    pub config: CaConfiguration,
}

impl Ca {
    /// Check to see if the https certifiate should be created
    pub async fn check_https_create(
        &mut self,
        hsm: Arc<crate::hsm2::Hsm>,
        main_config: &crate::main_config::MainConfiguration,
    ) -> Result<(), ()> {
        if let Some(https) = &main_config.https {
            if https.certificate.create_by_ca().is_some() {
                if let Some(pathbuf) = https.certificate.pathbuf() {
                    self.create_https_certificate(
                        hsm.clone(),
                        pathbuf,
                        main_config
                            .public_names
                            .iter()
                            .map(|a| a.to_string())
                            .collect(),
                        https.certificate.password().unwrap(), //assume that the password is valid if the path is valid
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    /// Create the required https certificate
    pub async fn create_https_certificate(
        &mut self,
        _hsm: Arc<crate::hsm2::Hsm>,
        destination: std::path::PathBuf,
        https_names: Vec<String>,
        password: &str,
    ) -> Result<(), ()> {
        service::log::info!("Generating an https certificate for web operations");
        let key_usage_oids = vec![OID_EXTENDED_KEY_USAGE_SERVER_AUTH.to_owned()];
        let extensions = vec![
            cert_common::CsrAttribute::build_extended_key_usage(key_usage_oids)
                .to_custom_extension()
                .unwrap(),
        ];

        let id = self.get_new_request_id().await.unwrap();
        let algorithm = {
            let root_cert = self.root_cert.as_ref().unwrap();
            root_cert.algorithm()
        };
        if let CertificateSigningMethod::Https(m) = algorithm {
            let https_options = SigningRequestParams {
                hsm: None, //TODO put in the hsm object when support is there for using an https certificate with external private key
                smartcard: None,
                t: m,
                name: "https".to_string(),
                common_name: "HTTPS Server".to_string(),
                names: https_names,
                extensions,
                id,
                days_valid: self.config.days, //TODO figure out a method to renew the https certificate automaticcally
            };
            let csr = https_options.generate_request();
            let root_cert = self.root_cert.as_ref().unwrap();
            let mut cert = root_cert
                .sign_csr(csr, self, id, time::Duration::days(self.config.days as i64))
                .unwrap();
            cert.medium = self.medium.clone();
            let (snb, _sn) = CaCertificateToBeSigned::calc_sn(id);
            self.save_user_cert(id, &cert.contents().map_err(|_| ())?, &snb)
                .await;
            let p12 = cert.try_p12(password).unwrap();
            tokio::fs::write(destination, p12).await.unwrap();
        }
        Ok(())
    }

    /// Create a Self from the application configuration
    pub async fn init_from_config(
        settings: &crate::ca::CaConfiguration,
    ) -> Result<Self, CaLoadError> {
        if settings.path.exists().await {
            return Err(CaLoadError::StorageError(
                StorageBuilderError::AlreadyExists,
            ));
        }
        let mut medium = settings
            .path
            .build()
            .await
            .map_err(|e| CaLoadError::StorageError(e))?;
        medium
            .init(settings)
            .await
            .map_err(|_| CaLoadError::StorageError(StorageBuilderError::FailedToInitStorage))?;
        Ok(Self {
            medium,
            root_cert: Err(CertificateLoadingError::DoesNotExist),
            ocsp_signer: Err(CertificateLoadingError::DoesNotExist),
            admin: Err(CertificateLoadingError::DoesNotExist),
            ocsp_urls: Self::get_ocsp_urls(settings)
                .map_err(|_| CaLoadError::FailedToBuildOcspUrl)?,
            admin_access: Zeroizing::new(settings.admin_access_password.to_string()),
            config: settings.to_owned(),
            super_admin: None,
            admin_authorities: Vec::new(),
        })
    }

    /// Initialize a Ca instance with the specified configuration.
    /// superior is used to generate the root certificate for intermediate authorities.
    pub async fn init(
        hsm: Arc<crate::hsm2::Hsm>,
        settings: &crate::ca::CaConfiguration,
        superior: Option<&mut Self>,
    ) -> Result<Self, CaLoadError> {
        service::log::info!("Attempting init for {}", settings.common_name);
        // Unable to to gnerate an intermediate instance without the superior ca reference
        if settings.inferior_to.is_some() && superior.is_none() {
            return Err(CaLoadError::SuperiorCaMissing);
        }

        let mut ca = Self::init_from_config(settings).await?;

        match settings.sign_method {
            CertificateSigningMethod::Https(m) => {
                {
                    service::log::info!("Generating a root certificate for ca operations");

                    let key_pair = hsm
                        .generate_https_keypair(&format!("{}-root", settings.common_name), m, 4096)
                        .unwrap();

                    let san: Vec<String> = settings.san.to_owned();
                    let mut certparams = rcgen::CertificateParams::new(san).unwrap();
                    certparams.distinguished_name = rcgen::DistinguishedName::new();

                    let cn = &settings.common_name;
                    let days = settings.days;
                    let chain_length = settings.chain_length;

                    certparams
                        .distinguished_name
                        .push(rcgen::DnType::CommonName, cn);
                    certparams.not_before = time::OffsetDateTime::now_utc();
                    certparams.not_after =
                        certparams.not_before + time::Duration::days(days as i64);
                    let basic_constraints = rcgen::BasicConstraints::Constrained(chain_length);
                    certparams.is_ca = rcgen::IsCa::Ca(basic_constraints);
                    let rootcert = if settings.inferior_to.is_none() {
                        use crate::hsm2::KeyPairTrait;
                        let cert = certparams.self_signed(&key_pair.keypair()).unwrap();
                        let cert_der = cert.der().to_owned();
                        CaCertificate::from_existing_https(
                            m,
                            ca.medium.clone(),
                            &cert_der,
                            Keypair::Hsm(key_pair),
                            "root".to_string(),
                            0,
                        )
                    } else if let Some(superior) = superior {
                        let id = superior.get_new_request_id().await.unwrap();
                        let key_usage_oids = vec![OID_EXTENDED_KEY_USAGE_SERVER_AUTH.to_owned()];
                        let extensions = vec![cert_common::CsrAttribute::build_extended_key_usage(
                            key_usage_oids,
                        )
                        .to_custom_extension()
                        .unwrap()];
                        let root_options = SigningRequestParams {
                            hsm: Some(hsm.clone()),
                            smartcard: None,
                            t: m,
                            name: format!("{}-root", ca.config.common_name),
                            common_name: ca.config.common_name.clone(),
                            names: ca.config.san.clone(),
                            extensions,
                            id,
                            days_valid: ca.config.days,
                        };
                        let root_csr = root_options.generate_request();
                        let mut root_cert = superior
                            .root_cert
                            .as_ref()
                            .unwrap()
                            .sign_csr(
                                root_csr,
                                &ca,
                                id,
                                time::Duration::days(ca.config.days as i64),
                            )
                            .unwrap();
                        let (snb, _sn) = CaCertificateToBeSigned::calc_sn(id);
                        superior
                            .save_user_cert(
                                id,
                                &root_cert.contents().map_err(|_| {
                                    CaLoadError::FailedToSaveCertificate("root".to_string())
                                })?,
                                &snb,
                            )
                            .await;
                        root_cert.medium = ca.medium.clone();
                        root_cert
                    } else {
                        todo!("Intermediate certificate authority generation not possible");
                    };

                    rootcert.save_to_medium(&mut ca, "").await;
                    ca.root_cert = Ok(rootcert);
                }
                service::log::info!("Generating OCSP responder certificate");
                let key_usage_oids = vec![OID_EXTENDED_KEY_USAGE_OCSP_SIGNING.to_owned()];
                let extensions =
                    vec![
                        cert_common::CsrAttribute::build_extended_key_usage(key_usage_oids)
                            .to_custom_extension()
                            .unwrap(),
                    ];

                let id = ca.get_new_request_id().await.unwrap();
                let ocsp_options = SigningRequestParams {
                    hsm: Some(hsm.clone()),
                    smartcard: None,
                    t: m,
                    name: format!("{}-ocsp", ca.config.common_name),
                    common_name: "OCSP Responder".to_string(),
                    names: ca.ocsp_urls.to_owned(),
                    extensions,
                    id,
                    days_valid: ca.config.days,
                };
                let ocsp_csr = ocsp_options.generate_request();
                let mut ocsp_cert = ca
                    .root_cert
                    .as_ref()
                    .unwrap()
                    .sign_csr(
                        ocsp_csr,
                        &ca,
                        id,
                        time::Duration::days(ca.config.days as i64),
                    )
                    .unwrap();
                ocsp_cert.medium = ca.medium.clone();
                ocsp_cert.save_to_medium(&mut ca, "").await;
                ca.ocsp_signer = Ok(ocsp_cert);

                let key_usage_oids = vec![OID_EXTENDED_KEY_USAGE_CLIENT_AUTH.to_owned()];
                let extensions =
                    vec![
                        cert_common::CsrAttribute::build_extended_key_usage(key_usage_oids)
                            .to_custom_extension()
                            .unwrap(),
                    ];
                service::log::info!("Generating administrator certificate");
                let id = ca.get_new_request_id().await.unwrap();
                let mut options = SigningRequestParams {
                    hsm: None,
                    smartcard: None,
                    t: m,
                    name: format!("{}-admin", ca.config.common_name),
                    common_name: format!("{} Administrator", settings.common_name),
                    names: Vec::new(),
                    extensions,
                    id,
                    days_valid: ca.config.days,
                };
                let admin_cert = match ca.config.admin_cert.clone() {
                    CertificateType::Soft(p) => {
                        let admin_csr = options.generate_request();
                        let mut admin_cert = ca
                            .root_cert
                            .as_ref()
                            .unwrap()
                            .sign_csr(
                                admin_csr,
                                &ca,
                                id,
                                time::Duration::days(ca.config.days as i64),
                            )
                            .unwrap();
                        admin_cert.medium = ca.medium.clone();
                        admin_cert.save_to_medium(&mut ca, &p).await;
                        admin_cert
                    }
                    CertificateType::SmartCard(p) => {
                        let label = format!("{}-admin", ca.config.common_name);
                        let keypair = crate::card::KeyPair::generate_with_smartcard(
                            p.as_bytes().to_vec(),
                            &label,
                        )
                        .ok_or(CaLoadError::FailedToCreateKeypair("admin".to_string()))?;
                        options.smartcard = Some(keypair);
                        let admin_csr = options.generate_request();
                        let mut admin_cert = ca
                            .root_cert
                            .as_ref()
                            .unwrap()
                            .sign_csr(
                                admin_csr,
                                &ca,
                                id,
                                time::Duration::days(ca.config.days as i64),
                            )
                            .unwrap();
                        admin_cert.medium = ca.medium.clone();
                        admin_cert.save_to_medium(&mut ca, &p).await;
                        admin_cert
                    }
                };
                ca.admin = Ok(admin_cert);
            }
            CertificateSigningMethod::Ssh(m) => {
                if settings.inferior_to.is_none() {
                    let key = m.generate_keypair(4096).unwrap();

                    let valid_after = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let valid_before = valid_after + (ca.config.days as u64 * 86400); // e.g. 1 year

                    let mut cert_builder = ssh_key::certificate::Builder::new_with_random_nonce(
                        &mut rand::thread_rng(),
                        key.public_key(),
                        valid_after,
                        valid_before,
                    )
                    .unwrap();
                    cert_builder.serial(0).unwrap();
                    cert_builder.key_id("root").unwrap();
                    cert_builder
                        .cert_type(ssh_key::certificate::CertType::User)
                        .unwrap();
                    cert_builder.valid_principal("invalid").unwrap();
                    cert_builder.comment(ca.config.common_name.clone()).unwrap();
                    let cert = cert_builder.sign(&key).unwrap();
                    let sshc = SshCertificate::new(m, Some(key.key_data().to_owned()), cert);
                    let root = CaCertificate::from_existing_ssh(
                        ca.medium.clone(),
                        sshc,
                        "root".to_string(),
                        0,
                    );
                    root.save_to_medium(&mut ca, "").await;
                    ca.root_cert = Ok(root);
                } else if let Some(_superior) = superior {
                    todo!("Intermediate certificate authority generation not implemented");
                } else {
                    todo!("Intermediate certificate authority generation not possible");
                }
            }
        }
        Ok(ca)
    }

    /// Return a reference to the root cert
    pub fn root_ca_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.root_cert.as_ref()
    }

    /// Return a reference to the ocsp cert
    pub fn ocsp_ca_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.ocsp_signer.as_ref()
    }

    /// Returns true if the provided certificate is an admin certificate
    pub async fn is_admin(&self, cert: &x509_cert::Certificate) -> bool {
        let mut any_admin = false;
        if let Some(admin) = &self.super_admin {
            any_admin = true;
            let admin_x509_cert = admin.x509_cert();
            if let Ok(admin_x509_cert) = admin_x509_cert {
                if cert.tbs_certificate.serial_number
                    == admin_x509_cert.tbs_certificate.serial_number
                    && cert.tbs_certificate.subject == admin_x509_cert.tbs_certificate.subject
                    && cert.tbs_certificate.issuer == admin_x509_cert.tbs_certificate.issuer
                {
                    return true;
                }
            }
        }
        if let Ok(admin) = &self.admin {
            any_admin = true;
            let admin_x509_cert = admin.x509_cert();
            if let Ok(admin_x509_cert) = admin_x509_cert {
                if cert.tbs_certificate.serial_number
                    == admin_x509_cert.tbs_certificate.serial_number
                    && cert.tbs_certificate.subject == admin_x509_cert.tbs_certificate.subject
                    && cert.tbs_certificate.issuer == admin_x509_cert.tbs_certificate.issuer
                {
                    return true;
                }
            }
        }
        if !any_admin {
            service::log::error!("No admin certificate for admin operations available");
        }
        false
    }

    /// Performs an iteration of all certificates, processing them with the given closure.
    pub async fn certificate_processing<'a, F>(&'a self, mut process: F)
    where
        F: FnMut(usize, x509_cert::Certificate, u64) + Send + 'a,
    {
        let (s, mut r) = tokio::sync::mpsc::unbounded_channel();

        let self2_medium = self.medium.to_owned();
        tokio::spawn(async move {
            use der::Decode;
            match self2_medium {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::Sqlite(p) => {
                    p.conn(move |conn| {
                        let mut stmt = conn.prepare("SELECT * from certs").unwrap();
                        let mut rows = stmt.query([]).unwrap();
                        let mut index = 0;
                        while let Ok(Some(r)) = rows.next() {
                            let id = r.get(0).unwrap();
                            let der: Vec<u8> = r.get(1).unwrap();
                            let cert: x509_cert::Certificate =
                                x509_cert::Certificate::from_der(&der).unwrap();
                            s.send((index, cert, id)).unwrap();
                            index += 1;
                        }
                        Ok(())
                    })
                    .await
                    .unwrap();
                }
            }
        });
        while let Some((index, csr, id)) = r.recv().await {
            process(index, csr, id);
        }
    }

    /// Performs an iteration of all csr that are not done, processing them with the given closure.
    pub async fn csr_processing<'a, F>(&'a self, mut process: F)
    where
        F: FnMut(usize, CsrRequest, u64) + Send + 'a,
    {
        let (s, mut r) = tokio::sync::mpsc::unbounded_channel();

        let self2_medium = self.medium.to_owned();
        tokio::spawn(async move {
            match self2_medium {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::Sqlite(p) => {
                    p.conn(move |conn| {
                        let mut stmt = conn.prepare("SELECT * from csr WHERE done='0'").unwrap();
                        let mut rows = stmt.query([]).unwrap();
                        let mut index = 0;
                        while let Ok(Some(r)) = rows.next() {
                            let id = r.get(0).unwrap();
                            let dbentry = DbEntry::new(r);
                            let csr = dbentry.into();
                            s.send((index, csr, id)).unwrap();
                            index += 1;
                        }
                        Ok(())
                    })
                    .await
                    .unwrap();
                }
            }
        });
        while let Some((index, csr, id)) = r.recv().await {
            process(index, csr, id);
        }
    }

    /// Performs an iteration of all ssh request that are not done, processing them with the given closure.
    pub async fn ssh_processing<'a, F>(&'a self, mut process: F)
    where
        F: FnMut(usize, SshRequest, u64) + Send + 'a,
    {
        let (s, mut r) = tokio::sync::mpsc::unbounded_channel();

        let self2_medium = self.medium.to_owned();
        tokio::spawn(async move {
            match self2_medium {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::Sqlite(p) => {
                    p.conn(move |conn| {
                        let mut stmt = conn.prepare("SELECT * from sshr WHERE done='0'").unwrap();
                        let mut rows = stmt.query([]).unwrap();
                        let mut index = 0;
                        while let Ok(Some(r)) = rows.next() {
                            let id = r.get(0).unwrap();
                            let dbentry = DbEntry::new(r);
                            let csr = dbentry.into();
                            s.send((index, csr, id)).unwrap();
                            index += 1;
                        }
                        Ok(())
                    })
                    .await
                    .unwrap();
                }
            }
        });
        while let Some((index, csr, id)) = r.recv().await {
            process(index, csr, id);
        }
    }

    /// Retrieve the specified index of user certificate
    pub async fn get_user_cert(&self, id: u64) -> Option<Vec<u8>> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<Vec<u8>, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row(
                            &format!("SELECT der FROM certs WHERE id='{}'", id),
                            [],
                            |r| r.get(0),
                        )
                    })
                    .await;
                match cert {
                    Ok(c) => Some(c),
                    Err(_e) => None,
                }
            }
        }
    }

    /// Retrieve the reason the csr was rejected
    pub async fn get_rejection_reason_by_id(&self, id: u64) -> Option<String> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => match &self.config.sign_method {
                cert_common::CertificateSigningMethod::Https(_) => {
                    let cert: Result<CsrRejection, async_sqlite::Error> = p
                        .conn(move |conn| {
                            conn.query_row(
                                &format!("SELECT * FROM csr WHERE id='{}'", id),
                                [],
                                |r| {
                                    let dbentry = DbEntry::new(r);
                                    let csr = dbentry.into();
                                    Ok(csr)
                                },
                            )
                        })
                        .await;
                    let rejection: Option<CsrRejection> = cert.ok();
                    rejection.map(|r| r.rejection)
                }
                cert_common::CertificateSigningMethod::Ssh(_) => {
                    let cert: Result<SshRejection, async_sqlite::Error> = p
                        .conn(move |conn| {
                            conn.query_row(
                                &format!("SELECT * FROM sshr WHERE id='{}'", id),
                                [],
                                |r| {
                                    let dbentry = DbEntry::new(r);
                                    let csr = dbentry.into();
                                    Ok(csr)
                                },
                            )
                        })
                        .await;
                    let rejection: Option<SshRejection> = cert.ok();
                    rejection.map(|r| r.rejection)
                }
            },
        }
    }

    /// Reject an existing certificate signing request by id.
    pub async fn reject_csr_by_id(
        &mut self,
        id: u64,
        reason: &String,
    ) -> Result<(), CertificateSigningError> {
        let csr = self.get_csr_by_id(id).await;
        if csr.is_none() {
            return Err(CertificateSigningError::CsrDoesNotExist);
        }
        let csr = csr.unwrap();
        let reject = CsrRejection::from_csr_with_reason(csr, reason);
        self.store_rejection(&reject).await?;
        Ok(())
    }

    /// Store a rejection struct
    async fn store_rejection(
        &mut self,
        reject: &CsrRejection,
    ) -> Result<(), CertificateSigningError> {
        match &self.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::Sqlite(p) => {
                let rejection = reject.rejection.to_owned();
                let id = reject.id;
                let s = p
                    .conn(move |conn| {
                        let mut stmt = conn
                            .prepare(&format!(
                                "UPDATE csr SET 'rejection' = $1 WHERE id='{}'",
                                id
                            ))
                            .unwrap();
                        stmt.execute([rejection.to_sql().unwrap()])
                    })
                    .await;
                self.mark_csr_done(id).await;
                match s {
                    Err(_) => Err(CertificateSigningError::FailedToDeleteRequest),
                    Ok(_) => Ok(()),
                }
            }
        }
    }

    /// Retrieve a https certificate signing request by id, if it exists
    pub async fn get_csr_by_id(&self, id: u64) -> Option<CsrRequest> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<CsrRequest, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row(&format!("SELECT * FROM csr WHERE id='{}'", id), [], |r| {
                            let dbentry = DbEntry::new(r);
                            let csr = dbentry.into();
                            Ok(csr)
                        })
                    })
                    .await;
                match cert {
                    Ok(c) => Some(c),
                    Err(e) => {
                        service::log::error!("Error retrieving csr {:?}", e);
                        None
                    }
                }
            }
        }
    }

    /// Retrieve a ssh certificate signing request by id, if it exists
    pub async fn get_ssh_request_by_id(&self, id: u64) -> Option<SshRequest> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<SshRequest, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row(&format!("SELECT * FROM sshr WHERE id='{}'", id), [], |r| {
                            let dbentry = DbEntry::new(r);
                            let csr = dbentry.into();
                            Ok(csr)
                        })
                    })
                    .await;
                match cert {
                    Ok(c) => Some(c),
                    Err(e) => {
                        service::log::error!("Error retrieving sshr {:?}", e);
                        None
                    }
                }
            }
        }
    }

    /// Save an ssh request to the storage medium
    pub async fn save_ssh_request(&mut self, sshr: &SshRequest) -> Result<(), ()> {
        match &self.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::Sqlite(p) => {
                let csr = sshr.to_owned();
                p.conn(move |conn| {
                    let principals = csr.principals.join("/n");
                    let mut stmt = conn.prepare("INSERT INTO sshr (id, requestor, email, phone, pubkey, principals, comment, usage) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)").expect("Failed to build statement");
                    stmt.execute([
                        csr.id.to_sql().unwrap(),
                        csr.name.to_sql().unwrap(),
                        csr.email.to_sql().unwrap(),
                        csr.phone.to_sql().unwrap(),
                        csr.pubkey.to_sql().unwrap(),
                        principals.to_sql().unwrap(),
                        csr.comment.to_sql().unwrap(),
                        csr.usage.to_sql().unwrap(),
                    ]).expect("Failed to insert ssh request");
                    Ok(())
                }).await.expect("Failed to insert ssh request");
                Ok(())
            }
        }
    }

    /// Save the csr to the storage medium
    pub async fn save_csr(&mut self, csr: &CsrRequest) -> Result<(), ()> {
        match &self.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::Sqlite(p) => {
                let csr = csr.to_owned();
                p.conn(move |conn| {
                    let mut stmt = conn.prepare("INSERT INTO csr (id, requestor, email, phone, pem) VALUES (?1, ?2, ?3, ?4, ?5)").expect("Failed to build statement");
                    stmt.execute([
                        csr.id.to_sql().unwrap(),
                        csr.name.to_sql().unwrap(),
                        csr.email.to_sql().unwrap(),
                        csr.phone.to_sql().unwrap(),
                        csr.cert.to_sql().unwrap(),
                    ]).expect("Failed to insert csr");
                    Ok(())
                }).await.expect("Failed to insert csr");
                Ok(())
            }
        }
    }

    /// Get the dates the ca is valid
    pub fn get_validity(&self) -> Option<x509_cert::time::Validity> {
        if let Ok(root) = &self.root_cert {
            match &root.data {
                CertificateData::Https(m) => m.x509_cert().map(|c| c.tbs_certificate.validity).ok(),
                CertificateData::Ssh(m) => {
                    let after = m.cert.valid_after_time();
                    let before = m.cert.valid_before_time();

                    Some(x509_cert::time::Validity {
                        not_before: x509_cert::time::Time::UtcTime(
                            UtcTime::from_system_time(after).ok()?,
                        ),
                        not_after: x509_cert::time::Time::UtcTime(
                            UtcTime::from_system_time(before).ok()?,
                        ),
                    })
                }
            }
        } else {
            None
        }
    }

    /// Marks the specified csr as done
    pub async fn mark_csr_done(&mut self, id: u64) -> Result<(), ()> {
        match &self.medium {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::Sqlite(p) => {
                p.conn(move |conn| {
                    conn.execute(&format!("UPDATE csr SET done=1 WHERE id='{}'", id), [])
                })
                .await
                .map_err(|_| ())?;
            }
        }
        Ok(())
    }

    /// Save the user cert of the specified index to storage
    pub async fn save_user_cert(&mut self, id: u64, der: &[u8], sn: &[u8]) {
        match &self.medium {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::Sqlite(p) => {
                let cert_der = der.to_owned();
                p.conn(move |conn| {
                    let mut stmt = conn
                        .prepare("INSERT INTO certs (id, der) VALUES (?1, ?2)")
                        .expect("Failed to build prepared statement");
                    stmt.execute([id.to_sql().unwrap(), cert_der.to_sql().unwrap()])
                })
                .await
                .expect("Failed to insert certificate");
                let serial = sn.to_owned();
                p.conn(move |conn| {
                    let mut stmt = conn
                        .prepare("INSERT INTO serials (id, serial) VALUES (?1, ?2)")
                        .expect("Failed to build prepared statement");
                    stmt.execute([id.to_sql().unwrap(), serial.to_sql().unwrap()])
                })
                .await
                .expect("Failed to insert serial number for certificate");
            }
        }
    }

    /// Returns the ocsp url, based on the application settings, preferring https over http
    pub fn get_ocsp_urls(settings: &crate::ca::CaConfiguration) -> Result<Vec<String>, ()> {
        let mut urls = Vec::new();

        for san in &settings.san {
            let san: &str = san.as_str();

            let mut url = String::new();
            let mut port_override = None;
            if let Some(p) = settings.https_port {
                let default_port = 443;
                if p != default_port {
                    port_override = Some(p);
                }
                url.push_str("https://");
            } else if let Some(p) = settings.http_port {
                let default_port = 80;
                if p != default_port {
                    port_override = Some(p);
                }
                url.push_str("http://");
            } else {
                return Err(());
            }

            url.push_str(san);
            if let Some(p) = port_override {
                url.push_str(&format!(":{}", p));
            }

            let proxy = if let Some(p) = &settings.proxy { p } else { "" };

            let pki = settings.get_pki_name();
            url.push('/');
            url.push_str(proxy);
            url.push_str(pki);
            url.push_str("ca/ocsp");
            urls.push(url);
        }

        Ok(urls)
    }

    /// Retrieves a certificate, if it is valid, or a reason for it to be invalid
    /// # Arguments
    /// * serial - The serial number of the certificate
    async fn get_cert_by_serial(
        &self,
        serial: &[u8],
    ) -> MaybeError<x509_cert::Certificate, ocsp::response::RevokedInfo> {
        let s_str: Vec<String> = serial.iter().map(|v| format!("{:02X}", v)).collect();
        let s_str = s_str.concat();
        service::log::info!("Looking for serial number {}", s_str);
        match &self.medium {
            CaCertificateStorage::Nowhere => MaybeError::None,
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<Vec<u8>, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row(
                            &format!("SELECT der FROM certs INNER JOIN serials ON certs.id = serials.id WHERE serial=x'{}'", s_str),
                            [],
                            |r| r.get(0),
                        )
                    })
                    .await;
                match cert {
                    Ok(c) => {
                        use der::Decode;
                        let c = x509_cert::Certificate::from_der(&c);
                        match c {
                            Ok(c) => {
                                service::log::info!("Found the cert");
                                MaybeError::Ok(c)
                            }
                            Err(_e) => MaybeError::None,
                        }
                    }
                    Err(e) => {
                        service::log::error!("Did not find the cert {:?}", e);
                        MaybeError::None
                    }
                }
            }
        }
    }

    /// Attempt to load a certificate by id
    async fn load_user_cert(&self, id: u64) -> Result<CaCertificate, CertificateLoadingError> {
        match &self.medium {
            CaCertificateStorage::Nowhere => Err(CertificateLoadingError::DoesNotExist),
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<Vec<u8>, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row("SELECT der FROM certs WHERE id=?1", [id], |r| r.get(0))
                    })
                    .await;
                match cert {
                    Ok(c) => {
                        use der::Decode;
                        let c = x509_cert::Certificate::from_der(&c)
                            .map_err(|_| CertificateLoadingError::InvalidCert)?;
                        let cac = CaCertificate {
                            medium: self.medium.clone(),
                            data: CertificateData::from_x509(c)?,
                            name: "".to_string(), //TODO fill this in with data from the certificate subject name
                            id,
                        };
                        service::log::info!("Found the cert");
                        Ok(cac)
                    }
                    Err(e) => {
                        service::log::error!("Did not find the cert {:?}", e);
                        Err(CertificateLoadingError::DoesNotExist)
                    }
                }
            }
        }
    }

    /// Attempt to load a certificate by name, first from hsm, then from p12
    async fn load_cert(
        &self,
        hsm: Arc<crate::hsm2::Hsm>,
        name: &str,
        password: Option<&str>,
    ) -> Result<CaCertificate, CertificateLoadingError> {
        let hsm_name = format!("{}-{}", self.config.common_name, name);
        if let Ok(cert) = self.medium.load_hsm_from_medium(hsm, &hsm_name).await {
            Ok(cert)
        } else if let Ok(rc) = self.medium.load_p12_from_medium(&hsm_name).await {
            if let Some(password) = password {
                Ok(cert_common::pkcs12::Pkcs12::load_from_data(
                    &rc.contents,
                    password.as_bytes(),
                    rc.id,
                )
                .try_into()
                .map_err(|_| CertificateLoadingError::InvalidCert)?)
            } else {
                use der::Decode;
                let x509 = x509_cert::Certificate::from_der(&rc.contents)
                    .map_err(|_| CertificateLoadingError::InvalidCert)?;
                let cert = CaCertificate {
                    medium: self.medium.clone(),
                    data: CertificateData::from_x509(x509)
                        .map_err(|_| CertificateLoadingError::InvalidCert)?,
                    name: hsm_name.clone(),
                    id: rc.id,
                };
                Ok(cert)
            }
        } else {
            service::log::debug!("{} does not exist 2", name);
            Err(CertificateLoadingError::DoesNotExist)
        }
    }

    /// Load ca stuff
    pub async fn load(
        hsm: Arc<crate::hsm2::Hsm>,
        settings: &crate::ca::CaConfiguration,
    ) -> Result<Self, CaLoadError> {
        let mut ca = Self::from_config(settings).await?;

        // These will error when the ca needs to be built
        match &ca.config.sign_method {
            CertificateSigningMethod::Https(_m) => {
                ca.load_ocsp_cert(hsm.clone()).await?;
                match &settings.admin_cert {
                    CertificateType::Soft(p) => {
                        ca.load_admin_cert(hsm.clone(), p)
                            .await
                            .map_err(|e| CaLoadError::CertificateLoadingError(e.to_owned()))?;
                    }
                    CertificateType::SmartCard(_p) => {
                        ca.load_admin_smartcard(hsm.clone())
                            .await
                            .map_err(|e| CaLoadError::CertificateLoadingError(e.to_owned()))?;
                    }
                }

                ca.load_root_ca_cert(hsm)
                    .await
                    .map_err(|e| CaLoadError::CertificateLoadingError(e.to_owned()))?;
            }
            CertificateSigningMethod::Ssh(_m) => {
                ca.load_root_ca_cert(hsm)
                    .await
                    .map_err(|e| CaLoadError::CertificateLoadingError(e.to_owned()))?;
            }
        }
        Ok(ca)
    }

    /// Load the root ca cert from the specified storage media, converting to der as required.
    pub async fn load_root_ca_cert(
        &mut self,
        hsm: Arc<crate::hsm2::Hsm>,
    ) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.root_cert.is_err() {
            self.root_cert = self.load_cert(hsm, "root", None).await;
        }
        self.root_cert.as_ref()
    }

    /// Get the protected admin certificate, only useful for soft admin tokens
    pub async fn get_admin_cert(&self) -> Result<CaCertificate, CertificateLoadingError> {
        if let CertificateType::Soft(p) = &self.config.admin_cert {
            if let Ok(rc) = self.medium.load_p12_from_medium("admin").await {
                Ok(
                    cert_common::pkcs12::Pkcs12::load_from_data(&rc.contents, p.as_bytes(), rc.id)
                        .try_into()
                        .map_err(|_| CertificateLoadingError::InvalidCert)?,
                )
            } else {
                Err(CertificateLoadingError::DoesNotExist)
            }
        } else {
            Err(CertificateLoadingError::DoesNotExist)
        }
    }

    /// Returns the already loaded admin key
    pub fn examine_admin_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.admin.as_ref()
    }

    /// Load the admin certificate as defined by a smartcard certificate
    pub async fn load_admin_smartcard(
        &mut self,
        hsm: Arc<crate::hsm2::Hsm>,
    ) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.admin.is_err() {
            self.admin = self.load_cert(hsm, "admin", None).await.map(|mut a| {
                a.erase_private_key();
                a
            });
        }
        self.admin.as_ref()
    }

    /// Load the admin signer certificate, loading if required and erasing the private key.
    pub async fn load_admin_cert(
        &mut self,
        hsm: Arc<crate::hsm2::Hsm>,
        password: &str,
    ) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.admin.is_err() {
            self.admin = self
                .load_cert(hsm, "admin", Some(password))
                .await
                .map(|mut a| {
                    a.erase_private_key();
                    a
                });
        }
        self.admin.as_ref()
    }

    /// Load the ocsp signer certificate, loading if required.
    pub async fn load_ocsp_cert(
        &mut self,
        hsm: Arc<crate::hsm2::Hsm>,
    ) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.ocsp_signer.is_err() {
            self.ocsp_signer = self.load_cert(hsm, "ocsp", None).await;
        }
        self.ocsp_signer.as_ref()
    }

    /// Insert a super admin certificate if one does not already exist.
    pub fn insert_super_admin(&mut self, admin: CaCertificate) {
        if self.super_admin.is_none() {
            self.super_admin.replace(admin);
        }
    }

    /// Add an admin certificate from a superior certificate authority. A superior authority is one that is directly or indirectly responsible for creating this authority.
    pub fn add_superior_admin(&mut self, admin: CaCertificate) {
        self.admin_authorities.push(admin);
    }

    /// Retrieve a copy of all superior admin certificates, used for building the proper chain of superior admin certificates.
    pub fn get_superior_admin(&self) -> Vec<CaCertificate> {
        self.admin_authorities.clone()
    }

    /// Create a Self from the application configuration
    pub async fn from_config(settings: &crate::ca::CaConfiguration) -> Result<Self, CaLoadError> {
        let medium = settings
            .path
            .build()
            .await
            .map_err(|e| CaLoadError::StorageError(e))?;
        Ok(Self {
            medium,
            root_cert: Err(CertificateLoadingError::DoesNotExist),
            ocsp_signer: Err(CertificateLoadingError::DoesNotExist),
            admin: Err(CertificateLoadingError::DoesNotExist),
            ocsp_urls: Self::get_ocsp_urls(settings)
                .map_err(|_| CaLoadError::FailedToBuildOcspUrl)?,
            admin_access: Zeroizing::new(settings.admin_access_password.to_string()),
            config: settings.to_owned(),
            super_admin: None,
            admin_authorities: Vec::new(),
        })
    }

    /// Get a new request id, if possible
    pub async fn get_new_request_id(&mut self) -> Option<u64> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => p
                .conn(|conn| {
                    conn.execute("INSERT INTO id VALUES (NULL)", [])?;
                    Ok(conn.last_insert_rowid())
                })
                .await
                .ok()
                .map(|v| v as u64),
        }
    }

    /// Get the status of the status, part of handling an ocsp request
    /// # Arguments
    /// * root_cert - The root certificate of the ca authority
    /// * certid - The certid from an ocsp request to check
    pub async fn get_cert_status(
        &self,
        root_cert: &x509_cert::Certificate,
        certid: &ocsp::common::asn1::CertId,
    ) -> Result<ocsp::response::CertStatus, ()> {
        let oid_der = certid.hash_algo.to_der_raw().map_err(|_| ())?;
        let oid: yasna::models::ObjectIdentifier = yasna::decode_der(&oid_der).map_err(|_| ())?;

        let mut revoke_reason = None;
        let mut status = ocsp::response::CertStatusCode::Unknown;

        let hash = if oid == OID_HASH_SHA1.to_yasna() {
            service::log::info!("Using sha1 for hashing");
            HashType::Sha1
        } else {
            service::log::error!("Unknown OID for hash is {:?}", oid);
            HashType::Unknown
        };

        let dn = {
            use der::Encode;
            root_cert.tbs_certificate.subject.to_der().map_err(|_| ())?
        };
        let dnhash = hash.hash(&dn).ok_or(())?;

        if dnhash == certid.issuer_name_hash {
            let key2 = root_cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let keyhash = hash.hash(key2).ok_or(())?;
            if keyhash == certid.issuer_key_hash {
                let cert = self.get_cert_by_serial(&certid.serial_num).await;
                match cert {
                    MaybeError::Ok(_cert) => {
                        status = ocsp::response::CertStatusCode::Good;
                    }
                    MaybeError::Err(e) => {
                        status = ocsp::response::CertStatusCode::Revoked;
                        revoke_reason = Some(e);
                    }
                    MaybeError::None => {
                        status = ocsp::response::CertStatusCode::Revoked;
                        let reason = ocsp::response::CrlReason::OcspRevokeUnspecified;
                        revoke_reason = Some(ocsp::response::RevokedInfo::new(
                            ocsp::common::asn1::GeneralizedTime::now(),
                            Some(reason),
                        ))
                    }
                }
            }
        }

        Ok(ocsp::response::CertStatus::new(status, revoke_reason))
    }
}

/// Errors that can occur when signing a csr
#[allow(dead_code)]
pub enum CertificateSigningError {
    /// The requested csr does not exist
    CsrDoesNotExist,
    /// Unable to delete the request after processing
    FailedToDeleteRequest,
    /// The issuer is unable to sign
    UnableToSign,
    /// The generated x509 cert is unusable for some reason
    UndecipherableX509Generated,
}

/// The types of methods that can be specified by authority info access
#[derive(Debug)]
pub enum AuthorityInfoAccess {
    /// Info is by ocsp provider at the specified url
    Ocsp(String),
    /// Unknown authority info access
    Unknown(String),
}

impl TryFrom<&AccessDescription> for AuthorityInfoAccess {
    type Error = ();
    fn try_from(value: &AccessDescription) -> Result<Self, Self::Error> {
        let s = match &value.access_location {
            x509_cert::ext::pkix::name::GeneralName::OtherName(_a) => {
                return Err(());
            }
            x509_cert::ext::pkix::name::GeneralName::Rfc822Name(_a) => {
                return Err(());
            }
            x509_cert::ext::pkix::name::GeneralName::DnsName(a) => {
                let s: &str = a.as_ref();
                s.to_string()
            }
            x509_cert::ext::pkix::name::GeneralName::DirectoryName(_a) => {
                return Err(());
            }
            x509_cert::ext::pkix::name::GeneralName::EdiPartyName(_a) => {
                return Err(());
            }
            x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(a) => {
                let s: &str = a.as_ref();
                s.to_string()
            }
            x509_cert::ext::pkix::name::GeneralName::IpAddress(a) => {
                String::from_utf8(a.as_bytes().to_vec()).map_err(|_| ())?
            }
            x509_cert::ext::pkix::name::GeneralName::RegisteredId(_a) => {
                return Err(());
            }
        };
        if value.access_method == OID_OCSP.to_const() {
            Ok(Self::Ocsp(s))
        } else {
            Ok(Self::Unknown(s))
        }
    }
}

/// The types of attributes that can be present in a certificate
#[allow(dead_code)]
pub enum CertAttribute {
    /// The alternate names for the certificate
    SubjectAlternativeName(Vec<String>),
    /// The subject key identifier
    SubjectKeyIdentifier(Vec<u8>),
    /// What the certificate can be used for
    ExtendedKeyUsage(Vec<cert_common::ExtendedKeyUsage>),
    /// The basic constraints extension
    BasicContraints {
        /// Is this certificate a certificate authority
        ca: bool,
        /// How deep can the nesting of certificate authorities go?
        path_len: u8,
    },
    /// Authority info access
    AuthorityInfoAccess(Vec<AuthorityInfoAccess>),
    /// All other types of attributes
    Unrecognized(Oid, der::asn1::OctetString),
}

impl CertAttribute {
    #[allow(dead_code)]
    /// Build a cert attribute from an oid and octetstring
    pub fn with_oid_and_data(oid: Oid, data: der::asn1::OctetString) -> Result<Self, ()> {
        if oid == *OID_CERT_EXTENDED_KEY_USAGE {
            let oids: Vec<yasna::models::ObjectIdentifier> =
                yasna::parse_der(data.as_bytes(), |r| r.collect_sequence_of(|r| r.read_oid()))
                    .map_err(|_| ())?;
            let eku = oids
                .iter()
                .map(|o| Oid::from_yasna(o.clone()).into())
                .collect();
            Ok(Self::ExtendedKeyUsage(eku))
        } else if oid == *OID_CERT_ALTERNATIVE_NAME {
            let names: Vec<String> = yasna::parse_der(data.as_bytes(), |r| {
                r.collect_sequence_of(|r| {
                    let der = r.read_tagged_der()?;
                    let string = String::from_utf8(der.value().to_vec())
                        .map_err(|_| yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid))?;
                    Ok(string)
                })
            })
            .map_err(|_| ())?;
            Ok(Self::SubjectAlternativeName(names))
        } else if oid == *OID_CERT_SUBJECT_KEY_IDENTIFIER {
            let data: Vec<u8> = yasna::decode_der(data.as_bytes()).map_err(|_| ())?;
            Ok(Self::SubjectKeyIdentifier(data))
        } else if oid == *OID_CERT_BASIC_CONSTRAINTS {
            let (ca, len) = yasna::parse_der(data.as_bytes(), |r| {
                r.read_sequence(|r| {
                    let ca = r.next().read_bool()?;
                    let len = r.next().read_u8()?;
                    Ok((ca, len))
                })
            })
            .map_err(|_| ())?;
            Ok(Self::BasicContraints { ca, path_len: len })
        } else if oid == *OID_PKIX_AUTHORITY_INFO_ACCESS {
            use der::Decode;
            let aia = x509_cert::ext::pkix::AuthorityInfoAccessSyntax::from_der(data.as_bytes())
                .map_err(|_| ())?;
            let aias: Vec<AuthorityInfoAccess> = aia
                .0
                .iter()
                .map(|a| a.try_into().map_err(|_| ()).unwrap()) //TODO remove this unwrap
                .collect();
            Ok(Self::AuthorityInfoAccess(aias))
        } else {
            Ok(Self::Unrecognized(oid, data))
        }
    }
}

/// Contains a user signing request for a certificate
#[derive(serde::Deserialize, serde::Serialize)]
pub struct CsrRejection {
    /// The actual certificate request in pem format
    cert: String,
    /// The name of the person issuing the request
    name: String,
    /// The email of the person issuing the request
    email: String,
    /// The phone number of the person issuing the request
    phone: String,
    /// The reason for rejection
    pub rejection: String,
    /// The id for the csr
    pub id: u64,
}

impl CsrRejection {
    #[allow(dead_code)]
    /// Build a new Self, with the csr and the reason.
    pub fn from_csr_with_reason(csr: CsrRequest, reason: &String) -> Self {
        Self {
            cert: csr.cert,
            name: csr.name,
            email: csr.email,
            phone: csr.phone,
            rejection: reason.to_owned(),
            id: csr.id,
        }
    }
}

/// Contains a user signing request for a certificate
#[derive(serde::Deserialize, serde::Serialize)]
pub struct SshRejection {
    /// The principals for the ssh cert
    principals: Vec<String>,
    /// The name of the person issuing the request
    name: String,
    /// The email of the person issuing the request
    email: String,
    /// The phone number of the person issuing the request
    phone: String,
    /// The reason for rejection
    pub rejection: String,
    /// The id for the csr
    pub id: u64,
}

impl SshRejection {
    #[allow(dead_code)]
    /// Build a new Self, with the csr and the reason.
    pub fn from_csr_with_reason(csr: SshRequest, reason: &String) -> Self {
        Self {
            principals: csr.principals.clone(),
            name: csr.name,
            email: csr.email,
            phone: csr.phone,
            rejection: reason.to_owned(),
            id: csr.id,
        }
    }
}

/// The database form of an entry
pub struct DbEntry<'a> {
    /// The row contents
    row_data: &'a async_sqlite::rusqlite::Row<'a>,
}

impl<'a> DbEntry<'a> {
    #[allow(dead_code)]
    /// Construct a new Self from a sqlite row
    pub fn new(row: &'a async_sqlite::rusqlite::Row<'a>) -> Self {
        Self { row_data: row }
    }
}

/// TODO: Convert to tryfrom
impl<'a> From<DbEntry<'a>> for CsrRequest {
    fn from(val: DbEntry<'a>) -> Self {
        Self {
            cert: val.row_data.get(4).unwrap(),
            name: val.row_data.get(1).unwrap(),
            email: val.row_data.get(2).unwrap(),
            phone: val.row_data.get(3).unwrap(),
            id: val.row_data.get(0).unwrap(),
        }
    }
}

/// TODO: Convert to tryfrom
impl<'a> From<DbEntry<'a>> for SshRequest {
    fn from(val: DbEntry<'a>) -> Self {
        let p: String = val.row_data.get(5).unwrap();
        Self {
            name: val.row_data.get(1).unwrap(),
            email: val.row_data.get(2).unwrap(),
            phone: val.row_data.get(3).unwrap(),
            id: val.row_data.get(0).unwrap(),
            pubkey: val.row_data.get(4).unwrap(),
            principals: p.lines().map(|a| a.to_string()).collect(),
            comment: val.row_data.get(6).unwrap(),
            usage: val.row_data.get(7).unwrap(),
        }
    }
}

/// TODO: Convert to tryfrom
impl<'a> From<DbEntry<'a>> for CsrRejection {
    fn from(val: DbEntry<'a>) -> Self {
        Self {
            cert: val.row_data.get(4).unwrap(),
            name: val.row_data.get(1).unwrap(),
            email: val.row_data.get(2).unwrap(),
            phone: val.row_data.get(3).unwrap(),
            rejection: val.row_data.get(5).unwrap(),
            id: val.row_data.get(0).unwrap(),
        }
    }
}

/// TODO: Convert to tryfrom
impl<'a> From<DbEntry<'a>> for SshRejection {
    fn from(val: DbEntry<'a>) -> Self {
        let p: String = val.row_data.get(5).unwrap();
        Self {
            name: val.row_data.get(1).unwrap(),
            email: val.row_data.get(2).unwrap(),
            phone: val.row_data.get(3).unwrap(),
            id: val.row_data.get(0).unwrap(),
            principals: p.lines().map(|a| a.to_string()).collect(),
            rejection: val.row_data.get(8).unwrap(),
        }
    }
}

/// Represents a raw certificate signing request, in pem format
pub struct RawCsrRequest {
    /// The csr, in pem format
    pub pem: String,
}

/// Errors that can occur when verifying a signature
pub enum SignatureVerifyError {
    /// The signature is invalid
    SignatureVerificationFailed,
    /// The mechanism for signing is not supported
    UnsupportedSignatureMechanism,
    /// The csr is invalid
    InvalidCsr,
}

impl RawCsrRequest {
    /// Verifies the signature on the request
    pub fn verify_request(&self) -> Result<(), SignatureVerifyError> {
        let pem = pem::parse(&self.pem).unwrap();
        let der = pem.contents();
        let parsed = yasna::parse_der(der, |r| {
            let info = r.read_sequence(|r| {
                let a = r.next().read_der()?;
                let (sig_alg, sig_param) = r.next().read_sequence(|r| {
                    let alg = r.next().read_oid()?;
                    let param = if alg == OID_PKCS1_SHA256_RSA_ENCRYPTION.to_yasna() {
                        r.next().read_null()?;
                        Ok(der::asn1::Any::null())
                    } else if alg == OID_ECDSA_P256_SHA256_SIGNING.to_yasna() {
                        Ok(der::asn1::Any::null())
                    } else {
                        Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid))
                    }?;
                    Ok((alg, param))
                })?;
                let (sig, _) = r.next().read_bitvec_bytes()?;
                Ok((a, sig_alg, sig_param, sig))
            })?;
            Ok(info)
        });
        if let Ok((info, alg, alg_param, sig)) = parsed {
            use der::Decode;
            use der::Encode;
            use yasna::parse_der;
            let cinfo = x509_cert::request::CertReqInfo::from_der(&info)
                .map_err(|_| SignatureVerifyError::InvalidCsr)?;
            let pubkey = cinfo.public_key.subject_public_key;
            let pder = pubkey
                .to_der()
                .map_err(|_| SignatureVerifyError::InvalidCsr)?;
            let pkey = parse_der(&pder, |r| {
                let (data, _size) = r.read_bitvec_bytes()?;
                Ok(data)
            })
            .map_err(|_| SignatureVerifyError::InvalidCsr)?;

            let signature = if let Ok(alg) = alg.try_into() {
                InternalSignature::make_ring(alg, pkey, info, sig)
            } else {
                return Err(SignatureVerifyError::UnsupportedSignatureMechanism);
            };
            signature.verify().map_err(|_| {
                service::log::error!("Error verifying the signature2 on the csr 1");
                SignatureVerifyError::SignatureVerificationFailed
            })
        } else {
            Err(SignatureVerifyError::InvalidCsr)
        }
    }
}

/// Contains a user signing request for a certificate
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct SshRequest {
    /// The public key of the ssh key
    pub pubkey: String,
    /// Requested usage for the key (see `ssh_key::certificate::CertType`)
    pub usage: u32,
    /// The principals for the ssh key
    pub principals: Vec<String>,
    /// The comment for the certificate
    pub comment: String,
    /// The name of the person issuing the request
    pub name: String,
    /// The email of the person issuing the request
    pub email: String,
    /// The phone number of the person issuing the request
    pub phone: String,
    /// The id of the request
    pub id: u64,
}

/// Contains a user signing request for a certificate
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct CsrRequest {
    /// The actual certificate request in pem format
    pub cert: String,
    /// The name of the person issuing the request
    pub name: String,
    /// The email of the person issuing the request
    pub email: String,
    /// The phone number of the person issuing the request
    pub phone: String,
    /// The id of the request
    pub id: u64,
}

/// The ways to hash data for the certificate checks
pub enum HashType {
    /// Use the sha1 algorithm
    Sha1,
    /// Unknown algorithm
    Unknown,
}

impl HashType {
    /// Perform a hash on the specified data
    pub fn hash(&self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            HashType::Unknown => None,
            HashType::Sha1 => {
                use sha1::{Digest, Sha1};
                let mut hasher = Sha1::new();
                hasher.update(data);
                Some(hasher.finalize().to_vec())
            }
        }
    }
}

/// Represents a type that can be good, an error, or non-existent.
#[allow(dead_code)]
pub enum MaybeError<T, E> {
    /// The element is good
    Ok(T),
    /// There was an error getting the element
    Err(E),
    /// The item does not exist
    None,
}

impl From<std::io::Error> for CertificateLoadingError {
    fn from(value: std::io::Error) -> Self {
        match value.kind() {
            std::io::ErrorKind::NotFound => CertificateLoadingError::DoesNotExist,
            std::io::ErrorKind::PermissionDenied => CertificateLoadingError::CantOpen,
            _ => CertificateLoadingError::OtherIo(value.to_string()),
        }
    }
}

/// A representation of a signature that can be verified
#[derive(Debug)]
pub enum InternalSignature {
    /// A ring based signature
    Ring {
        /// The public key
        key: ring::signature::UnparsedPublicKey<Vec<u8>>,
        /// The message that was signed
        message: Vec<u8>,
        /// The signature on that message
        sig: Vec<u8>,
    },
    /// an ssh based signature
    Ssh {
        /// The public key
        key: ssh_key::public::PublicKey,
        /// The namespace for the signature
        namespace: String,
        /// The message that was signed
        message: Vec<u8>,
        /// The signature for the message
        sig: Box<ssh_key::SshSig>,
    },
}

impl InternalSignature {
    /// Verify the signature as valid
    pub fn verify(&self) -> Result<(), ()> {
        match self {
            Self::Ring { key, message, sig } => key.verify(message, sig).map_err(|_| ()),
            Self::Ssh {
                key,
                namespace,
                message,
                sig,
            } => key.verify(namespace, message, sig).map_err(|_| ()),
        }
    }

    /// Build a ring signature
    pub fn make_ring(
        algorithm: HttpsSigningMethod,
        key: Vec<u8>,
        message: Vec<u8>,
        sig: Vec<u8>,
    ) -> Self {
        let key = match algorithm {
            HttpsSigningMethod::EcdsaSha256 => ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_ASN1,
                key,
            ),
            HttpsSigningMethod::RsaSha256 => ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                key,
            ),
        };
        Self::Ring { key, message, sig }
    }

    /// Build an ssh signature
    pub fn make_ssh() -> Self {
        todo!();
    }
}

/// The options required to build a signing request for a certificate
pub struct SigningRequestParams {
    /// The hsm to used when using the hsm to generate a certificate
    pub hsm: Option<Arc<crate::hsm2::Hsm>>,
    /// The smartcard keypair to use when using a certifcate for a smartcard
    pub smartcard: Option<crate::card::KeyPair>,
    /// The signing method
    pub t: HttpsSigningMethod,
    /// The name of the certificate
    pub name: String,
    /// The common name for the certificate
    pub common_name: String,
    /// The subject alternative names
    pub names: Vec<String>,
    /// Extensions for the certificate
    pub extensions: Vec<rcgen::CustomExtension>,
    /// The id for the certificate
    pub id: u64,
    /// The number of days the certificate should be valid
    pub days_valid: u32,
}

impl SigningRequestParams {
    /// Construct a signing request based on what options are present
    pub fn generate_request(&self) -> CaCertificateToBeSigned {
        let mut extensions = self.extensions.clone();
        let mut params = rcgen::CertificateParams::new(self.names.clone()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, self.common_name.clone());
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = params.not_before + time::Duration::days(self.days_valid as i64);
        params.custom_extensions.append(&mut extensions);
        let mut sn = [0; 20];
        for (i, b) in self.id.to_le_bytes().iter().enumerate() {
            sn[i] = *b;
        }
        if let Some(hsm) = &self.hsm {
            let keypair = hsm
                .generate_https_keypair(&self.name, self.t, 4096)
                .unwrap();
            use crate::hsm2::KeyPairTrait;
            let rckeypair = keypair.keypair();
            let csr = params.serialize_request(&rckeypair).unwrap();
            let csr_der = csr.der();
            let mut csr = rcgen::CertificateSigningRequestParams::from_der(csr_der).unwrap();
            let sn = rcgen::SerialNumber::from_slice(&sn);
            csr.params.serial_number = Some(sn);

            CaCertificateToBeSigned {
                algorithm: self.t,
                medium: CaCertificateStorage::Nowhere,
                csr,
                keypair: Some(Keypair::Hsm(keypair)),
                name: self.name.clone(),
                id: self.id,
            }
        } else if let Some(keypair) = &self.smartcard {
            let csr = params.serialize_request(&keypair.rcgen()).unwrap();
            let csr_der = csr.der();
            let mut csr = rcgen::CertificateSigningRequestParams::from_der(csr_der).unwrap();
            let sn = rcgen::SerialNumber::from_slice(&sn);
            csr.params.serial_number = Some(sn);

            CaCertificateToBeSigned {
                algorithm: self.t,
                medium: CaCertificateStorage::Nowhere,
                csr,
                keypair: Some(Keypair::SmartCard(keypair.clone())),
                name: self.name.clone(),
                id: self.id,
            }
        } else {
            let (keypair, priva) = self.t.generate_keypair(4096).unwrap();
            let csr = params.serialize_request(&keypair).unwrap();
            let csr_der = csr.der();
            let mut csr = rcgen::CertificateSigningRequestParams::from_der(csr_der).unwrap();
            let sn = rcgen::SerialNumber::from_slice(&sn);
            csr.params.serial_number = Some(sn);

            CaCertificateToBeSigned {
                algorithm: self.t,
                medium: CaCertificateStorage::Nowhere,
                csr,
                keypair: Some(Keypair::NotHsm(priva)),
                name: self.name.clone(),
                id: self.id,
            }
        }
    }
}
