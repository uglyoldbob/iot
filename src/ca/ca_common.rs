//! Common code for a certificate authority, used from both using the certificate authority and constructing a certificate authority.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use async_sqlite::rusqlite::ToSql;
use cert_common::oid::*;
use cert_common::pkcs12::ProtectedPkcs12;
use cert_common::CertificateSigningMethod;
use cert_common::HttpsSigningMethod;
use cert_common::SshSigningMethod;
use chrono::Datelike;
use chrono::Timelike;
use der::asn1::UtcTime;
use der::Decode;
use ocsp::response::RevokedInfo;
use rcgen::RemoteKeyPair;
use rustls_pki_types::pem::PemObject;
use serde::Serialize;
use tokio_rustls::rustls::pki_types;
use x509_cert::ext::pkix::AccessDescription;
use zeroize::Zeroizing;

use crate::hsm2::KeyPairTrait;
use crate::hsm2::SecurityModule;
use crate::hsm2::SecurityModuleTrait;
use crate::hsm2::Ssm;
use crate::main_config::DatabaseSettings;
use crate::main_config::GeneralSettings;
use crate::main_config::SecurityModuleConfiguration;
use crate::MainConfiguration;
use cert_common::pkcs12::BagAttribute;

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
    fn build_gui(
        &mut self,
        ui: &mut egui::Ui,
        name: Option<&str>,
        comment: Option<&str>,
    ) -> Result<(), String> {
        if let Some(comment) = comment {
            ui.label(comment);
        }
        if let Some(n) = name {
            ui.label(n);
        }
        let p: &mut String = &mut self.0;
        let pe = egui::TextEdit::singleline(p).password(true);
        ui.add(pe);
        let p: &mut String = &mut self.1;
        let pe = egui::TextEdit::singleline(p).password(true);
        ui.add(pe);
        self.check(name)
    }

    fn check(&self, name: Option<&str>) -> Result<(), String> {
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
    fn prompt(name: Option<&str>, comment: Option<&str>) -> Result<Self, userprompt::Error> {
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

impl From<&str> for SmartCardPin2 {
    fn from(value: &str) -> Self {
        Self(value.to_string(), value.to_string())
    }
}

impl std::fmt::Display for SmartCardPin2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
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
    #[PromptComment = "A soft certificate, password protected, the password is not stored anywhere"]
    /// A certificate represented by a regular protected p12 document, secured by a password
    Soft {
        #[PromptComment = "The password to protect the soft administrator certificate"]
        password: userprompt::Password2,
    },
    #[PromptComment = "The certificate is stored by an external device"]
    External,
}

impl Default for CertificateTypeAnswers {
    fn default() -> Self {
        Self::Soft {
            password: userprompt::Password2::default(),
        }
    }
}

/// The kinds of tokens that can exist for certificates generated
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum CertificateType {
    /// A certificate represented by a regular protected p12 document, secured by a password
    Soft(String),
    /// The certificate private key is held by an external device
    External,
}

impl From<CertificateTypeAnswers> for CertificateType {
    fn from(value: CertificateTypeAnswers) -> Self {
        match value {
            CertificateTypeAnswers::Soft { password } => Self::Soft(password.to_string()),
            CertificateTypeAnswers::External => Self::External,
        }
    }
}

/// The items used to configure a standalone certificate authority, typically used as part of a large pki installation.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct StandaloneCaConfiguration {
    /// The settings specified to run the ca service
    pub service: Option<crate::main_config::ServerConfiguration>,
    /// The desired minimum debug level
    pub debug_level: Option<service::LogLevel>,
    /// security module configuration
    pub security_module: SecurityModuleConfiguration,
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
    /// The pki name to use, must be blank or end with /
    pub pki_name: String,
    /// The public name of the service, contains example.com/asdf for the example
    pub public_names: Vec<ComplexName>,
    /// The optional proxy configuration
    pub proxy_config: Option<ProxyConfig>,
    /// Is tpm2 hardware required to setup the pki?
    #[cfg(feature = "tpm2")]
    pub tpm2_required: bool,
    /// General settings
    pub general: GeneralSettings,
}

impl StandaloneCaConfiguration {
    /// Set the log level
    pub fn set_log_level(&self) {
        service::log::set_max_level(
            self.debug_level
                .as_ref()
                .unwrap_or(&service::LogLevel::Trace)
                .level_filter(),
        );
    }

    /// Build a Self using answers and the containing pki_name, which must be blank or end with /
    fn from(value: &StandaloneCaConfigurationAnswers, pki_name: String) -> Self {
        Self {
            general: value.general.clone(),
            proxy_config: value.proxy_config.clone(),
            debug_level: Some(value.debug_level.clone()),
            service: value.service.clone().map(|a| a.into()),
            security_module: value.security_module.clone(),
            sign_method: value.sign_method,
            path: value.path.clone().into(),
            inferior_to: value.inferior_to.clone(),
            common_name: value.common_name.clone(),
            days: value.days,
            chain_length: value.chain_length,
            admin_access_password: value.admin_access_password.to_string(),
            admin_cert: value.admin_cert.clone().into(),
            ocsp_signature: value.ocsp_signature,
            name: value.name.clone(),
            pki_name: pki_name.clone(),
            public_names: value.public_names.clone(),
            #[cfg(feature = "tpm2")]
            tpm2_required: value.tpm2_required,
        }
    }
}

impl StandaloneCaConfiguration {
    ///Get a CaConfiguration from a StandaloneCaConfiguration
    /// # Arguments
    /// * name - The name of the ca for pki purposes
    /// * settings - The application settings
    pub fn get_ca(&self, settings: &MainConfiguration) -> CaConfiguration {
        let mut full_name = self.name.clone();
        if !full_name.ends_with('/') && !full_name.is_empty() {
            full_name.push('/');
        }
        let public_names = &self.public_names;
        let san: Vec<String> = public_names.iter().map(|n| n.domain.clone()).collect();
        let http_port = self.proxy_config.as_ref().map(|pc| pc.http_port).flatten();
        let https_port = self.proxy_config.as_ref().map(|pc| pc.https_port).flatten();
        let proxy = if !public_names.is_empty() {
            Some(public_names[0].subdomain.to_owned())
        } else {
            None
        };
        let (http, https) = match &settings.pki {
            PkiConfigurationEnum::Pki(pki_configuration) => (
                pki_configuration.service.http.clone(),
                pki_configuration.service.https.clone(),
            ),
            PkiConfigurationEnum::AddedCa(local_ca_configuration) => (None, None),
            PkiConfigurationEnum::Ca(standalone_ca_configuration) => standalone_ca_configuration
                .service
                .as_ref()
                .map(|service| (service.http.clone(), service.https.clone()))
                .unwrap_or((None, None)),
        };
        let service = match &settings.pki {
            PkiConfigurationEnum::Pki(pki_configuration) => Some(&pki_configuration.service),
            PkiConfigurationEnum::AddedCa(local_ca_configuration) => unimplemented!(),
            PkiConfigurationEnum::Ca(standalone_ca_configuration) => {
                standalone_ca_configuration.service.as_ref()
            }
        };
        CaConfiguration {
            public_names: public_names.clone(),
            database: service.map(|s| s.database.clone()).flatten(),
            http,
            https,
            general: settings.pki.get_general_settings(),
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
            pki_name: Some(format!("{}{}", self.pki_name, full_name)),
            debug_level: self.debug_level.clone(),
            security_config: Some(self.security_module.clone()),
            #[cfg(feature = "tpm2")]
            tpm2_required: self.tpm2_required,
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
    #[PromptComment = "The security module configuration"]
    /// security module configuration
    pub security_module: SecurityModuleConfiguration,
    /// The settings specified to run the ca service
    #[PromptComment = "Settings for the service"]
    pub service: Option<crate::main_config::ServerConfigurationAnswers>,
    #[PromptComment = "Settings for the database"]
    /// Optional settings for the mysql database
    pub database: Option<DatabaseSettings>,
    #[PromptComment = "The public name of the service, such as example.com/asdf"]
    /// The public name of the service, contains example.com/asdf for the example
    pub public_names: Vec<ComplexName>,
    #[PromptComment = "The optional proxy port configuration"]
    /// The optional proxy configuration
    pub proxy_config: Option<ProxyConfig>,
    #[PromptComment = "An optional list of custom client certificates to load"]
    /// Settings for client certificates
    pub client_certs: Option<Vec<userprompt::FileOpen>>,
    #[PromptComment = "The desired level for logging"]
    /// The desired minimum debug level
    pub debug_level: service::LogLevel,
    #[PromptComment = "Should a trusted platform module version 2 be required?"]
    /// Is tpm2 hardware required to setup the pki?
    #[cfg(feature = "tpm2")]
    pub tpm2_required: bool,
    #[PromptComment = "The signing method for this authority"]
    /// The signing method for the certificate authority
    pub sign_method: CertificateSigningMethod,
    #[PromptComment = "Where the authority should be stored"]
    /// Where to store the certificate authority
    pub path: CaCertificateStorageBuilderAnswers,
    #[PromptComment = "Does this authority have a superior authority?"]
    /// Does this authority have a superior authority?
    pub inferior_to: Option<String>,
    #[PromptComment = "The common name of the authority"]
    /// The common name of the certificate authority
    pub common_name: String,
    #[PromptComment = "The number of days the authority is good for"]
    /// The number of days the certificate authority should be good for.
    pub days: u32,
    #[PromptComment = "The maximum chain length for the authority, used when creating more authorities"]
    /// The maximum chain length for a chain of certificate authorities.
    pub chain_length: u8,
    #[PromptComment = "The password required to download the admin certificate"]
    /// The password required in order to download the admin certificate over the web
    pub admin_access_password: userprompt::Password2,
    #[PromptComment = "The certificate type for the administrator certificate"]
    /// The certificate type for the admin cert
    pub admin_cert: CertificateTypeAnswers,
    #[PromptComment = "Is a signature required for ocsp requests?"]
    /// Is a signature required for ocsp requests?
    pub ocsp_signature: bool,
    #[PromptComment = "The name of the authority instance"]
    /// The name of the ca instance
    pub name: String,
    #[PromptComment = "The general settings"]
    /// General settings
    pub general: GeneralSettings,
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
            general: GeneralSettings::default(),
            security_module: SecurityModuleConfiguration::default(),
            client_certs: None,
            database: None,
            public_names: Vec::new(),
            proxy_config: None,
            debug_level: service::LogLevel::Warning,
            #[cfg(feature = "tpm2")]
            tpm2_required: false,
            service: Default::default(),
            sign_method: CertificateSigningMethod::Https(HttpsSigningMethod::RsaSha256),
            path: CaCertificateStorageBuilderAnswers::Nowhere,
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

    /// Convert to a local ca configuration
    pub fn to_local(&self) -> LocalCaConfigurationAnswers {
        LocalCaConfigurationAnswers {
            security_module: self.security_module.clone(),
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

    ///Get a Caconfiguration for editing
    pub fn get_editable_ca(&self) -> CaConfigurationAnswers {
        CaConfigurationAnswers {
            security_module: self.security_module.clone(),
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
        let san: Vec<String> = self.public_names.iter().map(|n| n.domain.clone()).collect();
        let http_port = self
            .proxy_config
            .as_ref()
            .and_then(|a| a.http_port)
            .or_else(|| settings.get_http_port());
        let https_port = self
            .proxy_config
            .as_ref()
            .and_then(|a| a.https_port)
            .or_else(|| settings.get_https_port());
        CaConfigurationAnswers {
            security_module: self.security_module.clone(),
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
            proxy: Some(self.public_names[0].subdomain.to_owned()),
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
    #[PromptComment = "The security module configuration"]
    /// security module configuration
    pub security_module: SecurityModuleConfiguration,
    #[PromptComment = "The signing method used by the authority"]
    /// The signing method for the certificate authority
    pub sign_method: CertificateSigningMethod,
    #[PromptComment = "Where to store the certificate authority"]
    /// Where to store the certificate authority
    pub path: CaCertificateStorageBuilderAnswers,
    #[PromptComment = "Does this have an authority that is superior to it?"]
    /// Does this authority have a superior authority?
    pub inferior_to: Option<String>,
    #[PromptComment = "The common name of the certificate authority"]
    /// The common name of the certificate authority
    pub common_name: String,
    #[PromptComment = "The number of days the authority is good for"]
    /// The number of days the certificate authority should be good for.
    pub days: u32,
    #[PromptComment = "The maximum chain length for the authority, used when creating other authorities"]
    /// The maximum chain length for a chain of certificate authorities.
    pub chain_length: u8,
    #[PromptComment = "The password required to download the administrator certificate"]
    /// The password required in order to download the admin certificate over the web
    pub admin_access_password: userprompt::Password2,
    #[PromptComment = "The certificate type for the administrator certificate"]
    /// The certificate type for the admin cert
    pub admin_cert: CertificateTypeAnswers,
    #[PromptComment = "Is a signature required for ocsp requests?"]
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
            security_module: Default::default(),
            sign_method: CertificateSigningMethod::Https(HttpsSigningMethod::RsaSha256),
            path: CaCertificateStorageBuilderAnswers::Nowhere,
            inferior_to: None,
            common_name: "".to_string(),
            days: 1,
            chain_length: 0,
            admin_access_password: userprompt::Password2::new("".to_string()),
            admin_cert: Default::default(),
            ocsp_signature: false,
        }
    }

    /// Convert into a LocalCaConfiguration
    pub fn into_local_config(self) -> LocalCaConfiguration {
        LocalCaConfiguration {
            security_module: self.security_module,
            sign_method: self.sign_method,
            path: self.path.into(),
            inferior_to: self.inferior_to,
            common_name: self.common_name,
            days: self.days,
            chain_length: self.chain_length,
            admin_access_password: self.admin_access_password.to_string(),
            admin_cert: self.admin_cert.into(),
            ocsp_password: String::new(),
            root_password: String::new(),
            ocsp_signature: self.ocsp_signature,
            pki_name: String::new(),
        }
    }

    ///Get a Caconfiguration for editing
    pub fn get_editable_ca(&self) -> CaConfigurationAnswers {
        CaConfigurationAnswers {
            security_module: self.security_module.clone(),
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

/// The items used to configure a remote certificate authority in a pki configuration
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct RemoteCaConfiguration {
    /// The url for the remote ca server
    pub url: String,
}

/// The items used to configure a local certificate authority in a pki configuration
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalCaConfiguration {
    /// security module configuration
    pub security_module: SecurityModuleConfiguration,
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
    /// The name of the pki this ca belongs to, must be blank or end with a /
    pub pki_name: String,
}

impl LocalCaConfigurationAnswers {
    fn into_config(self, pki_config: &PkiConfigurationAnswers) -> LocalCaConfiguration {
        LocalCaConfiguration {
            security_module: self.security_module,
            sign_method: self.sign_method,
            path: self.path.into(),
            inferior_to: self.inferior_to,
            common_name: self.common_name,
            days: self.days,
            chain_length: self.chain_length,
            admin_access_password: self.admin_access_password.to_string(),
            admin_cert: self.admin_cert.into(),
            ocsp_password: crate::utility::generate_password(32),
            root_password: crate::utility::generate_password(32),
            ocsp_signature: self.ocsp_signature,
            pki_name: pki_config.pki_name.clone(),
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
        CaConfiguration {
            public_names: Vec::new(),
            database: None,
            http: None,
            https: None,
            general: settings.pki.get_general_settings(),
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
            pki_name: Some(format!("{}{}", self.pki_name, full_name)),
            debug_level: None,
            security_config: None,
            #[cfg(feature = "tpm2")]
            tpm2_required: false,
        }
    }
}

/// The items used to configure a certificate authority
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CaConfiguration {
    /// General settings
    pub general: Option<crate::main_config::GeneralSettings>,
    /// Settings for the database
    pub database: Option<crate::main_config::DatabaseSettings>,
    /// The public name of the service, contains example.com/asdf for the example
    pub public_names: Vec<ComplexName>,
    /// Settings for the http server
    pub http: Option<crate::main_config::HttpSettings>,
    /// Settings for the https server
    pub https: Option<crate::main_config::HttpsSettings>,
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
    /// The proxy configuration for this authority, must be blank or end with a /
    pub proxy: Option<String>,
    /// The pki name for the authority, used when operating a pki, must be blank or end with a /
    pub pki_name: Option<String>,
    /// The desired minimum debug level
    pub debug_level: Option<service::LogLevel>,
    /// Is tpm2 hardware required to setup the pki?
    #[cfg(feature = "tpm2")]
    pub tpm2_required: bool,
    /// The security module configuration
    security_config: Option<SecurityModuleConfiguration>,
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
    pub path: CaCertificateStorageBuilderAnswers,
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
    /// security module configuration
    pub security_module: SecurityModuleConfiguration,
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
            security_module: self.security_module.clone(),
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
            path: CaCertificateStorageBuilderAnswers::Nowhere,
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
            security_module: SecurityModuleConfiguration::default(),
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
    DoesNotExist(String),
    /// Cannot open the certificate
    CantOpen(String),
    /// Other io error
    OtherIo(String, String),
    /// The certificate loaded is invalid
    InvalidCert(String),
    /// There is no algorithm detected
    NoAlgorithm(String),
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
pub enum CaCertificateStorageBuilderAnswers {
    #[PromptComment = "Don't store certificates anywhere (only for testing)"]
    /// Certificates are stored nowhere
    Nowhere,
    #[PromptComment = "Store the certificates in a sqlite database on local storage"]
    /// Ca uses a sqlite database on a filesystem
    Sqlite(userprompt::FileCreate),
}

impl From<CaCertificateStorageBuilderAnswers> for CaCertificateStorageBuilder {
    fn from(value: CaCertificateStorageBuilderAnswers) -> Self {
        match value {
            CaCertificateStorageBuilderAnswers::Nowhere => CaCertificateStorageBuilder::Nowhere,
            CaCertificateStorageBuilderAnswers::Sqlite(p) => {
                CaCertificateStorageBuilder::Sqlite(p.to_path_buf())
            }
        }
    }
}

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
    #[PromptComment = "Don't store certificates anywhere (only for testing)"]
    /// Certificates are stored nowhere
    Nowhere,
    #[PromptComment = "Store the certificates in a sqlite database on local storage"]
    /// Ca uses a sqlite database on a filesystem
    Sqlite(std::path::PathBuf),
}

impl CaCertificateStorageBuilder {
    /// Remove relative paths, path might need to exist for this to succeed
    pub async fn remove_relative_paths(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Nowhere => {}
            Self::Sqlite(p) => {
                if p.is_relative() {
                    use tokio::io::AsyncWriteExt;
                    let mut f = tokio::fs::File::create(&p).await?;
                    f.write_all(" ".as_bytes()).await?;
                    *p = p.canonicalize()?;
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
        let r = match self {
            CaCertificateStorageBuilder::Nowhere => Ok(CaCertificateStorage::Nowhere),
            CaCertificateStorageBuilder::Sqlite(p) => {
                service::log::info!("Building sqlite with {}", p.display());
                let mut count = 0;
                let mut pool;
                loop {
                    let p: &std::path::PathBuf = p;
                    let mode = async_sqlite::JournalMode::Wal;
                    service::log::info!("Attempting to create poolbuilder for sqlite");
                    pool = async_sqlite::PoolBuilder::new()
                        .path(p)
                        .journal_mode(mode)
                        .open()
                        .await;
                    if pool.is_err() {
                        count += 1;
                        service::log::info!(
                            "FAILED {} Attempting to create poolbuilder for sqlite",
                            count
                        );
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
        };
        service::log::debug!("Done building storage");
        r
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
    /// The serial of the certificate to be signed
    pub serial: Vec<u8>,
}

impl CaCertificateToBeSigned {
    /// Generate a random serial number. 20 bytes should be enough to never have a collision.
    pub fn calc_sn() -> ([u8; 20], rcgen::SerialNumber) {
        let mut snb = [0; 20];
        snb = rand::random();
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
        let mut serial = None;
        if let Ok(x509_cert) = cert {
            let mut name = "whatever".to_string();
            for a in &value.attributes {
                if let BagAttribute::FriendlyName(n) = a {
                    n.clone_into(&mut name);
                    break;
                }
            }
            let algorithm = x509_cert.signature_algorithm;
            serial = Some(x509_cert.tbs_certificate.serial_number.as_bytes().to_vec());
            return Ok(Self {
                medium: CaCertificateStorage::Nowhere,
                data: CertificateData::Https(HttpsCertificate {
                    algorithm: algorithm.try_into().unwrap(),
                    cert: cert_der.to_owned(),
                    keypair: Some(Keypair::NotHsm(value.pkey)),
                    attributes: value.attributes.clone(),
                }),
                name,
                serial: x509_cert.tbs_certificate.serial_number.as_bytes().to_vec(),
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
                serial: serial.unwrap(),
            });
        }
        Err(Pkcs12ImportError::InvalidCertificate)
    }
}

/// Errors that can occur when saving a certificate
#[derive(Debug)]
pub enum CertificateSaveError {
    /// Unable to save for some reason
    FailedToSave,
    /// The certificate being saved is invalid
    FailedToParseCertificate,
}

impl CaCertificateStorage {
    /// Perform any needed in place updates to the database
    /// This prevents the need to build a new ca for database additions.
    pub async fn validate(&mut self) -> Result<(), ()> {
        service::log::info!("Validating database tables");
        match self {
            CaCertificateStorage::Nowhere => {}
            CaCertificateStorage::Sqlite(p) => {
                p.conn(move |conn| {
                    conn.execute("CREATE TABLE IF NOT EXISTS revoked ( id INTEGER PRIMARY KEY, date TEXT, reason INTEGER)", [])
                })
                .await.map_err(|_|())?;
                p.conn(move |conn| {
                    conn.execute("CREATE TABLE IF NOT EXISTS searchable ( id INTEGER PRIMARY KEY, cn TEXT, country TEXT, state TEXT, locality TEXT, organization TEXT, ou TEXT)", [])
                })
                .await.map_err(|_|())?;
            }
        }
        Ok(())
    }

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
                        conn.execute("CREATE TABLE p12 ( id INTEGER PRIMARY KEY, der BLOB)", [])?;
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
        self.validate().await?;
        Ok(())
    }

    /// Save this certificate to the storage medium
    pub async fn save_to_medium(
        &self,
        ca: &mut Ca,
        cert: CaCertificate,
        password: &str,
    ) -> Result<(), CertificateSaveError> {
        let hsm_label = if let Some(a) = cert.data.hsm_label() {
            if a.is_empty() {
                Some(cert.name.clone())
            } else {
                Some(a)
            }
        } else {
            Some(cert.name.clone())
        };
        service::log::debug!(
            "Save {:02x?} {} to medium {:?}",
            cert.serial,
            cert.name,
            hsm_label
        );
        let id = ca.get_new_request_id().await.unwrap();
        let cert_der = &cert
            .contents()
            .map_err(|_| CertificateSaveError::FailedToParseCertificate)?;
        ca.save_user_cert(
            id,
            cert_der,
            Some(
                &cert
                    .get_snb()
                    .map_err(|_| CertificateSaveError::FailedToParseCertificate)?,
            ),
        )
        .await;
        if let Some(label) = hsm_label {
            match self {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::Sqlite(p) => {
                    service::log::info!("Inserting hsm data for {}", id);
                    p.conn(move |conn| {
                        let mut stmt = conn
                            .prepare("INSERT INTO hsm_labels (id, label) VALUES (?1, ?2)")
                            .expect("Failed to build prepared statement");
                        stmt.execute([id.to_sql().unwrap(), label.to_sql().unwrap()])
                    })
                    .await
                    .map_err(|_| CertificateSaveError::FailedToSave)?;
                }
            }
        }
        if let Some(p12) = cert.try_p12(password) {
            service::log::info!("Inserting p12 data {:02X?} for {}", p12, id);
            match self {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::Sqlite(p) => {
                    p.conn(move |conn| {
                        let mut stmt = conn
                            .prepare("INSERT INTO p12 (id, der) VALUES (?1, ?2)")
                            .expect("Failed to build prepared statement");
                        stmt.execute([id.to_sql().unwrap(), p12.to_sql().unwrap()])
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
        hsm: Arc<crate::hsm2::SecurityModule>,
        name: &str,
    ) -> Result<CaCertificate, CertificateLoadingError> {
        match self {
            CaCertificateStorage::Nowhere => {
                service::log::debug!("Tried to load {} certificate from nowhere", name);
                Err(CertificateLoadingError::DoesNotExist(name.to_string()))
            }
            CaCertificateStorage::Sqlite(p) => {
                let name = name.to_owned();
                let name2 = name.to_owned();
                let serial: Vec<u8> = p
                    .conn(move |conn| {
                        conn.query_row(
                            &format!("SELECT serial FROM hsm_labels LEFT JOIN serials ON hsm_labels.id=serials.id WHERE label='{}'", name2),
                            [],
                            |r| Ok(r.get(0).unwrap()),
                        )
                    })
                    .await
                    .map_err(|_| {
                        service::log::debug!("Cannot load cert {}", name);
                        CertificateLoadingError::DoesNotExist(name.to_string())
                    })?;
                let serial2 = serial.clone();
                let cert: Vec<u8> = p
                    .conn(move |conn| {
                        let mut stmt = conn.prepare("SELECT der FROM certs LEFT JOIN serials on certs.id=serials.id WHERE serials.serial=?1")?;
                        stmt.query_row([serial.clone()],
                            |r| Ok(r.get(0).unwrap()),
                        )
                    })
                    .await
                    .map_err(|_| {
                        service::log::debug!("Cannot load cert {}", name);
                        CertificateLoadingError::DoesNotExist(name.to_string())
                    })?;
                let (alg, kp) = {
                    let hsm_cert = crate::hsm2::KeyPair::load_with_label(hsm, &name);
                    let kp = hsm_cert
                        .as_ref()
                        .ok_or(CertificateLoadingError::NoAlgorithm(name.to_string()));
                    if let Ok(kp) = kp {
                        let alg = kp
                            .https_algorithm()
                            .ok_or(CertificateLoadingError::NoAlgorithm(name.to_string()))?;
                        let hsm_cert = hsm_cert.map(Keypair::Hsm);
                        (alg, hsm_cert)
                    } else {
                        use der::Decode;
                        let cert: Result<x509_cert::certificate::CertificateInner, der::Error> =
                            x509_cert::Certificate::from_der(&cert);
                        let cert = cert.unwrap();
                        let alg = cert.signature_algorithm;
                        let cid = const_oid::ObjectIdentifier::from_bytes(alg.oid.as_bytes())
                            .map_err(|e| CertificateLoadingError::NoAlgorithm(e.to_string()))?;
                        let alg_b = cert_common::oid::Oid::from_const(cid);
                        let alg = if alg_b == *cert_common::oid::OID_PKCS1_SHA256_RSA_ENCRYPTION {
                            HttpsSigningMethod::RsaSha256
                        } else if alg_b == *cert_common::oid::OID_ECDSA_P256_SHA256_SIGNING {
                            HttpsSigningMethod::EcdsaSha256
                        } else {
                            panic!("Unknown signing algorithm : {:?}", alg_b);
                        };
                        (alg, None)
                    }
                };
                //TODO dynamically pick the correct certificate type here
                let hcert = HttpsCertificate {
                    algorithm: alg,
                    cert,
                    keypair: kp,
                    attributes: Vec::new(),
                };
                let cert = CaCertificate {
                    medium: self.clone(),
                    data: CertificateData::Https(hcert),
                    name: name.to_owned(),
                    serial: serial2,
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
        service::log::debug!("Attempting to load {} from storage p12", label);
        match self {
            CaCertificateStorage::Nowhere => {
                service::log::debug!("Tried to load {} p12 certificate from nowhere", label);
                Err(CertificateLoadingError::DoesNotExist(label.to_string()))
            }
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
                        CertificateLoadingError::DoesNotExist(label2.clone())
                    })?;
                let cert: Result<Vec<u8>, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row("SELECT der FROM p12 WHERE id=?1", [id], |r| r.get(0))
                    })
                    .await;
                let p12 = cert_common::pkcs12::ProtectedPkcs12 {
                    contents: cert.map_err(|_e| {
                        service::log::debug!("Failed to parse open pkcs12 of {}", label2);
                        CertificateLoadingError::DoesNotExist(label2)
                    })?,
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
    /// A keypair not contained in the hsm
    NotHsm(Zeroizing<Vec<u8>>),
}

impl Keypair {
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
            Self::Hsm(_) => {}
            Self::NotHsm(k) => {
                *k = Zeroizing::new(Vec::new());
            }
        }
    }

    /// Get the hsm keypair, if possible
    pub fn hsm_keypair(&self) -> Option<&crate::hsm2::KeyPair> {
        match self {
            Keypair::Hsm(k) => Some(k),
            Keypair::NotHsm(_) => None,
        }
    }

    /// Sign a chunk of data
    pub fn sign(&self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Keypair::Hsm(k) => k.sign(data).ok(),
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
    fn hsm_label(&self) -> Option<String> {
        self.keypair.as_ref().and_then(|kp| {
            let keypair = kp.hsm_keypair();
            let label = keypair.map(|kp| {
                use crate::hsm2::KeyPairTrait;
                kp.label()
            });
            let kp2 = kp.private();
            let label3 = if kp2.is_some() {
                let mut r = None;
                for attr in &self.attributes {
                    match attr {
                        BagAttribute::FriendlyName(n) => r = Some(n.to_owned()),
                        _ => {}
                    }
                }
                r
            } else {
                None
            };
            label.or(label3)
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
                    BagAttribute::LocalKeyId(local_key_id.clone()),
                    BagAttribute::FriendlyName(csr.name.clone()),
                ],
            }),
            name: csr.name.clone(),
            serial: local_key_id,
        })
    }

    fn get_attributes(&self) -> Vec<cert_common::pkcs12::BagAttribute> {
        self.attributes.clone()
    }

    fn try_p12(&self, serial: Vec<u8>, password: &str) -> Option<Vec<u8>> {
        self.keypair.as_ref().and_then(|kp| {
            let keypair = kp.private();
            keypair.map(|kp| {
                let p12: cert_common::pkcs12::Pkcs12 = cert_common::pkcs12::Pkcs12 {
                    cert: self.cert.clone(),
                    pkey: kp.to_owned(),
                    attributes: self.attributes.clone(),
                    serial,
                };
                p12.get_pkcs12(password)
            })
        })
    }

    fn algorithm(&self) -> CertificateSigningMethod {
        CertificateSigningMethod::Https(self.algorithm)
    }

    fn get_snb(&self, _serial: Vec<u8>) -> Result<Vec<u8>, der::Error> {
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
            algorithm: x509.signature_algorithm.clone().try_into().map_err(|_e| {
                CertificateLoadingError::InvalidCert(x509.tbs_certificate.subject.to_string())
            })?,
            cert: x509.to_der().map_err(|_e| {
                CertificateLoadingError::InvalidCert(x509.tbs_certificate.subject.to_string())
            })?,
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

    fn try_p12(&self, serial: Vec<u8>, password: &str) -> Option<Vec<u8>> {
        use ssh_encoding::Encode;
        let public_contents = self.cert.to_bytes().unwrap();
        if let Some(keypair) = &self.keypair {
            let mut con = Vec::new();
            keypair.encode(&mut con).ok()?;
            let p12: cert_common::pkcs12::Pkcs12 = cert_common::pkcs12::Pkcs12 {
                cert: public_contents,
                pkey: Zeroizing::new(con),
                attributes: Vec::new(),
                serial,
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

    fn get_snb(&self, serial: Vec<u8>) -> Result<Vec<u8>, der::Error> {
        Ok(serial)
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
    fn try_p12(&self, serial: Vec<u8>, password: &str) -> Option<Vec<u8>>;
    /// Get the algorithm
    fn algorithm(&self) -> CertificateSigningMethod;
    /// Retrieve the serial number as a vector
    fn get_snb(&self, serial: Vec<u8>) -> Result<Vec<u8>, der::Error>;
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
    /// The serial of the certificate
    pub serial: Vec<u8>,
}

impl CaCertificate {
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
        self.data.get_snb(self.serial.clone())
    }

    /// Retrieve the contents of the certificate data in a storable format
    pub fn contents(&self) -> Result<Vec<u8>, ()> {
        self.data.contents()
    }

    /// Attempt to build a p12 document
    pub fn try_p12(&self, password: &str) -> Option<Vec<u8>> {
        self.data.try_p12(self.serial.clone(), password)
    }

    /// Load an ssh certificate
    pub fn from_existing_ssh(
        medium: CaCertificateStorage,
        cert: SshCertificate,
        name: String,
        serial: Vec<u8>,
    ) -> Self {
        Self {
            medium,
            data: CertificateData::Ssh(cert),
            name,
            serial,
        }
    }

    /// Load a caCertificate instance from der data of the certificate
    pub fn from_existing_https(
        algorithm: HttpsSigningMethod,
        medium: CaCertificateStorage,
        der: &[u8],
        keypair: Keypair,
        name: String,
        _id: u64,
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
            serial: x509.tbs_certificate.serial_number.as_bytes().to_vec(),
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
    pub async fn save_to_medium(
        &self,
        ca: &mut Ca,
        password: &str,
    ) -> Result<(), CertificateSaveError> {
        self.medium
            .save_to_medium(ca, self.to_owned(), password)
            .await
    }

    /// Sign a csr with the certificate, if possible
    pub fn sign_csr(
        &self,
        mut csr: CaCertificateToBeSigned,
        ca: &Ca,
        serial: Vec<u8>,
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
        let sn = rcgen::SerialNumber::from_slice(&serial);
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
    #[PromptComment = "The domain name, such as example.com"]
    /// The domain name, such as example.com
    pub domain: String,
    #[PromptComment = "The subdomain, such as / or /asdf"]
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
                subdomain: "".to_string(),
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
    #[PromptComment = "The optional http port to use for proxies"]
    /// The public port number for http, 80 for the example (the default port for http)
    pub http_port: Option<u16>,
    #[PromptComment = "The optional https port to use for https proxies"]
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
    /// The settings specified to run the pki service
    #[PromptComment = "Settings for the service"]
    pub service: crate::main_config::ServerConfigurationAnswers,
    #[PromptComment = "A list of local ca configurations"]
    /// List of local ca
    pub local_ca: userprompt::SelectedHashMap<LocalCaConfigurationAnswers>,
    #[PromptComment = "The optional password for the super-admin"]
    /// The provider for the super-admin key
    super_admin: Option<String>,
    #[PromptComment = "The name to use for the pki"]
    /// The name to use for the pki
    pub pki_name: String,
    /// security module configuration
    pub security_module: SecurityModuleConfiguration,
    /// Is tpm2 hardware required to setup the pki?
    #[cfg(feature = "tpm2")]
    pub tpm2_required: bool,
    /// The public name of the service, contains example.com/asdf for the example
    pub public_names: Vec<ComplexName>,
    /// The desired minimum debug level
    pub debug_level: Option<service::LogLevel>,
    /// The optional proxy configuration
    pub proxy_config: Option<ProxyConfig>,
    /// General settings
    pub general: GeneralSettings,
}

/// The configuration of a general pki instance.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct PkiConfiguration {
    /// The settings specified to run the pki service
    pub service: crate::main_config::ServerConfiguration,
    /// List of local ca
    pub local_ca: std::collections::HashMap<String, LocalCaConfiguration>,
    /// List of remote ca
    pub remote_ca: std::collections::HashMap<String, RemoteCaConfiguration>,
    /// The super-admin certificate provider
    pub super_admin: Option<String>,
    /// The name to use for the pki
    pub pki_name: String,
    /// security module configuration
    pub security_module: SecurityModuleConfiguration,
    /// Is tpm2 hardware required to setup the pki?
    #[cfg(feature = "tpm2")]
    pub tpm2_required: bool,
    /// The public name of the service, contains example.com/asdf for the example
    pub public_names: Vec<ComplexName>,
    /// The desired minimum debug level
    pub debug_level: Option<service::LogLevel>,
    /// The optional proxy configuration
    pub proxy_config: Option<ProxyConfig>,
    /// General settings
    pub general: GeneralSettings,
}

impl PkiConfiguration {
    /// Set the log level
    pub fn set_log_level(&self) {
        service::log::set_max_level(
            self.debug_level
                .as_ref()
                .unwrap_or(&service::LogLevel::Trace)
                .level_filter(),
        );
    }
}

impl From<PkiConfigurationAnswers> for PkiConfiguration {
    fn from(value: PkiConfigurationAnswers) -> Self {
        let map = value.local_ca.map().clone();
        let map2 = map
            .iter()
            .map(|(s, v)| {
                let v: LocalCaConfiguration = v.to_owned().into_config(&value);
                (s.to_owned(), v.to_owned())
            })
            .collect();
        Self {
            general: value.general.clone(),
            proxy_config: value.proxy_config,
            local_ca: map2,
            service: value.service.into(),
            super_admin: value.super_admin.clone(),
            pki_name: value.pki_name.clone(),
            remote_ca: HashMap::new(),
            debug_level: value.debug_level,
            public_names: value.public_names.clone(),
            security_module: value.security_module.clone(),
            #[cfg(feature = "tpm2")]
            tpm2_required: value.tpm2_required,
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
    #[PromptComment = "A generic pki configuration, you probably want this one"]
    /// A generic Pki configuration
    Pki(PkiConfigurationAnswers),
    #[PromptComment = "A local certificate authority configuration, use this one if you have already created your pki instance."]
    /// A certificate authority added after the fact
    AddedCa(LocalCaConfigurationAnswers),
    #[PromptComment = "Advanced: A remote certificate authority configuration to be paired with a Pki provider somewhere else"]
    /// A standard certificate authority configuration, paired with an external pki provider
    Ca {
        #[PromptComment = "The pki name for the ca to use"]
        /// The pki_name for the ca to use when generating urls
        pki_name: String,
        #[PromptComment = "The configuration data"]
        /// The configuration
        config: Box<StandaloneCaConfigurationAnswers>,
    },
}

impl Default for PkiConfigurationEnumAnswers {
    fn default() -> Self {
        Self::new()
    }
}

impl PkiConfigurationEnumAnswers {
    /// Construct a new ca, defaulting to a Pki configuration
    pub fn new() -> Self {
        Self::Pki(PkiConfigurationAnswers {
            general: GeneralSettings::default(),
            proxy_config: None,
            service: Default::default(),
            local_ca: Default::default(),
            super_admin: Default::default(),
            pki_name: Default::default(),
            debug_level: None,
            public_names: Vec::new(),
            security_module: SecurityModuleConfiguration::default(),
            #[cfg(feature = "tpm2")]
            tpm2_required: false,
        })
    }

    pub fn get_username(&self) -> Option<String> {
        match self {
            PkiConfigurationEnumAnswers::Pki(config) => config.service.username.clone(),
            PkiConfigurationEnumAnswers::AddedCa(config) => None,
            PkiConfigurationEnumAnswers::Ca { pki_name, config } => config
                .service
                .as_ref()
                .map(|s| s.username.clone())
                .flatten(),
        }
    }

    /// Makes extended configuration data, if applicable
    pub fn make_extended_config(&self) -> Option<crate::main_config::ExtendedConfiguration> {
        match self {
            PkiConfigurationEnumAnswers::Pki(config) => None,
            PkiConfigurationEnumAnswers::AddedCa(config) => {
                let e = crate::main_config::ExtendedConfiguration::ExtraPkiCaInstance {
                    name: todo!(),
                    instance: config.clone().into_local_config(),
                };
                Some(e)
            }
            PkiConfigurationEnumAnswers::Ca { pki_name, config } => None,
        }
    }

    /// Build a service config, if possible
    pub fn make_service_config(
        &self,
        service_args: Vec<String>,
        name: &str,
        path: std::path::PathBuf,
    ) -> Option<service::ServiceConfig> {
        if let Some(username) = self.get_username() {
            Some(service::ServiceConfig::new(
                service_args,
                format!("{} Iot Certificate Authority and Iot Manager", name),
                path,
                Some(username),
            ))
        } else {
            None
        }
    }

    /// Build an owner options struct
    pub fn build_owner_options(&self) -> Option<crate::ca::OwnerOptions> {
        let username = self.get_username();
        service::log::error!("Checking user {:?}", username);
        username.map(|u| {
            if u.is_empty() {
                panic!("Invalid empty user specified");
            }
            #[cfg(target_family = "unix")]
            let user_obj = nix::unistd::User::from_name(&u).unwrap().unwrap();
            #[cfg(target_family = "unix")]
            let user_uid = user_obj.uid;

            #[cfg(target_family = "unix")]
            let options = crate::ca::OwnerOptions::new(user_uid.as_raw());
            #[cfg(target_family = "windows")]
            let options = crate::ca::OwnerOptions::new(&u);
            options
        })
    }
}

///A simplified form of PkiConfigurationEnum that just identifies the type
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum SimplifiedPkiConfigurationEnum {
    /// A generic Pki configuration
    Pki,
    /// A certificate authority added after the fact
    AddedCa,
    /// A standard certificate authority configuration
    Ca,
}

impl From<PkiConfigurationEnum> for SimplifiedPkiConfigurationEnum {
    fn from(value: PkiConfigurationEnum) -> Self {
        match value {
            PkiConfigurationEnum::Pki(pki_configuration) => SimplifiedPkiConfigurationEnum::Pki,
            PkiConfigurationEnum::AddedCa(local_ca_configuration) => {
                SimplifiedPkiConfigurationEnum::AddedCa
            }
            PkiConfigurationEnum::Ca(standalone_ca_configuration) => {
                SimplifiedPkiConfigurationEnum::Ca
            }
        }
    }
}

///A generic configuration for a pki or certificate authority.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum PkiConfigurationEnum {
    /// A generic Pki configuration
    Pki(PkiConfiguration),
    /// A certificate authority added after the fact
    AddedCa(LocalCaConfiguration),
    /// A standard certificate authority configuration
    Ca(StandaloneCaConfiguration),
}

impl PkiConfigurationEnum {
    /// Initialize the hsm
    pub async fn init_hsm(
        &self,
        config_path: &PathBuf,
        name: &str,
        settings: &MainConfiguration,
        admin_csr: Option<&String>,
    ) -> Result<Arc<crate::hsm2::SecurityModule>, PkiLoadError> {
        use crate::hsm2;
        let security_config = match self {
            PkiConfigurationEnum::Pki(c) => c.security_module.clone(),
            PkiConfigurationEnum::AddedCa(c) => c.security_module.clone(),
            PkiConfigurationEnum::Ca(c) => c.security_module.clone(),
        };
        match security_config {
            SecurityModuleConfiguration::Hardware {
                hsm_path_override,
                hsm_pin,
                hsm_pin2,
                hsm_slot,
            } => {
                let n = config_path.join(format!("{}-initialized", name));
                if !n.exists() {
                    let hsm2 = if let Some(hsm_t) = hsm2::Hsm::create(
                        hsm_path_override.as_ref().map(|a| a.to_path_buf()),
                        Zeroizing::new(hsm_pin.clone()),
                        Zeroizing::new(hsm_pin2.clone()),
                    ) {
                        hsm_t
                    } else {
                        service::log::error!("Failed to create the hardware security module");
                        return Err(PkiLoadError::HsmInitFailed("HSM ERROR 1".to_string()));
                    };

                    hsm2.list_certificates();

                    let hsm = Arc::new(hsm2::SecurityModule::Hardware(hsm2));

                    use tokio::io::AsyncWriteExt;
                    let _ca_instance = crate::ca::PkiInstance::init(
                        hsm.clone(),
                        &settings.pki,
                        &settings,
                        admin_csr,
                    )
                    .await?;
                    let mut f = tokio::fs::File::create(&n).await.unwrap();
                    f.write_all("".as_bytes())
                        .await
                        .expect("Failed to initialization file update");
                    Ok(hsm)
                } else {
                    let hsm2 = if let Some(hsm_t) = hsm2::Hsm::open(
                        hsm_slot.unwrap_or(0),
                        hsm_path_override.as_ref().map(|a| a.to_path_buf()),
                        Zeroizing::new(hsm_pin2.clone()),
                    ) {
                        hsm_t
                    } else {
                        service::log::error!("Failed to open the hardware security module");
                        return Err(PkiLoadError::HsmInitFailed("HSM ERROR 2".to_string()));
                    };

                    Ok(Arc::new(hsm2::SecurityModule::Hardware(hsm2)))
                }
            }
            SecurityModuleConfiguration::Software(p) => {
                let n = config_path.join(format!("{}-initialized", name));
                let ssm = Arc::new(hsm2::SecurityModule::Software(Ssm { path: p.clone() }));
                service::log::info!("Checking for {} existing", n.display());
                service::log::info!("Checking for {} existing", p.display());
                if !p.exists() {
                    std::fs::create_dir_all(&p).unwrap();
                }
                if !n.exists() {
                    service::log::info!("Creating ssm");
                    use tokio::io::AsyncWriteExt;
                    let _ca_instance = crate::ca::PkiInstance::init(
                        ssm.clone(),
                        &settings.pki,
                        &settings,
                        admin_csr,
                    )
                    .await
                    .inspect_err(|_| {
                        let _ = std::fs::remove_dir_all(&p);
                    })?;
                    let mut f = tokio::fs::File::create(&n).await.unwrap();
                    f.write_all("".as_bytes())
                        .await
                        .expect("Failed to initialization file update");
                }
                Ok(ssm)
            }
        }
    }

    /// Set the log level
    pub fn set_log_level(&self) {
        match self {
            PkiConfigurationEnum::AddedCa(ca) => {}
            PkiConfigurationEnum::Pki(pki) => pki.set_log_level(),
            PkiConfigurationEnum::Ca(config) => config.set_log_level(),
        }
    }

    /// Return the port number for the http server
    pub fn get_http_port(&self) -> Option<u16> {
        match self {
            PkiConfigurationEnum::AddedCa(ca) => None,
            PkiConfigurationEnum::Pki(pki) => pki.service.http.as_ref().map(|a| a.port),
            PkiConfigurationEnum::Ca(config) => config
                .service
                .as_ref()
                .map(|service| service.http.as_ref().map(|a| a.port))
                .flatten(),
        }
    }

    /// Return the port number for the https server
    pub fn get_https_port(&self) -> Option<u16> {
        match self {
            PkiConfigurationEnum::AddedCa(ca) => None,
            PkiConfigurationEnum::Pki(pki) => pki.service.https.as_ref().map(|a| a.port),
            PkiConfigurationEnum::Ca(config) => config
                .service
                .as_ref()
                .map(|service| service.https.as_ref().map(|a| a.port))
                .flatten(),
        }
    }

    // Get the public names if applicable
    pub fn get_public_names(&self) -> Vec<ComplexName> {
        match self {
            PkiConfigurationEnum::AddedCa(ca) => Vec::new(),
            PkiConfigurationEnum::Pki(pki) => pki.public_names.clone(),
            PkiConfigurationEnum::Ca(config) => config.public_names.clone(),
        }
    }

    // Get the general settings if applicable
    pub fn get_general_settings(&self) -> Option<crate::main_config::GeneralSettings> {
        match self {
            PkiConfigurationEnum::AddedCa(ca) => None,
            PkiConfigurationEnum::Pki(pki) => Some(pki.general.clone()),
            PkiConfigurationEnum::Ca(config) => Some(config.general.clone()),
        }
    }

    /// Create a PkiConfigurationEnum from configuration answers
    pub fn from_config(value: PkiConfigurationEnumAnswers) -> Self {
        match value {
            PkiConfigurationEnumAnswers::AddedCa(ca) => Self::AddedCa(ca.into_local_config()),
            PkiConfigurationEnumAnswers::Pki(pki) => Self::Pki(pki.into()),
            PkiConfigurationEnumAnswers::Ca { pki_name, config } => {
                let ca = StandaloneCaConfiguration::from(&config, pki_name);
                Self::Ca(ca)
            }
        }
    }

    /// Get the static root for the website
    pub fn get_static_root(&self) -> Option<String> {
        match self {
            Self::AddedCa(_) => None,
            Self::Pki(pki) => Some(pki.general.static_content.to_owned()),
            Self::Ca(ca) => Some(ca.general.static_content.to_owned()),
        }
    }

    /// Remove relative pathnames from all paths specified
    pub async fn remove_relative_paths(&mut self) {
        match self {
            PkiConfigurationEnum::AddedCa(ca) => {
                let _ = ca.path.remove_relative_paths().await;
            }
            PkiConfigurationEnum::Pki(pki) => {
                pki.service.remove_relative_paths().await;
                for (_k, a) in pki.local_ca.iter_mut() {
                    let _ = a.path.remove_relative_paths().await;
                }
            }
            PkiConfigurationEnum::Ca(ca) => {
                if let Some(service) = &mut ca.service {
                    service.remove_relative_paths().await;
                }
                let _ = ca.path.remove_relative_paths().await;
            }
        }
    }

    /// Build an nginx reverse proxy config
    fn nginx_reverse(&self, proxy: &ProxyConfig, config: &MainConfiguration) -> String {
        let mut contents = String::new();
        contents.push_str("#nginx reverse proxy settings\n");
        let location_name = if let PkiConfigurationEnum::Ca(ca) = self {
            format!("pki/{}", ca.name)
        } else {
            "".to_string()
        };
        let http = match self {
            PkiConfigurationEnum::Pki(pki_configuration) => &pki_configuration.service.http,
            PkiConfigurationEnum::AddedCa(local_ca_configuration) => &None,
            PkiConfigurationEnum::Ca(standalone_ca_configuration) => &standalone_ca_configuration
                .service
                .as_ref()
                .map(|service| service.http.clone())
                .flatten(),
        };
        let https = match self {
            PkiConfigurationEnum::Pki(pki_configuration) => &pki_configuration.service.https,
            PkiConfigurationEnum::AddedCa(local_ca_configuration) => &None,
            PkiConfigurationEnum::Ca(standalone_ca_configuration) => &standalone_ca_configuration
                .service
                .as_ref()
                .map(|service| service.https.clone())
                .flatten(),
        };
        let public_names = match self {
            PkiConfigurationEnum::Pki(pki_configuration) => &pki_configuration.public_names,
            PkiConfigurationEnum::AddedCa(local_ca_configuration) => &Vec::new(),
            PkiConfigurationEnum::Ca(standalone_ca_configuration) => {
                &standalone_ca_configuration.public_names
            }
        };
        if let Some(http_port) = proxy.http_port {
            for complex_name in public_names {
                contents.push_str("server {\n");
                contents.push_str(&format!("\tlisten {};\n", http_port));
                contents.push_str(&format!("\tserver_name {};\n", complex_name.domain));
                contents.push_str(&format!(
                    "\tlocation {}{} {{\n",
                    complex_name.subdomain, location_name
                ));
                if let Some(https) = &https {
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
                } else if let Some(http) = &http {
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
        if let Some(https_port) = proxy.https_port {
            for complex_name in public_names {
                contents.push_str("server {\n");
                contents.push_str(&format!("\tlisten {} ssl;\n", https_port));
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
                if let Some(https) = &https {
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
                } else if let Some(http) = &http {
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
        let proxy_config = match self {
            PkiConfigurationEnum::Pki(pki_configuration) => &pki_configuration.proxy_config,
            PkiConfigurationEnum::AddedCa(local_ca_configuration) => &None,
            PkiConfigurationEnum::Ca(standalone_ca_configuration) => {
                &standalone_ca_configuration.proxy_config
            }
        };
        if let Some(proxy) = &proxy_config {
            match self {
                PkiConfigurationEnum::AddedCa(_) => None,
                PkiConfigurationEnum::Pki(_) => {
                    let mut contents = String::new();
                    contents.push_str(&self.nginx_reverse(proxy, config));
                    Some(contents)
                }
                PkiConfigurationEnum::Ca(ca) => {
                    let mut contents = String::new();
                    contents.push_str(&self.nginx_reverse(proxy, config));
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
            Self::Ca(_) => "Remote Certificate Authority",
            Self::AddedCa(_) => "Local Certificate Authority",
        }
    }
}

/// A normal pki object, containing one or more Certificate authorities
#[derive(Debug)]
pub struct Pki {
    /// General settings
    pub general: crate::main_config::GeneralSettings,
    /// Settings for the database
    pub database: Option<crate::main_config::DatabaseSettings>,
    /// The public name of the service, contains example.com/asdf for the example
    pub public_names: Vec<ComplexName>,
    /// Settings for the http server
    pub http: Option<crate::main_config::HttpSettings>,
    /// Settings for the https server
    pub https: Option<crate::main_config::HttpsSettings>,
    /// All of the ca instances for the pki
    pub all_ca: HashMap<String, LocalOrRemoteCa>,
    /// The super-admin certificate
    pub super_admin: Option<CaCertificate>,
    /// The desired minimum debug level
    pub debug_level: Option<service::LogLevel>,
    /// Is tpm2 hardware required to setup the pki?
    #[cfg(feature = "tpm2")]
    pub tpm2_required: bool,
    /// The security module configuration
    pub security_module: SecurityModuleConfiguration,
}

/// Potential errors when loading a pki object
#[derive(Debug)]
pub enum PkiLoadError {
    /// An individual ca failed to load with the config data specified
    FailedToLoadCa(String, CaLoadError),
    /// A ca cannot be superior to itself
    CannotBeOwnSuperior(String),
    /// Failed to initialize the hsm
    HsmInitFailed(String),
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
    /// Failed to save to medium
    FailedToSaveToMedium(CertificateSaveError),
    /// General settings missing
    GeneralSettingsMissing,
    /// Failed to create admin certificate using external provider
    AdminCreationExternalFailed(String),
}

impl From<&CertificateLoadingError> for CaLoadError {
    fn from(value: &CertificateLoadingError) -> Self {
        Self::CertificateLoadingError(value.to_owned())
    }
}

impl Pki {
    /// Handle a local ca configuration, adding it to the local pki instance
    pub async fn handle_local_ca_configuration(
        hm: &mut HashMap<String, LocalOrRemoteCa>,
        name: &String,
        config: &LocalCaConfiguration,
        main_config: &crate::main_config::MainConfiguration,
        service: Option<&crate::main_config::ServerConfiguration>,
        hsm: &Arc<crate::hsm2::SecurityModule>,
        done: Option<&mut bool>,
    ) -> Result<(), PkiLoadError> {
        let ca_name =
            service.and_then(|s| s.https.as_ref().and_then(|h| h.certificate.create_by_ca()));

        if !hm.contains_key(name) {
            let config = &config.get_ca(name, main_config);
            let ca = crate::ca::Ca::init(
                hsm.clone(),
                config,
                config.inferior_to.as_ref().and_then(|n| hm.get_mut(n)),
                None,
            )
            .await;
            match ca {
                Ok(mut ca) => {
                    if let Some(ca_name) = &ca_name {
                        service::log::debug!(
                            "Checking if CA '{}' matches HTTPS CA name '{}'",
                            name,
                            ca_name
                        );
                        if ca_name == name {
                            service::log::info!("Creating HTTPS certificate for CA '{}'", name);
                            // Pass the service HTTPS config and public names to the CA for certificate creation
                            let service_https = service.and_then(|s| s.https.as_ref());
                            let public_names = main_config.pki.get_public_names();
                            ca.check_https_create_with_config(
                                hsm.clone(),
                                main_config,
                                service_https,
                                public_names,
                            )
                            .await
                            .map_err(|_| {
                                service::log::error!(
                                    "Failed to load ca due to https certificate creation"
                                );
                                PkiLoadError::FailedToLoadCa(
                                    name.to_owned(),
                                    CaLoadError::FailedToInitHttps,
                                )
                            })?;
                        }
                    } else {
                        service::log::debug!("No HTTPS CA name configured for service");
                    }
                    hm.insert(name.to_owned(), LocalOrRemoteCa::Local(ca));
                }
                Err(e) => match e {
                    CaLoadError::SuperiorCaMissing => {
                        if let Some(done) = done {
                            *done = false;
                        }
                    }
                    _ => {
                        service::log::error!("Failed to load ca 7 {} {:?}", name, e);
                        return Err(PkiLoadError::FailedToLoadCa(name.to_owned(), e));
                    }
                },
            }
        }
        Ok(())
    }

    /// Initialize a Pki instance with the specified configuration and options for setting file ownerships (as required).
    #[allow(dead_code)]
    pub async fn init(
        hsm: Arc<crate::hsm2::SecurityModule>,
        settings: &crate::ca::PkiConfiguration,
        main_config: &crate::main_config::MainConfiguration,
        admin_csr: Option<&String>,
    ) -> Result<Self, PkiLoadError> {
        let mut hm: HashMap<String, LocalOrRemoteCa> = std::collections::HashMap::new();
        loop {
            let mut done = true;
            for (name, config) in &settings.local_ca {
                Self::handle_local_ca_configuration(
                    &mut hm,
                    name,
                    config,
                    main_config,
                    Some(&settings.service),
                    &hsm,
                    Some(&mut done),
                )
                .await?;
            }
            if done {
                break;
            }
        }
        Ok(Self {
            debug_level: settings.debug_level.clone(),
            security_module: settings.security_module.clone(),
            #[cfg(feature = "tpm2")]
            tpm2_required: settings.tpm2_required,
            public_names: settings.public_names.clone(),
            database: settings.service.database.clone(),
            http: settings.service.http.clone(),
            https: settings.service.https.clone(),
            general: settings.general.clone(),
            all_ca: hm,
            super_admin: None,
        })
    }

    /// Load pki stuff
    #[allow(dead_code)]
    pub async fn load(
        hsm: Arc<crate::hsm2::SecurityModule>,
        settings: &crate::ca::PkiConfiguration,
        main_config: &MainConfiguration,
    ) -> Result<Self, PkiLoadError> {
        let mut hm: HashMap<String, LocalOrRemoteCa> = HashMap::new();
        for (name, config) in &settings.local_ca {
            let config = &config.get_ca(name, main_config);
            let ca = crate::ca::Ca::load(hsm.clone(), config)
                .await
                .map_err(|e| {
                    service::log::error!("Failed to load ca 8 {} {:?}", name, e);
                    PkiLoadError::FailedToLoadCa(name.to_owned(), e)
                })?;
            hm.insert(name.to_owned(), LocalOrRemoteCa::Local(ca));
        }
        let super_admin: Option<CaCertificate> = if let Some(sa) = &settings.super_admin {
            if let Some(ca) = hm.get_mut(sa) {
                match ca {
                    LocalOrRemoteCa::Local(ca) => {
                        let p = ca.admin_access.to_string();
                        Some(
                            ca.load_admin_cert(hsm.clone(), &p)
                                .await
                                .map(|a| a.to_owned())
                                .map_err(|e| {
                                    service::log::error!("Failed to load super admin {:?}", e);
                                    PkiLoadError::FailedToLoadCa(
                                        sa.to_owned(),
                                        CaLoadError::CertificateLoadingError(e.to_owned()),
                                    )
                                })?,
                        )
                    }
                    LocalOrRemoteCa::Remote => todo!(),
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some(sa) = &super_admin {
            for ca in hm.values_mut() {
                if let LocalOrRemoteCa::Local(ca) = ca {
                    ca.insert_super_admin(sa.to_owned());
                }
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
                            admin = sca.admin().ok();
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
            debug_level: settings.debug_level.clone(),
            security_module: settings.security_module.clone(),
            #[cfg(feature = "tpm2")]
            tpm2_required: settings.tpm2_required,
            public_names: settings.public_names.clone(),
            database: settings.service.database.clone(),
            http: settings.service.http.clone(),
            https: settings.service.https.clone(),
            general: settings.general.clone(),
            all_ca: hm,
            super_admin,
        })
    }

    /// Retrieve the certificate authorities associated with verifying client certificates
    #[allow(dead_code)]
    pub async fn get_client_certifiers(
        &self,
    ) -> std::collections::hash_map::Values<String, LocalOrRemoteCa> {
        self.all_ca.values()
    }
}

/// An instance of either a pki or ca.
/// TODO: Change this to a struct containing common data to both elements and an enum containing what is different
pub enum PkiInstance {
    /// A generic pki instance
    Pki(Pki),
    /// A single certificate authority instance
    Ca(Ca),
}

impl PkiInstance {
    /// Builds a proxy map
    pub fn build_proxy_map(&self) -> HashMap<String, String> {
        let mut proxy_map = std::collections::HashMap::new();

        let public_names = match self {
            PkiInstance::Pki(pki) => &pki.public_names,
            PkiInstance::Ca(ca) => &ca.public_names,
        };
        for name in public_names {
            proxy_map.insert(name.domain.clone(), name.subdomain.clone());
        }
        proxy_map
    }

    /// Connects to the mysql server, if applicable
    pub fn connect_to_mysql(&self) -> Option<mysql::Pool> {
        let mut mysql_pool = None;

        let database = match self {
            PkiInstance::Pki(pki) => &pki.database,
            PkiInstance::Ca(ca) => &ca.database,
        };

        if let Some(settings) = database {
            let mysql_pw = &settings.password;
            let mysql_user = &settings.username;
            let mysql_dbname = &settings.name;
            let mysql_url = &settings.url;
            let mysql_conn_s = format!(
                "mysql://{}:{}@{}/{}",
                mysql_user, mysql_pw, mysql_url, mysql_dbname,
            );
            let mysql_opt = mysql::Opts::from_url(mysql_conn_s.as_str()).unwrap();
            let mysql_temp = mysql::Pool::new(mysql_opt);
            match mysql_temp {
                Ok(ref _bla) => service::log::info!("I have a bla"),
                Err(ref e) => service::log::error!("Error connecting to mysql: {}", e),
            }
            mysql_pool = mysql_temp.ok();
            let _mysql_conn_s = mysql_pool.as_mut().map(|s| s.get_conn().unwrap());
        }
        mysql_pool
    }

    /// Checks an verifies that if an https server is required, that the certificate is also present
    pub fn check_for_existing_https_certificate(&self) {
        let https = match self {
            PkiInstance::Pki(pki) => &pki.https,
            PkiInstance::Ca(ca) => &ca.https,
        };
        if let Some(https) = https {
            if !https.certificate.exists() {
                service::log::error!("Failed to open https certificate");
                panic!("No https certificate to run with");
            }
        }
    }

    /// Get the static root for the webserver
    pub fn get_static_root(&self) -> String {
        match self {
            Self::Pki(pki) => pki.general.static_content.clone(),
            Self::Ca(ca) => ca.general.static_content.clone(),
        }
    }

    /// Set the shutdown for all pki
    pub fn set_shutdown(&mut self, sd: tokio::sync::mpsc::UnboundedSender<()>) {
        match self {
            PkiInstance::Pki(pki) => {
                for ca in pki.all_ca.values_mut() {
                    if let LocalOrRemoteCa::Local(ca) = ca {
                        ca.set_shutdown(sd.clone());
                    }
                }
            }
            PkiInstance::Ca(ca) => {
                ca.set_shutdown(sd);
            }
        }
    }

    /// Register all extra configurations present, each extra configuration represents a single server instance setup after the initial instance was setup
    pub async fn register_extra_configs(
        &mut self,
        extra_configs: Vec<crate::main_config::ExtendedConfiguration>,
        hsm: Arc<crate::hsm2::SecurityModule>,
        main_config: &crate::main_config::MainConfiguration,
    ) {
        if let PkiInstance::Pki(pki) = self {
            for config in extra_configs {
                match config {
                    crate::main_config::ExtendedConfiguration::ExtraPkiCaInstance {
                        name,
                        instance,
                    } => {
                        Pki::handle_local_ca_configuration(
                            &mut pki.all_ca,
                            &name,
                            &instance,
                            main_config,
                            None,
                            &hsm,
                            None,
                        )
                        .await;
                    }
                    crate::main_config::ExtendedConfiguration::ExtraPkiRemoteCaInstance {
                        name,
                        instance,
                    } => {}
                }
            }
        } else {
            if !extra_configs.is_empty() {
                unimplemented!();
            }
        }
    }

    /// Init a pki Instance from the given settings
    #[allow(dead_code)]
    pub async fn init(
        hsm: Arc<crate::hsm2::SecurityModule>,
        settings: &crate::ca::PkiConfigurationEnum,
        main_config: &crate::main_config::MainConfiguration,
        admin_csr: Option<&String>,
    ) -> Result<Self, PkiLoadError> {
        match settings {
            PkiConfigurationEnum::AddedCa(ca) => {
                todo!();
            }
            PkiConfigurationEnum::Pki(pki_config) => {
                let pki = crate::ca::Pki::init(hsm, pki_config, main_config, admin_csr).await?;
                Ok(Self::Pki(pki))
            }
            PkiConfigurationEnum::Ca(ca_config) => {
                let ca = ca_config.get_ca(main_config);
                let mut ca = match crate::ca::Ca::init(hsm.clone(), &ca, None, admin_csr).await {
                    Ok(a) => a,
                    Err(e) => {
                        service::log::error!("Failed to load ca 9 {:?}", e);
                        ca_config.get_ca(main_config).destroy_backend().await;
                        return Err(PkiLoadError::FailedToLoadCa("ca".to_string(), e));
                    }
                }; //TODO Use the proper ca superior object instead of None
                if let Some(service) = &ca_config.service {
                    if let Some(service_https) = service.https.as_ref() {
                        let public_names = main_config.pki.get_public_names();
                        ca.check_https_create_with_config(
                            hsm.clone(),
                            main_config,
                            Some(service_https),
                            public_names,
                        )
                        .await
                        .map_err(|_| {
                            service::log::error!("Failed to init https cert");
                            PkiLoadError::FailedToLoadCa(
                                "ca".to_string(),
                                CaLoadError::FailedToInitHttps,
                            )
                        })?;
                    }
                }
                Ok(Self::Ca(ca))
            }
        }
    }

    /// Load an instance of self from the settings.
    #[allow(dead_code)]
    pub async fn load(
        hsm: Arc<crate::hsm2::SecurityModule>,
        settings: &crate::MainConfiguration,
    ) -> Result<Self, PkiLoadError> {
        match &settings.pki {
            PkiConfigurationEnum::AddedCa(ca) => {
                todo!();
            }
            PkiConfigurationEnum::Pki(pki_config) => {
                let pki = crate::ca::Pki::load(hsm, &pki_config, settings).await?;
                Ok(Self::Pki(pki))
            }
            PkiConfigurationEnum::Ca(ca_config) => {
                let ca_config = &ca_config.get_ca(settings);
                let ca = Ca::load(hsm, ca_config).await.map_err(|e| {
                    service::log::error!("Failed to load ca 10 {:?}", e);
                    PkiLoadError::FailedToLoadCa("ca".to_string(), e)
                })?;
                Ok(Self::Ca(ca))
            }
        }
    }
}

/// The structure containing revokation data for a certificate
pub struct RevokeData {
    /// The raw revoked info data
    pub data: ocsp::response::RevokedInfo,
    /// More usable form of when the certificate was revoked
    pub revoked: chrono::DateTime<chrono::Utc>,
}

fn match_crl_reason(cr: i32) -> Option<ocsp::response::CrlReason> {
    match cr {
        0 => Some(ocsp::response::CrlReason::OcspRevokeUnspecified),
        1 => Some(ocsp::response::CrlReason::OcspRevokeKeyCompromise),
        2 => Some(ocsp::response::CrlReason::OcspRevokeCaCompromise),
        3 => Some(ocsp::response::CrlReason::OcspRevokeAffChanged),
        4 => Some(ocsp::response::CrlReason::OcspRevokeSuperseded),
        5 => Some(ocsp::response::CrlReason::OcspRevokeCessOperation),
        6 => Some(ocsp::response::CrlReason::OcspRevokeCertHold),
        8 => Some(ocsp::response::CrlReason::OcspRevokeRemoveFromCrl),
        9 => Some(ocsp::response::CrlReason::OcspRevokePrivWithdrawn),
        10 => Some(ocsp::response::CrlReason::OcspRevokeAaCompromise),
        _ => None,
    }
}

impl TryFrom<DbEntry<'_>> for RevokeData {
    type Error = async_sqlite::rusqlite::Error;
    fn try_from(value: DbEntry<'_>) -> Result<Self, Self::Error> {
        let ts: String = value.row_data.get(0)?;
        let tsa: Vec<u32> = ts.split(';').map(|a| a.parse::<u32>().unwrap()).collect();
        let tstring = format!(
            "{:04};{:02};{:02};{:02};{:02};{:02}",
            tsa[0], tsa[1], tsa[2], tsa[3], tsa[4], tsa[5]
        );
        let datetime = chrono::NaiveDateTime::parse_from_str(&tstring, "%Y;%m;%d;%H;%M;%S")
            .unwrap()
            .and_utc();
        let t = ocsp::common::asn1::GeneralizedTime::new(
            tsa[0] as i32,
            tsa[1],
            tsa[2],
            tsa[3],
            tsa[4],
            tsa[5],
        )
        .unwrap();
        let cr = value.row_data.get(1)?;
        let r = match_crl_reason(cr);
        Ok(Self {
            data: ocsp::response::RevokedInfo::new(t, r),
            revoked: datetime.into(),
        })
    }
}

/// An intermediate object used by the pki to keep track of local and remote ca instances
#[derive(Debug)]
pub enum LocalOrRemoteCa {
    /// A local ca
    Local(Ca),
    /// A remote ca
    Remote,
}

impl LocalOrRemoteCa {
    /// Retrieve a copy of all superior admin certificates, used for building the proper chain of superior admin certificates.
    pub fn get_superior_admin(&self) -> Vec<CaCertificate> {
        match self {
            LocalOrRemoteCa::Local(ca) => ca.get_superior_admin(),
            LocalOrRemoteCa::Remote => todo!(),
        }
    }

    /// Get the dates the ca is valid
    pub fn get_validity(&self) -> Option<x509_cert::time::Validity> {
        match self {
            LocalOrRemoteCa::Local(ca) => ca.get_validity(),
            LocalOrRemoteCa::Remote => todo!(),
        }
    }

    /// Retrieve the sign method for the ca
    pub fn sign_method(&self) -> CertificateSigningMethod {
        match self {
            LocalOrRemoteCa::Local(ca) => ca.config.sign_method,
            LocalOrRemoteCa::Remote => todo!(),
        }
    }

    /// Add an admin certificate from a superior certificate authority. A superior authority is one that is directly or indirectly responsible for creating this authority.
    pub fn add_superior_admin(&mut self, admin: CaCertificate) {
        match self {
            LocalOrRemoteCa::Local(ca) => ca.add_superior_admin(admin),
            LocalOrRemoteCa::Remote => todo!(),
        }
    }

    /// Get a new request id, if possible
    pub async fn get_new_request_id(&mut self) -> Option<u64> {
        match self {
            LocalOrRemoteCa::Local(ca) => ca.get_new_request_id().await,
            LocalOrRemoteCa::Remote => todo!(),
        }
    }

    /// Get a copy of the admin certificate
    pub fn admin(&self) -> Result<CaCertificate, CertificateLoadingError> {
        match self {
            LocalOrRemoteCa::Local(ca) => ca.admin.clone(),
            LocalOrRemoteCa::Remote => todo!(),
        }
    }

    /// Get a copy of the root certificate
    pub fn root_cert(&self) -> Result<CaCertificate, CertificateLoadingError> {
        match self {
            LocalOrRemoteCa::Local(ca) => ca.root_cert.clone(),
            LocalOrRemoteCa::Remote => todo!(),
        }
    }

    /// Get a reference to the root certificate
    pub fn root_cert_ref(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        match self {
            LocalOrRemoteCa::Local(ca) => ca.root_cert.as_ref(),
            LocalOrRemoteCa::Remote => todo!(),
        }
    }
}

/// The actual ca object
#[derive(Debug)]
pub struct Ca {
    /// General settings
    pub general: crate::main_config::GeneralSettings,
    /// Settings for the database
    pub database: Option<crate::main_config::DatabaseSettings>,
    /// The public name of the service, contains example.com/asdf for the example
    pub public_names: Vec<ComplexName>,
    /// Settings for the http server
    pub http: Option<crate::main_config::HttpSettings>,
    /// Settings for the https server
    pub https: Option<crate::main_config::HttpsSettings>,
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
    /// The optional shutdown message sender
    pub shutdown: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    /// The desired minimum debug level
    pub debug_level: Option<service::LogLevel>,
    /// Is tpm2 hardware required to setup the pki?
    #[cfg(feature = "tpm2")]
    pub tpm2_required: bool,
    /// Security module configuration
    security_configuration: Option<SecurityModuleConfiguration>,
}

/// The data submitted by the user or admin for revoking a certificate
pub struct RevokeFormData {
    /// The id of the certificate to revoke
    pub id: usize,
    /// The numeric code for revoking the certificate. see RFC 5280 or ocsp::response::CrlReason
    pub reason: u8,
}

/// A structure holding the raw der contents of a certificate, like CertificateInfo
pub struct RawCertificateInfo {
    /// The certificate in der format
    pub cert: Vec<u8>,
    /// The serial number of the certificate
    pub serial: Vec<u8>,
    /// The revocation status
    pub revoked: Option<RevokeData>,
}

/// A structure used when iterating over certificates for the front end
pub struct CertificateInfo {
    /// The index of the certificate
    index: usize,
    /// The certificate
    pub cert: x509_cert::certificate::CertificateInner,
    /// The serial number of the certificate
    pub serial: Vec<u8>,
    /// The revocation status
    pub revoked: Option<ocsp::response::CrlReason>,
}

/// A structure containining the things that might be searched for in a certificate
#[derive(Debug, Default)]
pub struct CertificateSearchable {
    /// THe CN field of the subject
    common_name: Option<String>,
    /// The country field
    country: Option<String>,
    /// the state field
    state: Option<String>,
    /// The locality field
    locality: Option<String>,
    /// The organization field
    organization: Option<String>,
    /// The organizational unit field
    ou: Option<String>,
}

impl TryFrom<&x509_cert::Certificate> for CertificateSearchable {
    type Error = String;
    fn try_from(value: &x509_cert::Certificate) -> Result<Self, Self::Error> {
        let s = &value.tbs_certificate.subject;
        let mut searchable = CertificateSearchable::default();
        for item in &s.0 {
            for l in item.0.iter() {
                let v = String::from_utf8(l.value.value().to_vec());
                if l.oid
                    == cert_common::oid::Oid::from_const(
                        const_oid::ObjectIdentifier::from_arcs([2, 5, 4, 3]).unwrap(),
                    )
                    .to_const()
                {
                    searchable.common_name = v.ok();
                } else if l.oid
                    == cert_common::oid::Oid::from_const(
                        const_oid::ObjectIdentifier::from_arcs([2, 5, 4, 6]).unwrap(),
                    )
                    .to_const()
                {
                    searchable.country = v.ok();
                } else if l.oid
                    == cert_common::oid::Oid::from_const(
                        const_oid::ObjectIdentifier::from_arcs([2, 5, 4, 8]).unwrap(),
                    )
                    .to_const()
                {
                    searchable.state = v.ok();
                } else if l.oid
                    == cert_common::oid::Oid::from_const(
                        const_oid::ObjectIdentifier::from_arcs([2, 5, 4, 7]).unwrap(),
                    )
                    .to_const()
                {
                    searchable.locality = v.ok();
                } else if l.oid
                    == cert_common::oid::Oid::from_const(
                        const_oid::ObjectIdentifier::from_arcs([2, 5, 4, 10]).unwrap(),
                    )
                    .to_const()
                {
                    searchable.organization = v.ok();
                } else if l.oid
                    == cert_common::oid::Oid::from_const(
                        const_oid::ObjectIdentifier::from_arcs([2, 5, 4, 11]).unwrap(),
                    )
                    .to_const()
                {
                    searchable.ou = v.ok();
                } else {
                    if let Ok(v) = v {
                        return Err(format!("UNHANDLED OID: {} - {}", l.oid, v));
                    } else {
                        return Err(format!("UNHANDLED OID: {} - ?", l.oid));
                    }
                }
            }
        }
        Ok(searchable)
    }
}

impl Ca {
    /// Set the shutdown sender
    pub fn set_shutdown(&mut self, sd: tokio::sync::mpsc::UnboundedSender<()>) {
        self.shutdown = Some(sd);
    }

    pub async fn revoke_certificate(&mut self, form: RevokeFormData) -> Result<(), ()> {
        match &self.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::Sqlite(p) => {
                p.conn(move |conn| {
                    let date = chrono::Utc::now();
                    let dates = format!(
                        "{};{};{};{};{};{}",
                        date.year(),
                        date.month(),
                        date.day(),
                        date.hour(),
                        date.minute(),
                        date.second()
                    );
                    let mut stmt =
                        conn.prepare("INSERT INTO revoked (id, date, reason) VALUES (?1, ?2, ?3)")?;
                    stmt.execute([
                        form.id.to_sql().unwrap(),
                        dates.to_sql().unwrap(),
                        form.reason.to_sql().unwrap(),
                    ])?;
                    Ok(())
                })
                .await
                .map_err(|_| ())?;
                Ok(())
            }
        }
    }

    /// Check to see if the https certifiate should be created
    pub async fn check_https_create(
        &mut self,
        hsm: Arc<crate::hsm2::SecurityModule>,
        main_config: &crate::main_config::MainConfiguration,
    ) -> Result<(), ()> {
        service::log::debug!(
            "check_https_create called with {} public names",
            self.public_names.len()
        );
        self.create_https_certificate(
            hsm.clone(),
            self.public_names.iter().map(|a| a.to_string()).collect(),
            None,
        )
        .await?;
        Ok(())
    }

    /// Check to see if the https certificate should be created, with optional service HTTPS config
    pub async fn check_https_create_with_config(
        &mut self,
        hsm: Arc<crate::hsm2::SecurityModule>,
        main_config: &crate::main_config::MainConfiguration,
        service_https: Option<&crate::main_config::HttpsSettings>,
        public_names: Vec<ComplexName>,
    ) -> Result<(), ()> {
        // Use provided public names if not empty, otherwise fall back to self.public_names
        let names_to_use = if !public_names.is_empty() {
            public_names
        } else {
            self.public_names.clone()
        };
        service::log::debug!(
            "check_https_create_with_config called with {} public names, service_https: {:?}",
            names_to_use.len(),
            service_https.is_some()
        );
        self.create_https_certificate(
            hsm.clone(),
            names_to_use.iter().map(|a| a.to_string()).collect(),
            service_https,
        )
        .await?;
        Ok(())
    }

    /// Create the required https certificate
    pub async fn create_https_certificate(
        &mut self,
        _hsm: Arc<crate::hsm2::SecurityModule>,
        https_names: Vec<String>,
        service_https: Option<&crate::main_config::HttpsSettings>,
    ) -> Result<(), ()> {
        let mut stuff = None;
        service::log::debug!(
            "create_https_certificate: checking HTTPS config, self.https={:?}, service_https={:?}",
            self.https.is_some(),
            service_https.is_some()
        );
        // Use service_https if provided (for PKI setups), otherwise use self.https (for standalone CA)
        let https = service_https.or(self.https.as_ref());
        if let Some(https) = https {
            service::log::debug!("HTTPS config exists, checking for certificate path");
            if let Some(destination) = https.certificate.pathbuf() {
                service::log::debug!("Certificate destination path: {:?}", destination);
                let password = https.certificate.password().unwrap();
                service::log::info!("Generating an https certificate for web operations");
                let key_usage_oids = vec![OID_EXTENDED_KEY_USAGE_SERVER_AUTH.to_owned()];
                let extensions =
                    vec![
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
                    let (snb, _sn) = CaCertificateToBeSigned::calc_sn();
                    let mut cert = root_cert
                        .sign_csr(
                            csr,
                            self,
                            snb.to_vec(),
                            time::Duration::days(self.config.days as i64),
                        )
                        .unwrap();
                    cert.medium = self.medium.clone();
                    stuff = Some((id, cert, snb, password.to_owned(), destination));
                }
            }
        }
        if let Some((id, cert, snb, password, destination)) = stuff {
            service::log::info!("Saving HTTPS certificate to {:?}", destination);
            self.save_user_cert(id, &cert.contents().map_err(|_| ())?, Some(&snb))
                .await;
            let p12 = cert.try_p12(&password).unwrap();
            tokio::fs::write(&destination, p12).await.unwrap();
            service::log::info!(
                "HTTPS certificate successfully written to {:?}",
                destination
            );
        } else {
            service::log::debug!("No HTTPS certificate to create");
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
        let medium = settings
            .path
            .build()
            .await
            .map_err(|e| CaLoadError::StorageError(e));
        let mut medium = match medium {
            Ok(m) => m,
            Err(e) => {
                settings.destroy_backend().await;
                return Err(e);
            }
        };
        let a = medium.init(settings).await;
        if a.is_err() {
            settings.destroy_backend().await;
        }
        a.map_err(|_| CaLoadError::StorageError(StorageBuilderError::FailedToInitStorage))?;
        Ok(Self {
            public_names: settings.public_names.clone(),
            database: settings.database.clone(),
            http: settings.http.clone(),
            https: settings.https.clone(),
            general: settings
                .general
                .clone()
                .ok_or(CaLoadError::GeneralSettingsMissing)?,
            medium,
            root_cert: Err(CertificateLoadingError::DoesNotExist("root".to_string())),
            ocsp_signer: Err(CertificateLoadingError::DoesNotExist("ocsp".to_string())),
            admin: Err(CertificateLoadingError::DoesNotExist("admin".to_string())),
            ocsp_urls: Self::get_ocsp_urls(settings)
                .map_err(|_| CaLoadError::FailedToBuildOcspUrl)?,
            admin_access: Zeroizing::new(settings.admin_access_password.to_string()),
            config: settings.to_owned(),
            super_admin: None,
            admin_authorities: Vec::new(),
            shutdown: None,
            debug_level: settings.debug_level.clone(),
            security_configuration: settings.security_config.clone(),
            #[cfg(feature = "tpm2")]
            tpm2_required: settings.tpm2_required,
        })
    }

    /// Initialize a Ca instance with the specified configuration.
    /// superior is used to generate the root certificate for intermediate authorities.
    pub async fn init(
        hsm: Arc<crate::hsm2::SecurityModule>,
        settings: &crate::ca::CaConfiguration,
        superior: Option<&mut LocalOrRemoteCa>,
        admin_csr: Option<&String>,
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
                            t: m,
                            name: format!("{}-root", ca.config.common_name),
                            common_name: ca.config.common_name.clone(),
                            names: ca.config.san.clone(),
                            extensions,
                            id,
                            days_valid: ca.config.days,
                        };
                        let root_csr = root_options.generate_request();
                        let (snb, _sn) = CaCertificateToBeSigned::calc_sn();
                        let mut root_cert = superior
                            .root_cert()
                            .unwrap()
                            .sign_csr(
                                root_csr,
                                &ca,
                                snb.to_vec(),
                                time::Duration::days(ca.config.days as i64),
                            )
                            .unwrap();
                        if let LocalOrRemoteCa::Local(superior) = superior {
                            superior
                                .save_user_cert(
                                    id,
                                    &root_cert.contents().map_err(|_| {
                                        CaLoadError::FailedToSaveCertificate("root".to_string())
                                    })?,
                                    Some(&snb),
                                )
                                .await;
                        }
                        root_cert.medium = ca.medium.clone();
                        root_cert
                    } else {
                        todo!("Intermediate certificate authority generation not possible");
                    };

                    rootcert
                        .save_to_medium(&mut ca, "")
                        .await
                        .map_err(|e| CaLoadError::FailedToSaveToMedium(e))?;
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
                        CaCertificateToBeSigned::calc_sn().0.to_vec(),
                        time::Duration::days(ca.config.days as i64),
                    )
                    .unwrap();
                ocsp_cert.medium = ca.medium.clone();
                ocsp_cert
                    .save_to_medium(&mut ca, "")
                    .await
                    .map_err(|e| CaLoadError::FailedToSaveToMedium(e))?;
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
                    t: m,
                    name: format!("{}-admin", ca.config.common_name),
                    common_name: format!("{} Administrator", settings.common_name),
                    names: Vec::new(),
                    extensions,
                    id,
                    days_valid: ca.config.days,
                };
                let admin_cert = match ca.config.admin_cert.clone() {
                    CertificateType::External => {
                        let Some(csr) = admin_csr else {
                            return Err(CaLoadError::AdminCreationExternalFailed(
                                "No csr present".to_string(),
                            ));
                        };
                        let (_, csr2) = der::Document::from_pem(csr).map_err(|e| {
                            CaLoadError::AdminCreationExternalFailed(format!(
                                "Invalid csr document 2 {} - {}",
                                e, csr
                            ))
                        })?;
                        use der::Encode;
                        let der = csr2.to_der().unwrap();
                        let csr_der = rustls_pki_types::CertificateSigningRequestDer::from(der);
                        let admin_csr = rcgen::CertificateSigningRequestParams::from_der(&csr_der)
                            .map_err(|e| {
                                CaLoadError::AdminCreationExternalFailed(format!(
                                    "Cannot parse csr {}",
                                    e
                                ))
                            })?;
                        let serial = CaCertificateToBeSigned::calc_sn().0.to_vec();
                        let cert_to_sign = CaCertificateToBeSigned {
                            algorithm: m,
                            medium: ca.medium.clone(),
                            csr: admin_csr,
                            keypair: None,
                            name: "".into(),
                            serial,
                        };
                        let mut admin_cert = ca
                            .root_cert
                            .as_ref()
                            .unwrap()
                            .sign_csr(
                                cert_to_sign,
                                &ca,
                                CaCertificateToBeSigned::calc_sn().0.to_vec(),
                                time::Duration::days(ca.config.days as i64),
                            )
                            .unwrap();
                        admin_cert.medium = ca.medium.clone();
                        admin_cert.name = format!("{}-admin", ca.config.common_name);
                        let p = "whatever"; // it won't matter because there is only public data in the certificate
                        admin_cert
                            .save_to_medium(&mut ca, p)
                            .await
                            .map_err(|e| CaLoadError::FailedToSaveToMedium(e))?;
                        admin_cert
                    }
                    CertificateType::Soft(p) => {
                        let admin_csr = options.generate_request();
                        let mut admin_cert = ca
                            .root_cert
                            .as_ref()
                            .unwrap()
                            .sign_csr(
                                admin_csr,
                                &ca,
                                CaCertificateToBeSigned::calc_sn().0.to_vec(),
                                time::Duration::days(ca.config.days as i64),
                            )
                            .unwrap();
                        admin_cert.medium = ca.medium.clone();
                        service::log::debug!("Saving admin cert to medium");
                        admin_cert
                            .save_to_medium(&mut ca, &p)
                            .await
                            .map_err(|e| CaLoadError::FailedToSaveToMedium(e))?;
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
                        CaCertificateToBeSigned::calc_sn().0.to_vec(),
                    );
                    root.save_to_medium(&mut ca, "")
                        .await
                        .map_err(CaLoadError::FailedToSaveToMedium)?;
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

    /// Return a reference to the ocsp cert
    pub fn ocsp_ca_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.ocsp_signer.as_ref()
    }

    /// Return a reference to the root cert
    pub fn root_ca_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.root_cert.as_ref()
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

    /// Performs an iteration of all certificates, processing them with the given closure. It returns the number of certificates total
    pub async fn certificate_processing<'a, F>(
        &'a self,
        num_results: usize,
        offset: usize,
        mut process: F,
    ) -> usize
    where
        F: FnMut(CertificateInfo) + Send + 'a,
    {
        let (s, mut r) = tokio::sync::mpsc::unbounded_channel();

        let self2_medium = self.medium.to_owned();
        let a = tokio::spawn(async move {
            use der::Decode;
            match self2_medium {
                CaCertificateStorage::Nowhere => 0,
                CaCertificateStorage::Sqlite(p) => {
                    p.conn(move |conn| {
                        let counti : usize = conn.query_row("SELECT COUNT(*) from certs", [], |r| {
                            r.get(0)
                        }).unwrap();
                        let mut stmt = conn
                            .prepare(
                                &format!("SELECT certs.*, revoked.*, serials.serial from certs LEFT JOIN revoked ON certs.id = revoked.id LEFT JOIN serials ON certs.id=serials.id LIMIT {} OFFSET {}", num_results, offset),
                            )
                            .unwrap();
                        let mut rows = stmt.query([]).unwrap();
                        let mut index = 0;
                        while let Ok(Some(r)) = rows.next() {
                            let der: Vec<u8> = r.get(1).unwrap();
                            let date: Option<String> = r.get(3).ok();
                            let reason: Option<u32> = r.get(4).ok();
                            let serial: Vec<u8> = r.get(5).unwrap();
                            let revoked = if let Some(date) = date {
                                if let Some(reason) = reason {
                                    match reason {
                                        0 => Some(ocsp::response::CrlReason::OcspRevokeUnspecified),
                                        1 => {
                                            Some(ocsp::response::CrlReason::OcspRevokeKeyCompromise)
                                        }
                                        2 => {
                                            Some(ocsp::response::CrlReason::OcspRevokeCaCompromise)
                                        }
                                        3 => Some(ocsp::response::CrlReason::OcspRevokeAffChanged),
                                        4 => Some(ocsp::response::CrlReason::OcspRevokeSuperseded),
                                        5 => {
                                            Some(ocsp::response::CrlReason::OcspRevokeCessOperation)
                                        }
                                        6 => Some(ocsp::response::CrlReason::OcspRevokeCertHold),
                                        8 => {
                                            Some(ocsp::response::CrlReason::OcspRevokeRemoveFromCrl)
                                        }
                                        9 => {
                                            Some(ocsp::response::CrlReason::OcspRevokePrivWithdrawn)
                                        }
                                        10 => {
                                            Some(ocsp::response::CrlReason::OcspRevokeAaCompromise)
                                        }
                                        _ => None,
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            };
                            let cert: x509_cert::Certificate =
                                x509_cert::Certificate::from_der(&der).unwrap();
                            let ci = CertificateInfo {
                                index,
                                cert,
                                serial,
                                revoked,
                            };
                            s.send(ci).unwrap();
                            index += 1;
                        }
                        Ok(counti)
                    })
                    .await
                    .unwrap()
                }
            }
        });
        while let Some(c) = r.recv().await {
            process(c);
        }
        a.await.unwrap()
    }

    /// Performs an iteration of all csr that are not done, processing them with the given closure.
    pub async fn csr_processing<'a, F>(&'a self, mut process: F)
    where
        F: FnMut(usize, CsrRequest, Vec<u8>) + Send + 'a,
    {
        let (s, mut r) = tokio::sync::mpsc::unbounded_channel();

        let self2_medium = self.medium.to_owned();
        tokio::spawn(async move {
            match self2_medium {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::Sqlite(p) => {
                    p.conn(move |conn| {
                        let mut stmt = conn.prepare("SELECT * from csr INNER JOIN serials ON csr.id = serials.id WHERE done='0'").unwrap();
                        let mut rows = stmt.query([]).unwrap();
                        let mut index = 0;
                        while let Ok(Some(r)) = rows.next() {
                            let serial = r.get(8).unwrap();
                            let dbentry = DbEntry::new(r);
                            let csr : CsrRequest = dbentry.into();
                            s.send((index, csr, serial)).unwrap();
                            index += 1;
                        }
                        Ok(())
                    })
                    .await
                    .unwrap();
                }
            }
        });
        while let Some((index, csr, serial)) = r.recv().await {
            process(index, csr, serial);
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

    /// Retrieve the specified serial number of user certificate
    pub async fn get_user_cert(&self, serial: Vec<u8>) -> Option<RawCertificateInfo> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<RawCertificateInfo, async_sqlite::Error> = p
                    .conn(move |conn| {
                        let mut stmt = conn.prepare("SELECT der, reason, date FROM certs LEFT JOIN revoked on certs.id=revoked.id LEFT JOIN serials on certs.id=serials.id WHERE serials.serial=?1")?;
                        stmt.query_row(
                            [serial.clone()],
                            |r| {
                                let cert = r.get(0)?;
                                let reason: Option<u32> = r.get(1).ok();
                                let reason = reason.map(|r| match_crl_reason(r as i32)).flatten();
                                let ts: Option<String> = r.get(2).ok();
                                let t = if let Some(ts) = &ts {
                                    let tsa: Vec<u32> = ts.split(';').map(|a| a.parse::<u32>().unwrap()).collect();
                                    ocsp::common::asn1::GeneralizedTime::new(
                                        tsa[0] as i32,
                                        tsa[1],
                                        tsa[2],
                                        tsa[3],
                                        tsa[4],
                                        tsa[5],
                                    ).ok()
                                } else {
                                    None
                                };
                                let data = if let Some(t) = t {
                                    let tstring = ts.unwrap();
                                    let tsa: Vec<u32> = tstring.split(';').map(|a| a.parse::<u32>().unwrap()).collect();
                                    let tstring = format!("{:04};{:02};{:02};{:02};{:02};{:02}", tsa[0], tsa[1], tsa[2], tsa[3], tsa[4], tsa[5]);
                                    service::log::info!("Parsing revoke string {:?}", tstring);
                                    let datetime = chrono::NaiveDateTime::parse_from_str(&tstring, "%Y;%m;%d;%H;%M;%S").unwrap().and_utc();
                                    let a = RevokedInfo::new(t, reason);
                                    Some(RevokeData {
                                        data: a,
                                        revoked: datetime,
                                    })
                                } else {
                                    None
                                };
                                Ok(RawCertificateInfo {
                                    cert,
                                    serial,
                                    revoked: data,
                                })
                            }
                        )
                    })
                    .await;
                cert.inspect_err(|a| service::log::info!("USER CERT ERR IS {:?}", a))
                    .ok()
            }
        }
    }

    /// Retrieve the reason the csr was rejected
    pub async fn get_rejection_reason_by_serial(&self, serial: Vec<u8>) -> Option<String> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => match &self.config.sign_method {
                cert_common::CertificateSigningMethod::Https(_) => {
                    let cert: Result<CsrRejection, async_sqlite::Error> = p
                        .conn(move |conn| {
                            let mut stmt = conn.prepare("SELECT csr.*, serials.serial FROM csr LEFT JOIN serials ON csr.id=serials.id WHERE serials.serial=?1")?;
                            stmt.query_row(
                                [&serial],
                                |r| {
                                    let dbentry = DbEntry::new(r);
                                    dbentry.try_into()
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
                            let mut stmt = conn.prepare("SELECT * FROM sshr WHERE id=?1")?;
                            stmt.query_row([&serial], |r| {
                                let dbentry = DbEntry::new(r);
                                let csr = dbentry.into();
                                Ok(csr)
                            })
                        })
                        .await;
                    let rejection: Option<SshRejection> = cert.ok();
                    rejection.map(|r| r.rejection)
                }
            },
        }
    }

    /// Reject an existing certificate signing request by id.
    pub async fn reject_csr_by_serial(
        &mut self,
        serial: Vec<u8>,
        reason: &String,
    ) -> Result<(), CertificateSigningError> {
        let csr = self.get_csr_by_serial(serial).await;
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
        let id = self
            .get_id_from_serial(reject.serial.clone())
            .await
            .unwrap();
        match &self.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::Sqlite(p) => {
                let rejection = reject.rejection.to_owned();
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
                self.mark_csr_done(id)
                    .await
                    .map_err(|_| CertificateSigningError::FailedToDeleteRequest)?;
                match s {
                    Err(_) => Err(CertificateSigningError::FailedToDeleteRequest),
                    Ok(_) => Ok(()),
                }
            }
        }
    }

    /// Retrieve a https certificate signing request by id, if it exists
    pub async fn get_csr_by_serial(&self, sn: Vec<u8>) -> Option<CsrRequest> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<CsrRequest, async_sqlite::Error> = p
                    .conn(move |conn| {
                        let mut stmt = conn.prepare("SELECT * FROM csr INNER JOIN serials ON csr.id = serials.id WHERE serials.serial=?1")?;
                        stmt.query_row([sn.to_sql().unwrap()], |r| {
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
    pub async fn get_ssh_request_by_serial(&self, serial: Vec<u8>) -> Option<SshRequest> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<SshRequest, async_sqlite::Error> = p
                    .conn(move |conn| {
                        let mut stmt = conn.prepare("SELECT sshr.* FROM sshr LEFT JOIN serials on sshr.id=serials.id WHERE serial=?1")?;
                        stmt.query_row([&serial], |r| {
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
        let CsrRequest {
            cert,
            name,
            email,
            phone,
            id,
            sn,
        } = csr.to_owned();
        match &self.medium {
            CaCertificateStorage::Nowhere => Ok(()),
            CaCertificateStorage::Sqlite(p) => {
                p.conn(move |conn| {
                    let mut stmt = conn.prepare("INSERT INTO csr (id, requestor, email, phone, pem) VALUES (?1, ?2, ?3, ?4, ?5)").expect("Failed to build statement");
                    stmt.execute([
                        id.to_sql().unwrap(),
                        name.to_sql().unwrap(),
                        email.to_sql().unwrap(),
                        phone.to_sql().unwrap(),
                        cert.to_sql().unwrap(),
                    ]).expect("Failed to insert csr");
                    let mut stmt = conn.prepare("INSERT INTO serials (id, serial) VALUES (?1, ?2)").expect("Failed to build statement");
                    stmt.execute([
                        id.to_sql().unwrap(),
                        sn.to_sql().unwrap(),
                    ]).expect("Failed to insert csr serial");
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

    /// Looks up the certificate id from the serial number
    pub async fn get_id_from_serial(&mut self, serial: Vec<u8>) -> Option<u64> {
        match &self.medium {
            CaCertificateStorage::Nowhere => None,
            CaCertificateStorage::Sqlite(p) => p
                .conn(move |conn| {
                    let mut stmt = conn
                        .prepare("SELECT id from serials where serial=?1")
                        .expect("Failed to build prepared statement");
                    stmt.query_row([&serial], |r| {
                        let cert = r.get(0)?;
                        Ok(cert)
                    })
                })
                .await
                .expect("Failed to insert"),
        }
    }

    pub async fn insert_searchable(&mut self, cert: &x509_cert::Certificate, id: u64) {
        let searchable = CertificateSearchable::try_from(cert);
        if let Ok(s) = searchable {
            // destructure to make it obvious that items were missed if they are added in the future
            let CertificateSearchable {
                common_name,
                country,
                state,
                locality,
                organization,
                ou,
            } = s;
            match &self.medium {
                CaCertificateStorage::Nowhere => {}
                CaCertificateStorage::Sqlite(p) => {
                    p.conn(move |conn| {
                        let mut stmt = conn
                            .prepare("REPLACE INTO searchable (id, cn, country, state, locality, organization, ou) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)")
                            .expect("Failed to build prepared statement");
                        stmt.execute([id.to_sql().unwrap(),
                            common_name.to_sql().unwrap(),
                            country.to_sql().unwrap(),
                            state.to_sql().unwrap(),
                            locality.to_sql().unwrap(),
                            organization.to_sql().unwrap(),
                            ou.to_sql().unwrap()])
                    }).await.expect("Failed to insert");
                }
            }
        }
    }

    /// Save the user cert of the specified index to storage
    pub async fn save_user_cert(&mut self, id: u64, der: &[u8], sn: Option<&[u8]>) {
        let decoded_cert = x509_cert::Certificate::from_der(der);
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
                if let Some(sn) = sn {
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
                if let Ok(cert) = decoded_cert {
                    self.insert_searchable(&cert, id).await;
                }
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
                url.push_str("https://");
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
        let s_str = crate::utility::encode_hex(serial);
        service::log::info!("Looking for serial number {}", s_str);
        match &self.medium {
            CaCertificateStorage::Nowhere => MaybeError::None,
            CaCertificateStorage::Sqlite(p) => {
                let s2_str = s_str.clone();
                let cert: Result<Vec<u8>, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row(
                            &format!("SELECT der FROM certs INNER JOIN serials ON certs.id = serials.id WHERE serial=x'{}'", s2_str),
                            [],
                            |r| r.get(0),
                        )
                    })
                    .await;

                let revoke_query = p
                .conn(move |conn| {
                    conn.query_row(
                        &format!("SELECT date, reason FROM revoked INNER JOIN serials ON certs.id = serials.id WHERE serial=x'{}'", s_str),
                        [],
                        |r| {
                            let dbentry = DbEntry::new(r);
                            let revoke_data = RevokeData::try_from(dbentry);
                            revoke_data
                        }
                    )
                });
                match cert {
                    Ok(c) => {
                        let revoked = revoke_query.await;
                        match revoked {
                            Ok(revoked) => MaybeError::Err(revoked.data),
                            Err(_) => {
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
            CaCertificateStorage::Nowhere => {
                service::log::debug!("Tried to load {} certificate from nowhere", id);
                Err(CertificateLoadingError::DoesNotExist(format!("ID: {}", id)))
            }
            CaCertificateStorage::Sqlite(p) => {
                let cert: Result<Vec<u8>, async_sqlite::Error> = p
                    .conn(move |conn| {
                        conn.query_row("SELECT der FROM certs WHERE id=?1", [id], |r| r.get(0))
                    })
                    .await;
                match cert {
                    Ok(c) => {
                        use der::Decode;
                        let c = x509_cert::Certificate::from_der(&c).map_err(|_| {
                            CertificateLoadingError::InvalidCert(format!("ID: {}", id))
                        })?;
                        let serial = c.tbs_certificate.serial_number.as_bytes().to_vec();
                        let cac = CaCertificate {
                            medium: self.medium.clone(),
                            data: CertificateData::from_x509(c)?,
                            name: "".to_string(), //TODO fill this in with data from the certificate subject name
                            serial,
                        };
                        service::log::info!("Found the cert");
                        Ok(cac)
                    }
                    Err(e) => {
                        service::log::error!("Did not find the cert {:?}", e);
                        Err(CertificateLoadingError::DoesNotExist(format!("ID: {}", id)))
                    }
                }
            }
        }
    }

    /// Attempt to load a certificate by name, first from hsm, from external, then from p12
    async fn load_cert(
        &self,
        hsm: Arc<crate::hsm2::SecurityModule>,
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
                .map_err(|_| CertificateLoadingError::InvalidCert(name.to_string()))?)
            } else {
                use der::Decode;
                let x509 = x509_cert::Certificate::from_der(&rc.contents)
                    .map_err(|_| CertificateLoadingError::InvalidCert(name.to_string()))?;
                let serial = x509.tbs_certificate.serial_number.as_bytes().to_vec();
                let cert = CaCertificate {
                    medium: self.medium.clone(),
                    data: CertificateData::from_x509(x509)
                        .map_err(|_| CertificateLoadingError::InvalidCert(name.to_string()))?,
                    name: hsm_name.clone(),
                    serial,
                };
                Ok(cert)
            }
        } else {
            service::log::debug!("{} does not exist 2", name);
            Err(CertificateLoadingError::DoesNotExist(name.to_string()))
        }
    }

    /// Load ca stuff
    pub async fn load(
        hsm: Arc<crate::hsm2::SecurityModule>,
        settings: &crate::ca::CaConfiguration,
    ) -> Result<Self, CaLoadError> {
        service::log::debug!("Trying to load ca from config");
        let mut ca = Self::from_config(settings).await?;
        service::log::debug!("Done loading ca from config");
        // These will error when the ca needs to be built
        match &ca.config.sign_method {
            CertificateSigningMethod::Https(_m) => {
                service::log::debug!("Trying to load ocsp cert");
                ca.load_ocsp_cert(hsm.clone()).await?;
                match &settings.admin_cert {
                    CertificateType::External => {
                        service::log::debug!("Trying to load admin cert");
                        ca.load_admin_cert(hsm.clone(), "whatever")
                            .await
                            .map_err(|e| {
                                service::log::debug!(
                                    "There was a problem loading the admin certificate {:?}",
                                    e
                                );
                                CaLoadError::CertificateLoadingError(e.to_owned())
                            })?;
                        service::log::debug!("Success load admin cert");
                    }
                    CertificateType::Soft(p) => {
                        service::log::debug!("Trying to load admin cert");
                        ca.load_admin_cert(hsm.clone(), p).await.map_err(|e| {
                            service::log::debug!(
                                "There was a problem loading the admin certificate {:?}",
                                e
                            );
                            CaLoadError::CertificateLoadingError(e.to_owned())
                        })?;
                        service::log::debug!("Success load admin cert");
                    }
                }
                service::log::debug!("Trying to load root cert");
                ca.load_root_ca_cert(hsm).await.map_err(|e| {
                    service::log::debug!(
                        "There was a problem loading the root certificate {:?}",
                        e
                    );
                    CaLoadError::CertificateLoadingError(e.to_owned())
                })?;
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
        hsm: Arc<crate::hsm2::SecurityModule>,
    ) -> Result<&CaCertificate, &CertificateLoadingError> {
        if self.root_cert.is_err() {
            self.root_cert = self.load_cert(hsm, "root", None).await;
        }
        self.root_cert.as_ref()
    }

    /// Get the protected admin certificate, only useful for soft admin tokens
    pub async fn get_admin_cert(&self) -> Result<CaCertificate, CertificateLoadingError> {
        let cname = format!("{}-admin", self.config.common_name);
        match &self.config.admin_cert {
            CertificateType::Soft(p) => {
                if let Ok(rc) = self.medium.load_p12_from_medium(&cname).await {
                    Ok(cert_common::pkcs12::Pkcs12::load_from_data(
                        &rc.contents,
                        p.as_bytes(),
                        rc.id,
                    )
                    .try_into()
                    .map_err(|_| CertificateLoadingError::InvalidCert("admin".to_string()))?)
                } else {
                    service::log::debug!("Failed to load p12 from medium");
                    Err(CertificateLoadingError::DoesNotExist("admin".to_string()))
                }
            }
            CertificateType::External => self.admin.clone(),
        }
    }

    /// Returns the already loaded admin key
    pub fn examine_admin_cert(&self) -> Result<&CaCertificate, &CertificateLoadingError> {
        self.admin.as_ref()
    }

    /// Load the admin certificate as defined by a smartcard certificate
    pub async fn load_admin_smartcard(
        &mut self,
        hsm: Arc<crate::hsm2::SecurityModule>,
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
        hsm: Arc<crate::hsm2::SecurityModule>,
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
        hsm: Arc<crate::hsm2::SecurityModule>,
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
        let mut medium = settings
            .path
            .build()
            .await
            .map_err(|e| CaLoadError::StorageError(e))?;
        medium.validate().await;
        Ok(Self {
            public_names: settings.public_names.clone(),
            database: settings.database.clone(),
            http: settings.http.clone(),
            https: settings.https.clone(),
            general: settings
                .general
                .clone()
                .ok_or(CaLoadError::GeneralSettingsMissing)?,
            medium,
            root_cert: Err(CertificateLoadingError::DoesNotExist("root".to_string())),
            ocsp_signer: Err(CertificateLoadingError::DoesNotExist("ocsp".to_string())),
            admin: Err(CertificateLoadingError::DoesNotExist("admin".to_string())),
            ocsp_urls: Self::get_ocsp_urls(settings)
                .map_err(|_| CaLoadError::FailedToBuildOcspUrl)?,
            admin_access: Zeroizing::new(settings.admin_access_password.to_string()),
            config: settings.to_owned(),
            super_admin: None,
            admin_authorities: Vec::new(),
            shutdown: None,
            debug_level: settings.debug_level.clone(),
            security_configuration: settings.security_config.clone(),
            #[cfg(feature = "tpm2")]
            tpm2_required: settings.tpm2_required,
        })
    }

    /// Get a new request id, if possible
    pub async fn get_new_request_id(&self) -> Option<u64> {
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
    /// The serial number for the csr
    pub serial: Vec<u8>,
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
            serial: csr.sn,
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
            sn: val.row_data.get(8).unwrap(),
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

impl<'a> TryFrom<DbEntry<'a>> for CsrRejection {
    type Error = async_sqlite::rusqlite::Error;
    fn try_from(val: DbEntry<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            cert: val.row_data.get(4)?,
            name: val.row_data.get(1)?,
            email: val.row_data.get(2)?,
            phone: val.row_data.get(3)?,
            rejection: val.row_data.get(5)?,
            serial: val.row_data.get(6)?,
        })
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
    /// The serial number of the certificate request
    pub sn: Vec<u8>,
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
            std::io::ErrorKind::NotFound => {
                CertificateLoadingError::DoesNotExist("Certificate io error".to_string())
            }
            std::io::ErrorKind::PermissionDenied => {
                CertificateLoadingError::CantOpen("unknown Permission denied".to_string())
            }
            _ => CertificateLoadingError::OtherIo("unknown".to_string(), value.to_string()),
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
    pub hsm: Option<Arc<crate::hsm2::SecurityModule>>,
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
            let snr = rcgen::SerialNumber::from_slice(&sn);
            csr.params.serial_number = Some(snr);

            CaCertificateToBeSigned {
                algorithm: self.t,
                medium: CaCertificateStorage::Nowhere,
                csr,
                keypair: Some(Keypair::Hsm(keypair)),
                name: self.name.clone(),
                serial: sn.to_vec(),
            }
        } else {
            let (keypair, priva) = self.t.generate_keypair(4096).unwrap();
            let csr = params.serialize_request(&keypair).unwrap();
            let csr_der = csr.der();
            let mut csr = rcgen::CertificateSigningRequestParams::from_der(csr_der).unwrap();
            let snr = rcgen::SerialNumber::from_slice(&sn);
            csr.params.serial_number = Some(snr);

            CaCertificateToBeSigned {
                algorithm: self.t,
                medium: CaCertificateStorage::Nowhere,
                csr,
                keypair: Some(Keypair::NotHsm(priva)),
                name: self.name.clone(),
                serial: sn.to_vec(),
            }
        }
    }
}
