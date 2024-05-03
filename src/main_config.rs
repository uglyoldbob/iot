//! Contains code related to the main configuration of the application

use egui_multiwin::egui;

use std::path::PathBuf;

use prompt::Prompting;

use crate::ca::{ComplexName, ProxyConfig};

#[cfg(target_os = "linux")]
/// Returns the default config file.
pub fn default_config_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/etc/rust-iot/")
}

#[cfg(target_os = "windows")]
/// Returns the default config file.
pub fn default_config_path() -> std::path::PathBuf {
    std::path::PathBuf::from("./")
}

/// The main configuration for the application
#[derive(
    Clone, Debug, prompt::Prompting, prompt::EguiPrompting, serde::Deserialize, serde::Serialize,
)]
pub struct GeneralSettings {
    /// The name of the cookie to use.
    pub cookie: String,
    /// The path to get to the static content of the site
    pub static_content: String,
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self::new()
    }
}

impl GeneralSettings {
    /// Construct a blank Self
    fn new() -> Self {
        Self {
            cookie: "".into(),
            static_content: "./content".into(),
        }
    }
}

/// The admin configuration for the application
#[derive(
    Clone,
    Debug,
    Default,
    prompt::Prompting,
    prompt::EguiPrompting,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct AdminSettings {
    /// The password for the administrator
    pub pass: prompt::Password2,
    /// The n parameter for expanding passwords
    pub n: u8,
    /// The r parameter for expanding passwords
    pub r: u32,
    /// The p parameter for expanding passwords
    pub p: u32,
}

impl AdminSettings {
    /// Construct a blank Self
    fn new() -> Self {
        Self {
            pass: prompt::Password2::new("".into()),
            n: 1,
            r: 1,
            p: 1,
        }
    }
}

/// The http configuration for the application
#[derive(
    Clone,
    Debug,
    Default,
    prompt::Prompting,
    prompt::EguiPrompting,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct HttpSettings {
    /// The port number to listen on
    pub port: u16,
}

impl HttpSettings {
    /// Construct a blank Self
    fn new() -> Self {
        Self { port: 3 }
    }
}

/// The https configuration for the application
#[derive(
    Clone,
    Debug,
    Default,
    prompt::Prompting,
    prompt::EguiPrompting,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct HttpsSettings {
    /// The path to the p12 certificate to use for the https server certificate
    pub certificate: prompt::FileOpen,
    /// The password for the certificate, probably not necessary to prompt twice, but it does ensure the password is correct.
    pub certpass: prompt::Password2,
    /// The port number to listen on
    pub port: u16,
    /// True when a user certificate should be required to access the system
    pub require_certificate: bool,
}

impl HttpsSettings {
    /// Construct a blank Self
    fn new() -> Self {
        Self {
            certificate: prompt::FileOpen::default(),
            certpass: prompt::Password2::new("".into()),
            port: 4,
            require_certificate: false,
        }
    }
}

/// The database configuration for the application
#[derive(
    Clone, Debug, prompt::Prompting, prompt::EguiPrompting, serde::Deserialize, serde::Serialize,
)]
pub struct DatabaseSettings {
    /// The username
    pub username: String,
    /// The password
    pub password: prompt::Password2,
    /// The name of the database
    pub name: String,
    /// The url for the database
    pub url: String,
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        Self::new()
    }
}

impl DatabaseSettings {
    /// Construct a blank Self
    fn new() -> Self {
        Self {
            username: "dummy".into(),
            password: prompt::Password2::new("dummy".into()),
            name: "dummy".into(),
            url: "dummy".into(),
        }
    }
}

/// The main configuration of the application
#[derive(
    Clone,
    Debug,
    Default,
    prompt::Prompting,
    prompt::EguiPrompting,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct MainConfigurationAnswers {
    /// General settings
    pub general: GeneralSettings,
    /// Admin user settings
    pub admin: AdminSettings,
    /// Settings for the http server
    pub http: Option<HttpSettings>,
    /// Settings for the https server
    pub https: Option<HttpsSettings>,
    /// Settings for the database
    pub database: DatabaseSettings,
    /// The public name of the service, contains example.com/asdf for the example
    pub public_names: Vec<ComplexName>,
    /// The optional proxy configuration
    pub proxy_config: Option<ProxyConfig>,
    /// The settings for a pki
    pub pki: crate::ca::PkiConfigurationEnum,
}

/// The main configuration of the application
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct MainConfiguration {
    /// General settings
    pub general: GeneralSettings,
    /// Admin user settings
    pub admin: AdminSettings,
    /// Settings for the http server
    pub http: Option<HttpSettings>,
    /// Settings for the https server
    pub https: Option<HttpsSettings>,
    /// Settings for the database
    pub database: DatabaseSettings,
    /// The public name of the service, contains example.com/asdf for the example
    pub public_names: Vec<ComplexName>,
    /// The optional proxy configuration
    pub proxy_config: Option<ProxyConfig>,
    /// Settings for client certificates
    pub client_certs: Option<Vec<String>>,
    /// The settings for a pki
    pub pki: crate::ca::PkiConfigurationEnum,
}

impl Default for MainConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

impl MainConfiguration {
    /// Construct an empty configuration file
    pub fn new() -> Self {
        Self {
            general: GeneralSettings::new(),
            admin: AdminSettings::new(),
            http: None,
            https: None,
            proxy_config: None,
            database: DatabaseSettings::new(),
            public_names: Vec::new(),
            client_certs: None,
            pki: crate::ca::PkiConfigurationEnum::new(),
        }
    }

    /// Process the answers, cloning them into self.
    fn process_answers(&mut self, answers: &MainConfigurationAnswers) {
        self.general = answers.general.clone();
        self.admin = answers.admin.clone();
        self.http = answers.http.clone();
        self.https = answers.https.clone();
        self.database = answers.database.clone();
        self.public_names = answers.public_names.clone();
        self.proxy_config = answers.proxy_config.clone();
        self.pki = answers.pki.clone();
    }

    /// Fill out the configuration by asking the user for input, using standard input and output
    pub fn prompt_for_answers(&mut self) {
        let a: MainConfigurationAnswers = MainConfigurationAnswers::prompt(None).unwrap();
        self.process_answers(&a);
    }

    /// Fill out this configuration file with answers from the specified answer configuration
    pub fn provide_answers(&mut self, answers: &MainConfigurationAnswers) {
        self.process_answers(answers);
    }

    /// Return the port number for the http server
    pub fn get_http_port(&self) -> Option<u16> {
        self.http.as_ref().map(|a| a.port)
    }

    /// Return the port number for the https server
    pub fn get_https_port(&self) -> Option<u16> {
        self.https.as_ref().map(|a| a.port)
    }
}
