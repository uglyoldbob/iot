//! Contains code related to the main configuration of the application

use std::path::PathBuf;

use prompt::Prompting;

use crate::ca::CaConfiguration;

/// The main configuration for the application
#[derive(Clone, prompt::Prompting, serde::Deserialize, serde::Serialize)]
pub struct GeneralSettings {
    /// The name of the cookie to use.
    pub cookie: String,
    /// The proxy string for the server. When set to some, this path prefixes all paths because it is behing a reverse proxy.
    pub proxy: Option<String>,
    /// The path to get to the static content of the site
    pub static_content: String,
}

impl GeneralSettings {
    /// Construct a blank Self
    fn new() -> Self {
        Self {
            cookie: "".into(),
            proxy: None,
            static_content: "".into(),
        }
    }
}

/// The admin configuration for the application
#[derive(Clone, prompt::Prompting, serde::Deserialize, serde::Serialize)]
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
#[derive(Clone, prompt::Prompting, serde::Deserialize, serde::Serialize)]
pub struct HttpSettings {
    /// True when the http server should be enabled
    pub enabled: bool,
    /// The port number to listen on
    pub port: u16,
}

impl HttpSettings {
    /// Construct a blank Self
    fn new() -> Self {
        Self {
            enabled: false,
            port: 3,
        }
    }
}

/// The https configuration for the application
#[derive(Clone, prompt::Prompting, serde::Deserialize, serde::Serialize)]
pub struct HttpsSettings {
    /// True when the server is enabled
    pub enabled: bool,
    /// The path to the p12 certificate to use for the https server certificate
    pub certificate: PathBuf,
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
            enabled: false,
            certificate: PathBuf::new(),
            certpass: prompt::Password2::new("".into()),
            port: 4,
            require_certificate: false,
        }
    }
}

/// The database configuration for the application
#[derive(Clone, prompt::Prompting, serde::Deserialize, serde::Serialize)]
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

impl DatabaseSettings {
    /// Construct a blank Self
    fn new() -> Self {
        Self {
            username: "".into(),
            password: prompt::Password2::new("".into()),
            name: "".into(),
            url: "".into(),
        }
    }
}

/// The main configuration of the application
#[derive(prompt::Prompting, serde::Deserialize, serde::Serialize)]
pub struct MainConfigurationAnswers {
    /// General settings
    pub general: GeneralSettings,
    /// Admin user settings
    pub admin: AdminSettings,
    /// Settings for the http server
    pub http: HttpSettings,
    /// Settings for the https server
    pub https: HttpsSettings,
    /// Settings for the database
    pub database: DatabaseSettings,
    /// The table for ca settings
    pub ca: crate::ca::CaConfiguration,
}

/// The main configuration of the application
#[derive(serde::Deserialize, serde::Serialize)]
pub struct MainConfiguration {
    /// General settings
    pub general: GeneralSettings,
    /// Admin user settings
    pub admin: AdminSettings,
    /// Settings for the http server
    pub http: HttpSettings,
    /// Settings for the https server
    pub https: HttpsSettings,
    /// Settings for the database
    pub database: DatabaseSettings,
    /// Settings for client certificates
    pub client_certs: Option<Vec<String>>,
    /// The table for ca settings
    pub ca: crate::ca::CaConfiguration,
}

impl MainConfiguration {
    /// Construct an empty configuration file
    pub fn new() -> Self {
        Self {
            general: GeneralSettings::new(),
            admin: AdminSettings::new(),
            http: HttpSettings::new(),
            https: HttpsSettings::new(),
            database: DatabaseSettings::new(),
            client_certs: None,
            ca: CaConfiguration::new(),
        }
    }

    /// Process the answers, cloning them into self.
    fn process_answers(&mut self, answers: &MainConfigurationAnswers) {
        self.general = answers.general.clone();
        self.admin = answers.admin.clone();
        self.http = answers.http.clone();
        self.https = answers.https.clone();
        self.database = answers.database.clone();
        self.ca = answers.ca.clone();
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
    pub fn get_http_port(&self) -> u16 {
        self.http.port
    }

    /// Return the port number for the https server
    pub fn get_https_port(&self) -> u16 {
        self.https.port
    }
}
