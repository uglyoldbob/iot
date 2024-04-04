use std::path::PathBuf;

use prompt::Prompting;

/// The main configuration for the application
#[derive(Clone, prompt::Prompting, serde::Deserialize, serde::Serialize)]
pub struct GeneralSettings {
    pub cookie: String,
    pub proxy: String,
    pub static_content: String,
}

impl GeneralSettings {
    fn new() -> Self {
        Self {
            cookie: "".into(),
            proxy: "".into(),
            static_content: "".into(),
        }
    }
}

/// The admin configuration for the application
#[derive(Clone, prompt::Prompting, serde::Deserialize, serde::Serialize)]
pub struct AdminSettings {
    pub pass: prompt::Password2,
    pub n: u8,
    pub r: u32,
    pub p: u32,
}

impl AdminSettings {
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
    pub enabled: bool,
    pub port: u16,
}

impl HttpSettings {
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
    pub enabled: bool,
    pub certificate: PathBuf,
    /// The password for the certificate, probably not necessary to prompt twice, but it does ensure the password is correct.
    pub certpass: prompt::Password2,
    pub port: u16,
}

impl HttpsSettings {
    fn new() -> Self {
        Self {
            enabled: false,
            certificate: PathBuf::new(),
            certpass: prompt::Password2::new("".into()),
            port: 4,
        }
    }
}

/// The database configuration for the application
#[derive(Clone, prompt::Prompting, serde::Deserialize, serde::Serialize)]
pub struct DatabaseSettings {
    pub username: String,
    pub password: prompt::Password2,
    pub name: String,
    pub url: String,
}

impl DatabaseSettings {
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
    pub ca: Option<crate::ca::CaConfiguration>,
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
    pub ca: Option<crate::ca::CaConfiguration>,
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
            ca: None,
        }
    }

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
