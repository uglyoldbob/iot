/// The main configuration for the application
#[derive(serde::Deserialize, serde::Serialize)]
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
#[derive(serde::Deserialize, serde::Serialize)]
pub struct AdminSettings {
    pub pass: String,
    pub n: u8,
    pub r: u32,
    pub p: u32,
}

impl AdminSettings {
    fn new() -> Self {
        Self {
            pass: "".into(),
            n: 1,
            r: 1,
            p: 1,
        }
    }
}

/// The main configuration of the application
#[derive(serde::Deserialize)]
pub struct MainConfigurationAnswers {}

/// The main configuration of the application
#[derive(serde::Deserialize, serde::Serialize)]
pub struct MainConfiguration {
    /// General settings
    pub general: GeneralSettings,
    /// Admin user settings
    pub admin: AdminSettings,
    /// Settings for the http server
    pub http: toml::Table,
    /// Settings for the https server
    pub https: toml::Table,
    /// Settings for the database
    pub database: toml::Table,
    /// Settings for client certificates
    pub client_certs: Option<Vec<String>>,
    /// The table for ca settings
    pub ca: Option<toml::Table>,
}

impl MainConfiguration {
    /// Construct an empty configuration file
    pub fn new() -> Self {
        Self {
            general: GeneralSettings::new(),
            admin: AdminSettings::new(),
            http: toml::Table::new(),
            https: toml::Table::new(),
            database: toml::Table::new(),
            client_certs: None,
            ca: None,
        }
    }

    /// Fill out the configuration by asking the user for input, using standard input and output
    pub fn prompt_for_answers(&mut self) {}

    /// Fill out this configuration file with answers from the specified answer configuration
    pub fn provide_answers(&mut self, answers: &MainConfigurationAnswers) {}

    /// Return the port number for the http server
    pub fn get_http_port(&self) -> u16 {
        self.http
            .get("port")
            .unwrap_or(&toml::Value::Integer(3000))
            .as_integer()
            .unwrap_or(3000) as u16
    }

    /// Return the port number for the https server
    pub fn get_https_port(&self) -> u16 {
        self.https
            .get("port")
            .unwrap_or(&toml::Value::Integer(3001))
            .as_integer()
            .unwrap_or(3001) as u16
    }
}
