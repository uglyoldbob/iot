//! The main configuration for the application

/// The main configuration of the application
#[derive(serde::Deserialize)]
pub struct MainConfiguration {
    /// General settings
    pub general: toml::Table,
    /// Admin user settings
    pub admin: toml::Table,
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
