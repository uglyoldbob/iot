//! Contains code for establishing a service

pub struct Service {
    name: String,
    display: String,
    description: String,
}

impl Service {
    /// Construct a new self
    pub fn new(name: String, display: String, description: String,) -> Self {
        Self {
            name,
            display,
            description,
        }
    }

    /// Does the service already exist?
    #[cfg(target_os = "linux")]
    pub fn exists(&self) -> bool {
        let systemd_path = PathBuf::from("/etc/systemd/system");
        let pb = systemd_path.join(format!("{}.service", self.name));
        pb.exists()
    }

    /// Does the service already exist?
    #[cfg(target_os = "windows")]
    pub fn exists(&self) -> bool {
        todo!();
    }

    /// Create the service
    #[cfg(target_os = "windows")]
    pub fn create(&mut self) {
        todo!();
    }

    /// Create the service
    #[cfg(target_os = "linux")]
    pub fn create(&mut self) {
        let mut con = String::new();
        con.push_str(&format!(
            "[Unit]
Description=Iot Certificate Authority and Iot Manager

[Service]
User={2}
WorkingDirectory={0}
ExecStart=/usr/bin/rust-iot --name={1}

[Install]
WantedBy=multi-user.target
        ",
            config_path.display(),
            name,
            username
        ));
        println!("Saving service file as {}", pb.display());
        let mut fpw = tokio::fs::File::create(pb).await.unwrap();
        fpw.write_all(con.as_bytes())
            .await
            .expect("Failed to write service file");
    }
}