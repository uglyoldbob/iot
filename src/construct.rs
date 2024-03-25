#[path = "ca_construct.rs"]
mod ca;
mod main_config;
pub mod oid;
pub mod pkcs12;

pub use main_config::MainConfiguration;

use clap::Parser;
use std::{io::Write, path::PathBuf};

use crate::main_config::MainConfigurationAnswers;

/// Arguments for creating an iot instance
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The config path to override the default with
    #[arg(short, long)]
    config: Option<String>,

    /// A configuration file with the answers already filled out
    answers: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let dirs = directories::ProjectDirs::from("com", "UglyOldBob", "Iot").unwrap();
    let config_path = if let Some(p) = args.config {
        std::path::PathBuf::from(p)
    } else {
        dirs.config_dir().to_path_buf()
    };

    println!("The path for the iot instance config is {:?}", config_path);
    tokio::fs::create_dir_all(&config_path).await;

    let mut config = main_config::MainConfiguration::new();
    if let Some(answers) = &args.answers {
        let answers_file = tokio::fs::read_to_string(answers)
            .await
            .expect("Expected some answers where specified");
        let answers: MainConfigurationAnswers =
            toml::from_str(&answers_file).expect("Failed to parse configuration");
        config.provide_answers(&answers)
    } else {
        config.prompt_for_answers();
    }
    println!("Saving the configuration file");
    let config_data = toml::to_string(&config).unwrap();
    let mut f = std::fs::File::create(config_path.join("config.toml")).unwrap();
    f.write_all(config_data.as_bytes())
        .expect("Failed to write configuration file");
    ca::Ca::init(&config).await;
}
