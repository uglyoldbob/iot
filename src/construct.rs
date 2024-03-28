#[path = "ca_construct.rs"]
mod ca;
mod main_config;
pub mod oid;
pub mod pkcs12;
#[cfg(feature = "tpm2")]
mod tpm2;

pub use main_config::MainConfiguration;

use clap::Parser;
use prompt::Prompting;
use ring::aead::BoundKey;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

use crate::main_config::MainConfigurationAnswers;

/// Arguments for creating an iot instance
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The config path to override the default with
    #[arg(short, long)]
    config: Option<String>,

    /// A configuration file with the answers already filled out
    #[arg(short, long)]
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
        println!("Expect to read answers from {}", answers.to_str().unwrap());
        let answers_file = tokio::fs::read_to_string(answers)
            .await
            .expect("Expected some answers were specified");
        let answers: MainConfigurationAnswers =
            toml::from_str(&answers_file).expect("Failed to parse configuration");
        config.provide_answers(&answers)
    } else {
        config.prompt_for_answers();
    }
    println!("Saving the configuration file");
    let config_data = toml::to_string(&config).unwrap();

    let mut f = tokio::fs::File::create(config_path.join("config.toml"))
        .await
        .unwrap();

    #[cfg(feature = "tpm2")]
    {
        let mut tpm2 = tpm2::Tpm2::new("/dev/tpmrm0");
        let (_private, public) = tpm2.make_rsa().unwrap();
        let mut password: String;
        loop {
            println!("Please enter a password:");
            password = String::prompt(None).unwrap();
            if !password.is_empty() {
                break;
            }
        }

        let econfig = tpm2::encrypt(config_data.as_bytes(), &password);
        let edata = tpm2.encrypt(password.as_bytes(), public).unwrap();

        let mut f2 = tokio::fs::File::create(config_path.join("password.bin"))
            .await
            .unwrap();
        f2.write_all(&edata)
            .await
            .expect("Failed to write ecrypted password");

        f.write_all(&econfig)
            .await
            .expect("Failed to write encrypted configuration file");
    }
    #[cfg(not(feature = "tpm2"))]
    {
        f.write_all(config_data.as_bytes())
            .await
            .expect("Failed to write configuration file");
    }
    ca::Ca::init(&config).await;
}
