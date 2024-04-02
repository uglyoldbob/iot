#[path = "ca_construct.rs"]
mod ca;
mod main_config;
pub mod oid;
pub mod pkcs12;
mod tpm2;

pub use main_config::MainConfiguration;

use clap::Parser;
use prompt::Prompting;
use std::{io::Write, path::PathBuf};
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

    /// The path answers should be saved to, if desired
    #[arg(short, long)]
    save_answers: Option<PathBuf>,
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
    tokio::fs::create_dir_all(&config_path).await.unwrap();

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
    if let Some(pb) = &args.save_answers {
        println!("Saving answers to {}", pb.display());
        let answers = toml::to_string(&config).unwrap();
        let mut f = tokio::fs::File::create(pb).await.unwrap();
        f.write_all(answers.as_bytes())
            .await
            .expect("Failed to write answers file");
    }
    println!("Saving the configuration file");
    let config_data = toml::to_string(&config).unwrap();

    let mut f = tokio::fs::File::create(config_path.join("config.toml"))
        .await
        .unwrap();

    let mut password: String;
    loop {
        print!("Please enter a password:");
        std::io::stdout().flush().unwrap();
        password = String::prompt(None).unwrap();
        if !password.is_empty() {
            break;
        }
    }

    #[cfg(feature = "tpm2")]
    {
        let mut tpm2 = tpm2::Tpm2::new(tpm2::tpm2_path());

        let password2: [u8; 32] = rand::random();

        let protected_password =
            tpm2::Password::build(&password2, std::num::NonZeroU32::new(2048).unwrap());

        let password_combined = [password.as_bytes(), protected_password.password()].concat();

        let econfig: Vec<u8> = tpm2::encrypt(config_data.as_bytes(), &password_combined);

        let epdata = protected_password.data();
        let tpmblob: tpm2::TpmBlob = tpm2.encrypt(&epdata).unwrap();

        let mut f2 = tokio::fs::File::create(config_path.join("password.bin"))
            .await
            .unwrap();
        f2.write_all(&tpmblob.data())
            .await
            .expect("Failed to write protected password");

        f.write_all(&econfig)
            .await
            .expect("Failed to write encrypted configuration file");
    }
    #[cfg(not(feature = "tpm2"))]
    {
        let password_combined = password.as_bytes();
        let econfig: Vec<u8> = tpm2::encrypt(config_data.as_bytes(), &password_combined);

        f.write_all(&econfig)
            .await
            .expect("Failed to write configuration file");
    }
    ca::Ca::init(&config).await;
}
