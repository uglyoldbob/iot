#[path = "ca_construct.rs"]
mod ca;
mod main_config;
pub mod oid;
pub mod pkcs12;
mod tpm2;

use ca::PkiConfiguration;
pub use main_config::MainConfiguration;

use clap::Parser;
use prompt::Prompting;
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

    /// The path answers should be saved to, if desired
    #[arg(short, long)]
    save_answers: Option<PathBuf>,

    /// The name of the config being created
    #[arg(short, long)]
    name: Option<String>,

    /// Path for where the service file description goes, to start up the service
    #[arg(long)]
    service: Option<PathBuf>,

    /// The user to run the service under, pki is the default username
    #[arg(short, long)]
    user: Option<String>,

    /// Use a randomly generated password
    #[arg(long, default_value_t = false)]
    generate_password: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let config_path = if let Some(p) = args.config {
        std::path::PathBuf::from(p)
    } else {
        crate::main_config::default_config_path()
    };

    let name = args.name.unwrap_or("default".to_string());

    let username = args.user.unwrap_or("pki".to_string());

    #[cfg(target_family = "unix")]
    let user_obj = nix::unistd::User::from_name(&username).unwrap().unwrap();
    #[cfg(target_family = "unix")]
    let user_uid = user_obj.uid;

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

    if let crate::ca::PkiConfigurationEnum::Pki(p) = &mut config.pki {
        for (name, ca) in p.local_ca.iter_mut() {
            if ca.pki_name.is_none() {
                ca.pki_name = Some(format!("pki/{}/", name));
            }
        }
    }

    println!("Saving the configuration file");
    let config_data = toml::to_string(&config).unwrap();

    let mut f = tokio::fs::File::create(config_path.join(format!("{}-config.toml", name)))
        .await
        .unwrap();

    let mut password: prompt::Password2 = prompt::Password2::new(String::new());

    if args.generate_password {
        let s: String =
            rand::Rng::sample_iter(rand::thread_rng(), &rand::distributions::Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();
        password = prompt::Password2::new(s);
    }

    if password.is_empty() {
        loop {
            password = prompt::Password2::prompt(None).unwrap();
            if !password.is_empty() {
                break;
            }
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

        let p = config_path.join(format!("{}-password.bin", name));
        let mut f2 = tokio::fs::File::create(p).await.unwrap();
        f2.write_all(&tpmblob.data())
            .await
            .expect("Failed to write protected password");
        #[cfg(target_family = "unix")]
        {
            std::os::unix::fs::chown(p, Some(user_uid.as_raw), None);
            let mut perms = std::fs::metadata(p).unwrap().permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o400);
            std::fs::set_permissions(p, perms);
        }

        f.write_all(&econfig)
            .await
            .expect("Failed to write encrypted configuration file");
    }
    #[cfg(not(feature = "tpm2"))]
    {
        let password_combined = password.as_bytes();

        let p = config_path.join(format!("{}-credentials.bin", name));
        let mut fpw = tokio::fs::File::create(&p).await.unwrap();
        fpw.write_all(password.to_string().as_bytes())
            .await
            .expect("Failed to write credentials");
        #[cfg(target_family = "unix")]
        {
            std::os::unix::fs::chown(&p, Some(user_uid.as_raw()), None).unwrap();
            let mut perms = std::fs::metadata(&p).unwrap().permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o400);
            std::fs::set_permissions(p, perms).unwrap();
        }

        let econfig: Vec<u8> = tpm2::encrypt(config_data.as_bytes(), password_combined);

        f.write_all(&econfig)
            .await
            .expect("Failed to write configuration file");
    }

    #[cfg(target_family = "unix")]
    let options = ca::OwnerOptions::new(user_uid.as_raw());

    ca::PkiInstance::init(&config.pki, options).await;

    #[cfg(target_os = "linux")]
    {
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

        if let Some(p) = args.service {
            let pb = p.join(format!("rust-iot-{}.service", name));
            let mut fpw = tokio::fs::File::create(pb).await.unwrap();
            fpw.write_all(con.as_bytes())
                .await
                .expect("Failed to write service file");
        }
    }
}
