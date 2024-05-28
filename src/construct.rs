#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(unused_extern_crates)]

//! This binary is used to construct the elements necessary to operate an iot instance.

#[path = "ca_construct.rs"]
/// The ca module, with code used to construct a ca
mod ca;
mod main_config;
mod tpm2;

pub use main_config::MainConfiguration;

use clap::Parser;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use userprompt::Prompting;

use crate::main_config::MainConfigurationAnswers;

/// Sends a string over the ipc pipe, length and then string. Will not send empty strings.
fn send_string(s: &mut interprocess::local_socket::SendHalf, msg: String) {
    use std::io::Write;
    let c = msg.as_bytes();
    let length = c.len() as u32;
    let len = length.to_le_bytes();
    if length != 0 {
        s.write_all(&len).unwrap();
        s.write_all(c).unwrap();
    }
}

/// end communications on the pipe by sending empty data
fn end_ipc(mut s: interprocess::local_socket::SendHalf) {
    use std::io::Write;
    s.write_all(&[0, 0, 0, 0]).unwrap();
}

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

    /// An ipc communication method to use
    #[arg(long)]
    ipc: Option<String>,

    /// The name of the config being created
    #[arg(short, long)]
    name: Option<String>,

    /// Use a randomly generated password
    #[arg(long, default_value_t = false)]
    generate_password: bool,

    /// Allow the system to operate without tpm
    #[arg(long, default_value_t = false)]
    allow_no_tpm2: bool,
}

struct LocalLogging {
    s: std::sync::Mutex<interprocess::local_socket::SendHalf>,
}

impl LocalLogging {
    pub fn new(s: interprocess::local_socket::SendHalf) -> Self {
        Self {
            s: std::sync::Mutex::new(s),
        }
    }
}

impl service::log::Log for LocalLogging {
    fn enabled(&self, _metadata: &service::log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &service::log::Record) {
        let m = format!("{} - {}", record.level(), record.args());
        println!("Trying to log {}", m);
        let mut s = self.s.lock().unwrap();
        send_string(&mut s, m);
    }

    fn flush(&self) {
        let mut s = self.s.lock().unwrap();
        use std::io::Write;
        s.flush();
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.ipc.is_none() {
        simple_logger::SimpleLogger::new().init().unwrap();
    }

    let config_path = if let Some(p) = args.config {
        std::path::PathBuf::from(p)
    } else {
        crate::main_config::default_config_path()
    };
    let config_path = std::fs::canonicalize(&config_path).unwrap();

    let name = args.name.unwrap_or("default".to_string());

    if let Some(pb) = &args.save_answers {
        if pb.exists() {
            panic!("Answers file already exists")
        }
    }

    tokio::fs::create_dir_all(&config_path).await.unwrap();

    let mut config = main_config::MainConfiguration::new();
    let answers: MainConfigurationAnswers;
    if let Some(ipc) = &args.ipc {
        use interprocess::local_socket::ToFsName;
        let ipc_name = ipc
            .clone()
            .to_fs_name::<interprocess::local_socket::GenericFilePath>()
            .unwrap();
        let stream_local = <interprocess::local_socket::prelude::LocalSocketStream as interprocess::local_socket::traits::Stream>::connect(ipc_name.clone()).unwrap();
        answers = bincode::deserialize_from(&stream_local).unwrap();
        use interprocess::local_socket::traits::Stream;
        let s = stream_local.split().1;
        let ipc_log = LocalLogging::new(s);
        service::log::set_max_level(service::log::LevelFilter::Debug);
        service::log::set_boxed_logger(Box::new(ipc_log)).unwrap();
        config.provide_answers(&answers);
    } else if let Some(answers_path) = &args.answers {
        println!(
            "Expect to read answers from {}",
            answers_path.to_str().unwrap()
        );
        let answers_file = tokio::fs::read_to_string(answers_path)
            .await
            .expect("Expected some answers were specified");
        answers = toml::from_str(&answers_file).expect("Failed to parse configuration");
        config.provide_answers(&answers);
    } else {
        answers = MainConfigurationAnswers::prompt(None).unwrap();
        config.provide_answers(&answers);
    };

    #[cfg(target_family = "unix")]
    let user_obj = nix::unistd::User::from_name(&answers.username)
        .unwrap()
        .unwrap();
    #[cfg(target_family = "unix")]
    let user_uid = user_obj.uid;

    #[cfg(target_family = "unix")]
    let options = ca::OwnerOptions::new(user_uid.as_raw());
    #[cfg(target_family = "windows")]
    let options = ca::OwnerOptions::new(&answers.username);

    if let Some(pb) = &args.save_answers {
        println!("Saving answers to {}", pb.display());
        let answers = toml::to_string(&answers).unwrap();
        if pb.exists() {
            panic!("Answers file already exists")
        }
        let mut f = tokio::fs::File::create(pb).await.unwrap();
        f.write_all(answers.as_bytes())
            .await
            .expect("Failed to write answers file");
        options.set_owner(pb, 0o600);
    }

    let mut exe = std::env::current_exe().unwrap();
    exe.pop();

    let mut service = service::Service::new(format!("rust-iot-{}", name));
    if service.exists() {
        panic!("Service already exists");
    }

    let _ca_instance = ca::PkiInstance::init(&config.pki, &answers, &config, &options).await;

    if let Some(https) = &config.https {
        if !https.certificate.exists() {
            service::log::error!("Failed to open https certificate");
            panic!("No https certificate to run with");
        }
    }

    if let Some(proxy) = config.pki.reverse_proxy(&config) {
        let proxy_name = PathBuf::from(format!("./reverse-proxy-{}.txt", &name));
        service::log::info!(
            "Saving reverse proxy information to {}",
            proxy_name.display()
        );
        let mut f2 = tokio::fs::File::create(&proxy_name)
            .await
            .expect("Failed to create reverse proxy file");
        f2.write_all(proxy.as_bytes())
            .await
            .expect("Failed to write reverse proxy file");
        options.set_owner(&proxy_name, 0o644);
    }

    let service_args = vec![
        format!("--name={}", name),
        format!("--config={}", config_path.display()),
    ];

    let mut service_config = service::ServiceConfig::new(
        service_args,
        format!("{} Iot Certificate Authority and Iot Manager", name),
        exe.join("rust-iot"),
        Some(answers.username.clone()),
    );

    #[cfg(target_os = "linux")]
    {
        service_config.config_path = config_path.clone();
    }
    #[cfg(target_family = "windows")]
    {
        service_config.display = format!("Rust Iot {} Service", name);
        service_config.user_password = answers.password.clone().map(|a| a.to_string());
    }

    service::log::info!("Saving the configuration file");
    config.remove_relative_paths();
    let config_data = toml::to_string(&config).unwrap();
    let config_file = config_path.join(format!("{}-config.toml", name));
    if config_file.exists() {
        panic!(
            "Configuration file {} already exists",
            config_file.display()
        );
    }
    let mut f = tokio::fs::File::create(config_file).await.unwrap();

    let do_without_tpm2 = || async {
        let mut password: userprompt::Password2 = userprompt::Password2::new(String::new());

        if args.generate_password {
            let s: String =
                rand::Rng::sample_iter(rand::thread_rng(), &rand::distributions::Alphanumeric)
                    .take(32)
                    .map(char::from)
                    .collect();
            password = userprompt::Password2::new(s);
        }

        if password.is_empty() {
            loop {
                password = userprompt::Password2::prompt(None).unwrap();
                if !password.is_empty() {
                    break;
                }
            }
        }

        let password_combined = password.as_bytes();
        let p = config_path.join(format!("{}-credentials.bin", name));
        if p.exists() {
            panic!("Credendials file already exists");
        }
        let mut fpw = tokio::fs::File::create(&p).await.unwrap();
        fpw.write_all(password.to_string().as_bytes())
            .await
            .expect("Failed to write credentials");
        options.set_owner(&p, 0o400);
        tpm2::encrypt(config_data.as_bytes(), password_combined)
    };

    #[cfg(feature = "tpm2")]
    {
        let mut tpm2 = tpm2::Tpm2::new(tpm2::tpm2_path());

        let econfig = if let Some(tpm2) = &mut tpm2 {
            let password2: [u8; 32] = rand::random();

            let protected_password =
                tpm2::Password::build(&password2, std::num::NonZeroU32::new(2048).unwrap());

            let password_combined = protected_password.password();

            let econfig: Vec<u8> = tpm2::encrypt(config_data.as_bytes(), password_combined);

            let epdata = protected_password.data();
            let tpmblob: tpm2::TpmBlob = tpm2.encrypt(&epdata).unwrap();

            let p = config_path.join(format!("{}-password.bin", name));
            if p.exists() {
                panic!("Password file aready exists");
            }
            let mut f2 = tokio::fs::File::create(&p)
                .await
                .expect("Failed to create password file");
            f2.write_all(&tpmblob.data())
                .await
                .expect("Failed to write protected password");
            options.set_owner(&p, 0o400);
            econfig
        } else {
            service::log::error!("TPM2 NOT DETECTED!!!");
            if !args.allow_no_tpm2 {
                panic!("Cannot continue without tpm2 support, try --allow-no-tpm2");
            }
            do_without_tpm2().await
        };

        f.write_all(&econfig)
            .await
            .expect("Failed to write encrypted configuration file");
    }
    #[cfg(not(feature = "tpm2"))]
    {
        do_without_tpm2().await
    }

    service.create_async(service_config).await;
    let _ = service.start();
}
