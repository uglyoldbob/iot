#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(unused_extern_crates)]

//! This binary is used to construct the elements necessary to operate an iot instance.

#[path = "ca_construct.rs"]
/// The ca module, with code used to construct a ca
mod ca;
mod main_config;
pub mod oid;
pub mod pkcs12;
mod tpm2;

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

    /// An ipc communication method to use
    #[arg(long)]
    ipc: Option<String>,

    /// The name of the config being created
    #[arg(short, long)]
    name: Option<String>,

    /// The user to run the service under, pki is the default username
    #[arg(short, long)]
    user: Option<String>,

    /// Use a randomly generated password
    #[arg(long, default_value_t = false)]
    generate_password: bool,

    /// Allow the system to operate without tpm
    #[arg(long, default_value_t = false)]
    allow_no_tpm2: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    #[cfg(target_os = "windows")]
    let log = std::fs::OpenOptions::new()
        .truncate(true)
        .read(true)
        .create(true)
        .write(true)
        .open("C:/git/log.txt")
        .unwrap();
    #[cfg(target_os = "windows")]
    let log2 = std::fs::OpenOptions::new()
        .truncate(true)
        .read(true)
        .create(true)
        .write(true)
        .open("C:/git/log2.txt")
        .unwrap();
    #[cfg(target_os = "windows")]
    let print_redirect = gag::Redirect::stdout(log).unwrap();
    #[cfg(target_os = "windows")]
    let print_redirect2 = gag::Redirect::stderr(log2).unwrap();

    let config_path = if let Some(p) = args.config {
        std::path::PathBuf::from(p)
    } else {
        crate::main_config::default_config_path()
    };

    let name = args.name.unwrap_or("default".to_string());

    let username = args.user.unwrap_or("pki".to_string());

    let mut exe = std::env::current_exe().unwrap();
    exe.pop();

    let mut service = service::Service::new(format!("rust-iot-{}", name));
    if service.exists() {
        panic!("Service already exists");
    }

    std::env::set_current_dir(&config_path).expect("Failed to switch to config directory");

    #[cfg(target_family = "unix")]
    let user_obj = nix::unistd::User::from_name(&username).unwrap().unwrap();
    #[cfg(target_family = "unix")]
    let user_uid = user_obj.uid;

    println!("The path for the iot instance config is {:?}", config_path);
    tokio::fs::create_dir_all(&config_path).await.unwrap();

    let mut config = main_config::MainConfiguration::new();
    if let Some(ipc) = args.ipc {
        println!("IPC NAME IS {}", ipc);
        let stream = interprocess::local_socket::LocalSocketStream::connect(ipc.clone()).unwrap();
        println!("Waiting for answers");
        let answers: MainConfigurationAnswers = bincode::deserialize_from(stream).unwrap();
        println!("Providing answers");
        config.provide_answers(&answers);
        let p = std::path::Path::new(&ipc);
        let _ = std::fs::remove_file(p);
    } else if let Some(answers) = &args.answers {
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
        if pb.exists() {
            panic!("Answers file already exists")
        }
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
            if ca.http_port.is_none() && config.http.enabled {
                ca.http_port = Some(config.http.port);
            }
            if ca.https_port.is_none() && config.https.enabled {
                ca.https_port = Some(config.https.port);
            }
        }
    }
    if let crate::ca::PkiConfigurationEnum::Ca(ca) = &mut config.pki {
        if ca.http_port.is_none() && config.http.enabled {
            ca.http_port = Some(config.http.port);
        }
        if ca.https_port.is_none() && config.https.enabled {
            ca.https_port = Some(config.https.port);
        }
    }

    println!("Saving the configuration file");
    let config_data = toml::to_string(&config).unwrap();
    let config_file = config_path.join(format!("{}-config.toml", name));
    if config_file.exists() {
        panic!("Configuration file already exists");
    }
    let mut f = tokio::fs::File::create(config_file).await.unwrap();

    let do_without_tpm2 = || async {
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

        let password_combined = password.as_bytes();
        let p = config_path.join(format!("{}-credentials.bin", name));
        if p.exists() {
            panic!("Credendials file already exists");
        }
        let mut fpw = tokio::fs::File::create(&p).await.unwrap();
        fpw.write_all(password.to_string().as_bytes())
            .await
            .expect("Failed to write credentials");
        #[cfg(target_family = "unix")]
        {
            std::os::unix::fs::chown(&p, Some(user_uid.as_raw()), None)
                .expect("Failled to set file owner");
            let mut perms = std::fs::metadata(&p).unwrap().permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o400);
            std::fs::set_permissions(p, perms).expect("Failed to set file permissions");
        }

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
            #[cfg(target_family = "unix")]
            {
                std::os::unix::fs::chown(&p, Some(user_uid.as_raw()), None)
                    .expect("Failled to set file owner");
                let mut perms = std::fs::metadata(&p).unwrap().permissions();
                std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o400);
                std::fs::set_permissions(p, perms).expect("Failed to set file permissions");
            }
            econfig
        } else {
            println!("TPM2 NOT DETECTED!!!");
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

    #[cfg(target_family = "unix")]
    let options = ca::OwnerOptions::new(user_uid.as_raw());
    #[cfg(target_family = "windows")]
    let options = ca::OwnerOptions::new();

    let ca = ca::PkiInstance::init(&config.pki, options).await;
    if let Some(proxy) = ca.reverse_proxy() {
        let proxy_name = PathBuf::from(format!("./reverse-proxy-{}.txt", &name));
        service::log::info!("Saving reverse proxy information to {}", proxy_name.display());
        let mut f2 = tokio::fs::File::create(&proxy_name)
                .await
                .expect("Failed to create reverse proxy file");
        f2.write_all(proxy.as_bytes())
            .await
            .expect("Failed to write protected password");
        #[cfg(target_family = "unix")]
        {
            std::os::unix::fs::chown(&p, Some(user_uid.as_raw()), None)
                .expect("Failled to set file owner");
            let mut perms = std::fs::metadata(&p).unwrap().permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o644);
            std::fs::set_permissions(p, perms).expect("Failed to set file permissions");
        }
    }

    let service_config = service::ServiceConfig::new(
        format!("Rust Iot {} Service", name),
        name.clone(),
        format!("{} Iot Certificate Authority and Iot Manager", name),
        exe.join("rust-iot"),
        config_path.clone(),
        Some(username),
        #[cfg(target_family = "windows")]
        None,
    );
    service.create_async(service_config).await;
    service.start();
}
