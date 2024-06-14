#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(unused_extern_crates)]

//! This binary is used to destroy the elements necessary to operate an iot instance.

#[path = "ca_construct.rs"]
/// The ca module, with code used to destroy a ca
mod ca;
mod main_config;
mod tpm2;

pub use main_config::MainConfiguration;

use clap::Parser;
use std::io::Write;
use tokio::io::AsyncReadExt;
use userprompt::Prompting;

/// Arguments for creating an iot instance
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The config path to override the default with
    #[arg(short, long)]
    config: Option<String>,

    /// The name of the config being deleted
    #[arg(short, long)]
    name: String,

    /// Definitely delete the configuration without asking
    #[arg(long, default_value_t = false)]
    delete: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let config_path = if let Some(p) = args.config {
        std::path::PathBuf::from(p)
    } else {
        crate::main_config::default_config_path()
    };

    let name = args.name;

    if !args.delete {
        println!("Enter yes two times to delete the configuration");
        let p: userprompt::Password2 = userprompt::Password2::prompt(Some("Delete?")).unwrap();
        if p.as_str() != "yes" {
            return;
        }
    }

    let mut exe = std::env::current_exe().unwrap();
    exe.pop();

    {
        let mut service = service::Service::new(format!("rust-iot-{}", name));
        if service.exists() {
            let _ = service.stop();
            let _ = service.delete_async().await;
        }
    }

    println!("The path for the iot instance config is {:?}", config_path);
    tokio::fs::create_dir_all(&config_path).await.unwrap();

    let config_file = config_path.join(format!("{}-config.toml", name));

    let mut settings_con = Vec::new();
    let mut f = tokio::fs::File::open(&config_file).await.unwrap();
    f.read_to_end(&mut settings_con).await.unwrap();

    let settings: MainConfiguration;

    #[cfg(not(feature = "tpm2"))]
    let mut password: Option<String> = None;

    #[cfg(not(feature = "tpm2"))]
    if password.is_none() {
        let mut pw = Vec::new();
        let mut f = tokio::fs::File::open(config_path.join(format!("{}-credentials.bin", name)))
            .await
            .unwrap();
        f.read_to_end(&mut pw).await.unwrap();
        let mut pw = String::from_utf8(pw).unwrap();
        loop {
            if pw.ends_with('\n') {
                pw.pop();
                continue;
            }
            if pw.ends_with('\r') {
                pw.pop();
                continue;
            }
            break;
        }
        password = Some(pw);
    }

    let do_without_tpm2 = |settings_con: Vec<u8>| async {
        let mut password: Option<String> = None;
        if password.is_none() {
            let mut pw = Vec::new();
            let mut f =
                tokio::fs::File::open(config_path.join(format!("{}-credentials.bin", name)))
                    .await
                    .unwrap();
            f.read_to_end(&mut pw).await.unwrap();
            let mut pw = String::from_utf8(pw).unwrap();
            loop {
                if pw.ends_with('\n') {
                    pw.pop();
                    continue;
                }
                if pw.ends_with('\r') {
                    pw.pop();
                    continue;
                }
                break;
            }
            password = Some(pw);
        }
        if password.is_none() {
            let mut password2: userprompt::Password;
            loop {
                print!("Please enter a password:");
                std::io::stdout().flush().unwrap();
                password2 = userprompt::Password::prompt(None).unwrap();
                if !password2.is_empty() {
                    password = Some(password2.to_string());
                    break;
                }
            }
        }

        let password = password.expect("No password provided");
        let password_combined = password.as_bytes();
        let pconfig = tpm2::decrypt(settings_con, password_combined);
        let settings2 = toml::from_str(std::str::from_utf8(&pconfig).unwrap());
        if settings2.is_err() {
            panic!(
                "Failed to parse configuration file {}",
                settings2.err().unwrap()
            );
        }
        settings2.unwrap()
    };

    #[cfg(feature = "tpm2")]
    {
        let mut tpm_data = Vec::new();
        let mut f = tokio::fs::File::open(config_path.join(format!("{}-password.bin", name)))
            .await
            .unwrap();

        f.read_to_end(&mut tpm_data).await.unwrap();

        let mut tpm2 = tpm2::Tpm2::new(tpm2::tpm2_path());

        if let Some(tpm2) = &mut tpm2 {
            let tpm_data = tpm2::TpmBlob::rebuild(&tpm_data);

            let epdata = tpm2.decrypt(tpm_data).unwrap();
            let protected_password = tpm2::Password::rebuild(&epdata);
            let password_combined = protected_password.password();

            let pconfig = tpm2::decrypt(settings_con, password_combined);

            let settings2 = toml::from_str(std::str::from_utf8(&pconfig).unwrap());
            if settings2.is_err() {
                panic!("Failed to parse configuration file");
            }
            settings = settings2.unwrap();
        } else {
            settings = do_without_tpm2(settings_con).await;
        }
    }
    #[cfg(not(feature = "tpm2"))]
    {
        settings = do_without_tpm2(settings_con).await;
    }

    if let Some(https) = &settings.https {
        https.certificate.destroy();
    }

    match &settings.pki {
        ca::PkiConfigurationEnum::Pki(pki) => {
            for (name, ca) in &pki.local_ca {
                let ca = ca.get_ca(name, &settings);
                ca.destroy_backend().await;
            }
        }
        ca::PkiConfigurationEnum::Ca(ca) => {
            let ca = ca.get_ca(&settings);
            ca.destroy_backend().await;
        }
    }
    drop(settings);
    std::fs::remove_file(config_file).unwrap();

    let do_without_tpm2 = || async {
        let p = config_path.join(format!("{}-credentials.bin", name));
        let _e = std::fs::remove_file(p);
    };

    #[cfg(feature = "tpm2")]
    {
        let tpm2 = tpm2::Tpm2::new(tpm2::tpm2_path());
        if tpm2.is_some() {
            let p = config_path.join(format!("{}-password.bin", name));
            let mut perms = std::fs::metadata(&p).unwrap().permissions();
            perms.set_readonly(false);
            std::fs::set_permissions(&p, perms).unwrap();
            let e = std::fs::remove_file(&p);
            println!("Delete {} = {:?}", p.display(), e);
        } else {
            println!("TPM2 NOT DETECTED!!!");
            do_without_tpm2().await;
        };
    }
    #[cfg(not(feature = "tpm2"))]
    {
        do_without_tpm2().await;
    }

    let proxy_name = std::path::PathBuf::from(format!("./reverse-proxy-{}.txt", &name));
    if proxy_name.exists() {
        let _ = tokio::fs::remove_file(proxy_name).await;
    }
}
