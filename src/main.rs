#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(unused_extern_crates)]
#![allow(unused)]

//! This program is for managing iot devices.

//For the html crate
#![recursion_limit = "512"]

mod ca;
mod hsm2;
mod tpm2;
mod utility;

use std::io::Write;
use std::sync::Arc;

use hyper::header::HeaderValue;

mod webserver;

mod main_config;
pub use main_config::MainConfiguration;
use tokio::io::AsyncReadExt;
use userprompt::Prompting;
use zeroize::Zeroizing;

use webserver::*;

/// A test function that produces demo content
async fn test_func2(s: WebPageContext) -> webserver::WebResponse {
    let mut html = html::root::Html::builder();
    html.head(|h| h).body(|b| {
        b.ordered_list(|ol| {
            for name in ["I", "am", "groot"] {
                ol.list_item(|li| li.text(name));
            }
            ol
        })
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

/// Another test function that produces demo content
async fn test_func(s: WebPageContext) -> webserver::WebResponse {
    let mut html = html::root::Html::builder();
    html.head(|h| h).body(|b| {
        if !s.get.is_empty() {
            b.ordered_list(|ol| {
                for (a, b) in s.get.iter() {
                    ol.list_item(|li| li.text(format!("{}: {}", a, b)));
                }
                ol
            });
        }
        b
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

///The page that redirects to /main.rs
async fn main_redirect(s: WebPageContext) -> webserver::WebResponse {
    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let url = match &s.settings.pki {
        ca::PkiConfigurationEnum::AddedCa(ca) => format!("{}ca", s.proxy),
        ca::PkiConfigurationEnum::Pki(pki_configuration) => format!("{}pki", s.proxy),
        ca::PkiConfigurationEnum::Ca(standalone_ca_configuration) => format!("{}ca", s.proxy),
    };

    response.status = hyper::http::StatusCode::from_u16(302).unwrap();
    response
        .headers
        .insert("Location", HeaderValue::from_str(&url).unwrap());

    let body = http_body_util::Full::new(hyper::body::Bytes::from("I am GRooT?"));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

/// A test function that shows some demo content
async fn test_func3(s: WebPageContext) -> webserver::WebResponse {
    let mut html = html::root::Html::builder();
    html.head(|h| h).body(|b| {
        b.ordered_list(|ol| {
            for name in ["I", "am", "groot"] {
                ol.list_item(|li| li.text(name));
            }
            ol
        })
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

use clap::Parser;
/// Arguments for creating an iot instance
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The name of the instance
    #[arg(short, long)]
    name: Option<String>,

    /// The config path to override the default with
    #[arg(short, long)]
    config: Option<String>,

    /// The program should run for test mode
    #[arg(long, default_value_t = false)]
    test: bool,

    /// The program should run enable the shutdown trigger
    #[arg(long, default_value_t = false)]
    shutdown: bool,
}

async fn do_without_tpm2<T: serde::de::DeserializeOwned>(
    settings_con: Vec<u8>,
    config_path: &std::path::PathBuf,
    name: &String,
) -> T {
    let mut password: Option<String> = None;
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
    if password.is_none() {
        let mut password2: userprompt::Password;
        loop {
            print!("Please enter a password:");
            std::io::stdout().flush().unwrap();
            password2 = userprompt::Password::prompt(None, None).unwrap();
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
}

async fn do_tpm2_operation<T: serde::de::DeserializeOwned>(
    password_combined: Option<&Vec<u8>>,
    contents: Vec<u8>,
    config_path: &std::path::PathBuf,
    name: &String,
) -> T {
    let settings: T;
    #[cfg(feature = "tpm2")]
    {
        let mut tpm2 = tpm2::Tpm2::new(tpm2::tpm2_path());

        if let Some(tpm2) = &mut tpm2 {
            if let Some(password_combined) = &password_combined {
                let pconfig = tpm2::decrypt(contents, password_combined);

                let settings2 = toml::from_str(std::str::from_utf8(&pconfig).unwrap());
                if settings2.is_err() {
                    panic!("Failed to parse configuration file");
                }
                settings = settings2.unwrap();
            } else {
                settings = do_without_tpm2(contents, config_path, name).await;
            }
        } else {
            settings = do_without_tpm2(contents, config_path, name).await;
        }
    }
    #[cfg(not(feature = "tpm2"))]
    {
        settings = do_without_tpm2(contents, config_path, name).await;
    }
    settings
}

/// The main function for the service
async fn smain() {
    #[cfg(target_family = "windows")]
    {
        std::panic::set_hook(Box::new(|p| {
            service::log::debug!("Panic {:?}", p);
        }))
    }

    let args = Args::parse();
    let config_path = if let Some(p) = args.config {
        std::path::PathBuf::from(p).canonicalize().unwrap()
    } else {
        crate::main_config::default_config_path()
    };
    std::env::set_current_dir(&config_path).expect("Failed to switch to config directory");

    std::env::set_var("SOFTHSM2_CONF", config_path.join("softhsm2.conf"));

    let name = args.name.unwrap_or("default".to_string());

    service::log::debug!("Load config from {:?}", config_path);
    service::log::debug!(
        "Current path is {}",
        std::env::current_dir().unwrap().display()
    );

    let mut static_map = std::collections::HashMap::new();
    let mut router = webserver::WebRouter::new();
    router.register("/asdf", test_func);
    router.register("/groot", test_func2);
    router.register("/groot2", test_func3);
    router.register("", main_redirect);
    router.register("/", main_redirect);

    let mut settings_con = Vec::new();
    let pb = config_path.join(format!("{}-config.toml", name));
    service::log::debug!("Opening {}", pb.display());
    let mut f = tokio::fs::File::open(pb).await.unwrap();
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

    let mut password_combined: Option<Vec<u8>> = None;
    #[cfg(feature = "tpm2")]
    {
        let mut tpm2 = tpm2::Tpm2::new(tpm2::tpm2_path());

        if let Some(tpm2) = &mut tpm2 {
            let mut tpm_data = Vec::new();
            let mut f = tokio::fs::File::open(config_path.join(format!("{}-password.bin", name)))
                .await
                .unwrap();
            f.read_to_end(&mut tpm_data).await.unwrap();

            let tpm_data = tpm2::TpmBlob::rebuild(&tpm_data);

            let epdata = tpm2.decrypt(tpm_data).unwrap();
            let protected_password = tpm2::Password::rebuild(&epdata);
            password_combined = Some(protected_password.password().to_vec());
        }
    }

    settings = do_tpm2_operation(
        password_combined.as_ref(),
        settings_con,
        &config_path,
        &name,
    )
    .await;

    service::log::set_max_level(
        settings
            .debug_level
            .as_ref()
            .unwrap_or(&service::LogLevel::Trace)
            .level_filter(),
    );

    let hsm: Arc<hsm2::Hsm>;

    let mut proxy_map = std::collections::HashMap::new();

    for name in &settings.public_names {
        proxy_map.insert(name.domain.clone(), name.subdomain.clone());
    }

    {
        let n = config_path.join(format!("{}-initialized", name));
        if n.exists() && n.metadata().unwrap().len() > 2 {
            let hsm2 = if let Some(hsm_t) = hsm2::Hsm::create(
                settings.hsm_path_override.as_ref().map(|a| a.to_path_buf()),
                Zeroizing::new(settings.hsm_pin.clone()),
                Zeroizing::new(settings.hsm_pin2.clone()),
            ) {
                hsm_t
            } else {
                service::log::error!("Failed to open the hardware security module");
                panic!("Failed to open the hardware security module");
            };

            hsm = Arc::new(hsm2);

            hsm.list_certificates();

            use tokio::io::AsyncWriteExt;
            let _ca_instance = ca::PkiInstance::init(hsm.clone(), &settings.pki, &settings)
                .await
                .unwrap();
            let mut f = tokio::fs::File::create(&n).await.unwrap();
            f.write_all("".as_bytes())
                .await
                .expect("Failed to initialization file update");
        } else {
            let hsm2 = if let Some(hsm_t) = hsm2::Hsm::open(
                settings.hsm_slot.unwrap_or(0),
                settings.hsm_path_override.as_ref().map(|a| a.to_path_buf()),
                Zeroizing::new(settings.hsm_pin2.clone()),
            ) {
                hsm_t
            } else {
                service::log::error!("Failed to open the hardware security module");
                panic!("Failed to open the hardware security module");
            };

            hsm = Arc::new(hsm2);
        }
    }

    hsm.list_certificates();

    if let Some(https) = &settings.https {
        if !https.certificate.exists() {
            service::log::error!("Failed to open https certificate");
            panic!("No https certificate to run with");
        }
    }

    let (shutdown_send, mut shutdown_recv) = tokio::sync::mpsc::unbounded_channel::<()>();

    let settings = Arc::new(settings);
    let mut pki = ca::PkiInstance::load(hsm.clone(), &settings).await.unwrap(); //TODO remove this unwrap?

    ca::ca_register(&pki, &mut router);
    ca::ca_register_files(&pki, &mut static_map);
    if args.shutdown {
        pki.set_shutdown(shutdown_send);
        ca::ca_register_test(&pki, &mut router);
    }

    let mut mysql_pool = None;

    if let Some(settings) = &settings.database {
        let mysql_pw = &settings.password;
        let mysql_user = &settings.username;
        let mysql_dbname = &settings.name;
        let mysql_url = &settings.url;
        let mysql_conn_s = format!(
            "mysql://{}:{}@{}/{}",
            mysql_user, mysql_pw, mysql_url, mysql_dbname,
        );
        let mysql_opt = mysql::Opts::from_url(mysql_conn_s.as_str()).unwrap();
        let mysql_temp = mysql::Pool::new(mysql_opt);
        match mysql_temp {
            Ok(ref _bla) => service::log::info!("I have a bla"),
            Err(ref e) => service::log::error!("Error connecting to mysql: {}", e),
        }
        mysql_pool = mysql_temp.ok();
    }

    let _mysql_conn_s = mysql_pool.as_mut().map(|s| s.get_conn().unwrap());

    let mut extra_configs = Vec::new();
    {
        let mut i = 0;
        loop {
            let mut contents = Vec::new();
            let pb = config_path.join(format!("{name}-extra-config{i}.toml"));
            service::log::debug!("Checking for extra config {}", pb.display());
            if let Ok(mut f) = tokio::fs::File::open(&pb).await {
                service::log::debug!("Opening extra config {}", pb.display());
                f.read_to_end(&mut contents).await.unwrap();
                let ec =
                    do_tpm2_operation(password_combined.as_ref(), contents, &config_path, &name)
                        .await;
                extra_configs.push(ec);
                i += 1;
            } else {
                break;
            }
        }
    }
    pki.register_extra_configs(extra_configs, hsm, &settings)
        .await;

    let root = pki.get_static_root();
    let pki = Arc::new(futures::lock::Mutex::new(pki));

    let hc = HttpContext {
        static_map,
        dirmap: router,
        root,
        proxy: proxy_map,
        cookiename: "rustcookie".to_string(),
        pool: mysql_pool,
        settings: settings.clone(),
        pki,
    };

    if !hc.proxy.is_empty() {
        for (domain, proxy) in &hc.proxy {
            service::log::info!("Using {} as the proxy path for {}", proxy, domain);
        }
    } else {
        service::log::info!("Not using a proxy path");
    }

    let hc = Arc::new(hc);

    let mut tasks: tokio::task::JoinSet<Result<(), webserver::ServiceError>> =
        tokio::task::JoinSet::new();

    let client_certs = webserver::tls::load_user_cert_data(&settings);

    if !args.test {
        if let Some(http) = &settings.http {
            service::log::info!("Listening http on port {}", http.port);

            if let Err(e) = http_webserver(hc.clone(), http.port, &mut tasks).await {
                service::log::error!("https web server errored {}", e);
            }
        }

        if let Some(https) = &settings.https {
            service::log::info!("Listening https on port {}", https.port);

            let tls_cert = https.certificate.to_owned();
            let https_cert = tls_cert.get_usable();

            if let Err(e) = https_webserver(
                hc.clone(),
                https.port,
                https_cert,
                &mut tasks,
                client_certs,
                https.require_certificate,
            )
            .await
            {
                service::log::error!("https web server errored {}", e);
            }
        }

        tokio::select! {
            r = tasks.join_next() => {
                service::log::error!("A task exited {:?}, closing server in 5 seconds", r);
                tokio::time::sleep(tokio::time::Duration::from_millis(5000)).await;
            }
            _ = tokio::signal::ctrl_c() => {}
            _ = shutdown_recv.recv() => {}
        }
    }
    service::log::error!("Closing server now");
}

service::ServiceAsyncMacro!(service_starter, smain, u64);

#[tokio::main]
async fn main() -> Result<(), u32> {
    let args = Args::parse();

    let name = args.name.unwrap_or("default".to_string());

    let service = service::Service::new(format!("rust-iot-{}", name));
    service.new_log(service::LogLevel::Debug);
    if let Err(e) = service::DispatchAsync!(service, service_starter) {
        Err(e)
    } else {
        Ok(())
    }
}
