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

    let url = match &s.pki_type {
        ca::SimplifiedPkiConfigurationEnum::AddedCa => format!("{}ca", s.proxy),
        ca::SimplifiedPkiConfigurationEnum::Pki => format!("{}pki", s.proxy),
        ca::SimplifiedPkiConfigurationEnum::Ca => format!("{}ca", s.proxy),
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

use crate::hsm2::SecurityModuleTrait;
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

    unsafe {
        std::env::set_var("SOFTHSM2_CONF", config_path.join("softhsm2.conf"));
    }

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

    let mut password_combined: Option<Vec<u8>> = None;
    let settings: MainConfiguration = MainConfiguration::load(
        config_path.clone(),
        &name,
        settings_con,
        &mut password_combined,
    )
    .await;

    settings.pki.set_log_level();

    let hsm: Arc<hsm2::SecurityModule> =
        settings.pki.init_hsm(&config_path, &name, &settings).await;

    hsm.list_certificates();

    let (shutdown_send, mut shutdown_recv) = tokio::sync::mpsc::unbounded_channel::<()>();

    let settings = Arc::new(settings);
    let mut pki = ca::PkiInstance::load(hsm.clone(), &settings).await.unwrap(); //TODO remove this unwrap?

    pki.check_for_existing_https_certificate();

    let proxy_map = pki.build_proxy_map();

    ca::ca_register(&pki, &mut router);
    ca::ca_register_files(&pki, &mut static_map);
    if args.shutdown {
        pki.set_shutdown(shutdown_send);
        ca::ca_register_test(&pki, &mut router);
    }

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
                let ec = main_config::do_tpm2_decryption(
                    password_combined.as_ref(),
                    contents,
                    &config_path,
                    &name,
                )
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

    let mysql_pool = pki.connect_to_mysql();

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
        pki: pki.clone(),
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

    if !args.test {
        let mut pki = pki.lock().await;
        pki.start_web_services(&mut tasks, hc.clone()).await;

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
