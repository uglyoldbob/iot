#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(unused_extern_crates)]
#![allow(unused)]

//! This binary is a gui app used to work with smartcards.

mod main_config;

use std::io::Write;

pub use main_config::MainConfiguration;

#[path = "ca/ca_common.rs"]
/// The ca module, with code used to construct a ca
mod ca;
mod hsm2;
mod tpm2;
mod utility;

use egui_multiwin_dynamic::multi_window::{MultiWindow, NewWindowRequest};

/// The gui library code
pub mod egui_multiwin_dynamic {
    egui_multiwin::tracked_window!(
        crate::AppCommon,
        egui_multiwin::NoEvent,
        crate::smartcard_windows::MyWindows
    );
    egui_multiwin::multi_window!(
        crate::AppCommon,
        egui_multiwin::NoEvent,
        crate::smartcard_windows::MyWindows
    );
}

mod smartcard_windows;

use smartcard_windows::smartcard_root;

/// The common data for the gui
pub struct AppCommon {
    /// object to send messages to the async code
    pub send: tokio::sync::mpsc::Sender<smartcard_root::Message>,
    /// object to receive messages from the async code
    pub recv: tokio::sync::mpsc::Receiver<smartcard_root::Response>,
    /// The configuration
    pub config: SmartCardGuiConfig,
}

/// The types of servers that can exist
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum ServerConfig {
    /// A dedicated pki server
    DedicatedServer {
        /// The url
        url: String,
    },
    /// A server using cgi scripts
    Cgi {
        /// The url
        url: String,
    },
}

/// The configuration file contents for the gui
#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct SmartCardGuiConfig {
    /// The list of urls to use for smartcart certificate registration
    servers: Vec<ServerConfig>,
    /// The list of valid server certificates, all in pem format
    ca_certs: Vec<String>,
}

impl AppCommon {
    /// Process events sent to the gui
    fn process_event(&mut self, _event: egui_multiwin::NoEvent) -> Vec<NewWindowRequest> {
        Vec::new()
    }
}

async fn handle_card_stuff(
    mut recv: tokio::sync::mpsc::Receiver<smartcard_root::Message>,
    send: tokio::sync::mpsc::Sender<smartcard_root::Response>,
    ca_certs: Vec<String>,
) -> Result<(), ()> {
    while let Some(m) = recv.recv().await {
        match m {
            smartcard_root::Message::Exit => {
                let _ = send.send(smartcard_root::Response::Done).await;
                break;
            }
            smartcard_root::Message::ErasePivCard => {
                let erased = ::card::with_current_valid_piv_card_async(|card| {
                    let mut cw = card.to_writer();
                    cw.erase_card().is_ok()
                })
                .await;
                send.send(smartcard_root::Response::Erased(erased))
                    .await
                    .map_err(|_| ())?;
            }
            smartcard_root::Message::GenerateKeypair => {
                let keypair = card::KeyPair::generate_with_smartcard_async(
                    ::card::PIV_PIN_KEY_DEFAULT.to_vec(),
                    "TEST KEYPAIR",
                    false,
                )
                .await;
                let kp = keypair.map(|a| a.rcgen());
                service::log::info!("Got the keypair");
                send.send(smartcard_root::Response::KeypairGenerated(kp))
                    .await
                    .map_err(|_| ())?;
            }
            smartcard_root::Message::WriteCertificate(s) => {
                let cert_saved = ::card::with_current_valid_piv_card_async(|card| {
                    let mut cw = card.to_writer();
                    let thing = pem::parse(s).map_err(|_| ::card::Error::ExpectedDataMissing)?;
                    let thing2 = thing.into_contents();
                    service::log::info!("The der? is {:x?}", thing2);
                    cw.store_x509_cert(::card::MANAGEMENT_KEY_DEFAULT, thing2.as_slice(), 0x9A)
                })
                .await;
                send.send(smartcard_root::Response::CertificateStored(cert_saved))
                    .await
                    .map_err(|_| ())?;
            }
            smartcard_root::Message::CheckCsrStatus { server, serial } => {
                let mut client = reqwest::ClientBuilder::new();
                for s in &ca_certs {
                    service::log::info!("Trying to register server cert: -{}-", s);
                    if let Ok(cert) = reqwest::Certificate::from_pem(s.as_bytes()) {
                        service::log::info!("CERT IS {:?}", cert);
                        client = client.add_root_certificate(cert);
                    }
                }
                if let Ok(client) = client
                    .danger_accept_invalid_hostnames(true)
                    .use_rustls_tls()
                    .build()
                {
                    let url_get = url_encoded_data::stringify(&[
                        ("serial", crate::utility::encode_hex(&serial).as_str()),
                        ("smartcard", "1"),
                        ("type", "pem"),
                    ]);
                    let url = match server {
                        ServerConfig::DedicatedServer { url } => {
                            format!("{}/ca/get_cert.rs?{}", url, url_get)
                        }
                        ServerConfig::Cgi { url } => {
                            format!("{}/rust-iot.cgi?action=do_stuff&{}", url, url_get)
                        }
                    };
                    let res = client.get(url).send().await;
                    if let Ok(r) = res {
                        if let Ok(data) = r.bytes().await {
                            let data = data.to_vec();
                            if let Ok(s) = str::from_utf8(&data) {
                                let h = url_encoded_data::UrlEncodedData::parse_str(s);
                                let cert = h.get("cert");
                                if let Some(cert) = cert {
                                    if let Some(cert) = cert.first() {
                                        send.send(smartcard_root::Response::CertificateCreated(
                                            cert.to_string(),
                                        ))
                                        .await
                                        .map_err(|_| ())?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            smartcard_root::Message::SubmitCsr {
                csr,
                server,
                name,
                email,
                phone,
            } => {
                let mut client = reqwest::ClientBuilder::new();
                for s in &ca_certs {
                    service::log::info!("Trying to register server cert: -{}-", s);
                    if let Ok(cert) = reqwest::Certificate::from_pem(s.as_bytes()) {
                        service::log::info!("CERT IS {:?}", cert);
                        client = client.add_root_certificate(cert);
                    }
                }
                if let Ok(client) = client
                    .danger_accept_invalid_hostnames(true)
                    .use_rustls_tls()
                    .build()
                {
                    let url = match server {
                        ServerConfig::DedicatedServer { url } => {
                            format!("{}/ca/submit_request.rs", url)
                        }
                        ServerConfig::Cgi { url } => {
                            format!("{}/rust-iot.cgi?action=do_stuff", url)
                        }
                    };
                    let mut form = std::collections::HashMap::new();
                    form.insert("csr", csr);
                    form.insert("name", name);
                    form.insert("email", email);
                    form.insert("phone", phone);
                    form.insert("smartcard", "1".to_string());
                    let res = client.post(url).form(&form).send().await;
                    if let Ok(res) = res {
                        if let Ok(r) = res.bytes().await {
                            if let Ok(d) = String::from_utf8(r.to_vec()) {
                                let h = url_encoded_data::UrlEncodedData::parse_str(&d);
                                let serial = h.get("serial");
                                if let Some(serial) = serial {
                                    if let Some(serial) = serial.first() {
                                        if let Ok(serial) = crate::utility::decode_hex(serial) {
                                            service::log::info!("The serial is {:02x?}", serial);
                                            send.send(smartcard_root::Response::CsrSubmitStatus(
                                                Some(serial),
                                            ))
                                            .await
                                            .map_err(|_| ())?;
                                        }
                                    }
                                } else {
                                    send.send(smartcard_root::Response::CsrSubmitStatus(None))
                                        .await
                                        .map_err(|_| ())?;
                                }
                            }
                        }
                    } else {
                        service::log::error!("Error submitting csr: {:?}", res.err());
                        send.send(smartcard_root::Response::CsrSubmitStatus(None))
                            .await
                            .map_err(|_| ())?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn main() {
    let service = service::Service::new("smartcard-gui".to_string());
    service.new_log(service::LogLevel::Debug);
    let mut event_loop = egui_multiwin::winit::event_loop::EventLoopBuilder::with_user_event();
    let event_loop = match event_loop.build() {
        Ok(e) => e,
        Err(e) => panic!("Failed to build event loop: {}", e),
    };
    let mut multi_window: MultiWindow = MultiWindow::new();
    let root_window = smartcard_root::RootWindow::request();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(e) => e,
        Err(e) => panic!("Failed to build runtime: {}", e),
    };
    let ch = tokio::sync::mpsc::channel(10);
    let ch2 = tokio::sync::mpsc::channel(10);

    let config = {
        use std::io::Read;
        let mut settings_con = Vec::new();
        let pb = "./smartcard-gui.toml";
        service::log::debug!("Opening {}", pb);
        let mut f = match std::fs::File::open(pb) {
            Ok(e) => e,
            Err(e) => {
                let mut ec = SmartCardGuiConfig::default();
                ec.servers.push(ServerConfig::DedicatedServer {
                    url: "example.com".to_string(),
                });
                ec.servers.push(ServerConfig::Cgi {
                    url: "example.com".to_string(),
                });
                let t = toml::to_string(&ec).unwrap();
                let mut f = std::fs::File::create_new(pb).unwrap();
                f.write_all(t.as_bytes());
                panic!("Unable to open config file - created a sample config for you");
            }
        };
        if f.read_to_end(&mut settings_con).is_err() {
            panic!("Failed to read contents of smartcard-gui.toml");
        }
        let Ok(s) = std::str::from_utf8(&settings_con) else {
            panic!("Invalid string contents of config file")
        };
        let Ok(c) = toml::from_str::<SmartCardGuiConfig>(s) else {
            panic!("Invalid contents of config file");
        };
        c
    };

    let asdf = runtime.spawn(handle_card_stuff(ch.1, ch2.0, config.ca_certs.clone()));

    service::log::info!(
        "The urls for smartcard registering are {:?}",
        config.servers
    );

    let mut ac = AppCommon {
        send: ch.0,
        recv: ch2.1,
        config,
    };

    let _e = multi_window.add(root_window, &mut ac, &event_loop);
    if let Err(e) = multi_window.run(event_loop, ac) {
        panic!("Failed to run gui: {}", e);
    }
}
