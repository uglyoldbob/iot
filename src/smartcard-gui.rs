#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(unused_extern_crates)]
#![allow(unused)]

//! This binary is a gui app used to work with smartcards.

mod main_config;

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

/// The configuration file contents for the gui
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SmartCardGuiConfig {
    /// The list of urls to use for smartcart certificate registration
    ca_urls: Vec<String>,
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
) {
    while let Some(m) = recv.recv().await {
        match m {
            smartcard_root::Message::Exit => {
                send.send(smartcard_root::Response::Done).await.unwrap();
                break;
            }
            smartcard_root::Message::ErasePivCard => {
                let erased = ::card::with_current_valid_piv_card(|card| {
                    let mut cw = card.to_writer();
                    cw.erase_card().is_ok()
                })
                .await;
                send.send(smartcard_root::Response::Erased(erased))
                    .await
                    .unwrap();
            }
            smartcard_root::Message::GenerateKeypair => {
                let keypair = card::KeyPair::generate_with_smartcard(
                    ::card::PIV_PIN_KEY_DEFAULT.to_vec(),
                    "TEST KEYPAIR",
                    false,
                )
                .await;
                let kp = keypair.map(|a| a.rcgen());
                service::log::info!("Got the keypair");
                let _ = send
                    .send(smartcard_root::Response::KeypairGenerated(kp))
                    .await;
            }
            smartcard_root::Message::WriteCertificate(s) => {
                let cert_saved = ::card::with_current_valid_piv_card(|card| {
                    let mut cw = card.to_writer();
                    cw.store_x509_cert(::card::MANAGEMENT_KEY_DEFAULT, s.as_bytes(), 0x9A)
                })
                .await;
                send.send(smartcard_root::Response::CertificateStored(cert_saved))
                    .await
                    .unwrap();
            }
            smartcard_root::Message::SubmitCsr { csr, server, name, email, phone } => {
                {
                    use std::io::Write;
                    let mut f = std::fs::File::create("./cert.pem").unwrap();
                    f.write_all(csr.as_bytes());
                }
                let mut client = reqwest::ClientBuilder::new();
                for s in &ca_certs {
                    service::log::info!("Trying to register server cert: -{}-", s);
                    let cert = reqwest::Certificate::from_pem(s.as_bytes()).unwrap();
                    service::log::info!("CERT IS {:?}", cert);
                    client = client.add_root_certificate(cert);
                }
                let client = client.danger_accept_invalid_hostnames(true).use_rustls_tls().build().unwrap();
                let url = format!("{}/ca/submit_request.rs", server);
                let mut form = std::collections::HashMap::new();
                form.insert("csr", csr);
                form.insert("name", name);
                form.insert("email", email);
                form.insert("phone", phone);
                form.insert("smartcard", "1".to_string());
                let res = client.post(url)
                    .form(&form)
                    .send()
                    .await;
                if let Ok(res) = res {
                    let d = String::from_utf8(res.bytes().await.unwrap().to_vec()).unwrap();
                    let h = url_encoded_data::UrlEncodedData::parse_str(&d);
                    let id = h.get("id");
                    if let Some(id) = id {
                        let id = id.first().unwrap().parse::<usize>().unwrap();
                        service::log::info!("The id is {:?}", id);
                        let _ = send.send(smartcard_root::Response::CsrSubmitStatus(Some(id))).await;
                    }
                    else {
                        let _ = send.send(smartcard_root::Response::CsrSubmitStatus(None)).await;
                    }
                }
                else {
                    service::log::error!("Error submitting csr: {:?}", res.err());
                    let _ = send.send(smartcard_root::Response::CsrSubmitStatus(None)).await;
                }
            }
            _ => {}
        }
    }
}

fn main() {
    let service = service::Service::new("smartcard-gui".to_string());
    service.new_log(service::LogLevel::Debug);
    let mut event_loop = egui_multiwin::winit::event_loop::EventLoopBuilder::with_user_event();
    let event_loop = event_loop.build().unwrap();
    let mut multi_window: MultiWindow = MultiWindow::new();
    let root_window = smartcard_root::RootWindow::request();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let ch = tokio::sync::mpsc::channel(10);
    let ch2 = tokio::sync::mpsc::channel(10);

    let config = {
        use std::io::Read;
        let mut settings_con = Vec::new();
        let pb = "./smartcard-gui.toml";
        service::log::debug!("Opening {}", pb);
        let mut f = std::fs::File::open(pb).unwrap();
        f.read_to_end(&mut settings_con).unwrap();
        let c : SmartCardGuiConfig = toml::from_str(std::str::from_utf8(&settings_con).unwrap()).unwrap();
        c
    };

    let asdf = runtime.spawn(handle_card_stuff(ch.1, ch2.0, config.ca_certs.clone()));

    service::log::info!("The urls for smartcard registering are {:?}", config.ca_urls);

    let mut ac = AppCommon {
        send: ch.0,
        recv: ch2.1,
        config,
    };

    let _e = multi_window.add(root_window, &mut ac, &event_loop);
    multi_window.run(event_loop, ac).unwrap();
}
