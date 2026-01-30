use std::sync::{Arc, Mutex};

use eframe::{egui, NativeOptions};

mod android_nfc;
use android_nfc::*;

use jni_min_helper::*;

/// The api key for nxpnfclib
const NFC_KEY: &str = include_str!("../nfc_key.txt");
/// The offline api key for nxpnfclib
const NFC_KEY_OFFLINE: &str = include_str!("../nfc_key_offline.txt");

pub enum NfcCardCommand {
    BasicInfo,
}

pub enum NfcCardResponse {
    BasicInfo { stuff: String },
}

lazy_static::lazy_static! {
    static ref NFC_CARD_COMMAND : Arc<Mutex<Option<std::sync::mpsc::Receiver<NfcCardCommand>>>> = Arc::new(Mutex::new(None));
    static ref NFC_CARD_RESPONSE: Arc<Mutex<Option<std::sync::mpsc::Sender<NfcCardResponse>>>> = Arc::new(Mutex::new(None));
}

const CONFIGURATION_FILE: &str = "config.toml";

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_com_uglyoldbob_RustIotNfc_RegisterActivity_nativeDoCustomization(
    mut env: jni::JNIEnv,
    _: jni::objects::JClass,
    jurl: jni::objects::JString,
) {
    let url: String = env.get_string(&jurl).expect("invalid string").into();
    android_nfc::start_registration(url);
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_com_uglyoldbob_RustIotNfc_ModdedActivity_notifyOnTag(
    mut env: jni::JNIEnv,
    this: jni::objects::JObject,
    ma: jni::objects::JObject,
    tag: jni::objects::JObject,
) {
    let mut m = NxpNfcInstance.lock().unwrap();
    let m: Option<&mut NxpNfcLib> = m.as_mut();
    if let Some(i) = m {
        match i.get_card_type_from_tag(&mut env, tag) {
            Ok(t) => match t.process(&mut env, i) {
                Ok(card) => {
                    log::error!("There is a nxpnfclib to use with {:?}", t);
                    let mut q = NFC_CARD_COMMAND.lock().unwrap();
                    if let Some(q) = q.as_mut() {
                        let mut r = NFC_CARD_RESPONSE.lock().unwrap();
                        if let Some(r) = r.as_mut() {
                            if let Ok(cmd) = q.try_recv() {
                                match cmd {
                                    NfcCardCommand::BasicInfo => {
                                        log::error!(
                                            "App select is {:?}",
                                            card.select_application(&mut env, None)
                                        );
                                        log::error!(
                                            "Authenticate is {:?}",
                                            card.authenticate(&mut env, None)
                                        );
                                        let _ = r.send(NfcCardResponse::BasicInfo {
                                            stuff: "TESTING".to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    log::error!("There was an error processing the card type: {e:?}");
                }
            },
            Err(e) => {
                log::error!("There was an error reading the card type: {e:?}");
            }
        }
    }
}

#[cfg(target_os = "android")]
use egui_winit::winit;
use pkcs8::der::{self, Decode};
#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: winit::platform::android::activity::AndroidApp) {
    use eframe::Renderer;

    std::env::set_var("RUST_BACKTRACE", "full");
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Error),
    );

    let chan_1 = std::sync::mpsc::channel();
    {
        let mut q = NFC_CARD_COMMAND.lock().unwrap();
        q.replace(chan_1.1);
    }

    let chan_2 = std::sync::mpsc::channel();
    {
        let mut r = NFC_CARD_RESPONSE.lock().unwrap();
        r.replace(chan_2.0);
    }

    let mut nfc = TapLinx::make_new(&app);

    let options = NativeOptions {
        android_app: Some(app),
        renderer: Renderer::Wgpu,
        ..Default::default()
    };
    DemoApp::run(options, nfc, chan_1.0, chan_2.1).unwrap();
}

#[derive(Debug)]
pub enum AppConfigError {
    NotLoaded,
    Corrupt,
    UnableToCreate,
}

#[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
pub struct AppConfig {
    /// The csr for registration
    pub csr_der: Option<String>,
    /// The keypair for the certificate
    pub cert_keypair: Option<Vec<u8>>,
    /// The serial number of the certificate
    cert_serial: Option<Vec<u8>>,
    /// The der format of x509_cert::Certificate
    certificate: Option<String>,
    /// The url to use for the server
    server_url: Option<String>,
}

impl AppConfig {
    pub fn get_cert(&self) -> Option<x509_cert::Certificate> {
        self.certificate.as_ref().and_then(|c| {
            let (_label, der) = pem_rfc7468::decode_vec(c.as_bytes()).ok()?;
            use x509_cert::der::Decode;
            x509_cert::Certificate::from_der(&der).ok()
        })
    }

    pub fn get_identity(&self) -> Option<reqwest::Identity> {
        let pem = if let Some(cert) = &self.certificate {
            if let Some(d) = &self.cert_keypair {
                let der = der::Document::from_der(d).unwrap();
                let p = der
                    .to_pem("PRIVATE KEY", der::pem::LineEnding::CRLF)
                    .unwrap();
                let mut res = cert.to_owned();
                res.push_str(&p);
                Some(res)
            } else {
                None
            }
        } else {
            None
        };
        pem.and_then(|pem| reqwest::Identity::from_pem(pem.as_bytes()).ok())
    }
}

pub struct DemoApp {
    local_storage: Option<std::path::PathBuf>,
    pub settings: Result<AppConfig, AppConfigError>,
    nfc: TapLinx,
    test: String,
    send: std::sync::mpsc::Sender<NfcCardCommand>,
    resp: std::sync::mpsc::Receiver<NfcCardResponse>,
    waiting_nfc_response: bool,
    nfc_response: Option<NfcCardResponse>,
}

impl DemoApp {
    pub fn run(
        options: NativeOptions,
        nfc: TapLinx,
        send: std::sync::mpsc::Sender<NfcCardCommand>,
        resp: std::sync::mpsc::Receiver<NfcCardResponse>,
    ) -> Result<(), eframe::Error> {
        eframe::run_native(
            "rust-iot-nfc",
            options.clone(),
            Box::new(|_cc| Ok(Box::<DemoApp>::new(DemoApp::new(options, nfc, send, resp)))),
        )
    }

    fn save_config(&self) -> Result<(), std::io::Error> {
        if let Some(p) = &self.local_storage {
            if let Ok(settings) = &self.settings {
                let mut config = p.clone();
                config.push(CONFIGURATION_FILE);
                let encoded: Vec<u8> = toml::to_string_pretty(settings)
                    .unwrap()
                    .as_bytes()
                    .to_vec();
                let mut f = std::fs::File::create(&config)?;
                use std::io::Write;
                match f.write_all(&encoded) {
                    Ok(_l) => Ok(()),
                    Err(e) => {
                        log::error!("Unable to save config file: {:?}", e);
                        Err(e)
                    }
                }
            } else {
                Err(std::io::Error::other("No valid local settings"))
            }
        } else {
            Err(std::io::Error::other("No local storage"))
        }
    }

    fn load_config(&mut self) {
        if let Some(p) = &self.local_storage {
            log::error!("Got local storage path: {}", p.display());
            let mut config = p.clone();
            config.push(CONFIGURATION_FILE);
            let settings = if let Ok(false) = std::fs::exists(&config) {
                let settings = AppConfig::default();
                let encoded: Vec<u8> = toml::to_string_pretty(&settings)
                    .unwrap()
                    .as_bytes()
                    .to_vec();
                let f = std::fs::File::create(&config);
                if let Ok(mut f) = f {
                    use std::io::Write;
                    match f.write_all(&encoded) {
                        Ok(_l) => Ok(settings),
                        Err(e) => {
                            log::error!("Unable to create config file: {:?}", e);
                            Err(AppConfigError::UnableToCreate)
                        }
                    }
                } else {
                    log::error!("Unable to create config file2: {:?}", f);
                    Err(AppConfigError::UnableToCreate)
                }
            } else {
                let f = std::fs::read(&config);
                if let Ok(a) = f {
                    let s = toml::from_str::<AppConfig>(str::from_utf8(&a).unwrap());
                    if let Ok(s) = s {
                        Ok(s)
                    } else {
                        Err(AppConfigError::Corrupt)
                    }
                } else {
                    Err(AppConfigError::Corrupt)
                }
            };
            self.settings = settings;
        } else {
            log::error!("NO LOCAL SETTINGS DIR?");
        }
    }

    fn new(
        options: NativeOptions,
        nfc: TapLinx,
        send: std::sync::mpsc::Sender<NfcCardCommand>,
        resp: std::sync::mpsc::Receiver<NfcCardResponse>,
    ) -> Self {
        let mut s = Self {
            local_storage: options.android_app.unwrap().internal_data_path(),
            settings: Err(AppConfigError::NotLoaded),
            nfc,
            test: String::new(),
            send,
            resp,
            waiting_nfc_response: false,
            nfc_response: None,
        };
        s.load_config();
        s.nfc.load_instance().expect("Failed to load instance");
        s.nfc
            .register_activity(NFC_KEY, NFC_KEY_OFFLINE)
            .expect("Failed to register activity with NxpNfcLib");
        s
    }
}

impl DemoApp {
    /// Get the minimum size for ui elements
    pub fn min_size(ui: &egui::Ui) -> egui::Vec2 {
        let m = ui.pixels_per_point();
        egui::vec2(10.0 * m, 10.0 * m)
    }

    /// Get the font size
    pub fn font_size() -> f32 {
        24.0
    }
}

impl eframe::App for DemoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(10));
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.label(
                egui::RichText::new(format!("Size 1: {}", ui.pixels_per_point()))
                    .size(Self::font_size()),
            );
            let min_size = Self::min_size(ui);
            egui::ScrollArea::vertical().show(ui, |ui| {
                if let Ok(resp) = self.resp.try_recv() {
                    self.waiting_nfc_response = false;
                    self.nfc_response.replace(resp);
                }
                let ver = self.nfc.get_version();
                ui.label(format!("TAPLINX VERSION: {:#?}", ver));
                android_nfc::handle_register(self, ui);
                if let Some(client) = android_nfc::get_client(self) {
                    if let Ok(Some(url)) = self.settings.as_ref().map(|a| a.server_url.clone()) {
                        if ui.button("Check login").clicked() {
                            let res = client.get(format!("https://{url}")).send();
                            log::error!("Check returned {res:?}");
                            if let Ok(r) = res {
                                if let Ok(data) = r.bytes() {
                                    let data = data.to_vec();
                                    if let Ok(s) = str::from_utf8(&data) {
                                        self.test = s.to_string();
                                    }
                                }
                            }
                        }
                    }
                    ui.label(&self.test);
                }
                if ui.button("Check card").clicked() {
                    self.nfc_response = None;
                    if self.send.send(NfcCardCommand::BasicInfo).is_ok() {
                        self.waiting_nfc_response = true;
                    }
                }
                if self.waiting_nfc_response {
                    ui.label("Waiting for nfc tag");
                }
                if let Some(resp) = &self.nfc_response {
                    match resp {
                        NfcCardResponse::BasicInfo { stuff } => {
                            ui.label(format!("Response is: {stuff}"));
                        }
                    }
                }
            });
        });
    }
}
