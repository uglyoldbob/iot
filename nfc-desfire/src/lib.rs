use eframe::{egui, NativeOptions};

mod android_nfc;
use android_nfc::*;

use jni::objects::GlobalRef;
use jni::sys::_jobject;
use jni_min_helper::*;

/// The api key for nxpnfclib
const NFC_KEY: &str = include_str!("../nfc_key.txt");
/// The offline api key for nxpnfclib
const NFC_KEY_OFFLINE: &str = include_str!("../nfc_key_offline.txt");

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
        let t = i.get_card_type_from_tag(&mut env, tag).unwrap();
        t.process(&mut env, i).unwrap();
        log::error!("There is a nxpnfclib to use with {:?}", t);
    }
}

#[cfg(target_os = "android")]
use egui_winit::winit;
#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: winit::platform::android::activity::AndroidApp) {
    use eframe::Renderer;

    std::env::set_var("RUST_BACKTRACE", "full");
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Error),
    );

    let mut nfc = TapLinx::make_new(&app);

    let options = NativeOptions {
        android_app: Some(app),
        renderer: Renderer::Wgpu,
        ..Default::default()
    };
    DemoApp::run(options, nfc).unwrap();
}

#[derive(Debug)]
enum AppConfigError {
    NotLoaded,
    Corrupt,
    UnableToCreate,
}

#[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
struct AppConfig {
    /// The csr for registration
    pub csr_der: Option<Vec<u8>>,
    /// The der format of x509_cert::Certificate
    certificate: Option<Vec<u8>>,
}

impl AppConfig {
    pub fn get_cert(&self) -> Option<x509_cert::Certificate> {
        self.certificate
            .as_ref()
            .map(|c| {
                use x509_cert::der::Decode;
                x509_cert::Certificate::from_der(c).ok()
            })
            .flatten()
    }
}

pub struct DemoApp {
    local_storage: Option<std::path::PathBuf>,
    pub settings: Result<AppConfig, AppConfigError>,
    nfc: TapLinx,
}

impl DemoApp {
    pub fn run(options: NativeOptions, nfc: TapLinx) -> Result<(), eframe::Error> {
        eframe::run_native(
            "rust-iot-nfc",
            options.clone(),
            Box::new(|_cc| Ok(Box::<DemoApp>::new(DemoApp::new(options, nfc)))),
        )
    }

    fn save_config(&self) -> Result<(), std::io::Error> {
        if let Some(p) = &self.local_storage {
            if let Ok(settings) = &self.settings {
                let mut config = p.clone();
                config.push("config.bin");
                let encoded: Vec<u8> =
                    bincode::serde::encode_to_vec(settings, bincode::config::standard()).unwrap();
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
            config.push("config.bin");
            let settings = if let Ok(false) = std::fs::exists(&config) {
                let settings = AppConfig::default();
                let encoded: Vec<u8> =
                    bincode::serde::encode_to_vec(&settings, bincode::config::standard()).unwrap();
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
                    let s = bincode::serde::decode_from_slice(&a, bincode::config::standard());
                    if let Ok((s, _len)) = s {
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

    fn new(options: NativeOptions, nfc: TapLinx) -> Self {
        let mut s = Self {
            local_storage: options.android_app.unwrap().internal_data_path(),
            settings: Err(AppConfigError::NotLoaded),
            nfc,
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
                ui.label("I am groot");
                let ver = self.nfc.get_version();
                ui.label(format!("TAPLINX VERSION: {:#?}", ver));
                android_nfc::handle_register(self, ui);
            });
        });
    }
}
