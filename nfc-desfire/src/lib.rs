use eframe::{egui, NativeOptions};

#[cfg(target_os = "android")]
use egui_winit::winit;
#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: winit::platform::android::activity::AndroidApp) {
    use eframe::Renderer;

    std::env::set_var("RUST_BACKTRACE", "full");
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info),
    );

    let options = NativeOptions {
        android_app: Some(app),
        renderer: Renderer::Wgpu,
        ..Default::default()
    };
    DemoApp::run(options).unwrap();
}

#[derive(Debug)]
enum AppConfigError {
    NotLoaded,
    Corrupt,
    UnableToCreate,
}

#[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
struct AppConfig {
    asdf: bool,
}

pub struct DemoApp {
    local_storage: Option<std::path::PathBuf>,
    settings: Result<AppConfig, AppConfigError>,
}

impl DemoApp {
    pub fn run(options: NativeOptions) -> Result<(), eframe::Error> {
        eframe::run_native(
            "rust-iot-nfc",
            options.clone(),
            Box::new(|_cc| Ok(Box::<DemoApp>::new(DemoApp::new(options)))),
        )
    }

    fn load_config(&mut self) {
        if let Some(p) = &self.local_storage {
            let mut config = p.clone();
            config.push("config.bin");
            let settings = if let Ok(false) = std::fs::exists(&config) {
                let settings = AppConfig::default();
                let encoded: Vec<u8> =
                    bincode::serde::encode_to_vec(&settings, bincode::config::standard()).unwrap();
                let f = std::fs::File::create(&config);
                if let Ok(mut f) = f {
                    use std::io::Write;
                    match f.write(&encoded) {
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
        }
    }

    fn new(options: NativeOptions) -> Self {
        let mut s = Self {
            local_storage: options.android_app.unwrap().internal_data_path(),
            settings: Err(AppConfigError::NotLoaded),
        };
        s.load_config();
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
            });
        });
    }
}
