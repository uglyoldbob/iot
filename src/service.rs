use std::sync::mpsc;

use ceviche::controller::*;
use ceviche::{Service, ServiceEvent};

enum CustomServiceEvent {}

fn my_service_main(
    rx: mpsc::Receiver<ServiceEvent<CustomServiceEvent>>,
    _tx: mpsc::Sender<ServiceEvent<CustomServiceEvent>>,
    args: Vec<String>,
    standalone_mode: bool,
) -> u32 {
    loop {
        if let Ok(control_code) = rx.recv() {
            match control_code {
                ServiceEvent::Stop => break,
                _ => (),
            }
        }
    }
    0
}

Service!(SERVICE_NAME, my_service_main);

static SERVICE_NAME: &'static str = "rust-iot";
static DISPLAY_NAME: &'static str = "rust-iot Service";
static DESCRIPTION: &'static str = "This is the rust-iot service";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut controller = Controller::new(SERVICE_NAME, DISPLAY_NAME, DESCRIPTION);

    match args[1].as_str() {
        "create" => {
            controller.create().unwrap();
        }
        "delete" => {
            controller.delete().unwrap();
        }
        "start" => {
            controller.start().unwrap();
        }
        "stop" => {
            controller.stop().unwrap();
        }
        "standalone" => {
            let (tx, rx) = mpsc::channel();
            let (tx2, rx2) = mpsc::channel();

            ctrlc::set_handler(move || {
                let _ = tx.send(ServiceEvent::Stop);
            }).expect("Failed to register Ctrl-C handler");

            my_service_main(rx, tx2, vec![], true);
        }
        _ => {
            let _result = controller.register(service_main_wrapper);
        }
    }
}