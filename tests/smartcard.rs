#![warn(missing_docs)]
#![allow(unused)]

//! This module contains the implementation of the smartcard tests.

#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/ca/ca_common.rs"]
mod ca;

#[path = "../src/main_config.rs"]
mod main_config;

pub use main_config::MainConfiguration;

#[path = "../src/utility.rs"]
mod utility;

async fn start_smartcard_sim() -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let a = tokio::task::spawn_blocking(|| {
        let mut p = std::process::Command::new("./run-piv-pcsc-sim.sh");
        let a = p.spawn().expect("Failed to start smartcard simulator");
        a
    })
    .await?;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    tokio::task::spawn_blocking(|| {
        let mut b = std::process::Command::new("opensc-tool");
        let mut p = b.args([
            "--card-driver",
            "default",
            "--send-apdu",
            "80b80000120ba000000308000010000100050000020F0F7f",
        ]);
        p.output()
            .expect("Failed to initialize smartcard simulator");
    })
    .await?;
    Ok(a)
}

#[tokio::test]
async fn test1() {
    let s = service::Service::new("Smartcard Testing".to_string());
    s.new_log(service::LogLevel::Trace);
    let mut simulator = start_smartcard_sim()
        .await
        .expect("Failed to start smartcard simulator");
    let card_keypair =
        card::KeyPair::generate_with_smartcard(b"123456".to_vec(), "test card", false)
            .await
            .expect("Failed to generate keypair for smartcard");
    let keypair = ca::Keypair::SmartCard(card_keypair);
    simulator.kill().expect("Failed to kill simulator");
}
