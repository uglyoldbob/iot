use pcsc::{Context, Protocols, Scope, ShareMode};
use std::thread;
use std::time::Duration;

/// Minimal PIV integration test using standard PIV APDUs.
/// This test assumes a PC/SC-compatible PIV simulator (e.g., PivApplet via vsmartcard) is running.
#[test]
fn piv_apdu_integration() {
    // Give the simulator a moment to start (if running as part of a harness)
    thread::sleep(Duration::from_secs(2));

    let ctx = Context::establish(Scope::User).expect("Failed to establish PC/SC context");
    let mut readers_buf = [0; 2048];
    let readers = ctx
        .list_readers(&mut readers_buf)
        .expect("Failed to list readers");
    let reader = readers.iter().next().expect("No PC/SC readers found");

    let card = ctx
        .connect(reader, ShareMode::Shared, Protocols::ANY)
        .expect("Failed to connect to card");

    // 1. SELECT PIV applet
    let select_piv = [
        0x00, 0xA4, 0x04, 0x00, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01,
        0x00, 0x00,
    ];
    let mut rapdu_buf = [0; 258];
    let rapdu = card
        .transmit(&select_piv, &mut rapdu_buf)
        .expect("APDU transmit failed");
    assert_eq!(
        &rapdu[rapdu.len() - 2..],
        &[0x90, 0x00],
        "PIV SELECT failed"
    );

    // 2. VERIFY PIN (default 123456)
    let verify_pin = [
        0x00, 0x20, 0x00, 0x80, 0x06, b'1', b'2', b'3', b'4', b'5', b'6',
    ];
    let rapdu = card
        .transmit(&verify_pin, &mut rapdu_buf)
        .expect("APDU transmit failed");
    assert_eq!(
        &rapdu[rapdu.len() - 2..],
        &[0x90, 0x00],
        "PIV VERIFY failed"
    );

    // 3. GET DATA: Authentication certificate (0x5FC105)
    let get_cert = [
        0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x00,
    ];
    let rapdu = card
        .transmit(&get_cert, &mut rapdu_buf)
        .expect("APDU transmit failed");
    println!("PIV cert GET DATA response: {:02X?}", &rapdu);

    // Optionally, add more PIV APDU tests here (signing, etc)
}
