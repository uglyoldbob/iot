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

#[path = "../src/card.rs"]
mod card;

#[tokio::test]
async fn test1() {
    panic!();
}
