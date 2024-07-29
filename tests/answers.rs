#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/ca/ca_common.rs"]
mod ca;

#[path = "../src/main_config.rs"]
mod main_config;

#[path = "../src/utility.rs"]
mod utility;

#[path = "../src/card.rs"]
mod card;

use ca::SmartCardPin2;
pub use main_config::MainConfiguration;
use serde::{Deserialize, Serialize};

#[test]
fn test_smardcard_answers() {
    let mut scpin = SmartCardPin2::default();
    scpin = "123456".into();

    let contents = bincode::serialize(&scpin).unwrap();
    let scpin2: SmartCardPin2 = bincode::deserialize(&contents).unwrap();
    assert_eq!(scpin.to_string(), scpin2.to_string());
}
