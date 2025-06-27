#![warn(missing_docs)]
#![allow(unused)]

//! Smart Card PIN serialization and deserialization testing
//!
//! This test module validates the proper serialization and deserialization
//! of smart card PIN data structures using bincode. It ensures that PIN
//! data can be safely stored and retrieved while maintaining consistency
//! across serialization boundaries.

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

/// Test smart card PIN serialization and deserialization consistency
///
/// This test validates that a SmartCardPin2 object can be:
/// 1. Converted from a string PIN ("123456")
/// 2. Serialized using bincode
/// 3. Deserialized back to the original structure
/// 4. Maintain string representation consistency after round-trip
///
/// This ensures PIN data integrity during storage and retrieval operations.
#[test]
fn test_smardcard_answers() {
    // Create a default SmartCardPin2 and set it to "123456"
    let mut scpin = SmartCardPin2::default();
    scpin = "123456".into();

    // Serialize the PIN using bincode
    let contents = bincode::serialize(&scpin).unwrap();

    // Deserialize back to SmartCardPin2
    let scpin2: SmartCardPin2 = bincode::deserialize(&contents).unwrap();

    // Verify that the string representation remains consistent after serialization round-trip
    assert_eq!(scpin.to_string(), scpin2.to_string());
}
