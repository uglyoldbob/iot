//! Basic smartcard certificate tests that work with cargo test
//!
//! This module provides fundamental tests for smartcard certificate operations
//! using mock implementations, designed to work seamlessly with the standard
//! Rust testing framework without external dependencies.

use serial_test::serial;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Test configuration
const DEFAULT_PIN: &[u8] = b"1234";

/// Sample DER-encoded X.509 certificate for testing (truncated for brevity)
const TEST_CERT_HEX: &str = "308201f23082019ba003020102020900e8f09d3fe25be5ae0a300d06092a864886f70d0101050500301e311c301a060355040a13135465737420427261636853536f6674776172653059301306072a8648ce3d020106082a8648ce3d03010703420004a3c4e2a5f1b7d6c8e9f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a38181307f301d0603551d0e041604142b0e03ed2552002cb0c3b0fd37e2d46d247a301f0603551d23041830168014747f2c4b87f8c92f0a5d6e7f8091a2b3c4d5e6f7081929300f0603551d130101ff040530030101ff30220603551d110101ff04183016811474657374406578616d706c652e636f6d300d06092a864886f70d010105050003410028";

/// Mock smartcard implementation for testing
pub mod mock_smartcard {
    use super::*;

    lazy_static::lazy_static! {
        static ref MOCK_CARDS: Arc<Mutex<HashMap<String, MockCard>>> = Arc::new(Mutex::new(HashMap::new()));
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum Error {
        CardError(String),
        Timeout,
        PinError,
        CertificateNotFound,
        InvalidCertificate,
    }

    #[derive(Clone, Debug)]
    pub struct MockCard {
        pub label: String,
        pub pin: Vec<u8>,
        pub certificate: Option<Vec<u8>>,
        pub keypair_generated: bool,
        pub inserted: bool,
    }

    #[derive(Clone, Debug)]
    pub struct KeyPair {
        pub label: String,
        pub pin: Vec<u8>,
    }

    impl KeyPair {
        /// Generate a new keypair with mock smartcard
        pub fn generate_with_smartcard(pin: Vec<u8>, label: &str) -> Option<Self> {
            let mut cards = MOCK_CARDS.lock().unwrap();
            let card = MockCard {
                label: label.to_string(),
                pin: pin.clone(),
                certificate: None,
                keypair_generated: true,
                inserted: true,
            };
            cards.insert(label.to_string(), card);

            Some(Self {
                label: label.to_string(),
                pin,
            })
        }

        /// Get the label for this keypair
        pub fn label(&self) -> String {
            self.label.clone()
        }

        /// Save certificate to the smartcard
        pub fn save_cert_to_card(&self, cert: &[u8]) -> Result<(), Error> {
            if cert.is_empty() {
                return Err(Error::InvalidCertificate);
            }

            if cert.len() > 2048 {
                return Err(Error::CardError("Certificate too large".to_string()));
            }

            let mut cards = MOCK_CARDS.lock().unwrap();
            if let Some(card) = cards.get_mut(&self.label) {
                if !card.inserted {
                    return Err(Error::CardError("Card not inserted".to_string()));
                }
                if card.pin != self.pin {
                    return Err(Error::PinError);
                }
                card.certificate = Some(cert.to_vec());
                Ok(())
            } else {
                Err(Error::CardError("Card not found".to_string()))
            }
        }

        /// Retrieve certificate from the smartcard
        pub fn get_cert_from_card(&self) -> Result<Option<Vec<u8>>, Error> {
            let cards = MOCK_CARDS.lock().unwrap();
            if let Some(card) = cards.get(&self.label) {
                if !card.inserted {
                    return Err(Error::CardError("Card not inserted".to_string()));
                }
                if card.pin != self.pin {
                    return Err(Error::PinError);
                }
                Ok(card.certificate.clone())
            } else {
                Err(Error::CardError("Card not found".to_string()))
            }
        }

        /// Sign data with the smartcard private key
        pub fn sign_with_pin(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
            if data.is_empty() {
                return Err(Error::CardError("No data to sign".to_string()));
            }

            let cards = MOCK_CARDS.lock().unwrap();
            if let Some(card) = cards.get(&self.label) {
                if !card.inserted {
                    return Err(Error::CardError("Card not inserted".to_string()));
                }
                if card.pin != self.pin {
                    return Err(Error::PinError);
                }
                if !card.keypair_generated {
                    return Err(Error::CardError("No keypair generated".to_string()));
                }

                // Generate a deterministic mock signature based on input data
                let mut signature = vec![0u8; 256]; // RSA-2048 signature size
                for (i, byte) in signature.iter_mut().enumerate() {
                    *byte = (i as u8)
                        .wrapping_add(data[i % data.len()])
                        .wrapping_add(self.label.len() as u8);
                }
                Ok(signature)
            } else {
                Err(Error::CardError("Card not found".to_string()))
            }
        }

        /// Remove the card from the reader
        pub fn remove_card(&self) -> Result<(), Error> {
            let mut cards = MOCK_CARDS.lock().unwrap();
            if let Some(card) = cards.get_mut(&self.label) {
                card.inserted = false;
                Ok(())
            } else {
                Err(Error::CardError("Card not found".to_string()))
            }
        }

        /// Insert the card into the reader
        pub fn insert_card(&self) -> Result<(), Error> {
            let mut cards = MOCK_CARDS.lock().unwrap();
            if let Some(card) = cards.get_mut(&self.label) {
                card.inserted = true;
                Ok(())
            } else {
                Err(Error::CardError("Card not found".to_string()))
            }
        }
    }

    /// Clear all mock cards for testing isolation
    pub fn clear_mock_cards() {
        let mut cards = MOCK_CARDS.lock().unwrap();
        cards.clear();
    }

    /// Get the number of mock cards for testing
    pub fn get_mock_card_count() -> usize {
        let cards = MOCK_CARDS.lock().unwrap();
        cards.len()
    }
}

/// Helper function to decode hex string to bytes
fn hex_decode(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

/// Test basic certificate storage and retrieval
#[test]
#[serial]
fn test_basic_certificate_operations() {
    mock_smartcard::clear_mock_cards();

    let pin = DEFAULT_PIN.to_vec();
    let test_cert = hex_decode(TEST_CERT_HEX).expect("Failed to decode test certificate");

    // Generate keypair
    let keypair = mock_smartcard::KeyPair::generate_with_smartcard(pin, "test-basic-cert")
        .expect("Failed to generate keypair");

    assert_eq!(keypair.label(), "test-basic-cert");

    // Store certificate
    keypair
        .save_cert_to_card(&test_cert)
        .expect("Failed to store certificate");

    // Retrieve certificate
    let retrieved_cert = keypair
        .get_cert_from_card()
        .expect("Failed to retrieve certificate")
        .expect("No certificate found");

    assert_eq!(
        test_cert, retrieved_cert,
        "Retrieved certificate should match stored certificate"
    );
}

/// Test certificate operations with wrong PIN
#[test]
#[serial]
fn test_certificate_operations_wrong_pin() {
    mock_smartcard::clear_mock_cards();

    let correct_pin = DEFAULT_PIN.to_vec();
    let wrong_pin = b"9999".to_vec();
    let test_cert = hex_decode(TEST_CERT_HEX).expect("Failed to decode test certificate");

    // Generate keypair with correct PIN
    let _keypair_correct =
        mock_smartcard::KeyPair::generate_with_smartcard(correct_pin, "test-pin-cert")
            .expect("Failed to generate keypair");

    // Try to use wrong PIN
    let keypair_wrong = mock_smartcard::KeyPair {
        label: "test-pin-cert".to_string(),
        pin: wrong_pin,
    };

    // Should fail with wrong PIN
    match keypair_wrong.save_cert_to_card(&test_cert) {
        Err(mock_smartcard::Error::PinError) => {
            // Expected behavior
        }
        Ok(_) => panic!("Certificate storage should fail with wrong PIN"),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

/// Test certificate operations error handling
#[test]
#[serial]
fn test_certificate_error_handling() {
    mock_smartcard::clear_mock_cards();

    let pin = DEFAULT_PIN.to_vec();
    let keypair = mock_smartcard::KeyPair::generate_with_smartcard(pin, "test-error-cert")
        .expect("Failed to generate keypair");

    // Test empty certificate
    match keypair.save_cert_to_card(&[]) {
        Err(mock_smartcard::Error::InvalidCertificate) => {
            // Expected behavior
        }
        Ok(_) => panic!("Empty certificate should be rejected"),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }

    // Test oversized certificate
    let oversized_cert = vec![0u8; 3000];
    match keypair.save_cert_to_card(&oversized_cert) {
        Err(mock_smartcard::Error::CardError(msg)) if msg.contains("too large") => {
            // Expected behavior
        }
        Ok(_) => panic!("Oversized certificate should be rejected"),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

/// Test signing operations
#[test]
#[serial]
fn test_signing_operations() {
    mock_smartcard::clear_mock_cards();

    let pin = DEFAULT_PIN.to_vec();
    let keypair = mock_smartcard::KeyPair::generate_with_smartcard(pin, "test-signing")
        .expect("Failed to generate keypair");

    let test_data = b"Hello, smartcard signing test!";
    let signature = keypair
        .sign_with_pin(test_data)
        .expect("Failed to sign data");

    assert_eq!(
        signature.len(),
        256,
        "Signature should be 256 bytes (RSA-2048)"
    );

    // Test that the same data produces the same signature
    let signature2 = keypair
        .sign_with_pin(test_data)
        .expect("Failed to sign data again");

    assert_eq!(
        signature, signature2,
        "Same data should produce same signature"
    );

    // Test that different data produces different signature
    let different_data = b"Different test data";
    let signature3 = keypair
        .sign_with_pin(different_data)
        .expect("Failed to sign different data");

    assert_ne!(
        signature, signature3,
        "Different data should produce different signature"
    );
}

/// Test multiple certificate operations
#[test]
#[serial]
fn test_multiple_certificate_operations() {
    mock_smartcard::clear_mock_cards();

    let pin = DEFAULT_PIN.to_vec();
    let test_cert = hex_decode(TEST_CERT_HEX).expect("Failed to decode test certificate");

    // Create first keypair
    let keypair1 = mock_smartcard::KeyPair::generate_with_smartcard(pin.clone(), "test-multi-1")
        .expect("Failed to generate first keypair");

    // Create second keypair
    let keypair2 = mock_smartcard::KeyPair::generate_with_smartcard(pin, "test-multi-2")
        .expect("Failed to generate second keypair");

    // Store certificates on both cards
    keypair1
        .save_cert_to_card(&test_cert)
        .expect("Failed to store certificate on first card");

    let mut test_cert2 = test_cert.clone();
    let last_idx = test_cert2.len() - 1;
    let last_byte = test_cert2[last_idx];
    test_cert2[last_idx] = last_byte.wrapping_add(1);

    keypair2
        .save_cert_to_card(&test_cert2)
        .expect("Failed to store certificate on second card");

    // Verify both certificates
    let retrieved1 = keypair1
        .get_cert_from_card()
        .expect("Failed to retrieve from first card")
        .expect("No certificate on first card");

    let retrieved2 = keypair2
        .get_cert_from_card()
        .expect("Failed to retrieve from second card")
        .expect("No certificate on second card");

    assert_eq!(test_cert, retrieved1, "First certificate should match");
    assert_eq!(test_cert2, retrieved2, "Second certificate should match");
    assert_ne!(retrieved1, retrieved2, "Certificates should be different");
}

/// Test card insertion and removal
#[test]
#[serial]
fn test_card_insertion_removal() {
    mock_smartcard::clear_mock_cards();

    let pin = DEFAULT_PIN.to_vec();
    let test_cert = hex_decode(TEST_CERT_HEX).expect("Failed to decode test certificate");
    let keypair = mock_smartcard::KeyPair::generate_with_smartcard(pin, "test-insertion")
        .expect("Failed to generate keypair");

    // Store certificate while card is inserted
    keypair
        .save_cert_to_card(&test_cert)
        .expect("Failed to store certificate");

    // Remove card
    keypair.remove_card().expect("Failed to remove card");

    // Try to access certificate with card removed
    match keypair.get_cert_from_card() {
        Err(mock_smartcard::Error::CardError(msg)) if msg.contains("not inserted") => {
            // Expected behavior
        }
        Ok(_) => panic!("Should not be able to access certificate with card removed"),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }

    // Re-insert card
    keypair.insert_card().expect("Failed to insert card");

    // Now certificate should be accessible again
    let retrieved_cert = keypair
        .get_cert_from_card()
        .expect("Failed to retrieve certificate after re-insertion")
        .expect("Certificate should still be there");

    assert_eq!(
        test_cert, retrieved_cert,
        "Certificate should persist across removal/insertion"
    );
}

/// Performance test for certificate operations
#[test]
#[serial]
fn test_certificate_performance() {
    mock_smartcard::clear_mock_cards();

    let pin = DEFAULT_PIN.to_vec();
    let test_cert = hex_decode(TEST_CERT_HEX).expect("Failed to decode test certificate");
    let keypair = mock_smartcard::KeyPair::generate_with_smartcard(pin, "test-performance")
        .expect("Failed to generate keypair");

    let num_operations = 100;
    let start_time = Instant::now();

    for i in 0..num_operations {
        // Modify the certificate slightly for each operation
        let mut cert = test_cert.clone();
        let last_idx = cert.len() - 1;
        let last_byte = cert[last_idx];
        cert[last_idx] = (i as u8).wrapping_add(last_byte);

        keypair
            .save_cert_to_card(&cert)
            .expect("Failed to store certificate");

        let retrieved = keypair
            .get_cert_from_card()
            .expect("Failed to retrieve certificate")
            .expect("No certificate found");

        assert_eq!(cert, retrieved, "Certificate mismatch at iteration {}", i);
    }

    let elapsed = start_time.elapsed();
    let avg_time = elapsed / num_operations;

    println!("Performance test results:");
    println!("  Operations: {}", num_operations);
    println!("  Total time: {:?}", elapsed);
    println!("  Average time per operation: {:?}", avg_time);

    // Performance assertion (should be fast for mock operations)
    assert!(
        avg_time < Duration::from_millis(10),
        "Average operation time should be less than 10ms, got {:?}",
        avg_time
    );
}

/// Test certificate lifecycle
#[test]
#[serial]
fn test_certificate_lifecycle() {
    mock_smartcard::clear_mock_cards();

    let pin = DEFAULT_PIN.to_vec();
    let test_cert = hex_decode(TEST_CERT_HEX).expect("Failed to decode test certificate");
    let keypair = mock_smartcard::KeyPair::generate_with_smartcard(pin, "test-lifecycle")
        .expect("Failed to generate keypair");

    // 1. Initially no certificate
    let initial_cert = keypair
        .get_cert_from_card()
        .expect("Failed to check initial certificate");
    assert!(
        initial_cert.is_none(),
        "Should have no certificate initially"
    );

    // 2. Store certificate
    keypair
        .save_cert_to_card(&test_cert)
        .expect("Failed to store certificate");

    // 3. Verify certificate is there
    let stored_cert = keypair
        .get_cert_from_card()
        .expect("Failed to retrieve stored certificate")
        .expect("Certificate should be present");
    assert_eq!(test_cert, stored_cert, "Stored certificate should match");

    // 4. Test signing with certificate
    let test_data = b"Lifecycle test data";
    let signature = keypair
        .sign_with_pin(test_data)
        .expect("Failed to sign with certificate");
    assert_eq!(signature.len(), 256, "Signature should be correct length");

    // 5. Overwrite with new certificate
    let mut new_cert = test_cert.clone();
    let last_idx = new_cert.len() - 1;
    let last_byte = new_cert[last_idx];
    new_cert[last_idx] = last_byte.wrapping_add(1);

    keypair
        .save_cert_to_card(&new_cert)
        .expect("Failed to overwrite certificate");

    // 6. Verify new certificate
    let final_cert = keypair
        .get_cert_from_card()
        .expect("Failed to retrieve final certificate")
        .expect("Final certificate should be present");
    assert_eq!(
        new_cert, final_cert,
        "Final certificate should match new certificate"
    );
    assert_ne!(
        test_cert, final_cert,
        "Final certificate should be different from original"
    );
}

/// Test concurrent operations on different cards
#[test]
#[serial]
fn test_concurrent_operations() {
    mock_smartcard::clear_mock_cards();

    let pin = DEFAULT_PIN.to_vec();
    let test_cert = hex_decode(TEST_CERT_HEX).expect("Failed to decode test certificate");

    // Create multiple keypairs
    let keypairs: Vec<_> = (0..5)
        .map(|i| {
            mock_smartcard::KeyPair::generate_with_smartcard(
                pin.clone(),
                &format!("test-concurrent-{}", i),
            )
            .expect("Failed to generate keypair")
        })
        .collect();

    // Store certificates on all cards concurrently (simulated)
    for (i, keypair) in keypairs.iter().enumerate() {
        let mut cert = test_cert.clone();
        let last_idx = cert.len() - 1;
        let last_byte = cert[last_idx];
        cert[last_idx] = last_byte.wrapping_add(i as u8);

        keypair
            .save_cert_to_card(&cert)
            .expect("Failed to store certificate");
    }

    // Verify all certificates
    for (i, keypair) in keypairs.iter().enumerate() {
        let retrieved = keypair
            .get_cert_from_card()
            .expect("Failed to retrieve certificate")
            .expect("Certificate should be present");

        let expected_last_byte = test_cert[test_cert.len() - 1].wrapping_add(i as u8);
        assert_eq!(
            retrieved[retrieved.len() - 1],
            expected_last_byte,
            "Certificate {} should have correct modification",
            i
        );
    }

    // Test that we have the expected number of cards
    assert_eq!(
        mock_smartcard::get_mock_card_count(),
        5,
        "Should have 5 mock cards"
    );
}

/// Test error scenarios with empty data
#[test]
#[serial]
fn test_empty_data_scenarios() {
    mock_smartcard::clear_mock_cards();

    let pin = DEFAULT_PIN.to_vec();
    let keypair = mock_smartcard::KeyPair::generate_with_smartcard(pin, "test-empty")
        .expect("Failed to generate keypair");

    // Test signing empty data
    match keypair.sign_with_pin(&[]) {
        Err(mock_smartcard::Error::CardError(msg)) if msg.contains("No data to sign") => {
            // Expected behavior
        }
        Ok(_) => panic!("Should not be able to sign empty data"),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }

    // Test storing empty certificate
    match keypair.save_cert_to_card(&[]) {
        Err(mock_smartcard::Error::InvalidCertificate) => {
            // Expected behavior
        }
        Ok(_) => panic!("Should not be able to store empty certificate"),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    #[serial]
    fn test_hex_decode_functionality() {
        let test_hex = "48656c6c6f";
        let expected = b"Hello";
        let decoded = hex_decode(test_hex).expect("Failed to decode hex");
        assert_eq!(decoded, expected);
    }

    #[test]
    #[serial]
    fn test_mock_card_clearing() {
        mock_smartcard::clear_mock_cards();
        assert_eq!(mock_smartcard::get_mock_card_count(), 0);

        let pin = DEFAULT_PIN.to_vec();
        let _keypair = mock_smartcard::KeyPair::generate_with_smartcard(pin.clone(), "test-clear")
            .expect("Failed to generate keypair");

        assert_eq!(mock_smartcard::get_mock_card_count(), 1);

        mock_smartcard::clear_mock_cards();
        assert_eq!(mock_smartcard::get_mock_card_count(), 0);

        // After clearing, the same label should work again
        let _keypair2 = mock_smartcard::KeyPair::generate_with_smartcard(pin, "test-clear")
            .expect("Failed to generate keypair after clear");

        assert_eq!(mock_smartcard::get_mock_card_count(), 1);
    }

    #[test]
    #[serial]
    fn test_certificate_data_integrity() {
        let test_cert = hex_decode(TEST_CERT_HEX).expect("Failed to decode test certificate");

        // Verify the test certificate has expected properties
        assert!(
            !test_cert.is_empty(),
            "Test certificate should not be empty"
        );
        assert!(
            test_cert.len() > 100,
            "Test certificate should be reasonably sized"
        );

        // Basic DER format check (should start with 0x30 for SEQUENCE)
        assert_eq!(
            test_cert[0], 0x30,
            "DER certificate should start with SEQUENCE tag"
        );
    }
}
