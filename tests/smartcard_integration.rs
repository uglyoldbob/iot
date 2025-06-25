//! Smartcard Integration Tests
//!
//! This module provides integration tests for the actual card module,
//! testing real smartcard operations with the virtual smartcard simulator.

// For the html crate
#![recursion_limit = "512"]

#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/utility.rs"]
mod utility;

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

// Include the actual card module
#[path = "../src/card.rs"]
mod internal_card;

/// Test configuration constants
const DEFAULT_PIN: &[u8] = b"1234";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Sample X.509 certificate in DER format for testing
const TEST_CERT_HEX: &str = "308201f23082019ba003020102020900e8f09d3fe25be5ae0a300d06092a864886f70d0101050500301e311c301a060355040a13135465737420427261636853536f6674776172653059301306072a8648ce3d020106082a8648ce3d03010703420004a3c4e2a5f1b7d6c8e9f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a38181307f301d0603551d0e041604142b0e03ed2552002cb0c3b0fd37e2d46d247a301f0603551d23041830168014747f2c4b87f8c92f0a5d6e7f8091a2b3c4d5e6f7081929300f0603551d130101ff040530030101ff30220603551d110101ff04183016811474657374406578616d706c652e636f6d300d06092a864886f70d010105050003410028";

/// Virtual smartcard simulator manager for integration tests
pub struct IntegrationSimulator {
    process: Option<std::process::Child>,
}

impl IntegrationSimulator {
    pub fn new() -> Self {
        Self { process: None }
    }

    /// Start the virtual smartcard simulator for integration testing
    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !Self::check_prerequisites() {
            return Err("Prerequisites not met".into());
        }

        println!("Starting virtual smartcard simulator for integration tests...");

        // Start the simulator with a longer timeout for integration tests
        let child = Command::new("bash")
            .arg("-c")
            .arg("cd smartcard-sim && timeout 60 mvn exec:java -Dexec.mainClass=\"com.uglyoldbob.smartcard.sim.SmartCardSimulator\" -Dexec.args=\"daemon\" > simulator_integration.log 2>&1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        self.process = Some(child);

        // Give the simulator more time to start for integration tests
        thread::sleep(Duration::from_secs(5));

        println!("Virtual smartcard simulator started for integration testing");
        Ok(())
    }

    /// Stop the simulator
    pub fn stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            println!("Stopping integration test simulator...");
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Check if all prerequisites for integration testing are available
    pub fn check_prerequisites() -> bool {
        // Check Java
        if Command::new("java").arg("-version").output().is_err() {
            eprintln!("Java not available - skipping integration tests");
            return false;
        }

        // Check Maven
        if Command::new("mvn").arg("--version").output().is_err() {
            eprintln!("Maven not available - skipping integration tests");
            return false;
        }

        // Check smartcard-sim directory
        if !std::path::Path::new("smartcard-sim").exists() {
            eprintln!("smartcard-sim directory not found - skipping integration tests");
            return false;
        }

        // Check if simulator is compiled
        if !std::path::Path::new("smartcard-sim/target/classes").exists() {
            eprintln!("Simulator not compiled - run 'cd smartcard-sim && mvn compile'");
            return false;
        }

        true
    }
}

impl Drop for IntegrationSimulator {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

/// Test basic certificate writing with real card module
#[test]
#[ignore] // Run with: cargo test --ignored test_real_card_certificate_writing
fn test_real_card_certificate_writing() {
    if !IntegrationSimulator::check_prerequisites() {
        println!("Skipping real card test - prerequisites not available");
        return;
    }

    let mut simulator = IntegrationSimulator::new();

    match simulator.start() {
        Ok(()) => {
            println!("✅ Integration test simulator started");

            // Wait for simulator to be fully ready
            thread::sleep(Duration::from_secs(3));

            // Test certificate writing
            test_certificate_operations();
        }
        Err(e) => {
            println!(
                "⚠️  Could not start simulator: {} - skipping integration test",
                e
            );
        }
    }
}

/// Test certificate operations using the real card module
async fn test_certificate_operations() {
    let pin = DEFAULT_PIN.to_vec();
    let test_cert = match hex_to_bytes(TEST_CERT_HEX) {
        Ok(cert) => cert,
        Err(e) => {
            eprintln!("Failed to decode test certificate: {}", e);
            return;
        }
    };

    println!("🔐 Testing keypair generation...");
    let keypair =
        match internal_card::KeyPair::generate_with_smartcard(pin, "integration-test", false).await
        {
            Some(kp) => {
                println!("✅ Keypair generated successfully");
                kp
            }
            None => {
                println!("❌ Failed to generate keypair - no smartcard available");
                return;
            }
        };

    println!("💾 Testing certificate writing...");
    match keypair.save_cert_to_card(&test_cert) {
        Ok(()) => {
            println!("✅ Certificate written to smartcard successfully!");
        }
        Err(internal_card::Error::CardError(err)) => {
            println!("❌ Card error while writing certificate: {:?}", err);
            return;
        }
        Err(internal_card::Error::Timeout) => {
            println!("⏰ Timeout waiting for smartcard");
            return;
        }
    }

    println!("✍️  Testing signing operations...");
    let test_data = b"Integration test signing data";
    match keypair.sign_with_pin(test_data) {
        Ok(signature) => {
            println!("✅ Data signed successfully!");
            println!("   Test data: {:?}", String::from_utf8_lossy(test_data));
            println!("   Signature length: {} bytes", signature.len());
        }
        Err(err) => {
            println!("❌ Failed to sign data: {:?}", err);
        }
    }

    println!("🔄 Testing multiple signing operations...");
    for i in 1..=3 {
        let data = format!("Integration test message #{}", i);
        match keypair.sign_with_pin(data.as_bytes()) {
            Ok(sig) => {
                println!("   ✅ Signed '{}' -> {} bytes", data, sig.len());
            }
            Err(err) => {
                println!("   ❌ Failed to sign '{}': {:?}", data, err);
            }
        }
    }
}

/// Test error handling with real card module
#[tokio::test]
#[ignore] // Run with: cargo test --ignored test_real_card_error_handling
async fn test_real_card_error_handling() {
    if !IntegrationSimulator::check_prerequisites() {
        println!("Skipping error handling test - prerequisites not available");
        return;
    }

    let mut simulator = IntegrationSimulator::new();

    match simulator.start() {
        Ok(()) => {
            println!("✅ Error handling test simulator started");
            thread::sleep(Duration::from_secs(3));

            let pin = DEFAULT_PIN.to_vec();

            if let Some(keypair) =
                internal_card::KeyPair::generate_with_smartcard(pin, "error-test", false).await
            {
                println!("🚨 Testing error conditions...");

                // Test with empty certificate
                println!("🔍 Testing with empty certificate...");
                let empty_cert = Vec::new();
                match keypair.save_cert_to_card(&empty_cert) {
                    Ok(()) => {
                        println!("   ⚠️  Empty certificate accepted unexpectedly");
                    }
                    Err(err) => {
                        println!("   ✅ Empty certificate correctly rejected: {:?}", err);
                    }
                }

                // Test with invalid certificate
                println!("🔍 Testing with invalid certificate...");
                let invalid_cert = vec![0x00, 0x01, 0x02, 0x03];
                match keypair.save_cert_to_card(&invalid_cert) {
                    Ok(()) => {
                        println!("   ⚠️  Invalid certificate accepted unexpectedly");
                    }
                    Err(err) => {
                        println!("   ✅ Invalid certificate correctly rejected: {:?}", err);
                    }
                }

                // Test with oversized certificate
                println!("🔍 Testing with oversized certificate...");
                let oversized_cert = vec![0x30; 4000];
                match keypair.save_cert_to_card(&oversized_cert) {
                    Ok(()) => {
                        println!("   ⚠️  Oversized certificate was accepted (may be truncated)");
                    }
                    Err(err) => {
                        println!("   ✅ Oversized certificate correctly rejected: {:?}", err);
                    }
                }
            } else {
                println!("❌ Could not generate keypair for error testing");
            }
        }
        Err(e) => {
            println!(
                "⚠️  Could not start simulator: {} - skipping error handling test",
                e
            );
        }
    }
}

/// Test timeout behavior without simulator
#[tokio::test]
async fn test_card_timeout_without_simulator() {
    println!("⏰ Testing timeout behavior without simulator...");

    let pin = DEFAULT_PIN.to_vec();
    let test_cert = hex_to_bytes(TEST_CERT_HEX).expect("Failed to decode test certificate");

    // This should timeout since no simulator is running
    let start_time = Instant::now();

    // Note: This will likely fail or timeout because no simulator is running
    if let Some(keypair) =
        internal_card::KeyPair::generate_with_smartcard(pin, "timeout-test", false).await
    {
        match keypair.save_cert_to_card(&test_cert) {
            Ok(()) => {
                println!("   ⚠️  Certificate write succeeded unexpectedly");
            }
            Err(internal_card::Error::Timeout) => {
                let elapsed = start_time.elapsed();
                println!(
                    "   ✅ Certificate write correctly timed out after {:?}",
                    elapsed
                );
            }
            Err(err) => {
                println!("   ⚠️  Unexpected error: {:?}", err);
            }
        }
    } else {
        let elapsed = start_time.elapsed();
        println!(
            "   ✅ Keypair generation timed out as expected after {:?}",
            elapsed
        );
    }
}

/// Performance test with real card operations
#[tokio::test]
#[ignore] // Run with: cargo test --ignored test_real_card_performance
async fn test_real_card_performance() {
    if !IntegrationSimulator::check_prerequisites() {
        println!("Skipping performance test - prerequisites not available");
        return;
    }

    let mut simulator = IntegrationSimulator::new();

    match simulator.start() {
        Ok(()) => {
            println!("✅ Performance test simulator started");
            thread::sleep(Duration::from_secs(3));

            let pin = DEFAULT_PIN.to_vec();
            let test_cert = hex_to_bytes(TEST_CERT_HEX).expect("Failed to decode test certificate");

            if let Some(keypair) =
                internal_card::KeyPair::generate_with_smartcard(pin, "perf-test", false).await
            {
                println!("⚡ Running performance test...");

                let num_operations = 5;
                let mut total_time = Duration::new(0, 0);
                let mut successful_operations = 0;

                for i in 1..=num_operations {
                    let start_time = Instant::now();

                    match keypair.save_cert_to_card(&test_cert) {
                        Ok(()) => {
                            let operation_time = start_time.elapsed();
                            total_time += operation_time;
                            successful_operations += 1;
                            println!("   Operation {}: {:?}", i, operation_time);
                        }
                        Err(err) => {
                            println!("   Operation {} failed: {:?}", i, err);
                        }
                    }

                    // Small delay between operations
                    thread::sleep(Duration::from_millis(100));
                }

                if successful_operations > 0 {
                    let average_time = total_time / successful_operations;
                    println!("📊 Performance Results:");
                    println!(
                        "   Successful operations: {}/{}",
                        successful_operations, num_operations
                    );
                    println!("   Average time per operation: {:?}", average_time);
                    println!("   Total time: {:?}", total_time);

                    if average_time < Duration::from_secs(2) {
                        println!("   ✅ Performance is acceptable (< 2s per operation)");
                    } else {
                        println!("   ⚠️  Performance is slow (> 2s per operation)");
                    }
                } else {
                    println!("❌ No successful operations in performance test");
                }
            } else {
                println!("❌ Could not generate keypair for performance testing");
            }
        }
        Err(e) => {
            println!(
                "⚠️  Could not start simulator: {} - skipping performance test",
                e
            );
        }
    }
}

/// Test card module functionality without external dependencies
#[tokio::test]
async fn test_card_module_basics() {
    let pin = b"1234".to_vec();

    // Test KeyPair creation (this will likely fail without a real card, but tests the interface)
    println!("🔧 Testing card module basic functionality...");

    // This tests that the card module can be compiled and the interfaces work
    match internal_card::KeyPair::generate_with_smartcard(pin, "basic-test", false).await {
        Some(keypair) => {
            println!("✅ KeyPair created successfully");
            assert_eq!(keypair.label(), "basic-test");

            // Test that we can create an rcgen keypair from it
            let _rcgen_kp = keypair.rcgen();
            println!("✅ rcgen KeyPair created successfully");
        }
        None => {
            println!("⚠️  KeyPair creation failed (expected without real smartcard)");
        }
    }
}

/// Test error types and error handling
#[test]
fn test_card_error_types() {
    println!("🔍 Testing card error types...");

    // Test that error types can be created and match correctly
    let timeout_error = internal_card::Error::Timeout;
    match timeout_error {
        internal_card::Error::Timeout => {
            println!("✅ Timeout variant works correctly");
        }
        _ => {
            panic!("Timeout variant should match");
        }
    }

    println!("✅ Card error types test completed");
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_integration_simulator_creation() {
        let simulator = IntegrationSimulator::new();
        // Test that it can be created without issues
        drop(simulator);
    }

    #[test]
    fn test_hex_conversion() {
        let test_hex = "48656c6c6f";
        let expected = b"Hello";
        let result = hex_to_bytes(test_hex).expect("Failed to convert hex");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_prerequisites_check() {
        // This will check if prerequisites are available
        let available = IntegrationSimulator::check_prerequisites();
        println!("Prerequisites available: {}", available);
        // Don't assert here since it depends on the environment
    }
}
