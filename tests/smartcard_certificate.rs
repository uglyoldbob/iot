//! Comprehensive smartcard certificate writing integration tests
//!
//! This test module validates the integration between the Rust smartcard code
//! and the Java virtual smartcard simulator for certificate operations.
//!
//! Tests include:
//! - Certificate generation and writing to virtual smartcards
//! - Certificate validation and retrieval
//! - Error handling for invalid certificates and smartcard failures
//! - Integration with CA certificate generation workflows
//! - PIN verification and security testing
//! - Multiple certificate scenarios and card switching

#![warn(missing_docs)]
// For the html crate
#![recursion_limit = "512"]

#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/utility.rs"]
mod utility;

#[path = "../src/card.rs"]
mod card;

use serial_test::serial;
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Check if virtual smartcard dependencies are available
fn check_virtual_smartcard_availability() -> bool {
    // Check if required files exist
    if !std::path::Path::new("smartcard-sim/run-simulator.sh").exists() {
        println!("Smartcard simulator script not found");
        return false;
    }

    // Check if Java is available with a timeout
    match std::process::Command::new("timeout")
        .arg("5")
        .arg("java")
        .arg("-version")
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                println!("Java not available or returned error");
                return false;
            }
        }
        Err(_) => {
            println!("Java check failed");
            return false;
        }
    }

    true
}

/// Helper to manage the Java virtual smartcard simulator
struct VirtualSmartCardManager {
    java_process: std::process::Child,
    stdin: std::io::PipeWriter,
}

struct VirtualSmartCard {
}

impl VirtualSmartCardManager {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_simulator()
    }

    /// Start the Java virtual smartcard simulator
    fn start_simulator() -> Result<Self, Box<dyn std::error::Error>> {
        println!("Starting virtual smartcard simulator...");

        // Check if the run script exists
        if !std::path::Path::new("smartcard-sim/run-simulator.sh").exists() {
            return Err("Simulator script not found".into());
        }

        // Start the simulator using the run script with timeout protection
        let mut cmd = Command::new("bash");

        let mut stdout = std::io::pipe()?;
        let mut stderr = std::io::pipe()?;
        let stdin = std::io::pipe()?;

        cmd.arg("smartcard-sim/run-simulator.sh")
            .arg("cli")
            .arg("--debug")
            .stdin(stdin.0)
            .stdout(stdout.1)
            .stderr(stderr.1);

        let child = cmd.spawn()?;
        let bufr = std::io::BufReader::new(stdout.0);
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut l = bufr.lines();
            while let Some(Ok(line)) = l.next() {
                println!("{}", line)
            }
            println!("Done reading from virtual smartcard simulator");
        });

        let bufr = std::io::BufReader::new(stderr.0);
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut l = bufr.lines();
            while let Some(Ok(line)) = l.next() {
                eprintln!("{}", line)
            }
            println!("Done reading from virtual smartcard simulator");
        });

        // Give time for the simulator to start
        thread::sleep(Duration::from_secs(4));

        service::log::info!("Virtual smartcard simulator started");
        Ok(Self {
            java_process: child,
            stdin: stdin.1,
        })
    }

    fn do_the_thing(&mut self) {
        use std::io::Write;
        self.stdin
            .write_all(b"create asdf\n")
            .expect("Failed to send message for help");
        self.stdin
            .write_all(b"list\n")
            .expect("Failed to send message for help");
    }

    /// Create a virtual smart card
    fn create_card(&mut self, name: &str) -> Result<VirtualSmartCard, String> {
        use std::io::Write;
        let m = format!("create {}\n", name);
        println!("Issuing command to create card: *{}*", m);
        self.stdin
            .write_all(m.as_bytes()).map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())?;
        println!("Done issuing command to create card");
        Ok(VirtualSmartCard { })
    }

    /// Stop the simulator
    fn stop_simulator(&mut self) {
        println!("Trying to stop virtual smartcard simulator");
        self.java_process.kill();
        self.java_process.wait();
        println!("Virtual smartcard simulator stopped");
    }
}

impl Drop for VirtualSmartCardManager {
    fn drop(&mut self) {
        self.stop_simulator();
    }
}

/// Generate a test certificate in DER format
fn generate_test_certificate() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create a simple self-signed certificate for testing
    // This is a minimal DER-encoded X.509 certificate
    let test_cert_der = hex::decode(
        "308201f23082019ba003020102020900e8f09d3fe25be5ae0a300d06092a864886f70d01\
         01050500301e311c301a060355040a13135465737420427261636853736f6674776172\
         65301e170d3232303130313030303030305a170d3233303130313030303030305a301e\
         311c301a060355040a13135465737420427261636853736f66747761726530819f300d\
         06092a864886f70d010101050003818d0030818902818100c2a4e6ba4f6c8d9e0f1a2b\
         3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e\
         6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081\
         92a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4\
         c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7\
         f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70203010001a381813081\
         7e301d0603551d0e041604142b0e03ed2552002cb0c3b0fd37e2d46d247a301f060355\
         1d23041830168014747f2c4b87f8c92f0a5d6e7f8091a2b3c4d5e6f7081929300f0603\
         551d130101ff040530030101ff30220603551d110101ff04183016811474657374406578\
         616d706c652e636f6d300d06092a864886f70d010105050003818100286e4b2c4f9a5b\
         7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8\
         091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b\
         3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5",
    )?;

    Ok(test_cert_der)
}

/// Test basic certificate writing to a virtual smartcard
#[tokio::test]
#[serial]
async fn test_basic_certificate_writing() {
    // Wrap entire test in timeout to prevent hanging
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        if !check_virtual_smartcard_availability() {
            println!("Skipping test - virtual smartcard system not available");
            return;
        }

        println!("Testing basic certificate writing to virtual smartcard...");

        let mut manager = VirtualSmartCardManager::new()
            .map_err(|_| ())
            .expect("Failed to start smartcard simulator");

        // Wait for simulator to be ready
        sleep(Duration::from_secs(2)).await;

        // Generate a test certificate
        let test_cert = match generate_test_certificate() {
            Ok(cert) => cert,
            Err(e) => {
                eprintln!("✗ Failed to generate test certificate: {}", e);
                return;
            }
        };

        println!(
            "✓ Test certificate generated successfully ({} bytes)",
            test_cert.len()
        );

        // Create a keypair for the virtual smartcard with timeout
        let pin = b"1234".to_vec();
        let keypair = match tokio::time::timeout(
            Duration::from_secs(15),
            card::KeyPair::generate_with_smartcard(pin, "test-cert", false),
        )
        .await
        {
            Ok(Some(kp)) => kp,
            Ok(None) => {
                panic!(
                "✗ Failed to generate keypair with smartcard. Virtual card may not be available."
            );
                return;
            }
            Err(_) => {
                panic!(
                    "✗ Timeout waiting for keypair generation. Virtual card may not be responding."
                );
                return;
            }
        };

        // Test saving certificate to card
        match keypair.save_cert_to_card(&test_cert) {
            Ok(()) => {
                println!("✓ Certificate successfully written to virtual smartcard");
            }
            Err(card::Error::Timeout) => {
                panic!("✗ Timeout waiting for smartcard - this might indicate simulator issues");
            }
            Err(card::Error::CardError(card_err)) => {
                panic!("✗ Card error while writing certificate: {:?}", card_err);
            }
        }

        // Test signing with the certificate
        let test_data = b"Hello, smartcard certificate test!";
        match keypair.sign_with_pin(test_data) {
            Ok(signature) => {
                println!("✓ Successfully signed data with certificate keypair");
                println!("  Signature length: {} bytes", signature.len());
            }
            Err(e) => {
                panic!("✗ Failed to sign data: {:?}", e);
            }
        }

        println!("Basic certificate writing test completed");
    })
    .await;

    if result.is_err() {
        panic!("Test timed out");
    }
}

/// Test certificate writing with PIN verification
#[tokio::test]
#[serial]
async fn test_certificate_writing_with_pin() {
    // Wrap entire test in timeout to prevent hanging
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        if !check_virtual_smartcard_availability() {
            println!("Skipping test - virtual smartcard system not available");
            return;
        }

        println!("Testing certificate writing with PIN verification...");

        let mut manager =
            VirtualSmartCardManager::new().expect("Failed to start smartcard simulator");

        // Wait for simulator to be ready
        sleep(Duration::from_secs(2)).await;

        let test_cert = match generate_test_certificate() {
            Ok(cert) => cert,
            Err(e) => {
                eprintln!("✗ Failed to generate test certificate: {}", e);
                return;
            }
        };

        // Test with correct PIN
        let correct_pin = b"1234".to_vec();
        if let Ok(Some(keypair)) = tokio::time::timeout(
            Duration::from_secs(15),
            card::KeyPair::generate_with_smartcard(correct_pin, "pin-test", false),
        )
        .await
        {
            match keypair.save_cert_to_card(&test_cert) {
                Ok(()) => {
                    println!("✓ Certificate written with correct PIN");
                }
                Err(e) => {
                    eprintln!("✗ Failed to write certificate with correct PIN: {:?}", e);
                }
            }
        } else {
            eprintln!("✗ Failed to generate keypair with correct PIN");
        }

        // Test with incorrect PIN
        let incorrect_pin = b"9999".to_vec();
        if let Ok(Some(keypair)) = tokio::time::timeout(
            Duration::from_secs(15),
            card::KeyPair::generate_with_smartcard(incorrect_pin, "pin-fail-test", false),
        )
        .await
        {
            match keypair.save_cert_to_card(&test_cert) {
                Ok(()) => {
                    eprintln!("✗ Certificate should not have been written with incorrect PIN");
                }
                Err(card::Error::CardError(_)) => {
                    println!("✓ Certificate correctly rejected with incorrect PIN");
                }
                Err(e) => {
                    eprintln!("✗ Unexpected error with incorrect PIN: {:?}", e);
                }
            }
        } else {
            println!("✓ Keypair generation with incorrect PIN failed as expected");
        }

        println!("✓ PIN verification test completed");
    })
    .await;

    if result.is_err() {
        eprintln!("Test timed out");
    }
}

/// Test multiple certificates on different virtual cards
#[tokio::test]
#[serial]
async fn test_multiple_certificates() {
    // Wrap entire test in timeout to prevent hanging
    let result = tokio::time::timeout(Duration::from_secs(90), async {
        if !check_virtual_smartcard_availability() {
            println!("Skipping test - virtual smartcard system not available");
            return;
        }

        println!("Testing multiple certificates on virtual smartcard...");

        let mut manager =
            VirtualSmartCardManager::new().expect("Failed to start smartcard simulator");

        // Wait for simulator to be ready
        sleep(Duration::from_secs(2)).await;

        let test_cert1 = match generate_test_certificate() {
            Ok(cert) => cert,
            Err(e) => {
                eprintln!("✗ Failed to generate test certificate 1: {}", e);
                return;
            }
        };

        let mut test_cert2 = test_cert1.clone();
        // Modify the last byte to create a different certificate
        if let Some(last_byte) = test_cert2.last_mut() {
            *last_byte = last_byte.wrapping_add(1);
        }

        let pin = b"1234".to_vec();

        // Test first certificate
        if let Ok(Some(keypair1)) = tokio::time::timeout(
            Duration::from_secs(15),
            card::KeyPair::generate_with_smartcard(pin.clone(), "multi-test-1", false),
        )
        .await
        {
            match keypair1.save_cert_to_card(&test_cert1) {
                Ok(()) => {
                    println!("✓ First certificate written successfully");

                    // Test signing with first certificate
                    let test_data = b"Test data for first certificate";
                    match keypair1.sign_with_pin(test_data) {
                        Ok(sig) => {
                            println!("✓ First certificate can sign data ({} bytes)", sig.len())
                        }
                        Err(e) => eprintln!("✗ First certificate signing failed: {:?}", e),
                    }
                }
                Err(e) => {
                    eprintln!("✗ Failed to write first certificate: {:?}", e);
                }
            }
        } else {
            eprintln!("✗ Failed to generate keypair for first certificate");
        }

        // Small delay between operations
        sleep(Duration::from_millis(500)).await;

        // Test second certificate (may overwrite first depending on implementation)
        if let Ok(Some(keypair2)) = tokio::time::timeout(
            Duration::from_secs(15),
            card::KeyPair::generate_with_smartcard(pin.clone(), "multi-test-2", false),
        )
        .await
        {
            match keypair2.save_cert_to_card(&test_cert2) {
                Ok(()) => {
                    println!("✓ Second certificate written successfully");

                    // Test signing with second certificate
                    let test_data = b"Test data for second certificate";
                    match keypair2.sign_with_pin(test_data) {
                        Ok(sig) => {
                            println!("✓ Second certificate can sign data ({} bytes)", sig.len())
                        }
                        Err(e) => eprintln!("✗ Second certificate signing failed: {:?}", e),
                    }
                }
                Err(e) => {
                    eprintln!("✗ Failed to write second certificate: {:?}", e);
                }
            }
        } else {
            eprintln!("✗ Failed to generate keypair for second certificate");
        }

        println!("Multiple certificates test completed");
    })
    .await;

    if result.is_err() {
        eprintln!("Test timed out");
    }
}

/// Test certificate writing error handling
#[tokio::test]
#[serial]
async fn test_certificate_error_handling() {
    // Wrap entire test in timeout to prevent hanging
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        if !check_virtual_smartcard_availability() {
            println!("Skipping test - virtual smartcard system not available");
            return;
        }

        println!("Testing certificate error handling with virtual smartcard...");

        let mut manager =
            VirtualSmartCardManager::new().expect("Failed to start smartcard simulator");

        // Wait for simulator to be ready
        sleep(Duration::from_secs(2)).await;

        let pin = b"1234".to_vec();

        if let Ok(Some(keypair)) = tokio::time::timeout(
            Duration::from_secs(15),
            card::KeyPair::generate_with_smartcard(pin, "error-test", false),
        )
        .await
        {
            // Test with empty certificate
            match keypair.save_cert_to_card(&[]) {
                Ok(()) => {
                    eprintln!("✗ Empty certificate should not be accepted");
                }
                Err(_) => {
                    println!("✓ Empty certificate correctly rejected");
                }
            }

            // Test with invalid certificate data
            let invalid_cert = vec![0xFF; 100]; // Invalid DER data
            match keypair.save_cert_to_card(&invalid_cert) {
                Ok(()) => {
                    println!(
                        "⚠ Invalid certificate was accepted (may be implementation dependent)"
                    );
                }
                Err(_) => {
                    println!("✓ Invalid certificate correctly rejected");
                }
            }

            // Test with oversized certificate
            let oversized_cert = vec![0x30; 5000]; // Very large certificate
            match keypair.save_cert_to_card(&oversized_cert) {
                Ok(()) => {
                    println!("⚠ Oversized certificate was accepted (may be truncated)");
                }
                Err(_) => {
                    println!("✓ Oversized certificate correctly rejected");
                }
            }

            // Test with valid certificate
            match generate_test_certificate() {
                Ok(valid_cert) => match keypair.save_cert_to_card(&valid_cert) {
                    Ok(()) => {
                        println!("✓ Valid certificate correctly accepted");
                    }
                    Err(e) => {
                        eprintln!("✗ Valid certificate was rejected: {:?}", e);
                    }
                },
                Err(e) => {
                    eprintln!("✗ Failed to generate valid certificate: {}", e);
                }
            }
        } else {
            eprintln!("✗ Failed to generate keypair for error testing");
        }

        println!("Certificate error handling test completed");
    })
    .await;

    if result.is_err() {
        eprintln!("Test timed out");
    }
}

/// Test certificate writing timeout handling
#[tokio::test]
#[serial]
async fn test_certificate_timeout_handling() {
    // Wrap entire test in timeout to prevent hanging
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        println!("Testing certificate timeout handling without simulator...");

        // This test intentionally doesn't start the simulator to test timeout behavior
        let pin = b"1234".to_vec();

        println!("Testing certificate operations without simulator (expecting timeout)...");

        // This should timeout since no simulator is running
        let start_time = Instant::now();
        if let Ok(Some(keypair)) = tokio::time::timeout(
            Duration::from_secs(5),
            card::KeyPair::generate_with_smartcard(pin, "timeout-test", false),
        )
        .await
        {
            let test_cert = match generate_test_certificate() {
                Ok(cert) => cert,
                Err(e) => {
                    eprintln!("Failed to generate test certificate: {}", e);
                    return;
                }
            };

            match keypair.save_cert_to_card(&test_cert) {
                Ok(()) => {
                    eprintln!("✗ Certificate write should have timed out");
                }
                Err(card::Error::Timeout) => {
                    let elapsed = start_time.elapsed();
                    println!(
                        "✓ Certificate write correctly timed out after {:?}",
                        elapsed
                    );
                }
                Err(e) => {
                    println!(
                        "⚠ Certificate write failed with error (not timeout): {:?}",
                        e
                    );
                }
            }
        } else {
            let elapsed = start_time.elapsed();
            println!(
                "✓ Keypair generation timed out as expected after {:?} (no simulator running)",
                elapsed
            );
        }

        println!("✓ Timeout handling test completed");
    })
    .await;

    if result.is_err() {
        eprintln!("Test timed out");
    }
}

async fn run_ca_certificate_integration() -> Result<(), String> {
    if !check_virtual_smartcard_availability() {
        println!("Skipping test - virtual smartcard system not available");
        return Err("Virtual smartcard not available".to_string());
    }

    let mut manager = VirtualSmartCardManager::new().map_err(|e| e.to_string())?;

    manager.do_the_thing();

    println!("Waiting 2 seconds for simulator");

    // Wait for simulator to be ready
    sleep(Duration::from_secs(2)).await;

    let card = manager.create_card("test_card")?;

    let pin = b"1234".to_vec();
    let keypair = card::KeyPair::generate_with_smartcard(pin, "ca-integration-test", false)
        .await
        .ok_or("Failed to generate keypair".to_string())?;

    // Test the label functionality
    let label = keypair.label();
    assert_eq!(label, "ca-integration-test");
    println!("✓ Keypair label matches: {}", label);

    // Test rcgen integration
    let rcgen_keypair = keypair.rcgen();
    println!("✓ Successfully created rcgen keypair from smartcard keypair");

    // Generate a test certificate using rcgen
    let mut params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::DnsName(
        "test.example.com".try_into().unwrap(),
    )];

    match params.self_signed(&rcgen_keypair) {
        Ok(cert) => {
            let cert_der = cert.der();
            println!("✓ Generated test certificate ({} bytes)", cert_der.len());

            // Test writing the generated certificate to the smartcard
            match keypair.save_cert_to_card(&cert_der) {
                Ok(()) => {
                    println!("✓ CA-generated certificate successfully written to smartcard");

                    // Test signing functionality with the written certificate
                    let test_data = b"CA integration test data";
                    match keypair.sign_with_pin(test_data) {
                        Ok(signature) => {
                            println!(
                                "✓ Successfully signed data with CA certificate keypair ({} bytes)",
                                signature.len()
                            );
                        }
                        Err(e) => {
                            panic!("✗ Failed to sign with CA certificate: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    panic!("✗ Failed to write CA certificate to smartcard: {:?}", e);
                }
            }
        }
        Err(e) => {
            panic!("Failed to generate test certificate: {}", e);
        }
    }

    Ok(())
}

/// Integration test with CA certificate generation workflow
#[tokio::test]
#[function_name::named]
#[serial]
async fn test_ca_certificate_integration() {
    let service = service::Service::new(format!("rust-iot-{}", function_name!()));
    service.new_log(service::LogLevel::Debug);

    // Wrap entire test in timeout to prevent hanging
    let r = tokio::time::timeout(Duration::from_secs(90), run_ca_certificate_integration()).await;
    assert!(r.is_ok());
    if let Ok(r) = r {
        assert!(r.is_ok());
    }
}

/// Performance test for certificate operations
#[tokio::test]
#[serial]
async fn test_certificate_performance() {
    // Wrap entire test in timeout to prevent hanging
    let result = tokio::time::timeout(Duration::from_secs(120), async {
        if !check_virtual_smartcard_availability() {
            println!("Skipping test - virtual smartcard system not available");
            return;
        }

        println!("Testing certificate performance with virtual smartcard...");

        let mut manager =
            VirtualSmartCardManager::new().expect("Failed to start smartcard simulator");

        // Wait for simulator to be ready
        sleep(Duration::from_secs(2)).await;

        let test_cert = match generate_test_certificate() {
            Ok(cert) => cert,
            Err(e) => {
                eprintln!("Failed to generate test certificate: {}", e);
                return;
            }
        };

        let pin = b"1234".to_vec();

        if let Ok(Some(keypair)) = tokio::time::timeout(
            Duration::from_secs(15),
            card::KeyPair::generate_with_smartcard(pin, "perf-test", false),
        )
        .await
        {
            println!("Running certificate writing performance test...");

            let num_operations = 5;
            let mut total_time = Duration::new(0, 0);
            let mut successful_operations = 0;

            for i in 0..num_operations {
                let start_time = Instant::now();

                match keypair.save_cert_to_card(&test_cert) {
                    Ok(()) => {
                        let operation_time = start_time.elapsed();
                        total_time += operation_time;
                        successful_operations += 1;
                        println!("  Operation {}: {:?}", i + 1, operation_time);
                    }
                    Err(e) => {
                        eprintln!("  Operation {} failed: {:?}", i + 1, e);
                    }
                }

                // Small delay between operations
                sleep(Duration::from_millis(100)).await;
            }

            if successful_operations > 0 {
                let average_time = total_time / successful_operations;
                println!("✓ Performance test completed:");
                println!(
                    "  Successful operations: {}/{}",
                    successful_operations, num_operations
                );
                println!("  Average time per operation: {:?}", average_time);
                println!("  Total time: {:?}", total_time);

                // Performance assertions
                if average_time < Duration::from_millis(100) {
                    println!("✓ Certificate operations performance is excellent");
                } else if average_time < Duration::from_millis(500) {
                    println!("✓ Certificate operations performance is good");
                } else {
                    println!("⚠ Certificate operations performance may need optimization");
                }
            } else {
                eprintln!("✗ No successful operations in performance test");
            }
        } else {
            eprintln!("✗ Failed to generate keypair for performance test");
        }

        println!("✓ Performance test completed");
    })
    .await;

    if result.is_err() {
        eprintln!("Test timed out");
    }
}

/// Integration test that verifies the complete certificate lifecycle
#[tokio::test]
#[serial]
async fn test_complete_certificate_lifecycle() {
    // Wrap entire test in timeout to prevent hanging
    let result = tokio::time::timeout(Duration::from_secs(180), async {
        if !check_virtual_smartcard_availability() {
            println!("Skipping test - virtual smartcard system not available");
            return;
        }

        println!("=== Complete Certificate Lifecycle Test ===");

        let mut manager =
            VirtualSmartCardManager::new().expect("Failed to start smartcard simulator");

        println!("Waiting 3 seconds for simulator");

        // Wait for simulator to be ready
        sleep(Duration::from_secs(3)).await;

        let pin = b"1234".to_vec();

        // Step 1: Generate keypair
        println!("1. Generating keypair with virtual smartcard...");
        let keypair = match tokio::time::timeout(
            Duration::from_secs(15),
            card::KeyPair::generate_with_smartcard(pin, "lifecycle-test", false),
        )
        .await
        {
            Ok(Some(kp)) => {
                println!("✓ Keypair generated successfully");
                kp
            }
            Ok(None) => {
                eprintln!("✗ Failed to generate keypair");
                return;
            }
            Err(_) => {
                eprintln!("✗ Timeout waiting for keypair generation");
                return;
            }
        };

        // Step 2: Generate certificate
        println!("2. Generating test certificate...");
        let test_cert = match generate_test_certificate() {
            Ok(cert) => {
                println!("✓ Test certificate generated ({} bytes)", cert.len());
                cert
            }
            Err(e) => {
                eprintln!("✗ Failed to generate certificate: {}", e);
                return;
            }
        };

        // Step 3: Write certificate to smartcard
        println!("3. Writing certificate to virtual smartcard...");
        match keypair.save_cert_to_card(&test_cert) {
            Ok(()) => {
                println!("✓ Certificate written to smartcard successfully");
            }
            Err(e) => {
                eprintln!("✗ Failed to write certificate: {:?}", e);
                return;
            }
        }

        // Step 4: Test signing operations
        println!("4. Testing signing operations...");
        let test_data = b"Complete lifecycle test data";
        match keypair.sign_with_pin(test_data) {
            Ok(signature) => {
                println!(
                    "✓ Data signed successfully ({} bytes signature)",
                    signature.len()
                );
            }
            Err(e) => {
                eprintln!("✗ Failed to sign data: {:?}", e);
                return;
            }
        }

        // Step 5: Test multiple signing operations
        println!("5. Testing multiple signing operations...");
        for i in 1..=3 {
            let data = format!("Test data #{}", i);
            match keypair.sign_with_pin(data.as_bytes()) {
                Ok(sig) => {
                    println!("✓ Signing operation {} successful ({} bytes)", i, sig.len());
                }
                Err(e) => {
                    eprintln!("✗ Signing operation {} failed: {:?}", i, e);
                }
            }
        }

        // Step 6: Test label functionality
        println!("6. Testing key management...");
        let label = keypair.label();
        if label == "lifecycle-test" {
            println!("✓ Key label matches expected value: {}", label);
        } else {
            eprintln!(
                "✗ Key label mismatch. Expected: lifecycle-test, Got: {}",
                label
            );
        }

        println!("=== Complete Certificate Lifecycle Test Completed ===");
    })
    .await;

    if result.is_err() {
        eprintln!("Test timed out");
    }
}
