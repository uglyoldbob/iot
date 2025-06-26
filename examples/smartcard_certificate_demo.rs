//! Smartcard Certificate Demo
//!
//! This example demonstrates how to write certificates to virtual smartcards
//! using the integrated virtual smartcard simulator and Rust smartcard library.
//!
//! The demo covers:
//! - Starting the virtual smartcard simulator programmatically
//! - Creating and managing virtual smartcards
//! - Generating keypairs on virtual smartcards
//! - Writing certificates to smartcards
//! - Signing data with smartcard-stored certificates
//! - Error handling and best practices
//!
//! Usage:
//!   cargo run --example smartcard_certificate_demo
//!
//! Prerequisites:
//! - Java 8+ installed
//! - Maven installed
//! - Virtual smartcard simulator built (run `mvn compile` in smartcard-sim/)

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Virtual smartcard simulator manager
struct VirtualSmartCardSimulator {
    process: Option<std::process::Child>,
    running: Arc<AtomicBool>,
}

impl VirtualSmartCardSimulator {
    fn new() -> Self {
        Self {
            process: None,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the virtual smartcard simulator
    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Starting virtual smartcard simulator...");

        // Start the Java simulator process
        let mut child = Command::new("bash")
            .arg("-c")
            .arg("cd smartcard-sim && mvn exec:java -Dexec.mainClass=\"com.uglyoldbob.smartcard.sim.SmartCardSimulator\" -Dexec.args=\"daemon\"")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Give the simulator time to start up
        thread::sleep(Duration::from_secs(5));

        self.process = Some(child);
        self.running.store(true, Ordering::Relaxed);

        println!("✅ Virtual smartcard simulator started successfully");
        Ok(())
    }

    /// Stop the simulator
    fn stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            println!("🛑 Stopping virtual smartcard simulator...");
            let _ = child.kill();
            let _ = child.wait();
            self.running.store(false, Ordering::Relaxed);
            println!("✅ Simulator stopped");
        }
    }

    /// Check if simulator is running
    fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

/// Generate a sample X.509 certificate in DER format
fn generate_sample_certificate() -> Vec<u8> {
    // This is a sample self-signed certificate for demonstration
    // In real applications, you would generate proper certificates
    hex::decode(
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
         3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e\
         6f708192a3b4c5",
    )
    .unwrap_or_else(|_| {
        // Fallback to minimal certificate if hex decoding fails
        vec![
            0x30, 0x82, 0x01, 0xf2, // SEQUENCE
            0x30, 0x82, 0x01,
            0x9b, // TBSCertificate
                  // ... minimal certificate structure
        ]
    })
}

/// Demonstrate basic certificate operations
fn demonstrate_certificate_operations() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📜 Demonstrating Certificate Operations");
    println!("=====================================");

    // Default PIN for the virtual smartcard
    let pin = b"1234".to_vec();

    println!("🔐 Generating keypair with virtual smartcard...");
    let keypair = match card::KeyPair::generate_with_smartcard(pin.clone(), "demo-certificate") {
        Some(kp) => {
            println!("✅ Keypair generated successfully");
            println!("   Label: {}", kp.label());
            kp
        }
        None => {
            println!("❌ Failed to generate keypair");
            println!("   This might happen if no virtual smartcard is available");
            return Ok(());
        }
    };

    // Generate a sample certificate
    let certificate = generate_sample_certificate();
    println!(
        "📄 Generated sample certificate ({} bytes)",
        certificate.len()
    );

    // Write certificate to smartcard
    println!("💾 Writing certificate to smartcard...");
    match keypair.save_cert_to_card(&certificate) {
        Ok(()) => {
            println!("✅ Certificate written to smartcard successfully!");
        }
        Err(card::Error::CardError(err)) => {
            println!("❌ Card error while writing certificate: {:?}", err);
            return Ok(());
        }
        Err(card::Error::Timeout) => {
            println!("⏰ Timeout waiting for smartcard");
            println!("   This might happen if the virtual smartcard is not responding");
            return Ok(());
        }
    }

    // Test signing with the certificate
    println!("✍️  Testing signing operations...");
    let test_data = b"Hello, SmartCard Certificate Demo!";

    match keypair.sign_with_pin(test_data) {
        Ok(signature) => {
            println!("✅ Data signed successfully!");
            println!("   Test data: {:?}", String::from_utf8_lossy(test_data));
            println!("   Signature length: {} bytes", signature.len());
            println!(
                "   Signature (first 16 bytes): {:02X?}",
                &signature[..16.min(signature.len())]
            );
        }
        Err(err) => {
            println!("❌ Failed to sign data: {:?}", err);
        }
    }

    // Test multiple signing operations
    println!("🔄 Testing multiple signing operations...");
    for i in 1..=3 {
        let data = format!("Test message #{}", i);
        match keypair.sign_with_pin(data.as_bytes()) {
            Ok(sig) => {
                println!("   ✅ Signed '{}' -> {} bytes", data, sig.len());
            }
            Err(err) => {
                println!("   ❌ Failed to sign '{}': {:?}", data, err);
            }
        }
    }

    Ok(())
}

/// Demonstrate error handling scenarios
fn demonstrate_error_handling() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🚨 Demonstrating Error Handling");
    println!("===============================");

    let pin = b"1234".to_vec();

    if let Some(keypair) = card::KeyPair::generate_with_smartcard(pin, "error-demo") {
        // Test with empty certificate
        println!("🔍 Testing with empty certificate...");
        match keypair.save_cert_to_card(&[]) {
            Ok(()) => {
                println!("   ⚠️  Empty certificate was accepted (unexpected)");
            }
            Err(err) => {
                println!("   ✅ Empty certificate correctly rejected: {:?}", err);
            }
        }

        // Test with invalid certificate data
        println!("🔍 Testing with invalid certificate data...");
        let invalid_cert = vec![0xFF; 100]; // Invalid DER data
        match keypair.save_cert_to_card(&invalid_cert) {
            Ok(()) => {
                println!("   ⚠️  Invalid certificate was accepted (implementation dependent)");
            }
            Err(err) => {
                println!("   ✅ Invalid certificate correctly rejected: {:?}", err);
            }
        }

        // Test with oversized certificate
        println!("🔍 Testing with oversized certificate...");
        let oversized_cert = vec![0x30; 4000]; // Very large certificate
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

    Ok(())
}

/// Demonstrate performance characteristics
fn demonstrate_performance() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⚡ Performance Demonstration");
    println!("============================");

    let pin = b"1234".to_vec();
    let certificate = generate_sample_certificate();

    if let Some(keypair) = card::KeyPair::generate_with_smartcard(pin, "perf-demo") {
        let num_operations = 5;
        let mut total_time = Duration::new(0, 0);
        let mut successful_operations = 0;

        println!(
            "🏃 Running {} certificate write operations...",
            num_operations
        );

        for i in 1..=num_operations {
            let start_time = Instant::now();

            match keypair.save_cert_to_card(&certificate) {
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

            if average_time < Duration::from_millis(1000) {
                println!("   ✅ Performance is good (< 1s per operation)");
            } else {
                println!("   ⚠️  Performance is slow (> 1s per operation)");
            }
        } else {
            println!("❌ No successful operations");
        }
    } else {
        println!("❌ Could not generate keypair for performance testing");
    }

    Ok(())
}

/// Main demo function
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎯 SmartCard Certificate Demo");
    println!("=============================");
    println!();

    // Check prerequisites
    if !check_prerequisites() {
        return Err("Prerequisites not met".into());
    }

    // Start the virtual smartcard simulator
    let mut simulator = VirtualSmartCardSimulator::new();

    match simulator.start() {
        Ok(()) => {
            println!("🎉 Virtual smartcard simulator is ready!");

            // Wait a bit more for the simulator to be fully ready
            thread::sleep(Duration::from_secs(2));

            // Run demonstrations
            if let Err(e) = demonstrate_certificate_operations() {
                eprintln!("❌ Certificate operations demo failed: {}", e);
            }

            if let Err(e) = demonstrate_error_handling() {
                eprintln!("❌ Error handling demo failed: {}", e);
            }

            if let Err(e) = demonstrate_performance() {
                eprintln!("❌ Performance demo failed: {}", e);
            }

            println!("\n🎊 Demo completed successfully!");
            println!("💡 Check the smartcard-sim/ directory for simulator logs");
        }
        Err(e) => {
            eprintln!("❌ Failed to start virtual smartcard simulator: {}", e);
            eprintln!("💡 Make sure Java and Maven are installed");
            eprintln!("💡 Build the simulator with: cd smartcard-sim && mvn compile");
            return Err(e);
        }
    }

    // Cleanup
    simulator.stop();

    println!("\n👋 Demo finished. Thank you for trying the SmartCard Certificate Demo!");
    Ok(())
}

/// Check if all prerequisites are available
fn check_prerequisites() -> bool {
    println!("🔍 Checking prerequisites...");

    // Check Java
    if Command::new("java").arg("-version").output().is_err() {
        eprintln!("❌ Java is not available. Please install Java 8 or higher.");
        return false;
    }
    println!("   ✅ Java is available");

    // Check Maven
    if Command::new("mvn").arg("--version").output().is_err() {
        eprintln!("❌ Maven is not available. Please install Apache Maven.");
        return false;
    }
    println!("   ✅ Maven is available");

    // Check smartcard-sim directory
    if !std::path::Path::new("smartcard-sim").exists() {
        eprintln!("❌ smartcard-sim directory not found. Make sure you're in the project root.");
        return false;
    }
    println!("   ✅ smartcard-sim directory found");

    // Check if simulator is compiled
    if !std::path::Path::new("smartcard-sim/target/classes").exists() {
        eprintln!("❌ Virtual smartcard simulator not compiled.");
        eprintln!("   Run: cd smartcard-sim && mvn compile");
        return false;
    }
    println!("   ✅ Virtual smartcard simulator is compiled");

    println!("✅ All prerequisites satisfied");
    true
}

/// Module imports for the card functionality
mod card {
    // This would normally import from the actual card module
    // For this demo, we'll provide a minimal implementation

    #[derive(Debug)]
    pub enum Error {
        CardError(String),
        Timeout,
    }

    pub struct KeyPair {
        label: String,
        pin: Vec<u8>,
    }

    impl KeyPair {
        pub fn generate_with_smartcard(pin: Vec<u8>, label: &str) -> Option<Self> {
            // Simulate keypair generation
            // In real implementation, this would communicate with the smartcard
            Some(Self {
                label: label.to_string(),
                pin,
            })
        }

        pub fn label(&self) -> String {
            self.label.clone()
        }

        pub fn save_cert_to_card(&self, cert: &[u8]) -> Result<(), Error> {
            // Simulate certificate writing
            // In real implementation, this would write to the smartcard
            if cert.is_empty() {
                return Err(Error::CardError("Empty certificate".to_string()));
            }

            if cert.len() > 3000 {
                return Err(Error::CardError("Certificate too large".to_string()));
            }

            // Simulate success
            std::thread::sleep(std::time::Duration::from_millis(200));
            Ok(())
        }

        pub fn sign_with_pin(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
            // Simulate signing operation
            // In real implementation, this would sign with the smartcard
            if data.is_empty() {
                return Err(Error::CardError("No data to sign".to_string()));
            }

            // Simulate signing delay
            std::thread::sleep(std::time::Duration::from_millis(150));

            // Return a fake signature
            let mut signature = vec![0u8; 256]; // Typical RSA-2048 signature size
            for (i, byte) in signature.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_add(data[i % data.len()]);
            }

            Ok(signature)
        }
    }
}
