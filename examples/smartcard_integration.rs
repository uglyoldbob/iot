//! Example of integrating the jCardSim-based smart card simulator with Rust code.
//!
//! This example demonstrates how to interact with the Java-based smart card simulator
//! from Rust using process communication or JNI bindings.
//!
//! # New Card Insertion/Removal Functionality
//!
//! This updated example includes comprehensive support for virtual smart card management:
//!
//! ## Virtual Card Management
//! - **Create Virtual Cards**: Create multiple named virtual smart cards
//! - **Insert/Remove Cards**: Dynamically insert and remove cards from the terminal
//! - **Card Status Monitoring**: Check insertion status and get card information
//! - **Card Lifecycle Management**: Delete cards when no longer needed
//!
//! ## Key Features Added
//! - `create_virtual_card(name)` - Create a new virtual card with a friendly name
//! - `insert_card(card_id)` - Insert a specific virtual card into the terminal
//! - `remove_card()` - Remove the currently inserted card
//! - `delete_virtual_card(card_id)` - Permanently delete a virtual card
//! - `is_card_inserted()` - Check if any card is currently inserted
//! - `get_current_card_id()` - Get the ID of the currently inserted card
//! - `get_virtual_card_ids()` - List all available virtual card IDs
//! - `get_card_status()` - Get comprehensive status including all cards and insertion state
//!
//! ## Usage Examples
//!
//! ### Basic Card Management
//! ```rust,no_run
//! let mut simulator = SmartCardSimulatorInterface::new("path/to/simulator.jar");
//! simulator.start()?;
//!
//! // Create virtual cards
//! let dev_card = simulator.create_virtual_card("Development Card")?;
//! let prod_card = simulator.create_virtual_card("Production Card")?;
//!
//! // Insert development card and perform operations
//! simulator.insert_card(&dev_card)?;
//! simulator.verify_pin("1234")?;
//! simulator.generate_key_pair(2048)?;
//!
//! // Switch to production card
//! simulator.remove_card()?;
//! simulator.insert_card(&prod_card)?;
//! // ... perform production operations
//!
//! simulator.stop()?;
//! ```
//!
//! ### Card Status Monitoring
//! ```rust,no_run
//! let status = simulator.get_card_status()?;
//! println!("Card inserted: {}", status.is_inserted);
//! for card in &status.available_cards {
//!     println!("Card: {} ({})", card.name, card.id);
//! }
//! ```
//!
//! ## Integration with CA Systems
//! The card insertion/removal functionality enables more sophisticated certificate
//! authority workflows where different cards can represent different roles or
//! security levels (e.g., separate cards for root CA, intermediate CA, and end-entity operations).

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Represents a smart card operation request
#[derive(Debug, Serialize, Deserialize)]
pub struct SmartCardRequest {
    pub operation: String,
    pub data: Option<Vec<u8>>,
    pub parameters: Option<std::collections::HashMap<String, String>>,
}

/// Represents a smart card operation response
#[derive(Debug, Serialize, Deserialize)]
pub struct SmartCardResponse {
    pub success: bool,
    pub data: Option<Vec<u8>>,
    pub error_message: Option<String>,
    pub status_word: Option<u16>,
}

/// Represents a virtual smart card
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualCard {
    pub id: String,
    pub name: String,
    pub is_inserted: bool,
}

/// Represents the card insertion/removal status
#[derive(Debug, Serialize, Deserialize)]
pub struct CardStatus {
    pub is_inserted: bool,
    pub current_card_id: Option<String>,
    pub current_card_name: Option<String>,
    pub available_cards: Vec<VirtualCard>,
}

/// Smart card simulator interface for Rust
pub struct SmartCardSimulatorInterface {
    java_process: Option<std::process::Child>,
    simulator_path: String,
}

impl SmartCardSimulatorInterface {
    /// Create a new smart card simulator interface
    pub fn new(simulator_jar_path: &str) -> Self {
        Self {
            java_process: None,
            simulator_path: simulator_jar_path.to_string(),
        }
    }

    /// Start the smart card simulator as a background process
    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting smart card simulator...");

        let mut child = Command::new("java")
            .arg("-jar")
            .arg(&self.simulator_path)
            .arg("--daemon") // Hypothetical daemon mode
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Give the simulator time to start up
        thread::sleep(Duration::from_secs(2));

        // Check if the process is still running
        match child.try_wait()? {
            Some(status) => {
                return Err(format!("Simulator process exited with status: {}", status).into());
            }
            None => {
                println!("Smart card simulator started successfully");
                self.java_process = Some(child);
            }
        }

        Ok(())
    }

    /// Stop the smart card simulator
    pub fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(mut child) = self.java_process.take() {
            println!("Stopping smart card simulator...");
            child.kill()?;
            child.wait()?;
            println!("Smart card simulator stopped");
        }
        Ok(())
    }

    /// Create a new virtual smart card
    pub fn create_virtual_card(
        &self,
        card_name: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        println!("Creating virtual card: {}", card_name);

        let _request = SmartCardRequest {
            operation: "create_virtual_card".to_string(),
            data: None,
            parameters: {
                let mut params = std::collections::HashMap::new();
                params.insert("card_name".to_string(), card_name.to_string());
                Some(params)
            },
        };

        // Simulate the operation - in real implementation, this would communicate with Java process
        thread::sleep(Duration::from_millis(100));

        // Generate a mock card ID
        let card_id = format!(
            "card_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        println!("Virtual card '{}' created with ID: {}", card_name, card_id);
        Ok(card_id)
    }

    /// Insert a virtual smart card into the terminal
    pub fn insert_card(&self, card_id: &str) -> Result<bool, Box<dyn std::error::Error>> {
        println!("Inserting card with ID: {}", card_id);

        let _request = SmartCardRequest {
            operation: "insert_card".to_string(),
            data: None,
            parameters: {
                let mut params = std::collections::HashMap::new();
                params.insert("card_id".to_string(), card_id.to_string());
                Some(params)
            },
        };

        // Simulate the operation
        thread::sleep(Duration::from_millis(200));

        println!("Card {} inserted successfully", card_id);
        Ok(true)
    }

    /// Remove the currently inserted virtual smart card
    pub fn remove_card(&self) -> Result<bool, Box<dyn std::error::Error>> {
        println!("Removing currently inserted card...");

        let _request = SmartCardRequest {
            operation: "remove_card".to_string(),
            data: None,
            parameters: None,
        };

        // Simulate the operation
        thread::sleep(Duration::from_millis(150));

        println!("Card removed successfully");
        Ok(true)
    }

    /// Delete a virtual smart card permanently
    pub fn delete_virtual_card(&self, card_id: &str) -> Result<bool, Box<dyn std::error::Error>> {
        println!("Deleting virtual card: {}", card_id);

        let _request = SmartCardRequest {
            operation: "delete_virtual_card".to_string(),
            data: None,
            parameters: {
                let mut params = std::collections::HashMap::new();
                params.insert("card_id".to_string(), card_id.to_string());
                Some(params)
            },
        };

        // Simulate the operation
        thread::sleep(Duration::from_millis(100));

        println!("Virtual card {} deleted successfully", card_id);
        Ok(true)
    }

    /// Check if a card is currently inserted
    pub fn is_card_inserted(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let _request = SmartCardRequest {
            operation: "is_card_inserted".to_string(),
            data: None,
            parameters: None,
        };

        // Simulate the operation
        thread::sleep(Duration::from_millis(50));

        // For demo purposes, assume a card is inserted
        Ok(true)
    }

    /// Get the ID of the currently inserted card
    pub fn get_current_card_id(&self) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let _request = SmartCardRequest {
            operation: "get_current_card_id".to_string(),
            data: None,
            parameters: None,
        };

        // Simulate the operation
        thread::sleep(Duration::from_millis(50));

        // Return a mock card ID
        Ok(Some("card_12345".to_string()))
    }

    /// Get all virtual card IDs
    pub fn get_virtual_card_ids(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let _request = SmartCardRequest {
            operation: "get_virtual_card_ids".to_string(),
            data: None,
            parameters: None,
        };

        // Simulate the operation
        thread::sleep(Duration::from_millis(100));

        // Return mock card IDs
        Ok(vec![
            "card_12345".to_string(),
            "card_67890".to_string(),
            "card_11111".to_string(),
        ])
    }

    /// Get the current card status including insertion state and available cards
    pub fn get_card_status(&self) -> Result<CardStatus, Box<dyn std::error::Error>> {
        println!("Getting card status...");

        // Combine multiple operations to get complete status
        let is_inserted = self.is_card_inserted()?;
        let current_card_id = self.get_current_card_id()?;
        let available_card_ids = self.get_virtual_card_ids()?;

        // Create mock virtual cards
        let available_cards: Vec<VirtualCard> = available_card_ids
            .into_iter()
            .enumerate()
            .map(|(i, id)| VirtualCard {
                id: id.clone(),
                name: format!("Virtual Card {}", i + 1),
                is_inserted: current_card_id.as_ref() == Some(&id),
            })
            .collect();

        let current_card_name = if let Some(ref card_id) = current_card_id {
            available_cards
                .iter()
                .find(|card| card.id == *card_id)
                .map(|card| card.name.clone())
        } else {
            None
        };

        let status = CardStatus {
            is_inserted,
            current_card_id,
            current_card_name,
            available_cards,
        };

        println!("Card status retrieved: {:?}", status);
        Ok(status)
    }

    /// Generate a key pair on the simulated smart card
    pub fn generate_key_pair(&self, key_size: u16) -> Result<bool, Box<dyn std::error::Error>> {
        println!("Generating {}-bit key pair on smart card...", key_size);

        // For demonstration, we'll simulate the operation
        // In a real implementation, this would communicate with the Java process
        let _request = SmartCardRequest {
            operation: "generate_keypair".to_string(),
            data: Some(key_size.to_be_bytes().to_vec()),
            parameters: None,
        };

        // Simulate the operation
        thread::sleep(Duration::from_millis(500));

        println!("Key pair generated successfully");
        Ok(true)
    }

    /// Sign data using the smart card's private key
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        println!("Signing {} bytes of data...", data.len());

        let _request = SmartCardRequest {
            operation: "sign_data".to_string(),
            data: Some(data.to_vec()),
            parameters: None,
        };

        // Simulate the signing operation
        thread::sleep(Duration::from_millis(200));

        // Return a mock signature (in real implementation, this would be the actual signature)
        let mock_signature = vec![
            0x30, 0x82, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
            0x9c,
            // ... more signature bytes would follow
        ];

        println!(
            "Data signed successfully, signature length: {} bytes",
            mock_signature.len()
        );
        Ok(mock_signature)
    }

    /// Get the public key from the smart card
    pub fn get_public_key(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        println!("Retrieving public key from smart card...");

        let _request = SmartCardRequest {
            operation: "get_public_key".to_string(),
            data: None,
            parameters: None,
        };

        // Simulate the operation
        thread::sleep(Duration::from_millis(100));

        // Return a mock public key (in real implementation, this would be the actual key)
        let mock_public_key = vec![
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a,
            0x86,
            // ... more public key bytes would follow
        ];

        println!(
            "Public key retrieved successfully, length: {} bytes",
            mock_public_key.len()
        );
        Ok(mock_public_key)
    }

    /// Verify PIN on the smart card
    pub fn verify_pin(&self, pin: &str) -> Result<bool, Box<dyn std::error::Error>> {
        println!("Verifying PIN...");

        let mut parameters = std::collections::HashMap::new();
        parameters.insert("pin".to_string(), pin.to_string());

        let _request = SmartCardRequest {
            operation: "verify_pin".to_string(),
            data: None,
            parameters: Some(parameters),
        };

        // Simulate PIN verification
        thread::sleep(Duration::from_millis(50));

        // For demo purposes, accept "1234" as correct PIN
        let success = pin == "1234";

        if success {
            println!("PIN verification successful");
        } else {
            println!("PIN verification failed");
        }

        Ok(success)
    }
}

impl Drop for SmartCardSimulatorInterface {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Example integration with the existing CA infrastructure
pub fn integrate_with_ca_system() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Smart Card Integration with CA System ===");

    // Initialize the PC/SC-compatible PIV simulator externally before running this example.
    println!("Please ensure a PC/SC-compatible PIV simulator is running before starting integration.");
    let ca_card_id = simulator.create_virtual_card("CA Signing Card")?;
    let user_card_id = simulator.create_virtual_card("User Certificate Card")?;

    // Get card status
    let status = simulator.get_card_status()?;
    println!("Available cards: {:?}", status.available_cards);

    // Insert the CA card for certificate authority operations
    simulator.insert_card(&ca_card_id)?;

    // Verify PIN (this would typically be prompted from user)
    let pin = "1234"; // Default PIN
    let pin_verified = simulator.verify_pin(pin)?;

    if !pin_verified {
        return Err("PIN verification failed".into());
    }

    // Generate a key pair for certificate operations
    let key_size = 2048;
    simulator.generate_key_pair(key_size)?;

    // Get the public key for certificate generation
    let _public_key = simulator.get_public_key()?;
    println!("Public key available for certificate generation");

    // Example: Sign a certificate signing request (CSR)
    let csr_data = b"Mock CSR data for signing";
    let _signature = simulator.sign_data(csr_data)?;
    println!("CSR signed with smart card private key");

    // Remove the CA card and insert user card
    simulator.remove_card()?;
    simulator.insert_card(&user_card_id)?;

    // Verify PIN for user card
    simulator.verify_pin(pin)?;

    // Generate user key pair
    simulator.generate_key_pair(2048)?;

    // Example: Sign a certificate
    let cert_data = b"Mock certificate data for signing";
    let _cert_signature = simulator.sign_data(cert_data)?;
    println!("Certificate signed with user smart card private key");

    // Clean up - remove card and stop simulator
    simulator.remove_card()?;
    simulator.stop()?;

    println!("Smart card integration example completed successfully");
    Ok(())
}

/// Example of using the smart card for SSH key operations
pub fn ssh_key_operations() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Smart Card SSH Key Operations ===");

    println!("Please ensure a PC/SC-compatible PIV simulator is running before starting SSH key operations.");

    println!("=== Personal SSH Key Operations ===");
    // Insert personal SSH card
    simulator.insert_card(&personal_ssh_card)?;

    // Verify PIN
    simulator.verify_pin("1234")?;

    // Generate SSH key pair
    simulator.generate_key_pair(2048)?;

    // Get public key in SSH format (would need format conversion)
    let _public_key_der = simulator.get_public_key()?;

    // In a real implementation, you would convert DER to SSH format here
    println!("Personal SSH public key generated (would need format conversion)");

    // Sign SSH authentication challenge
    let challenge_data = b"SSH authentication challenge for personal";
    let _auth_signature = simulator.sign_data(challenge_data)?;
    println!("Personal SSH authentication challenge signed");

    // Switch to work SSH card
    simulator.remove_card()?;
    println!("\n=== Work SSH Key Operations ===");
    simulator.insert_card(&work_ssh_card)?;

    // Verify PIN for work card
    simulator.verify_pin("1234")?;

    // Generate work SSH key pair
    simulator.generate_key_pair(4096)?; // Higher security for work

    // Sign work authentication challenge
    let work_challenge = b"SSH authentication challenge for work";
    let _work_signature = simulator.sign_data(work_challenge)?;
    println!("Work SSH authentication challenge signed");

    // Check final card status
    let status = simulator.get_card_status()?;
    println!("Final card status: {:?}", status);

    simulator.remove_card()?;
    simulator.stop()?;
    Ok(())
}

/// Example command-line interface for smart card operations
pub fn run_cli_interface() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Smart Card CLI Interface ===");
    println!("Available commands:");
    println!("  1. Create virtual card");
    println!("  2. Insert card");
    println!("  3. Remove card");
    println!("  4. Delete virtual card");
    println!("  5. Get card status");
    println!("  6. Generate key pair");
    println!("  7. Sign data");
    println!("  8. Get public key");
    println!("  9. Verify PIN");
    println!("  10. Exit");

    let simulator_jar = "smartcard-sim/target/smartcard-sim-1.0.0-SNAPSHOT.jar";
    let mut simulator = SmartCardSimulatorInterface::new(simulator_jar);

    simulator.start()?;

    // Create a default card for immediate use
    let default_card = simulator.create_virtual_card("Default Card")?;
    println!("Created default card: {}", default_card);

    loop {
        print!("\nEnter command (1-10): ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => {
                print!("Enter card name: ");
                std::io::stdout().flush()?;
                let mut name_input = String::new();
                std::io::stdin().read_line(&mut name_input)?;
                let card_name = name_input.trim();
                let card_id = simulator.create_virtual_card(card_name)?;
                println!("Created card '{}' with ID: {}", card_name, card_id);
            }
            "2" => {
                let card_ids = simulator.get_virtual_card_ids()?;
                if card_ids.is_empty() {
                    println!("No virtual cards available. Create one first.");
                    continue;
                }
                println!("Available cards:");
                for (i, card_id) in card_ids.iter().enumerate() {
                    println!("  {}: {}", i + 1, card_id);
                }
                print!("Enter card number to insert: ");
                std::io::stdout().flush()?;
                let mut choice_input = String::new();
                std::io::stdin().read_line(&mut choice_input)?;
                if let Ok(choice) = choice_input.trim().parse::<usize>() {
                    if choice > 0 && choice <= card_ids.len() {
                        let card_id = &card_ids[choice - 1];
                        simulator.insert_card(card_id)?;
                    } else {
                        println!("Invalid choice");
                    }
                }
            }
            "3" => {
                simulator.remove_card()?;
            }
            "4" => {
                let card_ids = simulator.get_virtual_card_ids()?;
                if card_ids.is_empty() {
                    println!("No virtual cards available.");
                    continue;
                }
                println!("Available cards:");
                for (i, card_id) in card_ids.iter().enumerate() {
                    println!("  {}: {}", i + 1, card_id);
                }
                print!("Enter card number to delete: ");
                std::io::stdout().flush()?;
                let mut choice_input = String::new();
                std::io::stdin().read_line(&mut choice_input)?;
                if let Ok(choice) = choice_input.trim().parse::<usize>() {
                    if choice > 0 && choice <= card_ids.len() {
                        let card_id = &card_ids[choice - 1];
                        simulator.delete_virtual_card(card_id)?;
                    } else {
                        println!("Invalid choice");
                    }
                }
            }
            "5" => {
                let status = simulator.get_card_status()?;
                println!("Card Status:");
                println!("  Card inserted: {}", status.is_inserted);
                if let Some(card_id) = &status.current_card_id {
                    println!("  Current card ID: {}", card_id);
                }
                if let Some(card_name) = &status.current_card_name {
                    println!("  Current card name: {}", card_name);
                }
                println!("  Available cards: {}", status.available_cards.len());
                for card in &status.available_cards {
                    let status_str = if card.is_inserted { " [INSERTED]" } else { "" };
                    println!("    - {} ({}){}", card.name, card.id, status_str);
                }
            }
            "6" => {
                if !simulator.is_card_inserted()? {
                    println!("No card inserted. Please insert a card first.");
                    continue;
                }
                print!("Enter key size (1024/2048/4096): ");
                std::io::stdout().flush()?;
                let mut size_input = String::new();
                std::io::stdin().read_line(&mut size_input)?;
                let key_size: u16 = size_input.trim().parse().unwrap_or(2048);
                simulator.generate_key_pair(key_size)?;
            }
            "7" => {
                if !simulator.is_card_inserted()? {
                    println!("No card inserted. Please insert a card first.");
                    continue;
                }
                print!("Enter data to sign: ");
                std::io::stdout().flush()?;
                let mut data_input = String::new();
                std::io::stdin().read_line(&mut data_input)?;
                let data = data_input.trim().as_bytes();
                let signature = simulator.sign_data(data)?;
                println!(
                    "Signature: {:02x?}",
                    &signature[..std::cmp::min(16, signature.len())]
                );
            }
            "8" => {
                if !simulator.is_card_inserted()? {
                    println!("No card inserted. Please insert a card first.");
                    continue;
                }
                let public_key = simulator.get_public_key()?;
                println!(
                    "Public key: {:02x?}",
                    &public_key[..std::cmp::min(32, public_key.len())]
                );
            }
            "9" => {
                if !simulator.is_card_inserted()? {
                    println!("No card inserted. Please insert a card first.");
                    continue;
                }
                print!("Enter PIN: ");
                std::io::stdout().flush()?;
                let mut pin_input = String::new();
                std::io::stdin().read_line(&mut pin_input)?;
                let pin = pin_input.trim();
                if simulator.verify_pin(pin)? {
                    println!("PIN verification successful");
                } else {
                    println!("PIN verification failed");
                }
            }
            "10" => {
                break;
            }
            _ => {
                println!("Invalid command");
            }
        }
    }

    // Clean up before exit
    if simulator.is_card_inserted()? {
        simulator.remove_card()?;
    }
    simulator.stop()?;
    println!("CLI interface closed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smart_card_interface_creation() {
        let simulator = SmartCardSimulatorInterface::new("test.jar");
        assert_eq!(simulator.simulator_path, "test.jar");
    }

    #[test]
    fn test_request_creation() {
        let request = SmartCardRequest {
            operation: "test".to_string(),
            data: Some(vec![1, 2, 3, 4]),
            parameters: None,
        };

        assert_eq!(request.operation, "test");
        assert_eq!(request.data, Some(vec![1, 2, 3, 4]));
        assert!(request.parameters.is_none());
    }

    #[test]
    fn test_response_creation() {
        let response = SmartCardResponse {
            success: true,
            data: Some(vec![1, 2, 3]),
            error_message: None,
            status_word: Some(36864),
        };

        assert!(response.success);
        assert_eq!(response.data, Some(vec![1, 2, 3]));
        assert_eq!(response.status_word, Some(36864));
    }

    #[test]
    fn test_virtual_card_creation() {
        let card = VirtualCard {
            id: "test_id".to_string(),
            name: "Test Card".to_string(),
            is_inserted: false,
        };

        assert_eq!(card.id, "test_id");
        assert_eq!(card.name, "Test Card");
        assert!(!card.is_inserted);
    }

    #[test]
    fn test_card_status_creation() {
        let status = CardStatus {
            is_inserted: true,
            current_card_id: Some("card_123".to_string()),
            current_card_name: Some("Test Card".to_string()),
            available_cards: vec![VirtualCard {
                id: "card_123".to_string(),
                name: "Test Card".to_string(),
                is_inserted: true,
            }],
        };

        assert!(status.is_inserted);
        assert_eq!(status.current_card_id, Some("card_123".to_string()));
        assert_eq!(status.current_card_name, Some("Test Card".to_string()));
        assert_eq!(status.available_cards.len(), 1);
        assert_eq!(status.available_cards[0].id, "card_123");
        assert_eq!(status.available_cards[0].name, "Test Card");
        assert!(status.available_cards[0].is_inserted);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Smart Card Simulator Integration Examples");
    println!("========================================");

    // Check if simulator JAR exists
    println!("Warning: This example assumes a PC/SC-compatible PIV simulator is running.");
    println!("Running examples in simulation mode...");
    println!("");

        // Run simulation-only demo to showcase new features
        println!("0. Card Management Simulation Demo:");
        if let Err(e) = run_simulation_demo() {
            eprintln!("Simulation demo failed: {}", e);
        }
        println!("");
    }

    // Run examples
    println!("1. CA System Integration Example:");
    if let Err(e) = integrate_with_ca_system() {
        eprintln!("CA integration example failed: {}", e);
    }

    println!("\n2. SSH Key Operations Example:");
    if let Err(e) = ssh_key_operations() {
        eprintln!("SSH key operations example failed: {}", e);
    }

    println!("\n3. Card Management Example:");
    if let Err(e) = card_management_example() {
        eprintln!("Card management example failed: {}", e);
    }

    println!("\n4. Interactive CLI Example:");
    println!("(Uncomment the following line to run interactive CLI)");
    // run_cli_interface()?;

    println!("\nAll examples completed!");
    Ok(())
}

/// Example demonstrating card management operations
pub fn card_management_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Card Management Example ===");

    println!("Please ensure a PC/SC-compatible PIV simulator is running before starting card management example.");
    let card2_id = simulator.create_virtual_card("Testing Card")?;
    let card3_id = simulator.create_virtual_card("Production Card")?;

    // Get initial status
    let status = simulator.get_card_status()?;
    println!(
        "Initial status: {} cards available",
        status.available_cards.len()
    );

    // Test card insertion and operations
    println!("\n--- Testing Development Card ---");
    simulator.insert_card(&card1_id)?;

    if simulator.is_card_inserted()? {
        simulator.verify_pin("1234")?;
        simulator.generate_key_pair(2048)?;

        let test_data = b"Development test data";
        let signature = simulator.sign_data(test_data)?;
        println!("Development card signature: {:02x?}", &signature[..8]);
    }

    // Switch to testing card
    simulator.remove_card()?;
    println!("\n--- Testing Testing Card ---");
    simulator.insert_card(&card2_id)?;

    if simulator.is_card_inserted()? {
        simulator.verify_pin("1234")?;
        simulator.generate_key_pair(2048)?;

        let test_data = b"Testing environment data";
        let signature = simulator.sign_data(test_data)?;
        println!("Testing card signature: {:02x?}", &signature[..8]);
    }

    // Switch to production card
    simulator.remove_card()?;
    println!("\n--- Testing Production Card ---");
    simulator.insert_card(&card3_id)?;

    if simulator.is_card_inserted()? {
        simulator.verify_pin("1234")?;
        simulator.generate_key_pair(4096)?; // Higher security for production

        let test_data = b"Production critical data";
        let signature = simulator.sign_data(test_data)?;
        println!("Production card signature: {:02x?}", &signature[..8]);
    }

    // Final status check
    let final_status = simulator.get_card_status()?;
    println!("\n--- Final Card Status ---");
    println!("Cards available: {}", final_status.available_cards.len());
    for card in &final_status.available_cards {
        let status_str = if card.is_inserted { " [INSERTED]" } else { "" };
        println!("  - {} ({}){}", card.name, card.id, status_str);
    }

    // Clean up - remove current card and delete one card
    simulator.remove_card()?;
    simulator.delete_virtual_card(&card2_id)?;
    println!("Deleted testing card");

    let cleanup_status = simulator.get_card_status()?;
    println!(
        "Cards after cleanup: {}",
        cleanup_status.available_cards.len()
    );

    simulator.stop()?;
    println!("Card management example completed successfully");
    Ok(())
}

/// Simulation-only demo that showcases card management features without requiring Java simulator
pub fn run_simulation_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Card Management Simulation Demo ===");
    println!("This demo showcases the new virtual card insertion/removal functionality");
    println!("without requiring the Java simulator to be built.");
    println!("");

    // Simulate card management operations
    println!("🔧 Creating virtual smart cards...");
    let cards = vec![
        ("dev_001", "Development Card"),
        ("test_002", "Testing Card"),
        ("prod_003", "Production Card"),
        ("ca_004", "Certificate Authority Card"),
        ("user_005", "User Certificate Card"),
    ];

    for (id, name) in &cards {
        println!("   ✓ Created '{}' with ID: {}", name, id);
        thread::sleep(Duration::from_millis(100));
    }

    println!("");
    println!("📊 Initial card status:");
    println!("   - Cards available: {}", cards.len());
    println!("   - Currently inserted: None");
    println!("   - Available cards:");
    for (id, name) in &cards {
        println!("     * {} ({}) [NOT INSERTED]", name, id);
    }

    println!("");
    println!("🔄 Demonstrating card insertion workflow...");

    // Simulate development workflow
    println!("");
    println!("--- Development Workflow ---");
    println!("📥 Inserting Development Card (dev_001)...");
    thread::sleep(Duration::from_millis(200));
    println!("   ✓ Card inserted successfully");
    println!("   ✓ PIN verified (1234)");
    println!("   ✓ Generated 2048-bit RSA key pair");

    let dev_data = b"Development test data";
    println!("   ✓ Signed {} bytes of data", dev_data.len());
    println!("   ✓ Signature: [30 82 01 00 02 82 01 01 00 9c ...]");

    println!("📤 Removing Development Card...");
    thread::sleep(Duration::from_millis(150));
    println!("   ✓ Card removed successfully");

    // Simulate production workflow
    println!("");
    println!("--- Production Workflow ---");
    println!("📥 Inserting Production Card (prod_003)...");
    thread::sleep(Duration::from_millis(200));
    println!("   ✓ Card inserted successfully");
    println!("   ✓ PIN verified (1234)");
    println!("   ✓ Generated 4096-bit RSA key pair (high security)");

    let prod_data = b"Production critical certificate data";
    println!("   ✓ Signed {} bytes of critical data", prod_data.len());
    println!("   ✓ Signature: [30 82 02 00 04 82 02 01 00 a1 ...]");

    // Simulate CA operations
    println!("");
    println!("--- Certificate Authority Workflow ---");
    println!("📤 Removing Production Card...");
    thread::sleep(Duration::from_millis(150));
    println!("   ✓ Card removed successfully");

    println!("📥 Inserting CA Card (ca_004)...");
    thread::sleep(Duration::from_millis(200));
    println!("   ✓ Card inserted successfully");
    println!("   ✓ PIN verified (1234)");
    println!("   ✓ CA root key pair already exists");

    let csr_data = b"Certificate signing request data";
    println!("   ✓ Signed CSR ({} bytes)", csr_data.len());
    println!("   ✓ Issued user certificate");

    // Simulate user certificate workflow
    println!("📤 Removing CA Card...");
    thread::sleep(Duration::from_millis(150));
    println!("📥 Inserting User Certificate Card (user_005)...");
    thread::sleep(Duration::from_millis(200));
    println!("   ✓ Card inserted successfully");
    println!("   ✓ PIN verified (1234)");
    println!("   ✓ Generated user key pair");

    let auth_data = b"Authentication challenge";
    println!(
        "   ✓ Signed authentication challenge ({} bytes)",
        auth_data.len()
    );

    println!("");
    println!("🗑️  Demonstrating card lifecycle management...");
    println!("📤 Removing current card...");
    thread::sleep(Duration::from_millis(150));
    println!("   ✓ Card removed successfully");

    println!("🗑️  Deleting Testing Card (test_002)...");
    thread::sleep(Duration::from_millis(100));
    println!("   ✓ Card deleted permanently");

    println!("");
    println!("📊 Final card status:");
    println!("   - Cards available: {}", cards.len() - 1);
    println!("   - Currently inserted: None");
    println!("   - Remaining cards:");
    for (id, name) in &cards {
        if *id != "test_002" {
            println!("     * {} ({}) [NOT INSERTED]", name, id);
        }
    }

    println!("");
    println!("✅ Card Management Simulation Demo Completed!");
    println!("");
    println!("🔑 Key Features Demonstrated:");
    println!("   • Virtual card creation with custom names");
    println!("   • Dynamic card insertion and removal");
    println!("   • Multiple card support for different workflows");
    println!("   • Card status monitoring");
    println!("   • Card lifecycle management (creation/deletion)");
    println!("   • Role-based card usage (dev/test/prod/CA)");
    println!("");
    println!("🚀 This enables sophisticated certificate authority workflows where");
    println!("   different cards represent different security levels and roles!");

    Ok(())
}
