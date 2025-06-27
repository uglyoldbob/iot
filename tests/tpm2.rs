#![warn(missing_docs)]
#![allow(unused)]
//! TPM 2.0 (Trusted Platform Module) hardware security testing suite
//!
//! This test module validates TPM 2.0 hardware integration for secure data encryption
//! and decryption operations. The tests cover:
//! - Software-based encryption/decryption fallback when TPM hardware is unavailable
//! - TPM 2.0 hardware-based key generation and data protection
//! - Password-based encryption with TPM-protected key derivation
//! - Hierarchical password protection using both user passwords and TPM-sealed data
//! - TPM blob serialization and deserialization for persistent storage
//! - Cross-session TPM key recovery and data decryption
//!
//! The tests use conditional compilation with the "tpm2" feature flag to enable
//! hardware-specific functionality while providing software fallbacks for testing.

#[path = "../src/tpm2.rs"]
mod tpm2;

#[path = "../src/utility.rs"]
mod utility;

/// Test enumeration for user prompting validation
///
/// This enum demonstrates the userprompt::Prompting derive macro functionality
/// with various enum variant types including unit variants, tuple variants,
/// and struct variants with named fields.
#[allow(dead_code)]
#[derive(Debug, userprompt::Prompting)]
enum TestEnum {
    /// Simple option without associated data
    Option1,
    /// Another simple option
    Option2,
    /// Option with tuple-style associated data (i8, i16)
    Option3(i8, i16),
    /// Option with struct-style named fields
    Option4 { a: u8, b: u16, c: String },
}

/// Test structure for complex user prompting scenarios
///
/// This struct demonstrates nested prompting capabilities with various field types
/// including enums, optional values, nested structs, and file paths.
#[allow(dead_code)]
#[derive(Debug, userprompt::Prompting)]
struct TestMe {
    /// Test enum field for validation
    e: TestEnum,
    /// Simple numeric field
    bob: u8,
    /// Optional numeric field
    jim: Option<u8>,
    /// Nested struct field
    asdf: TestMe2,
    /// File path field for testing path prompting
    path: std::path::PathBuf,
}

/// Nested test structure for prompting validation
///
/// This struct is used within TestMe to validate nested structure prompting
/// with both required and optional numeric fields.
#[allow(dead_code)]
#[derive(Debug, userprompt::Prompting)]
struct TestMe2 {
    /// Size field with u8 constraint
    size: u8,
    /// Optional number field
    number: Option<u8>,
}

/// Test software-based encryption/decryption without TPM hardware
///
/// This test validates the fallback encryption mechanism when TPM hardware
/// is not available or when testing software-only encryption paths.
///
/// The test performs:
/// 1. Random data generation (1024 bytes)
/// 2. Password-based encryption using software methods
/// 3. Decryption and data integrity validation
/// 4. Round-trip consistency verification
///
/// This ensures the system can operate securely even without TPM hardware.
#[tokio::test]
async fn non_tpm2() {
    #[cfg(feature = "tpm2")]
    {
        // Generate 1024 bytes of random test data
        let mut data: Vec<u8> = vec![0; 1024];
        for e in data.iter_mut() {
            *e = rand::random();
        }

        // Generate a 32-character random password
        let pw = utility::generate_password(32);

        // Encrypt data using software-based encryption
        let a = tpm2::encrypt(&data, pw.as_bytes());

        // Decrypt and verify data integrity
        let plain = tpm2::decrypt(a, pw.as_bytes());
        assert_eq!(plain, data);
    }
}

/// Test comprehensive TPM 2.0 hardware-based encryption and key management
///
/// This test validates the complete TPM 2.0 workflow for secure data protection:
/// 1. TPM hardware initialization and path discovery
/// 2. Hierarchical password protection (user password + TPM-sealed password)
/// 3. Data encryption using combined password scheme
/// 4. TPM blob serialization for persistent storage
/// 5. Cross-session key recovery and data decryption
/// 6. Multiple decryption attempts to validate consistency
///
/// The test demonstrates real-world TPM usage where sensitive data is protected
/// by both user-provided passwords and hardware-sealed cryptographic material.
/// This provides defense-in-depth against both software and hardware attacks.
#[tokio::test]
async fn tpm2() {
    println!("Running test program");

    #[cfg(feature = "tpm2")]
    {
        // Generate 1024 bytes of random test data to encrypt
        let mut data: Vec<u8> = vec![0; 1024];
        for e in data.iter_mut() {
            *e = rand::random();
        }

        // Generate user-provided password (first layer of security)
        let password = utility::generate_password(32);
        let config: Vec<u8>;
        let tpm_data: tpm2::TpmBlob;

        // Phase 1: Initial encryption with TPM-protected password
        {
            // Initialize TPM hardware connection
            let mut tpm2_instance =
                tpm2::Tpm2::new(tpm2::tpm2_path()).expect("TPM2 hardware not found");

            // Generate random 32-byte TPM-protected password (second layer of security)
            let password2: [u8; 32] = rand::random();

            // Build protected password with 2048 iterations for key strengthening
            let protected_password =
                tpm2::Password::build(&password2, std::num::NonZeroU32::new(2048).unwrap());

            // Combine user password with TPM-protected password for encryption
            let password_combined = [password.as_bytes(), protected_password.password()].concat();

            // Encrypt the test data using the combined password
            config = tpm2::encrypt(&data, &password_combined);

            // Extract the protected password data for TPM sealing
            let epdata = protected_password.data();

            // Seal the protected password data using TPM hardware
            tpm_data = tpm2_instance.encrypt(&epdata).unwrap();
        }

        // Phase 2: Test blob serialization and cross-session recovery
        {
            // Serialize TPM blob for storage/transmission
            let d = tpm_data.data();

            // Rebuild TPM blob from serialized data
            let e = tpm2::TpmBlob::rebuild(&d);

            // Create new TPM session to simulate cross-session recovery
            let mut tpm2_session =
                tpm2::Tpm2::new(tpm2::tpm2_path()).expect("TPM2 hardware not found");

            // Unseal the protected password data from TPM
            let epdata = tpm2_session.decrypt(e).unwrap();

            // Rebuild the protected password from unsealed data
            let protected_password = tpm2::Password::rebuild(&epdata);

            // Reconstruct the combined password for decryption
            let password_combined = [password.as_bytes(), protected_password.password()].concat();

            // Decrypt and verify data integrity
            let pconfig = tpm2::decrypt(config.clone(), &password_combined);
            assert_eq!(pconfig, data);
        }

        // Phase 3: Final verification with original TPM blob
        {
            // Create another new TPM session for final validation
            let mut tpm2_final =
                tpm2::Tpm2::new(tpm2::tpm2_path()).expect("TPM2 hardware not found");

            // Decrypt using original TPM blob (not serialized/rebuilt)
            let epdata = tpm2_final.decrypt(tpm_data).unwrap();

            // Rebuild protected password from decrypted data
            let protected_password = tpm2::Password::rebuild(&epdata);

            // Reconstruct combined password
            let password_combined = [password.as_bytes(), protected_password.password()].concat();

            // Final decryption and verification
            let pconfig = tpm2::decrypt(config, &password_combined);
            assert_eq!(pconfig, data);

            println!("TPM2 testing passed");
        }
    }
}
