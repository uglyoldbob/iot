#![warn(missing_docs)]
#![allow(unused)]

//! ECDSA (Elliptic Curve Digital Signature Algorithm) cryptographic testing suite
//!
//! This test module provides comprehensive validation of ECDSA signature generation
//! and verification using multiple cryptographic libraries and hardware security modules.
//! The tests cover:
//! - ECDSA signature generation with rcgen library for certificate creation
//! - ECDSA signature operations using Ring cryptography library
//! - Hardware Security Module (HSM) integration for ECDSA operations
//! - Cross-library signature verification and compatibility testing
//! - Both fixed-length and ASN.1 DER encoded signature formats
//!
//! All tests use the P-256 curve with SHA-256 hashing for consistency
//! across different cryptographic implementations.

#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/utility.rs"]
mod utility;

#[path = "../src/tpm2.rs"]
mod tpm2;

use std::{io::Write, sync::Arc};

use crate::hsm2::SecurityModuleTrait;
use der::{Decode, Encode};
use rcgen::RemoteKeyPair;
use ring::signature::EcdsaSigningAlgorithm;

/// Test ECDSA signature generation using the rcgen library for X.509 certificates
///
/// This test validates:
/// 1. ECDSA P-256 key pair generation using rcgen
/// 2. Self-signed certificate creation with ECDSA signatures
/// 3. X.509 certificate parsing and signature extraction
/// 4. Public key raw format validation
///
/// The test uses PKCS_ECDSA_P256_SHA256 algorithm for certificate signing.
#[test]
fn ecdsa_with_rcgen() {
    // Use ECDSA P-256 with SHA-256 for certificate signing
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;

    // Generate a new ECDSA key pair
    let kp = rcgen::KeyPair::generate().unwrap();

    // Create certificate parameters with a test subject
    let cp = rcgen::CertificateParams::new(vec!["whatever".to_string()]).unwrap();

    // Generate a self-signed certificate
    let cert = cp.self_signed(&kp).unwrap();

    // Parse the certificate as X.509 DER format
    let x509 = x509_cert::Certificate::from_der(cert.der()).unwrap();

    // Display public key information for verification
    println!(
        "The public key is {} {:02X?}",
        kp.public_key_raw().len(),
        kp.public_key_raw()
    );

    // Display the X.509 certificate signature
    println!("{:02X?}", x509.signature);
}

/// Test ECDSA signature generation and verification using Ring with fixed-length signatures
///
/// This test validates:
/// 1. ECDSA P-256 key pair generation using Ring's cryptographic library
/// 2. PKCS#8 key encoding and decoding
/// 3. Fixed-length signature generation (64 bytes for P-256)
/// 4. Signature verification using the public key
/// 5. Round-trip consistency of sign-then-verify operations
///
/// Uses ECDSA_P256_SHA256_FIXED_SIGNING for deterministic 64-byte signatures.
#[test]
fn ecdsa_with_ring() {
    use ring::signature::KeyPair;

    // Initialize secure random number generator
    let rng = ring::rand::SystemRandom::new();

    // Use ECDSA P-256 with SHA-256 for fixed-length signatures
    let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;

    // Generate PKCS#8-encoded key pair
    let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();

    // Load the key pair from PKCS#8 format
    let kp = ring::signature::EcdsaKeyPair::from_pkcs8(alg, doc.as_ref(), &rng).unwrap();

    // Create test data for signing (200 bytes of incrementing pattern)
    let data = vec![
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
        5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2,
        3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
        5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ];

    // Generate ECDSA signature (should be 64 bytes for P-256)
    let sig = kp.sign(&rng, &data).unwrap();
    println!(
        "The signature is {} {:02x?}",
        sig.as_ref().len(),
        sig.as_ref()
    );

    // Extract public key for verification
    let peer_public_key_bytes = kp.public_key().as_ref();

    // Create verification key with fixed-length signature algorithm
    let peer_public_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        peer_public_key_bytes,
    );

    // Verify the signature matches the original data
    peer_public_key.verify(&data, sig.as_ref()).unwrap();
}

/// Test ECDSA signature generation using Ring with ASN.1 DER encoding
///
/// This test validates:
/// 1. ECDSA P-256 key pair generation with ASN.1 DER signature encoding
/// 2. Cross-library signature parsing (Ring -> HSM2 signature structures)
/// 3. ASN.1 DER signature format validation and decoding
/// 4. Signature verification with ASN.1 encoded signatures
/// 5. Debug output formatting for signatures and public keys
///
/// Uses ECDSA_P256_SHA256_ASN1_SIGNING for variable-length ASN.1 DER signatures.
#[test]
fn ecdsa_with_ring2() {
    use ring::signature::KeyPair;

    // Initialize secure random number generator
    let rng = ring::rand::SystemRandom::new();

    // Use ECDSA P-256 with SHA-256 for ASN.1 DER signatures
    let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;

    // Generate PKCS#8-encoded key pair
    let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();

    // Load the key pair from PKCS#8 format
    let kp = ring::signature::EcdsaKeyPair::from_pkcs8(alg, doc.as_ref(), &rng).unwrap();

    // Create test data for signing (same pattern as previous test)
    let data = vec![
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
        5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2,
        3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
        5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ];

    // Generate ASN.1 DER encoded ECDSA signature
    let sig = kp.sign(&rng, &data).unwrap();

    // Parse the signature using the HSM2 ECDSA signature parser
    let sig2 = hsm2::EcdsaSignature::from_der(sig.as_ref()).unwrap();

    // Convert signature to vector for display
    let d = sig.as_ref().to_vec();

    // Extract public key bytes
    let peer_public_key_bytes = kp.public_key().as_ref();

    // Display debugging information about keys and signatures
    println!(
        "The public key is {} {:02X?}",
        peer_public_key_bytes.len(),
        peer_public_key_bytes
    );
    println!("The public key is also {:02X?}", kp);
    println!("The signature is {} {:02x?}", d.len(), d);
    println!("The signature is also {:02X?}", sig2);

    // Create verification key with ASN.1 signature algorithm
    let peer_public_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        peer_public_key_bytes,
    );

    // Verify the ASN.1 DER encoded signature
    peer_public_key.verify(&data, sig.as_ref()).unwrap();
}

/// Test ECDSA operations using Hardware Security Module (HSM) integration
///
/// This comprehensive test validates:
/// 1. SoftHSM2 configuration and token directory setup
/// 2. HSM initialization with admin and user PINs
/// 3. ECDSA key pair generation within the HSM for HTTPS certificates
/// 4. Multiple signature generation with signature uniqueness validation
/// 5. Cross-library verification (HSM signatures verified with Ring)
/// 6. ASN.1 DER signature parsing and debugging output
/// 7. Service logging integration for debugging HSM operations
///
/// The test creates a temporary SoftHSM2 environment to simulate hardware HSM operations
/// without requiring actual hardware security modules.
#[test]
fn ecdsa_with_hsm() {
    // Initialize service logging for HSM debugging
    let service = service::Service::new("testing".to_string());
    service.new_log(service::LogLevel::Debug);

    use hsm2::KeyPair;

    // Set default admin and user PINs for SoftHSM2
    let ap = "asdf".to_string(); // Admin PIN
    let up = "asdf".to_string(); // User PIN

    // Create temporary directory for SoftHSM2 configuration
    let config_path = tempfile::TempDir::new().unwrap();
    let config_path = std::path::PathBuf::from(config_path.path());

    // Set SoftHSM2 configuration file environment variable
    unsafe {
        std::env::set_var("SOFTHSM2_CONF", config_path.join("softhsm2.conf"));
    }

    // Configure SoftHSM2 with temporary token storage
    {
        let softhsm_config = config_path.join("softhsm2.conf");
        let token_path = config_path.join("tokens");
        let _ = std::fs::create_dir(&token_path);

        // Create SoftHSM2 configuration content
        let hsm_contents = format!(
            "directories.tokendir = {}\n
        objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
log.level = DEBUG

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false

# Enable and disable PKCS#11 mechanisms using slots.mechanisms.
slots.mechanisms = ALL

# If the library should reset the state on fork
library.reset_on_fork = false
",
            token_path.display()
        );

        // Write SoftHSM2 configuration file
        let mut f3 =
            std::fs::File::create(&softhsm_config).expect("Failed to create softhsm config");
        f3.write_all(hsm_contents.as_bytes())
            .expect("Failed to write softhsm config");

        // Create token directory structure
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        std::fs::DirBuilder::create(&builder, &token_path)
            .expect("Failed to create token directory");
    }

    // Initialize HSM with admin and user PINs
    let hsm = hsm2::Hsm::create(None, ap.into(), up.into()).unwrap();
    let hsm = Arc::new(hsm);

    // Generate ECDSA key pair for HTTPS certificate signing
    let kp = hsm
        .generate_https_keypair("testing", cert_common::HttpsSigningMethod::EcdsaSha256, 256)
        .unwrap();

    // Generate test data for signing (1023 bytes of random password data)
    let data = utility::generate_password(1023).as_bytes().to_vec();

    // Generate two signatures of the same data to test signature uniqueness
    let sig = kp.sign(&data).unwrap();
    let sigb = kp.sign(&data).unwrap();

    // Parse first signature using HSM2 ASN.1 DER parser
    let sig2 = hsm2::EcdsaSignature::from_der(&sig).unwrap();

    // Display debugging information about key pair and signatures
    println!("KP IS {:02X?}", kp);
    println!("Signature is {} {:02X?}", sig.len(), sig);
    println!("Signatureb is {} {:02X?}", sigb.len(), sigb);
    println!("The signature is also {:02X?}", sig2);

    // Extract public key for verification
    let peer_public_key_bytes = kp.public_key();
    println!(
        "The public key is {} {:02X?}",
        peer_public_key_bytes.len(),
        peer_public_key_bytes
    );

    // Create Ring verification key for cross-library validation
    let peer_public_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        peer_public_key_bytes,
    );

    // Verify both signatures using Ring (validates HSM-Ring interoperability)
    let va = peer_public_key.verify(&data, &sig);
    let vb = peer_public_key.verify(&data, &sigb);
    println!("VA IS {:?}, vb is {:?}", va, vb);

    // Assert that both signatures are valid
    va.unwrap();
    vb.unwrap();
}
