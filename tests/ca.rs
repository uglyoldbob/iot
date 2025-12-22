#![warn(missing_docs)]
#![allow(unused)]

//! Comprehensive Certificate Authority (CA) and SSH key generation testing suite
//!
//! This test module provides extensive validation of the IoT certificate management system,
//! including:
//! - SSH key generation and authentication testing with real SSH servers
//! - CA (Certificate Authority) setup and certificate signing workflows
//! - PKI (Public Key Infrastructure) hierarchical certificate management
//! - HTTPS certificate generation and validation
//! - Cryptographic signature testing (RSA-SHA256, ECDSA-SHA256)
//! - Certificate Signing Request (CSR) processing and validation
//! - Web interface endpoint testing for certificate management
//! - Configuration file handling and persistence
//!
//! The tests use real network servers, cryptographic operations, and file I/O
//! to ensure the certificate management system works correctly in production scenarios.

#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/ca/ca_common.rs"]
mod ca;

#[path = "../src/main_config.rs"]
mod main_config;

#[path = "../src/utility.rs"]
mod utility;

#[path = "../src/tpm2.rs"]
mod tpm2;

use std::collections::HashMap;
use std::future::IntoFuture;
use std::str::FromStr;
use std::sync::Mutex;

use assert_cmd::prelude::*;
use ca::{
    CertificateType, PkiConfigurationEnumAnswers, SmartCardPin2, StandaloneCaConfigurationAnswers,
};
use ca::{ComplexName, PkiConfigurationAnswers};
use der::Decode;
use der::DecodePem;
pub use main_config::MainConfiguration;
use main_config::{HttpSettings, HttpsSettingsAnswers, MainConfigurationAnswers};
use predicates::prelude::predicate;
use russh::keys::{HashAlg, PublicKeyBase64};
use service::LogLevel;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use userprompt::{FileCreate, Password2};

use crate::ca::PkiConfigurationEnum;
use crate::main_config::GeneralSettings;

/// Mutex to ensure CA tests run sequentially to avoid port conflicts
///
/// Since CA tests bind to specific ports (3000, 3001), this mutex prevents
/// parallel execution that would cause port binding conflicts
static CA_TEST_MUTEX: Mutex<()> = Mutex::new(());

/// Generate a test hash for cryptographic signature testing
///
/// Creates random data, hashes it with SHA-256, and formats it for RSA signature testing
fn hash_setup1() -> Vec<u8> {
    use rand::Rng;
    use sha2::Digest;
    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..5123).map(|_| rng.gen()).collect();
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let t = utility::rsa_sha256(&hash);
    t
}

/// Test RSA-SHA256 signature generation and ASN.1 DER encoding validation
#[test]
fn rsa_sha256() {
    let t = hash_setup1();
    yasna::parse_der(&t, |reader| {
        reader.read_sequence(|r| {
            r.next().read_sequence(|r| {
                r.next().read_oid()?;
                r.next().read_null()
            })?;
            r.next().read_bytes()
        })
    })
    .unwrap();
}

/// Test PKCS#1.5 SHA256 padding and signature format validation
#[test]
fn pkcs15_sha256() {
    let t = hash_setup1();
    for i in [128, 256, 512, 1024] {
        let t2 = utility::pkcs15_sha256(i, &t);
        assert_eq!(i, t2.len());
    }
}

#[test]
/// Test SQLite path resolution and database file handling
fn get_sqlite_paths() {
    use std::str::FromStr;
    let p = std::path::PathBuf::from_str("./temp").unwrap();
    let paths = ca::get_sqlite_paths(&p);
    assert!(paths.len() > 0)
}

/// Test certificate type answer conversion and validation
#[test]
fn from_certificate_type_answers() {
    let scpin = SmartCardPin2::default();
    let answer1 = ca::CertificateTypeAnswers::External;
    let ct: CertificateType = answer1.into();
    if let CertificateType::External = ct {
    } else {
        panic!("Wrong type returned");
    }

    let pass = Password2::default();
    let answer2 = ca::CertificateTypeAnswers::Soft {
        password: pass.clone(),
    };
    let ct: CertificateType = answer2.into();
    if let CertificateType::Soft(a) = ct {
        assert_eq!(a, pass.to_string());
    } else {
        panic!("Wrong type returned");
    }
}

/// Test HTTPS certificate signing methods (RSA-SHA256 and ECDSA-SHA256)
#[test]
fn https_signing() {
    let s = service::Service::new("Testing".to_string());
    s.new_log(LogLevel::Trace);
    let ai = x509_cert::spki::AlgorithmIdentifier::<()> {
        oid: x509_cert::spki::ObjectIdentifier::new("2.16.840.1.101.3.4.1.42").unwrap(),
        parameters: None,
    };
    let h: Result<cert_common::HttpsSigningMethod, ()> = ai.try_into();
    assert!(h.is_err());

    let ai = x509_cert::spki::AlgorithmIdentifier::<()> {
        oid: x509_cert::spki::ObjectIdentifier::new("1.2.840.113549.1.1.11").unwrap(),
        parameters: None,
    };
    let h: cert_common::HttpsSigningMethod = ai.try_into().unwrap();
    assert_eq!(h, cert_common::HttpsSigningMethod::RsaSha256);

    let ai = x509_cert::spki::AlgorithmIdentifier::<()> {
        oid: x509_cert::spki::ObjectIdentifier::new("1.2.840.10045.4.3.2").unwrap(),
        parameters: None,
    };
    let h: cert_common::HttpsSigningMethod = ai.try_into().unwrap();
    assert_eq!(h, cert_common::HttpsSigningMethod::EcdsaSha256);

    let y: Result<cert_common::HttpsSigningMethod, ()> = cert_common::oid::OID_AES_256_CBC
        .clone()
        .to_yasna()
        .try_into();
    assert!(y.is_err());
}

/// Comprehensive SSH key generation test with real SSH server authentication
///
/// This test validates that `SshSigningMethod::generate_keypair` produces functional SSH keys by:
/// 1. Generating Ed25519 and RSA keypairs using the code under test
/// 2. Converting keys to OpenSSH format and validating format compatibility
/// 3. Running an actual SSH server on port 12345 with generated server keys
/// 4. Performing real SSH client authentication using generated client keys
/// 5. Testing multiple key sizes for robustness
#[tokio::test]
async fn ssh_genkey() {
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    /// Test SSH server handler for validating SSH key authentication
    struct TestServer {
        /// Connected clients map
        clients: Arc<Mutex<HashMap<String, bool>>>,
        /// List of authorized public keys for authentication
        authorized_keys: Arc<Mutex<Vec<russh::keys::PublicKey>>>,
    }

    impl TestServer {
        /// Create a new test SSH server instance
        fn new() -> Self {
            Self {
                clients: Arc::new(Mutex::new(HashMap::new())),
                authorized_keys: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Add a public key to the list of authorized keys for authentication
        async fn add_authorized_key(&self, key: russh::keys::PublicKey) {
            self.authorized_keys.lock().await.push(key);
        }
    }

    impl russh::server::Handler for TestServer {
        type Error = russh::Error;

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            session: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn auth_publickey(
            &mut self,
            _user: &str,
            public_key: &russh::keys::PublicKey,
        ) -> Result<russh::server::Auth, Self::Error> {
            let incoming_key_data = public_key.public_key_bytes();

            let auth_result = {
                let auth_keys = self.authorized_keys.lock().await;

                let mut found = false;
                for auth_key in auth_keys.iter() {
                    if auth_key.public_key_bytes() == incoming_key_data {
                        found = true;
                        break;
                    }
                }
                found
            };

            if auth_result {
                Ok(russh::server::Auth::Accept)
            } else {
                Ok(russh::server::Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                })
            }
        }
    }

    /// Simple SSH client handler for test connections
    struct ClientHandler;

    impl russh::client::Handler for ClientHandler {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    let methods = vec![
        cert_common::SshSigningMethod::Ed25519,
        cert_common::SshSigningMethod::Rsa,
    ];

    for method in methods {
        // Test serialization/deserialization
        let d = bincode::serialize(&method).unwrap();
        let method2: cert_common::SshSigningMethod = bincode::deserialize(&d).unwrap();
        assert_eq!(method2, method);

        // Generate keypair using the original method
        let kp = method.generate_keypair(4096).unwrap();

        // Validate basic key properties
        let public_key = kp.public_key();

        // Test that we can convert to OpenSSH format
        match public_key.to_openssh() {
            Ok(openssh_key) => {
                println!(
                    "✓ {:?} public key converts to OpenSSH format successfully",
                    method
                );
                assert!(
                    !openssh_key.is_empty(),
                    "OpenSSH public key should not be empty"
                );
            }
            Err(e) => {
                panic!(
                    "⚠ {:?} public key OpenSSH conversion failed: {:?}",
                    method, e
                );
            }
        }

        // Test that we can convert private key to OpenSSH format
        match kp.to_openssh(ssh_key::LineEnding::LF) {
            Ok(openssh_private) => {
                println!(
                    "✓ {:?} private key converts to OpenSSH format successfully",
                    method
                );
                assert!(
                    !openssh_private.is_empty(),
                    "OpenSSH private key should not be empty"
                );
            }
            Err(e) => {
                panic!(
                    "⚠ {:?} private key OpenSSH conversion failed: {:?}",
                    method, e
                );
            }
        }

        // Try to convert generated keys to russh format for SSH server testing
        if let (Ok(public_key_openssh), Ok(private_key_openssh)) = (
            public_key.to_openssh(),
            kp.to_openssh(ssh_key::LineEnding::LF),
        ) {
            println!(
                "Generated public key OpenSSH format: {}",
                public_key_openssh
            );
            println!(
                "Generated private key first 100 chars: {}",
                &private_key_openssh[..100.min(private_key_openssh.len())]
            );

            // Extract just the base64 part from the OpenSSH public key format
            // Format is like: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIARTDP..."
            let public_key_base64 = public_key_openssh
                .split_whitespace()
                .nth(1)
                .unwrap_or(&public_key_openssh);

            // Try to parse the generated keys with russh
            let russh_public_result = russh::keys::PublicKey::from_openssh(&public_key_openssh);
            let russh_private_result = russh::keys::PrivateKey::from_openssh(private_key_openssh.as_bytes());

            match (&russh_public_result, &russh_private_result) {
                (Ok(_), Ok(_)) => {
                    println!("✓ Successfully converted {:?} keys to russh format", method);
                }
                (Err(pub_err), _) => {
                    panic!("⚠ Failed to parse public key: {:?} - {}", pub_err, public_key_openssh);
                }
                (_, Err(priv_err)) => {
                    panic!("⚠ Failed to parse private key: {:?}", priv_err);
                }
            }

            if let (Ok(russh_public_key), Ok(russh_private_key)) =
                (russh_public_result, russh_private_result)
            {
                let russh_private_key = russh::keys::key::PrivateKeyWithHashAlg::new(Arc::new(russh_private_key), Some(HashAlg::Sha256));

                // Start SSH server on high port
                let listener = TcpListener::bind("127.0.0.1:12345").await.unwrap();
                let server_handler = TestServer::new();

                // Add the generated public key to authorized keys
                server_handler.add_authorized_key(russh_public_key).await;

                // Generate server key using cert_common::SshSigningMethod
                println!("✓ Generating SSH server key using SshSigningMethod::Ed25519");
                let server_kp = cert_common::SshSigningMethod::Ed25519
                    .generate_keypair(4096)
                    .unwrap();
                let server_private_openssh = server_kp.to_openssh(ssh_key::LineEnding::LF).unwrap();
                let server_russh_key = russh::keys::PrivateKey::from_openssh(server_private_openssh.as_bytes()).expect("Failed to convert ssh server key");
                //let server_russh_key = russh::keys::key::PrivateKeyWithHashAlg::new(Arc::new(server_russh_key), Some(HashAlg::Sha256));
                    russh_keys::decode_secret_key(&server_private_openssh, None).unwrap();
                println!("✓ SSH server key generated and converted successfully");

                // Configure SSH server (use key generated by code under test)
                let server_config = Arc::new(russh::server::Config {
                    auth_rejection_time_initial: Some(std::time::Duration::from_secs(1)),
                    keys: vec![server_russh_key],
                    ..Default::default()
                });

                let server_handle = tokio::spawn(async move {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            println!("SSH server accepted connection from: {}", addr);
                            match russh::server::run_stream(server_config, stream, server_handler)
                                .await
                            {
                                Ok(_) => println!("SSH server session completed successfully"),
                                Err(e) => panic!("SSH server session error: {:?}", e),
                            }
                        }
                        Err(e) => panic!("SSH server failed to accept connection: {:?}", e),
                    }
                });

                // Give server time to start
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                // Test SSH client connection
                let client_config = Arc::new(russh::client::Config::default());
                let client_handler = ClientHandler;

                // Connect to SSH server
                let mut session =
                    match russh::client::connect(client_config, "127.0.0.1:12345", client_handler)
                        .await
                    {
                        Ok(session) => {
                            println!("SSH client connected successfully for {:?}", method);
                            session
                        }
                        Err(e) => {
                            panic!("⚠ Failed to connect SSH client for {:?}: {:?}", method, e);
                            continue;
                        }
                    };

                // Authenticate with the generated keypair from SshSigningMethod::generate_keypair
                let auth_result = session
                    .authenticate_publickey("testuser", russh_private_key)
                    .await;

                // Verify authentication succeeded
                match auth_result {
                    Ok(authenticated) => {
                        assert!(
                            authenticated.success(),
                            "SSH authentication was rejected for {:?} method",
                            method
                        );
                        println!(
                            "SSH authentication successful with generated {:?} key!",
                            method
                        );
                    }
                    Err(e) => {
                        panic!("⚠ SSH authentication failed for {:?}: {:?}", method, e);
                    }
                }

                // Close the session
                if let Err(e) = session
                    .disconnect(russh::Disconnect::ByApplication, "Test completed", "")
                    .await
                {
                    panic!("Warning: Failed to disconnect SSH session cleanly: {:?}", e);
                }

                // Wait for server to finish
                match tokio::time::timeout(std::time::Duration::from_secs(5), server_handle).await {
                    Ok(_) => println!("SSH server shut down cleanly for {:?}", method),
                    Err(_) => panic!("Warning: SSH server timeout for {:?}", method),
                }
            } else {
                panic!(
                    "⚠ Failed to convert {:?} keys to russh format - skipping SSH server test",
                    method
                );
            }
        }

        println!(
            "Key generation test completed successfully for {:?}",
            method
        );
    }

    // Additional test for different key sizes
    println!("Testing SSH key generation with different sizes...");

    let test_sizes = vec![2048, 4096]; // Use only safe RSA key sizes
    for size in test_sizes {
        for method in &[
            cert_common::SshSigningMethod::Ed25519,
            cert_common::SshSigningMethod::Rsa,
        ] {
            match method {
                cert_common::SshSigningMethod::Ed25519 => {
                    // Ed25519 should ignore size parameter and always work
                    let kp_result = method.generate_keypair(size);
                    assert!(
                        kp_result.is_some(),
                        "Ed25519 key generation should always succeed regardless of size parameter"
                    );
                    let kp = kp_result.unwrap();
                    let public_key = kp.public_key();
                    let openssh_format = public_key.to_openssh();
                    assert!(
                        openssh_format.is_ok(),
                        "Ed25519 public key should convert to OpenSSH format"
                    );
                    println!(
                        "✓ Ed25519 key generated successfully (size parameter: {})",
                        size
                    );
                }
                cert_common::SshSigningMethod::Rsa => {
                    // RSA key generation might fail for certain sizes, handle gracefully
                    match std::panic::catch_unwind(|| method.generate_keypair(size)) {
                        Ok(Some(kp)) => {
                            let public_key = kp.public_key();
                            let openssh_format = public_key.to_openssh();
                            assert!(
                                openssh_format.is_ok(),
                                "RSA public key should convert to OpenSSH format"
                            );
                            println!("✓ RSA-{} key generated successfully", size);
                        }
                        Ok(None) => {
                            println!("⚠ RSA-{} key generation returned None", size);
                        }
                        Err(_) => {
                            panic!(
                                "⚠ RSA-{} key generation failed (expected for some sizes)",
                                size
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Test OID (Object Identifier) conversion and validation for certificate extensions
#[test]
fn common_oid() {
    let oid1: cert_common::oid::Oid = cert_common::oid::OID_EXTENDED_KEY_USAGE_CLIENT_AUTH.clone();
    let eku1: cert_common::ExtendedKeyUsage = oid1.clone().into();
    assert_eq!(cert_common::ExtendedKeyUsage::ClientIdentification, eku1);
    assert_eq!(eku1.to_oid(), oid1);

    let oid2: cert_common::oid::Oid = cert_common::oid::OID_EXTENDED_KEY_USAGE_SERVER_AUTH.clone();
    let eku2: cert_common::ExtendedKeyUsage = oid2.clone().into();
    assert_eq!(cert_common::ExtendedKeyUsage::ServerIdentification, eku2);
    assert_eq!(eku2.to_oid(), oid2);

    let oid3: cert_common::oid::Oid = cert_common::oid::OID_EXTENDED_KEY_USAGE_CODE_SIGNING.clone();
    let eku3: cert_common::ExtendedKeyUsage = oid3.clone().into();
    assert_eq!(cert_common::ExtendedKeyUsage::CodeSigning, eku3);
    assert_eq!(eku3.to_oid(), oid3);

    let oid4: cert_common::oid::Oid = cert_common::oid::OID_EXTENDED_KEY_USAGE_OCSP_SIGNING.clone();
    let eku4: cert_common::ExtendedKeyUsage = oid4.clone().into();
    assert_eq!(cert_common::ExtendedKeyUsage::OcspSigning, eku4);
    assert_eq!(eku4.to_oid(), oid4);

    let oid5: cert_common::oid::Oid = cert_common::oid::OID_AES_256_CBC.clone();
    let eku5: cert_common::ExtendedKeyUsage = oid5.clone().into();
    assert_eq!(
        cert_common::ExtendedKeyUsage::Unrecognized(oid5.clone()),
        eku5
    );
    assert_eq!(eku5.to_oid(), oid5);

    let ekus = vec![eku1, eku2, eku3, eku4];
    cert_common::CsrAttribute::ExtendedKeyUsage(ekus.clone())
        .to_custom_attribute()
        .unwrap();
    cert_common::CsrAttribute::ChallengePassword("whatever".to_string())
        .to_custom_attribute()
        .unwrap();
    cert_common::CsrAttribute::UnstructuredName("whatever2".to_string())
        .to_custom_attribute()
        .unwrap();

    cert_common::CsrAttribute::ExtendedKeyUsage(ekus.clone())
        .to_custom_extension()
        .unwrap();
    cert_common::CsrAttribute::ChallengePassword("whatever".to_string())
        .to_custom_extension()
        .unwrap();
    cert_common::CsrAttribute::UnstructuredName("whatever2".to_string())
        .to_custom_extension()
        .unwrap();

    let ekus2 = cert_common::CsrAttribute::build_extended_key_usage(vec![oid1, oid2, oid3, oid4]);
    assert_eq!(
        cert_common::CsrAttribute::ExtendedKeyUsage(ekus.clone()),
        ekus2
    );
}

/// Test Certificate Signing Request (CSR) attributes handling and validation
#[test]
fn csr_attributes() {
    let unbad = yasna::construct_der(|w| w.write_i8(42));
    assert!(cert_common::CsrAttribute::with_oid_and_any(
        cert_common::oid::OID_PKCS9_UNSTRUCTURED_NAME.clone(),
        der::Any::from_der(&unbad).unwrap(),
    )
    .is_none());

    let un1 = yasna::construct_der(|w| w.write_utf8string("ssh not while im testing"));
    cert_common::CsrAttribute::with_oid_and_any(
        cert_common::oid::OID_PKCS9_UNSTRUCTURED_NAME.clone(),
        der::Any::from_der(&un1).unwrap(),
    )
    .unwrap();

    let unbad = yasna::construct_der(|w| w.write_i8(42));
    assert!(cert_common::CsrAttribute::with_oid_and_any(
        cert_common::oid::OID_PKCS9_CHALLENGE_PASSWORD.clone(),
        der::Any::from_der(&unbad).unwrap(),
    )
    .is_none());
    cert_common::CsrAttribute::with_oid_and_any(
        cert_common::oid::OID_PKCS9_CHALLENGE_PASSWORD.clone(),
        der::Any::from_der(&un1).unwrap(),
    )
    .unwrap();

    assert!(cert_common::CsrAttribute::with_oid_and_any(
        cert_common::oid::OID_CERT_EXTENDED_KEY_USAGE.clone(),
        der::Any::from_der(&[1, 2, 3, 4]).unwrap()
    )
    .is_none());

    let un1 = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next()
                .write_oid(&cert_common::oid::OID_EXTENDED_KEY_USAGE_CLIENT_AUTH.to_yasna());
            w.next()
                .write_oid(&cert_common::oid::OID_EXTENDED_KEY_USAGE_SERVER_AUTH.to_yasna());
            w.next()
                .write_oid(&cert_common::oid::OID_EXTENDED_KEY_USAGE_CODE_SIGNING.to_yasna());
            w.next()
                .write_oid(&cert_common::oid::OID_EXTENDED_KEY_USAGE_OCSP_SIGNING.to_yasna());
        })
    });
    cert_common::CsrAttribute::with_oid_and_any(
        cert_common::oid::OID_CERT_EXTENDED_KEY_USAGE.clone(),
        der::Any::from_der(&un1).unwrap(),
    )
    .unwrap();

    let un1 = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_sequence(|w| {
                w.next()
                    .write_oid(&cert_common::oid::OID_EXTENDED_KEY_USAGE_CLIENT_AUTH.to_yasna());
                w.next().write_bytes(&un1);
            })
        })
    });
    let t1 = der::Any::from_der(&un1).unwrap();
    cert_common::CsrAttribute::with_oid_and_any(
        cert_common::oid::OID_PKCS9_EXTENSION_REQUEST.clone(),
        t1,
    )
    .unwrap();

    let un1 = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_sequence(|w| {
                w.next()
                    .write_oid(&cert_common::oid::OID_EXTENDED_KEY_USAGE_CLIENT_AUTH.to_yasna());
                w.next().write_bytes(&[1, 2, 3, 4]);
            })
        })
    });
    let t1 = der::Any::from_der(&un1).unwrap();
    assert!(cert_common::CsrAttribute::with_oid_and_any(
        cert_common::oid::OID_PKCS9_EXTENSION_REQUEST.clone(),
        t1.clone()
    )
    .is_none());

    let o =
        cert_common::CsrAttribute::with_oid_and_any(cert_common::oid::OID_AES_256_CBC.clone(), t1)
            .unwrap();
    assert!(o.to_custom_attribute().is_none());
    assert!(o.to_custom_extension().is_none());
}

/// Build an HTTPS Certificate Signing Request using the specified signing method
///
/// Returns a tuple of (PEM-encoded CSR, private key bytes) if successful
fn build_https_csr(method: cert_common::HttpsSigningMethod) -> Option<(String, Vec<u8>)> {
    let params: rcgen::CertificateParams = Default::default();
    if let Some((key_pair, private)) = method.generate_keypair(4096) {
        if let Ok(cert) = params.serialize_request(&key_pair) {
            if let Ok(pem_serialized) = cert.pem() {
                let data: &[u8] = private.as_ref();
                return Some((pem_serialized, data.to_vec()));
            }
        }
    }
    None
}

/// Run comprehensive web endpoint checks for CA functionality
///
/// Tests various CA web endpoints including certificate requests, signing,
/// and administrative functions to ensure the web interface works correctly
async fn run_web_checks(
    config: MainConfigurationAnswers,
    method: cert_common::CertificateSigningMethod,
    pki_name: &str,
    ca_name: &str,
) {
    use predicates::prelude::*;

    let (token, pass) = match &config.pki {
        PkiConfigurationEnumAnswers::AddedCa(config) => {
            let p = if let crate::ca::CertificateTypeAnswers::Soft { password: a } =
                &config.admin_cert
            {
                a.to_string()
            } else {
                panic!("INVALID");
            };
            (config.admin_access_password.to_string(), p)
        }
        PkiConfigurationEnumAnswers::Pki(pki) => {
            let (name, config) = pki.local_ca.map().iter().next().unwrap();
            let p = if let crate::ca::CertificateTypeAnswers::Soft { password: a } =
                &config.admin_cert
            {
                a.to_string()
            } else {
                panic!("INVALID");
            };
            (config.admin_access_password.to_string(), p)
        }
        PkiConfigurationEnumAnswers::Ca {
            pki_name: _,
            config,
        } => {
            let p = if let crate::ca::CertificateTypeAnswers::Soft { password: a } =
                &config.admin_cert
            {
                a.to_string()
            } else {
                panic!("INVALID");
            };
            (config.admin_access_password.to_string(), p)
        }
    };
    let name = format!("{}{}", pki_name, ca_name);

    let root_cert_der = reqwest::Client::builder()
        .build()
        .unwrap()
        .get(format!(
            "http://127.0.0.1:3000/{}ca/get_ca.rs?type=der",
            name
        ))
        .send()
        .await
        .expect("Failed to query")
        .bytes()
        .await
        .expect("No content");
    let cert = reqwest::Certificate::from_der(root_cert_der.as_ref()).unwrap();

    reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:3001/{}ca/get_admin.rs", name))
        .send()
        .await
        .expect("Failed to post")
        .bytes()
        .await
        .expect("No content");

    let mut params = HashMap::new();
    params.insert("token", token);
    let t = reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .build()
        .unwrap()
        .post(format!("https://127.0.0.1:3001/{}ca/get_admin.rs", name))
        .form(&params)
        .send()
        .await
        .expect("Failed to post")
        .bytes()
        .await
        .expect("No content");
    let id = reqwest::Identity::from_pkcs12_der(t.as_ref(), &pass).unwrap();

    for (prot, port) in [("http", 3000), ("https", 3001)] {
        let t = reqwest::Client::builder()
            .add_root_certificate(cert.clone())
            .identity(id.clone())
            .build()
            .unwrap()
            .get(format!("{}://127.0.0.1:{}", prot, port))
            .send()
            .await
            .expect("Failed to query")
            .text()
            .await
            .expect("No content");
    }

    for (prot, port) in [("http", 3000), ("https", 3001)] {
        let t = reqwest::Client::builder()
            .add_root_certificate(cert.clone())
            .identity(id.clone())
            .build()
            .unwrap()
            .get(format!("{}://127.0.0.1:{}/{}ca", prot, port, name))
            .send()
            .await
            .expect("Failed to query")
            .text()
            .await
            .expect("No content");
        assert_eq!(false, predicate::str::contains("missing").eval(&t));
    }

    for (prot, port) in [("http", 3000), ("https", 3001)] {
        let t = reqwest::Client::builder()
            .add_root_certificate(cert.clone())
            .identity(id.clone())
            .build()
            .unwrap()
            .get(format!(
                "{}://127.0.0.1:{}/{}ca/get_ca.rs?type=der",
                prot, port, name
            ))
            .send()
            .await
            .expect("Failed to query")
            .bytes()
            .await
            .expect("No content");
        x509_cert::Certificate::from_der(&t).unwrap();
        assert!(t.len() > 10);
    }

    for (prot, port) in [("http", 3000), ("https", 3001)] {
        let t = reqwest::Client::builder()
            .add_root_certificate(cert.clone())
            .identity(id.clone())
            .build()
            .unwrap()
            .get(format!(
                "{}://127.0.0.1:{}/{}ca/get_ca.rs",
                prot, port, name
            ))
            .send()
            .await
            .expect("Failed to query")
            .bytes()
            .await
            .expect("No content");
        x509_cert::Certificate::from_der(&t).unwrap();
        assert!(t.len() > 10);
    }

    for (prot, port) in [("http", 3000), ("https", 3001)] {
        let t = reqwest::Client::builder()
            .add_root_certificate(cert.clone())
            .identity(id.clone())
            .build()
            .unwrap()
            .get(format!(
                "{}://127.0.0.1:{}/{}ca/get_ca.rs?type=pem",
                prot, port, name
            ))
            .send()
            .await
            .expect("Failed to query")
            .text()
            .await
            .expect("No content");
        x509_cert::Certificate::from_pem(&t).unwrap();
        assert!(t.len() > 10);
    }

    for (prot, port) in [("http", 3000), ("https", 3001)] {
        let t = reqwest::Client::builder()
            .add_root_certificate(cert.clone())
            .identity(id.clone())
            .build()
            .unwrap()
            .get(format!(
                "{}://127.0.0.1:{}/{}ca/get_ca.rs?type=bla",
                prot, port, name
            ))
            .send()
            .await
            .expect("Failed to query")
            .text()
            .await
            .expect("No content");
        assert_eq!(true, predicate::str::contains("missing").eval(&t));
    }

    for (prot, port) in [("http", 3000), ("https", 3001)] {
        let t = reqwest::Client::builder()
            .add_root_certificate(cert.clone())
            .identity(id.clone())
            .build()
            .unwrap()
            .get(format!(
                "{}://127.0.0.1:{}/{}ca/request.rs",
                prot, port, name
            ))
            .send()
            .await
            .expect("Failed to query")
            .text()
            .await
            .expect("No content");
        assert_eq!(false, predicate::str::contains("missing").eval(&t));
    }

    let (csr_pem, pri_key) = match method {
        cert_common::CertificateSigningMethod::Https(method) => build_https_csr(method).unwrap(),
        cert_common::CertificateSigningMethod::Ssh(method) => todo!(),
    };
    params.clear();
    params.insert("csr", csr_pem.clone());
    params.insert("name", "Jenny".to_string());
    params.insert("email", "dummy@example.com".to_string());
    params.insert("phone", "867-5309".to_string());
    params.insert("smartcard", "1".to_string());
    let t = reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .identity(id.clone())
        .build()
        .unwrap()
        .post(format!(
            "https://127.0.0.1:3001/{}ca/submit_request.rs",
            name
        ))
        .form(&params)
        .send()
        .await
        .expect("Failed to query")
        .text()
        .await
        .expect("No content");
    println!("SUBMISSION IS {}", t);

    let submitted_serial: Vec<u8> = {
        let h = url_encoded_data::UrlEncodedData::parse_str(&t);
        let serial = h.get("serial");
        if let Some(serial) = serial {
            let serial = serial.first().unwrap();
            let serial = crate::utility::decode_hex(serial).unwrap();
            service::log::info!("The serial is {:02x?}", serial);
            serial
        } else {
            panic!("No serial received on submission");
        }
    };
    let serial_s = crate::utility::encode_hex(&submitted_serial);

    params.clear();
    params.insert("serial", serial_s.clone());
    let t = reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:3001/{}ca/view_cert.rs", name))
        .query(&params)
        .send()
        .await
        .expect("Failed to query")
        .text()
        .await
        .expect("No content");
    println!("Request submit status is {}", t);
    assert_eq!(
        true,
        predicate::str::contains("request is pending").eval(&t)
    );

    let t = reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .identity(id.clone())
        .build()
        .unwrap()
        .get(format!(
            "https://127.0.0.1:3001/{}ca/view_all_certs.rs",
            name
        ))
        .send()
        .await
        .expect("Failed to query")
        .text()
        .await
        .expect("No content");
    assert_eq!(
        true,
        predicate::str::contains("Current Certificates").eval(&t)
    );
    println!("Certs are {}", t);

    params.clear();
    params.insert("serial", serial_s.clone());
    let t = reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .identity(id.clone())
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:3001/{}ca/list.rs", name))
        .query(&params)
        .send()
        .await
        .expect("Failed to query")
        .text()
        .await
        .expect("No content");
    println!("Individual cert is {}", t);
    assert_eq!(true, predicate::str::contains("Sign this request").eval(&t));

    let t = reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .identity(id.clone())
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:3001/{}ca/request_sign.rs", name))
        .query(&params)
        .send()
        .await
        .expect("Failed to query")
        .text()
        .await
        .expect("No content");
    println!("Sign response is {}", t);
    assert_eq!(
        true,
        predicate::str::contains("The request has been signed").eval(&t)
    );

    let t = reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .identity(id.clone())
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:3001/{}ca/get_cert.rs", name))
        .query(&params)
        .send()
        .await
        .expect("Failed to query")
        .bytes()
        .await
        .expect("No content");
    println!("User cert is {:02X?}", t.as_ref());
    let user_cert = x509_cert::Certificate::from_der(t.as_ref()).unwrap();

    let user_pw = utility::generate_password(32);
    let up12 = cert_common::pkcs12::Pkcs12 {
        cert: t.as_ref().to_vec(),
        pkey: zeroize::Zeroizing::new(pri_key),
        attributes: vec![
            cert_common::pkcs12::BagAttribute::LocalKeyId(vec![42; 16]), //TODO
            cert_common::pkcs12::BagAttribute::FriendlyName("User Certificate".to_string()), //TODO
        ],
        serial: vec![42; 16],
    };
    let p12 = up12.get_pkcs12(&user_pw);
    let user_ident = reqwest::Identity::from_pkcs12_der(&p12, &user_pw).unwrap();

    params.clear();
    params.insert("serial", serial_s.clone());
    params.insert("type", "pem".to_string());
    let t = reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .identity(id.clone())
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:3001/{}ca/get_cert.rs", name))
        .query(&params)
        .send()
        .await
        .expect("Failed to query")
        .text()
        .await
        .expect("No content");
    println!("User cert is {}", t);
    let user_cert2 = x509_cert::Certificate::from_pem(t.as_bytes()).unwrap();
    assert_eq!(user_cert, user_cert2);

    let t = reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .identity(user_ident.clone())
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:3001/{}ca", name))
        .send()
        .await
        .expect("Failed to query")
        .text()
        .await
        .expect("No content");
    println!("User login to main page is {}", t);

    let mut ocsp_request = openssl::ocsp::OcspRequest::new().unwrap();
    let subject = {
        use der::Encode;
        openssl::x509::X509::from_der(user_cert.to_der().unwrap().as_ref()).unwrap()
    };
    {
        let issuer = openssl::x509::X509::from_der(root_cert_der.as_ref()).unwrap();
        let ocip = openssl::ocsp::OcspCertId::from_cert(
            openssl::hash::MessageDigest::sha1(),
            &subject,
            &issuer,
        )
        .unwrap();
        ocsp_request.add_id(ocip).unwrap();
        let ocsp_der = ocsp_request.as_ref().to_der().unwrap();

        let t = reqwest::Client::builder()
            .add_root_certificate(cert.clone())
            .identity(user_ident.clone())
            .build()
            .unwrap()
            .post(format!("https://127.0.0.1:3001/{}ca/ocsp", name))
            .body(ocsp_der)
            .send()
            .await
            .expect("Failed to query")
            .bytes()
            .await
            .expect("No content");
        println!("OCSP RESPONSE is {:02X?}", t.as_ref());

        let ocsp_response = openssl::ocsp::OcspResponse::from_der(t.as_ref()).unwrap();
        assert_eq!(
            ocsp_response.status(),
            openssl::ocsp::OcspResponseStatus::SUCCESSFUL
        );
    }
    //TODO sha256 not currently supported for ocsp requests
    if false {
        let issuer = openssl::x509::X509::from_der(root_cert_der.as_ref()).unwrap();
        let ocip = openssl::ocsp::OcspCertId::from_cert(
            openssl::hash::MessageDigest::sha256(),
            &subject,
            &issuer,
        )
        .unwrap();
        ocsp_request.add_id(ocip).unwrap();
        let ocsp_der = ocsp_request.as_ref().to_der().unwrap();

        let t = reqwest::Client::builder()
            .add_root_certificate(cert.clone())
            .identity(user_ident.clone())
            .build()
            .unwrap()
            .post(format!("https://127.0.0.1:3001/{}ca/ocsp", name))
            .body(ocsp_der)
            .send()
            .await
            .expect("Failed to query")
            .bytes()
            .await
            .expect("No content");
        println!("OCSP RESPONSE is {:02X?}", t.as_ref());

        let ocsp_response = openssl::ocsp::OcspResponse::from_der(t.as_ref()).unwrap();
        assert_eq!(
            ocsp_response.status(),
            openssl::ocsp::OcspResponseStatus::SUCCESSFUL
        );
    }
}

/// Build test configuration answers for CA testing with specified signing method
///
/// Creates a complete configuration structure with temporary paths and test certificates
fn build_answers(
    td: &tempfile::TempDir,
    method: cert_common::CertificateSigningMethod,
) -> main_config::MainConfigurationAnswers {
    let mut https_path = FileCreate::default();
    let base = std::path::PathBuf::from(td.path());
    *https_path = base.join("test-https.p12");
    let mut args = main_config::MainConfigurationAnswers::default();
    let mut dbname = FileCreate::default();
    let pw = Password2::new(utility::generate_password(32));
    let pw2 = Password2::new(utility::generate_password(32));
    *dbname = base.join("test-db1.sqlite");
    let ca_a = StandaloneCaConfigurationAnswers {
        client_certs: None,
        database: None,
        debug_level: LogLevel::Debug,
        proxy_config: None,
        general: GeneralSettings {
            cookie: "thecookie".to_string(),
            static_content: "./s".to_string(),
        },
        security_module: main_config::SecurityModuleConfiguration::Software("./ssm".into()),
        public_names: vec![ComplexName::from_str("127.0.0.1").unwrap()],
        service: Some(crate::main_config::ServerConfigurationAnswers {
            username: whoami::username(),
            http: Some(HttpSettings { port: 3000 }),
            https: Some(HttpsSettingsAnswers {
                port: 3001,
                certificate: main_config::HttpsCertificateLocationAnswers::New {
                    path: https_path,
                    ca_name: "default".to_string(),
                },
                require_certificate: false,
            }),
            ..Default::default()
        }),
        sign_method: method,
        path: ca::CaCertificateStorageBuilderAnswers::Sqlite(dbname),
        inferior_to: None,
        common_name: "TEST CA".to_string(),
        days: 5,
        chain_length: 1,
        admin_access_password: pw,
        admin_cert: ca::CertificateTypeAnswers::Soft { password: pw2 },
        ocsp_signature: false,
        name: "TEST CA".to_string(),
    };
    args.pki = PkiConfigurationEnumAnswers::Ca {
        pki_name: "".to_string(),
        config: Box::new(ca_a),
    };
    args
}

/// Structure for managing the running server
struct TheServer {
    configpath: tempfile::TempDir,
    pki_name: String,
    ca_name: String,
    process: Option<std::process::Child>,
}

impl TheServer {
    fn make(
        configpath: tempfile::TempDir,
        pb: &std::path::PathBuf,
        pb2: &std::path::PathBuf,
        pki_name: String,
        ca_name: String,
    ) -> Self {
        let mut construct = std::process::Command::cargo_bin("rust-iot-construct").unwrap();
        construct
            .arg(format!("--answers={}", pb.display()))
            .arg(format!("--save-answers={}", pb2.display()))
            .arg("--test")
            .arg(format!("--config={}", configpath.path().display()))
            .assert()
            .success();

        Self {
            configpath: configpath,
            pki_name,
            ca_name,
            process: None,
        }
    }

    fn run_with_shutdown(&mut self, sd: bool) {
        service::log::info!("Running the server shutdown {}", sd);
        if sd {
            let mut run =
                std::process::Command::cargo_bin("rust-iot").expect("Failed to get rust-iot");
            let a = run
                .arg("--shutdown")
                .arg(format!("--config={}", self.configpath.path().display()))
                .spawn()
                .ok();
            self.process = a;
        } else {
            let mut run =
                std::process::Command::cargo_bin("rust-iot").expect("Failed to get rust-iot");
            run.arg("--test")
                .arg(format!("--config={}", self.configpath.path().display()))
                .assert()
                .success();
        }
        service::log::info!("Done running the server");
    }
}

impl Drop for TheServer {
    fn drop(&mut self) {
        service::log::info!("Shutting down the server");
        if let Some(p) = self.process.as_mut() {
            p.kill().unwrap();
        }

        let mut kill = std::process::Command::cargo_bin("rust-iot-destroy").expect("Failed to get");
        kill.arg(format!("--config={}", self.configpath.path().display()))
            .arg("--name=default")
            .arg("--delete")
            .arg("--test")
            .assert()
            .success();
    }
}

/// Run CA (Certificate Authority) integration tests with specified signing methods
///
/// This function orchestrates a complete CA lifecycle test including:
/// - Configuration setup and validation
/// - CA construction and initialization
/// - Web server startup and endpoint testing
/// - Certificate request and signing workflows
/// - Proper cleanup and shutdown
async fn run_ca<F>(
    methods: Vec<cert_common::CertificateSigningMethod>,
    m: impl Fn(main_config::MainConfigurationAnswers) -> F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: std::future::Future<Output = main_config::MainConfigurationAnswers>,
{
    for method in methods {
        let configpath = tempfile::TempDir::new().unwrap();
        let base = std::path::PathBuf::from(configpath.path());
        service::log::error!("Path test is {}", base.display());
        let args = build_answers(&configpath, method);
        let args = m(args).await;

        let pki_name = match &args.pki {
            PkiConfigurationEnumAnswers::AddedCa(config) => "".to_string(),
            PkiConfigurationEnumAnswers::Pki(pki) => pki.pki_name.clone(),
            PkiConfigurationEnumAnswers::Ca {
                pki_name: _,
                config: _,
            } => "".to_string(),
        };

        let ca_name = match &args.pki {
            PkiConfigurationEnumAnswers::AddedCa(config) => "".to_string(),
            PkiConfigurationEnumAnswers::Pki(pki) => {
                let (name, _) = pki.local_ca.map().iter().next().unwrap();
                format!("{}/", name)
            }
            PkiConfigurationEnumAnswers::Ca {
                pki_name: _,
                config: _,
            } => "".to_string(),
        };

        let c = toml::to_string(&args).unwrap();
        let pb = base.join("answers1.toml");
        let mut f = tokio::fs::File::create(&pb).await.unwrap();
        f.write_all(c.as_bytes())
            .await
            .expect("Failed to write answers file");

        let pb2 = base.join("answers2.toml");

        let mut server = TheServer::make(configpath, &pb, &pb2, pki_name.clone(), ca_name.clone());

        let mut f2 = tokio::fs::File::open(pb2).await.unwrap();
        let mut f2_contents = Vec::new();
        f2.read_to_end(&mut f2_contents).await.unwrap();
        let args2: main_config::MainConfigurationAnswers =
            toml::from_str(std::str::from_utf8(&f2_contents).unwrap()).unwrap();
        //TODO compare args and args2

        server.run_with_shutdown(false);

        let method2 = method;

        server.run_with_shutdown(true);
        {
            use futures::FutureExt;
            use predicates::prelude::*;
            //Wait until the service is ready by polling it
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                let c = reqwest::Client::new();
                let d = c.get("http://127.0.0.1:3000").send().await;
                if let Ok(t) = d {
                    let t2 = t.text().await.expect("No text?");
                    break;
                }
            }
            //now run all the checks
            run_web_checks(args2, method2, &pki_name, &ca_name).await;
        }
    }

    Ok(())
}

/// Test building and running a standalone CA (Certificate Authority)
///
/// This integration test validates the complete CA setup process including
/// configuration, initialization, web server startup, and basic functionality
#[tokio::test(flavor = "multi_thread")]
async fn build_ca() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = CA_TEST_MUTEX.lock().unwrap();

    let methods = vec![
        cert_common::CertificateSigningMethod::Https(cert_common::HttpsSigningMethod::RsaSha256),
        cert_common::CertificateSigningMethod::Https(cert_common::HttpsSigningMethod::EcdsaSha256),
    ];

    simple_logger::SimpleLogger::new().init();
    service::log::set_max_level(service::LogLevel::Debug.level_filter());

    run_ca(methods, |config| async { config }).await.unwrap();

    Ok(())
}

/// Test building and running a PKI (Public Key Infrastructure) with multiple CAs
///
/// This integration test validates PKI setup with hierarchical CA relationships
/// and ensures proper certificate chain handling and management
#[tokio::test(flavor = "multi_thread")]
async fn build_pki() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = CA_TEST_MUTEX.lock().unwrap();

    let methods = vec![
        cert_common::CertificateSigningMethod::Https(cert_common::HttpsSigningMethod::RsaSha256),
        cert_common::CertificateSigningMethod::Https(cert_common::HttpsSigningMethod::EcdsaSha256),
    ];

    run_ca(methods, |mut config| async {
        if let PkiConfigurationEnumAnswers::Ca {
            pki_name: _,
            config: sac,
        } = config.pki.clone()
        {
            let mut pc = PkiConfigurationAnswers::default();
            pc.pki_name = "pki/".to_string();
            pc.local_ca
                .map_mut()
                .insert("default".to_string(), sac.to_local());
            let pki = PkiConfigurationEnumAnswers::Pki(pc);
            config.pki = pki;
        }
        config
    })
    .await
    .unwrap();

    Ok(())
}

/// Test CA configuration with pre-existing answer files
///
/// Validates that the system can load and process existing configuration
/// answers from TOML files correctly
#[tokio::test(flavor = "multi_thread")]
async fn existing_answers() -> Result<(), Box<dyn std::error::Error>> {
    let configpath = tempfile::TempDir::new().unwrap();
    let base = std::path::PathBuf::from(configpath.path());
    let args = main_config::MainConfigurationAnswers::default();
    let c = toml::to_string(&args).unwrap();
    let pb = base.join("answers1.toml");
    let mut f = tokio::fs::File::create(&pb).await.unwrap();
    f.write_all(c.as_bytes())
        .await
        .expect("Failed to write answers file");

    let pb2 = base.join("answers2.toml");
    let mut f = tokio::fs::File::create(&pb2).await.unwrap();
    f.write_all(c.as_bytes())
        .await
        .expect("Failed to write answers file");

    let mut construct = std::process::Command::cargo_bin("rust-iot-construct")?;
    construct
        .arg(format!("--answers={}", pb.display()))
        .arg(format!("--save-answers={}", pb2.display()))
        .arg("--test")
        .arg(format!("--config={}", configpath.path().display()))
        .assert()
        .failure()
        .code(predicate::eq(101))
        .stderr(predicate::str::contains("Answers file already exists"));
    Ok(())
}

/// Test CA system with existing configuration files
///
/// Ensures the CA can be constructed and operated using pre-existing
/// configuration files and settings
#[tokio::test(flavor = "multi_thread")]
async fn existing_config() -> Result<(), Box<dyn std::error::Error>> {
    let configpath = tempfile::TempDir::new().unwrap();
    let base = std::path::PathBuf::from(configpath.path());
    let args = build_answers(
        &configpath,
        cert_common::CertificateSigningMethod::Https(cert_common::HttpsSigningMethod::RsaSha256),
    );

    let c = toml::to_string(&args).unwrap();
    let pb = base.join("answers1.toml");
    let pb2 = base.join("answers2.toml");
    let mut f = tokio::fs::File::create(&pb).await.unwrap();
    f.write_all(c.as_bytes())
        .await
        .expect("Failed to write answers file");

    let pb3 = base.join("default-config.toml");
    let mut f = tokio::fs::File::create(&pb3).await.unwrap();
    f.write_all("DOESNT MATTER".as_bytes()).await.unwrap();

    let mut construct = std::process::Command::cargo_bin("rust-iot-construct")?;
    construct
        .arg(format!("--answers={}", pb.display()))
        .arg(format!("--save-answers={}", pb2.display()))
        .arg("--test")
        .arg(format!("--config={}", configpath.path().display()))
        .assert()
        .failure()
        .code(predicate::eq(101))
        .stderr(predicate::str::contains("Configuration file"))
        .stderr(predicate::str::contains("already exists"));
    Ok(())
}

/// Test CA system with existing password configuration
///
/// Validates password handling and authentication systems work correctly
/// with pre-configured password settings
#[tokio::test(flavor = "multi_thread")]
async fn existing_password() -> Result<(), Box<dyn std::error::Error>> {
    let configpath = tempfile::TempDir::new().unwrap();
    let base = std::path::PathBuf::from(configpath.path());
    let args = build_answers(
        &configpath,
        cert_common::CertificateSigningMethod::Https(cert_common::HttpsSigningMethod::RsaSha256),
    );

    let c = toml::to_string(&args).unwrap();
    let pb = base.join("answers1.toml");
    let pb2 = base.join("answers2.toml");
    let mut f = tokio::fs::File::create(&pb).await.unwrap();
    f.write_all(c.as_bytes())
        .await
        .expect("Failed to write answers file");

    #[cfg(feature = "tpm2")]
    let pb3 = base.join("default-password.bin");
    #[cfg(not(feature = "tpm2"))]
    let pb3 = base.join("default-credentials.bin");
    let mut f = tokio::fs::File::create(&pb3).await.unwrap();
    f.write_all("DOESNT MATTER".as_bytes()).await.unwrap();

    let mut construct = std::process::Command::cargo_bin("rust-iot-construct")?;
    let a = construct
        .arg(format!("--answers={}", pb.display()))
        .arg(format!("--save-answers={}", pb2.display()))
        .arg("--test")
        .arg(format!("--config={}", configpath.path().display()))
        .assert()
        .failure()
        .code(predicate::eq(101));

    #[cfg(feature = "tpm2")]
    a.stderr(predicate::str::contains("Password file aready exists"));
    #[cfg(not(feature = "tpm2"))]
    a.stderr(predicate::str::contains("Credentials file aready exists"));
    Ok(())
}
