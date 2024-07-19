#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/utility.rs"]
mod utility;

use std::{io::Write, sync::Arc};

use der::{Decode, Encode};
use rcgen::RemoteKeyPair;
use ring::signature::EcdsaSigningAlgorithm;

#[test]
fn ecdsa_with_rcgen() {
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let kp = rcgen::KeyPair::generate().unwrap();
    let cp = rcgen::CertificateParams::new(vec!["whatever".to_string()]).unwrap();
    let cert = cp.self_signed(&kp).unwrap();
    let x509 = x509_cert::Certificate::from_der(cert.der()).unwrap();
    println!(
        "The public key is {} {:02X?}",
        kp.public_key_raw().len(),
        kp.public_key_raw()
    );
    println!("{:02X?}", x509.signature);
}

#[test]
fn ecdsa_with_ring() {
    use ring::signature::KeyPair;
    let rng = ring::rand::SystemRandom::new();
    let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
    let kp = ring::signature::EcdsaKeyPair::from_pkcs8(alg, doc.as_ref(), &rng).unwrap();
    let data = vec![
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
        5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2,
        3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
        5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ];
    let sig = kp.sign(&rng, &data).unwrap();
    println!(
        "The signature is {} {:02x?}",
        sig.as_ref().len(),
        sig.as_ref()
    );

    let peer_public_key_bytes = kp.public_key().as_ref();
    let peer_public_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        peer_public_key_bytes,
    );
    peer_public_key.verify(&data, sig.as_ref()).unwrap();
}

#[test]
fn ecdsa_with_ring2() {
    use ring::signature::KeyPair;
    let rng = ring::rand::SystemRandom::new();
    let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
    let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
    let kp = ring::signature::EcdsaKeyPair::from_pkcs8(alg, doc.as_ref(), &rng).unwrap();
    let data = vec![
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
        5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2,
        3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
        5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ];
    let sig = kp.sign(&rng, &data).unwrap();

    let sig2 = hsm2::EcdsaSignature::from_der(sig.as_ref()).unwrap();
    let d = sig.as_ref().to_vec();
    let peer_public_key_bytes = kp.public_key().as_ref();
    println!(
        "The public key is {} {:02X?}",
        peer_public_key_bytes.len(),
        peer_public_key_bytes
    );
    println!("The public key is also {:02X?}", kp);
    println!("The signature is {} {:02x?}", d.len(), d);
    println!("The signature is also {:02X?}", sig2);

    let peer_public_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        peer_public_key_bytes,
    );
    peer_public_key.verify(&data, sig.as_ref()).unwrap();
}

#[test]
fn ecdsa_with_hsm() {
    let service = service::Service::new("testing".to_string());
    service.new_log(service::LogLevel::Debug);

    use hsm2::KeyPair;
    let ap = "asdf".to_string();
    let up = "asdf".to_string();

    let config_path = tempfile::TempDir::new().unwrap();
    let config_path = std::path::PathBuf::from(config_path.path());
    std::env::set_var("SOFTHSM2_CONF", config_path.join("softhsm2.conf"));

    {
        let softhsm_config = config_path.join("softhsm2.conf");
        let token_path = config_path.join("tokens");
        let _ = std::fs::create_dir(&token_path);
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
        let mut f3 =
            std::fs::File::create(&softhsm_config).expect("Failed to create softhsm config");
        f3.write_all(hsm_contents.as_bytes())
            .expect("Failed to write softhsm config");

        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        std::fs::DirBuilder::create(&builder, &token_path)
            .expect("Failed to create token directory");
    }

    let hsm = hsm2::Hsm::create(None, ap.into(), up.into()).unwrap();
    let hsm = Arc::new(hsm);
    let kp = hsm
        .generate_https_keypair("testing", cert_common::HttpsSigningMethod::EcdsaSha256, 256)
        .unwrap();
    let data = utility::generate_password(1023).as_bytes().to_vec();
    let sig = kp.sign(&data).unwrap();
    let sigb = kp.sign(&data).unwrap();

    let sig2 = hsm2::EcdsaSignature::from_der(&sig).unwrap();
    println!("KP IS {:02X?}", kp);
    println!("Signature is {} {:02X?}", sig.len(), sig);
    println!("Signatureb is {} {:02X?}", sigb.len(), sigb);
    println!("The signature is also {:02X?}", sig2);

    let peer_public_key_bytes = kp.public_key().as_ref();
    println!(
        "The public key is {} {:02X?}",
        peer_public_key_bytes.len(),
        peer_public_key_bytes
    );
    let peer_public_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        peer_public_key_bytes,
    );
    let va = peer_public_key.verify(&data, &sig);
    let vb = peer_public_key.verify(&data, &sigb);
    println!("VA IS {:?}, vb is {:?}", va, vb);

    va.unwrap();
    vb.unwrap();
}
