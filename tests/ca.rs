#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/ca/ca_common.rs"]
mod ca;

#[path = "../src/main_config.rs"]
mod main_config;

use ca::{CertificateType, SmartCardPin2};
pub use main_config::MainConfiguration;
use userprompt::Password2;

#[path = "../src/utility.rs"]
mod utility;

#[path = "../src/card.rs"]
mod card;

fn hash_setup1() -> Vec<u8> {
    use rand::Rng;
    use sha2::Digest;
    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..5123).map(|_| rng.gen()).collect();
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let t = ca::rsa_sha256(&hash);
    t
}

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

#[test]
fn pkcs15_sha256() {
    let t = hash_setup1();
    for i in [128, 256, 512, 1024] {
        let t2 = ca::pkcs15_sha256(i, &t);
        assert_eq!(i, t2.len());
    }
}

#[test]
fn get_sqlite_paths() {
    use std::str::FromStr;
    let p = std::path::PathBuf::from_str("./temp").unwrap();
    let paths = ca::get_sqlite_paths(&p);
    assert!(paths.len() > 0)
}

#[test]
fn from_certificate_type_answers() {
    let scpin = SmartCardPin2::default();
    let answer1 = ca::CertificateTypeAnswers::SmartCard(scpin.clone());
    let ct: CertificateType = answer1.into();
    if let CertificateType::SmartCard(a) = ct {
        assert_eq!(a, scpin.to_string());
    } else {
        panic!("Wrong type returned");
    }

    let pass = Password2::default();
    let answer2 = ca::CertificateTypeAnswers::Soft(pass.clone());
    let ct: CertificateType = answer2.into();
    if let CertificateType::Soft(a) = ct {
        assert_eq!(a, pass.to_string());
    } else {
        panic!("Wrong type returned");
    }
}
