#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/ca/ca_common.rs"]
mod ca;

#[path = "../src/main_config.rs"]
mod main_config;

use std::str::FromStr;

use assert_cmd::prelude::*;
use ca::{
    CertificateType, PkiConfigurationEnumAnswers, SmartCardPin2, StandaloneCaConfigurationAnswers,
};
use der::Decode;
use der::DecodePem;
pub use main_config::MainConfiguration;
use main_config::{HttpSettings, HttpsSettingsAnswers};
use predicates::prelude::predicate;
use service::LogLevel;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use userprompt::{FileCreate, Password2};

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

async fn run_web_checks() {
    use predicates::prelude::*;

    for (prot, port) in [("http", 3000), ("https", 3001)] {
        let t = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .get(format!("{}://127.0.0.1:{}", prot, port))
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
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .get(format!("{}://127.0.0.1:{}/ca", prot, port))
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
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .get(format!(
                "{}://127.0.0.1:{}/ca/get_ca.rs?type=der",
                prot, port
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
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .get(format!("{}://127.0.0.1:{}/ca/get_ca.rs", prot, port))
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
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .get(format!(
                "{}://127.0.0.1:{}/ca/get_ca.rs?type=pem",
                prot, port
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
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .get(format!(
                "{}://127.0.0.1:{}/ca/get_ca.rs?type=bla",
                prot, port
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
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .get(format!("{}://127.0.0.1:{}/ca/request.rs", prot, port))
            .send()
            .await
            .expect("Failed to query")
            .text()
            .await
            .expect("No content");
        assert_eq!(false, predicate::str::contains("missing").eval(&t));
    }
}

async fn cleanup() {
    let _ = tokio::fs::remove_dir_all(std::path::PathBuf::from_str("./tokens").unwrap()).await;
    let _ = tokio::fs::remove_file(std::path::PathBuf::from_str("./test-https.p12").unwrap()).await;
    let _ = tokio::fs::remove_file(std::path::PathBuf::from_str("./answers2.toml").unwrap()).await;
    let _ = tokio::fs::remove_file(std::path::PathBuf::from_str("./default-config.toml").unwrap())
        .await;
    let _ = tokio::fs::remove_file(std::path::PathBuf::from_str("./default-initialized").unwrap())
        .await;
    let _ = tokio::fs::remove_file(std::path::PathBuf::from_str("./db1.sqlite").unwrap()).await;
    let _ = tokio::fs::remove_file(std::path::PathBuf::from_str("./db1.sqlite-shm").unwrap()).await;
    let _ = tokio::fs::remove_file(std::path::PathBuf::from_str("./db1.sqlite-wal").unwrap()).await;
    let _ = tokio::fs::remove_file(std::path::PathBuf::from_str("./default-password.bin").unwrap())
        .await;
}

fn build_answers() -> main_config::MainConfigurationAnswers {
    let mut https_path = FileCreate::default();
    *https_path = std::path::PathBuf::from_str("./test-https.p12").unwrap();
    let mut args = main_config::MainConfigurationAnswers::default();
    args.debug_level = LogLevel::Trace;
    args.username = whoami::username();
    args.http = Some(HttpSettings { port: 3000 });
    args.https = Some(HttpsSettingsAnswers {
        port: 3001,
        certificate: main_config::HttpsCertificateLocationAnswers::New {
            path: https_path,
            ca_name: "default".to_string(),
        },
        require_certificate: false,
    });
    let mut dbname = FileCreate::default();
    let pw = Password2::new(utility::generate_password(32));
    let pw2 = Password2::new(utility::generate_password(32));
    *dbname = std::path::PathBuf::from_str("./test-db1.sqlite").unwrap();
    let ca_a = StandaloneCaConfigurationAnswers {
        sign_method: cert_common::CertificateSigningMethod::Https(
            cert_common::HttpsSigningMethod::RsaSha256,
        ),
        path: ca::CaCertificateStorageBuilder::Sqlite(dbname),
        inferior_to: None,
        common_name: "TEST CA".to_string(),
        days: 5,
        chain_length: 1,
        admin_access_password: pw,
        admin_cert: ca::CertificateTypeAnswers::Soft(pw2),
        ocsp_signature: false,
        name: "TEST RSA CA".to_string(),
    };
    args.pki = PkiConfigurationEnumAnswers::Ca(Box::new(ca_a));
    args
}

#[tokio::test(flavor = "multi_thread")]
async fn build_pki() -> Result<(), Box<dyn std::error::Error>> {
    let args = build_answers();

    let c = toml::to_string(&args).unwrap();
    let pb = std::path::PathBuf::from_str("./answers1.toml").unwrap();
    let mut f = tokio::fs::File::create(pb).await.unwrap();
    f.write_all(c.as_bytes())
        .await
        .expect("Failed to write answers file");

    cleanup().await;

    let mut construct = std::process::Command::cargo_bin("rust-iot-construct")?;
    construct
        .arg("--answers=./answers1.toml")
        .arg("--save-answers=./answers2.toml")
        .arg("--test")
        .arg("--config=./")
        .assert()
        .success();

    let pb2 = std::path::PathBuf::from_str("./answers2.toml").unwrap();
    let mut f2 = tokio::fs::File::open(pb2).await.unwrap();
    let mut f2_contents = Vec::new();
    let c2 = f2.read_to_end(&mut f2_contents).await.unwrap();
    let args2: main_config::MainConfigurationAnswers =
        toml::from_str(std::str::from_utf8(&f2_contents).unwrap()).unwrap();
    //TODO compare args and args2

    let mut run = std::process::Command::cargo_bin("rust-iot").expect("Failed to get rust-iot");
    run.arg("--test").arg("--config=./").assert().success();

    tokio::spawn(async {
        use futures::FutureExt;
        use predicates::prelude::*;
        //Wait until the service is ready by polling it
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
            let c = reqwest::Client::new();
            let d = c.get("http://127.0.0.1:3000").send().await;
            if let Ok(t) = d {
                let t2 = t.text().await.expect("No text?");
                assert_eq!(true, predicate::str::contains("missing").eval(&t2));
                break;
            }
        }
        //no run all the checks
        let resp = std::panic::AssertUnwindSafe(run_web_checks())
            .catch_unwind()
            .await;
        // indicate that it should exit so the test can actually finish
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .get("http://127.0.0.1:3000/test-exit.rs")
            .send()
            .await
            .expect("Failed to shutdown");
        // indicate errors now
        if resp.is_err() {
            panic!("FAIL: {:?}", resp.err());
        }
    });

    let mut run = std::process::Command::cargo_bin("rust-iot").expect("Failed to get rust-iot");
    run.arg("--shutdown").arg("--config=./").assert().success();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_answers() -> Result<(), Box<dyn std::error::Error>> {
    cleanup().await;
    let args = main_config::MainConfigurationAnswers::default();
    let c = toml::to_string(&args).unwrap();
    let pb = std::path::PathBuf::from_str("./answers1.toml").unwrap();
    let mut f = tokio::fs::File::create(pb).await.unwrap();
    f.write_all(c.as_bytes())
        .await
        .expect("Failed to write answers file");

    let pb = std::path::PathBuf::from_str("./answers2.toml").unwrap();
    let mut f = tokio::fs::File::create(pb).await.unwrap();
    f.write_all(c.as_bytes())
        .await
        .expect("Failed to write answers file");

    let mut construct = std::process::Command::cargo_bin("rust-iot-construct")?;
    construct
        .arg("--answers=./answers1.toml")
        .arg("--save-answers=./answers2.toml")
        .arg("--test")
        .arg("--config=./")
        .assert()
        .failure()
        .code(predicate::eq(101))
        .stderr(predicate::str::contains("Answers file already exists"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_config() -> Result<(), Box<dyn std::error::Error>> {
    let args = build_answers();

    let c = toml::to_string(&args).unwrap();
    let pb = std::path::PathBuf::from_str("./answers1.toml").unwrap();
    let mut f = tokio::fs::File::create(pb).await.unwrap();
    f.write_all(c.as_bytes())
        .await
        .expect("Failed to write answers file");

    cleanup().await;
    let pb2 = std::path::PathBuf::from_str("./default-config.toml").unwrap();
    let mut f = tokio::fs::File::create(pb2).await.unwrap();
    f.write_all("DOESNT MATTER".as_bytes()).await.unwrap();

    let mut construct = std::process::Command::cargo_bin("rust-iot-construct")?;
    construct
        .arg("--answers=./answers1.toml")
        .arg("--save-answers=./answers2.toml")
        .arg("--test")
        .arg("--config=./")
        .assert()
        .failure()
        .code(predicate::eq(101))
        .stderr(predicate::str::contains("Configuration file"))
        .stderr(predicate::str::contains("already exists"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_password() -> Result<(), Box<dyn std::error::Error>> {
    let args = build_answers();

    let c = toml::to_string(&args).unwrap();
    let pb = std::path::PathBuf::from_str("./answers1.toml").unwrap();
    let mut f = tokio::fs::File::create(pb).await.unwrap();
    f.write_all(c.as_bytes())
        .await
        .expect("Failed to write answers file");

    cleanup().await;
    let pb2 = std::path::PathBuf::from_str("./default-password.bin").unwrap();
    let mut f = tokio::fs::File::create(pb2).await.unwrap();
    f.write_all("DOESNT MATTER".as_bytes()).await.unwrap();

    let mut construct = std::process::Command::cargo_bin("rust-iot-construct")?;
    construct
        .arg("--answers=./answers1.toml")
        .arg("--save-answers=./answers2.toml")
        .arg("--test")
        .arg("--config=./")
        .assert()
        .failure()
        .code(predicate::eq(101))
        .stderr(predicate::str::contains("Password file aready exists"));
    Ok(())
}
