#[path = "../src/hsm2.rs"]
mod hsm2;

#[path = "../src/ca/ca_common.rs"]
mod ca;

#[path = "../src/main_config.rs"]
mod main_config;

use std::collections::HashMap;
use std::future::IntoFuture;
use std::str::FromStr;

use assert_cmd::prelude::*;
use ca::ComplexName;
use ca::{
    CertificateType, PkiConfigurationEnumAnswers, SmartCardPin2, StandaloneCaConfigurationAnswers,
};
use der::Decode;
use der::DecodePem;
pub use main_config::MainConfiguration;
use main_config::{HttpSettings, HttpsSettingsAnswers, MainConfigurationAnswers};
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
    let t = utility::rsa_sha256(&hash);
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
        let t2 = utility::pkcs15_sha256(i, &t);
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

async fn run_web_checks(
    config: MainConfigurationAnswers,
    method: cert_common::CertificateSigningMethod,
) {
    use predicates::prelude::*;

    let t = reqwest::Client::builder()
        .build()
        .unwrap()
        .get("http://127.0.0.1:3000/ca/get_ca.rs?type=der".to_string())
        .send()
        .await
        .expect("Failed to query")
        .bytes()
        .await
        .expect("No content");
    let cert = reqwest::Certificate::from_der(t.as_ref()).unwrap();

    let (token, pass) = if let PkiConfigurationEnumAnswers::Ca {
        pki_name: _,
        config,
    } = &config.pki
    {
        let p = if let crate::ca::CertificateTypeAnswers::Soft(a) = &config.admin_cert {
            a.to_string()
        } else {
            panic!("INVALID");
        };
        (config.admin_access_password.to_string(), p)
    } else {
        panic!("Invalid config");
    };

    reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .build()
        .unwrap()
        .get("https://127.0.0.1:3001/ca/get_admin.rs".to_string())
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
        .post("https://127.0.0.1:3001/ca/get_admin.rs".to_string())
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
        assert_eq!(true, predicate::str::contains("missing").eval(&t));
    }

    for (prot, port) in [("http", 3000), ("https", 3001)] {
        let t = reqwest::Client::builder()
            .add_root_certificate(cert.clone())
            .identity(id.clone())
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
            .add_root_certificate(cert.clone())
            .identity(id.clone())
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
            .add_root_certificate(cert.clone())
            .identity(id.clone())
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
            .add_root_certificate(cert.clone())
            .identity(id.clone())
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
            .add_root_certificate(cert.clone())
            .identity(id.clone())
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
            .add_root_certificate(cert.clone())
            .identity(id.clone())
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

    let (csr_pem, pri_key) = match method {
        cert_common::CertificateSigningMethod::Https(method) => build_https_csr(method).unwrap(),
        cert_common::CertificateSigningMethod::Ssh(method) => todo!(),
    };
    params.clear();
    params.insert("csr", csr_pem.clone());
    params.insert("name", "Jenny".to_string());
    params.insert("email", "dummy@example.com".to_string());
    params.insert("phone", "867-5309".to_string());
    let t = reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .identity(id.clone())
        .build()
        .unwrap()
        .post("https://127.0.0.1:3001/ca/submit_request.rs")
        .form(&params)
        .send()
        .await
        .expect("Failed to query")
        .text()
        .await
        .expect("No content");
}

fn build_answers(
    td: &tempfile::TempDir,
    method: cert_common::CertificateSigningMethod,
) -> main_config::MainConfigurationAnswers {
    let mut https_path = FileCreate::default();
    let base = std::path::PathBuf::from(td.path());
    *https_path = base.join("test-https.p12");
    let mut args = main_config::MainConfigurationAnswers::default();
    args.debug_level = LogLevel::Debug;
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
    *dbname = base.join("test-db1.sqlite");
    let ca_a = StandaloneCaConfigurationAnswers {
        sign_method: method,
        path: ca::CaCertificateStorageBuilder::Sqlite(dbname),
        inferior_to: None,
        common_name: "TEST CA".to_string(),
        days: 5,
        chain_length: 1,
        admin_access_password: pw,
        admin_cert: ca::CertificateTypeAnswers::Soft(pw2),
        ocsp_signature: false,
        name: "TEST CA".to_string(),
    };
    args.pki = PkiConfigurationEnumAnswers::Ca {
        pki_name: "".to_string(),
        config: Box::new(ca_a),
    };
    args.public_names
        .push(ComplexName::from_str("127.0.0.1").unwrap());
    args
}

#[tokio::test(flavor = "multi_thread")]
async fn build_pki() -> Result<(), Box<dyn std::error::Error>> {
    let methods = vec![
        cert_common::CertificateSigningMethod::Https(cert_common::HttpsSigningMethod::RsaSha256),
        cert_common::CertificateSigningMethod::Https(cert_common::HttpsSigningMethod::EcdsaSha256),
    ];

    for method in methods {
        let configpath = tempfile::TempDir::new().unwrap();
        let base = std::path::PathBuf::from(configpath.path());
        let args = build_answers(&configpath, method);

        let c = toml::to_string(&args).unwrap();
        let pb = base.join("answers1.toml");
        let mut f = tokio::fs::File::create(&pb).await.unwrap();
        f.write_all(c.as_bytes())
            .await
            .expect("Failed to write answers file");

        let pb2 = base.join("answers2.toml");

        let mut construct = std::process::Command::cargo_bin("rust-iot-construct")?;
        construct
            .arg(format!("--answers={}", pb.display()))
            .arg(format!("--save-answers={}", pb2.display()))
            .arg("--test")
            .arg(format!("--config={}", configpath.path().display()))
            .assert()
            .success();

        let mut f2 = tokio::fs::File::open(pb2).await.unwrap();
        let mut f2_contents = Vec::new();
        f2.read_to_end(&mut f2_contents).await.unwrap();
        let args2: main_config::MainConfigurationAnswers =
            toml::from_str(std::str::from_utf8(&f2_contents).unwrap()).unwrap();
        //TODO compare args and args2

        let mut run = std::process::Command::cargo_bin("rust-iot").expect("Failed to get rust-iot");
        run.arg("--test")
            .arg(format!("--config={}", configpath.path().display()))
            .assert()
            .success();

        let method2 = method;
        let jh = tokio::spawn(async move {
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
            //now run all the checks
            let resp = std::panic::AssertUnwindSafe(run_web_checks(args2, method2))
                .catch_unwind()
                .await;
            // indicate that it should exit so the test can actually finish
            reqwest::Client::builder()
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
        let a = run
            .arg("--shutdown")
            .arg(format!("--config={}", configpath.path().display()))
            .assert()
            .success();
        let o = a.get_output();
        println!("OUTPUT IS {}", std::str::from_utf8(&o.stdout).unwrap());

        let r = jh.into_future().await;

        let mut kill = std::process::Command::cargo_bin("rust-iot-destroy").expect("Failed to get");
        kill.arg(format!("--config={}", configpath.path().display()))
            .arg("--name=default")
            .arg("--delete")
            .arg("--test")
            .assert()
            .success();

        r.unwrap();
    }

    Ok(())
}

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

    let pb3 = base.join("default-password.bin");
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
        .stderr(predicate::str::contains("Password file aready exists"));
    Ok(())
}
