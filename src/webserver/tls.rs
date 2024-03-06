use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pkcs8::DecodePrivateKey;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};

type Error = Box<dyn std::error::Error + 'static>;

pub struct TlsConfig {
    pub key_file: PathBuf,
    pub key_password: String,
    pub cert_file: PathBuf,
}

impl TlsConfig {
    pub fn new<P: Into<PathBuf>, S: Into<String>>(key_file: P, pass: S, cert_file: P) -> Self {
        TlsConfig {
            key_file: key_file.into(),
            key_password: pass.into(),
            cert_file: cert_file.into(),
        }
    }
}

struct Pkcs8PrivateKey {
    data: Vec<u8>,
}

impl DecodePrivateKey for Pkcs8PrivateKey {
    fn from_pkcs8_der(bytes: &[u8]) -> pkcs8::Result<Self> {
        Ok(Self {
            data: Vec::from(bytes),
        })
    }
}

pub fn load_certificate<P>(keyfile: P, certfile: P, pass: &str) -> Result<Arc<ServerConfig>, Error>
where
    P: AsRef<Path>,
{
    let mut keybytes = vec![];
    let mut key = File::open(&keyfile)?;
    key.read_to_end(&mut keybytes)?;
    let (asdf, fdsa) = pkcs8::SecretDocument::read_pem_file(keyfile).expect("Failed to open private key file");
    println!("Private key : {}", asdf);
    let pkcs8 = fdsa;
    let private_bytes = pkcs8.as_bytes().to_owned();
    let pkey = private_bytes.into();
    let pkey = PrivateKeyDer::Pkcs8(pkey);

    let mut certbytes = vec![];
    let mut cert = File::open(certfile)?;
    cert.read_to_end(&mut certbytes)?;
    let c1 = CertificateDer::from(certbytes);

    let certs = vec![c1];

    let mut sc: tokio_rustls::rustls::ConfigBuilder<
        ServerConfig,
        tokio_rustls::rustls::WantsVerifier,
    > = ServerConfig::builder();

    let sc = if false {
        let mut rcs = RootCertStore::empty();
        //todo fill out the rcs struct
        let roots = Arc::new(rcs);

        let client_verifier = WebPkiClientVerifier::builder(roots.into()).build().unwrap();
        sc.with_client_cert_verifier(client_verifier)
    } else {
        sc.with_no_client_auth()
    };
    let sc = sc.with_single_cert(certs, pkey)?;
    Ok(Arc::new(sc))
}
