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
    pub cert_file: PathBuf,
    pub key_password: String,
}

impl TlsConfig {
    pub fn new<P: Into<PathBuf>, S: Into<String>>(cert_file: P, pass: S) -> Self {
        TlsConfig {
            cert_file: cert_file.into(),
            key_password: pass.into(),
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

#[derive(Debug)]
struct EncryptedPkcs12 {
    pub encrypted: Vec<u8>,
}

impl EncryptedPkcs12 {
    fn parse(reader: yasna::BERReader) -> Self {
        let asdf = reader.read_sequence(|r| {
            let version = r.next().read_u8()?;
            println!("Version is {}", version);
            let thing1 = r.next().read_sequence(|r| {
                let oid = r.next().read_oid()?;
                println!("Oid is {}", oid);
                Ok(oid)
            })?;
            Ok(version)
        });

        Self {
            encrypted: Vec::new(),
        }
    }
}

pub fn load_certificate<P>(certfile: P, pass: &str) -> Result<Arc<ServerConfig>, Error>
where
    P: AsRef<Path>,
{
    let mut certbytes = vec![];
    let mut certf = File::open(&certfile)?;
    certf.read_to_end(&mut certbytes)?;

    let ec = yasna::parse_der(&certbytes, |reader| {
        println!("Mode is {:?}", reader.mode());
        let asdf = EncryptedPkcs12::parse(reader);
        println!("Object identifier is {:?}", asdf);

        Ok(asdf)
    })
    .expect("Failed to parse certificate");
    let ddata: &[u8] = [0, 1, 2].as_ref();
    let pkey = ddata.into();
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
