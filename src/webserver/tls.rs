use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pkcs8::DecodePrivateKey;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use yasna::models::ObjectIdentifier;
use yasna::ASN1Error;

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

fn as_oid(s: &'static [u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(s)
}

lazy_static::lazy_static! {
    static ref OID_DATA_CONTENT_TYPE: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 7, 1]);
    static ref OID_ENCRYPTED_DATA_CONTENT_TYPE: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 7, 6]);
}

pub fn load_certificate<P>(certfile: P, pass: &str) -> Result<Arc<ServerConfig>, Error>
where
    P: AsRef<Path>,
{
    let mut certbytes = vec![];
    let mut certf = File::open(&certfile)?;
    certf.read_to_end(&mut certbytes)?;

    let ec = p12::PFX::parse(&certbytes).expect("Failed to parse certificate");

    println!("Attempting to decode contents");

    let thing1 = ec.version;
    println!("PFX version is {}", thing1);
    let thing2a = ec.auth_safe.oid();
    let thing2 = ec.safe_bags(pass);
    match thing2 {
        Err(e) => println!("Error with reading bags: {:?}", e),
        Ok(thing2) => {
            println!("PFX bags {}:", thing2.len());
            for b in thing2.iter() {
                let data = b.bag.other_bag_data().expect("Expected other bag data");
                let oid = b.bag.oid();
                if oid == *OID_ENCRYPTED_DATA_CONTENT_TYPE {
                    println!("Decoding encrypted pkcs 7 data");
                    todo!("Do the thing");
                } else if oid == *OID_DATA_CONTENT_TYPE {
                    println!("Decoding pkcs 7 data");
                    todo!("Do the thing");
                } else {
                    println!("Unknown data {:?}", oid);
                    todo!("Figure out what to do");
                }
            }
        }
    }
    let thing3 = ec.mac_data;
    if let Some(thing3) = thing3 {
        println!("PFX MAC data is {:?}", thing3);
    }
    todo!("Parse the pfx data");

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
