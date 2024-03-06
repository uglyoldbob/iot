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

fn as_oid(s: &'static [u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(s)
}

lazy_static::lazy_static! {
    static ref OID_DATA_CONTENT_TYPE: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 7, 1]);
    static ref OID_ENCRYPTED_DATA_CONTENT_TYPE: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 7, 6]);
    static ref OID_FRIENDLY_NAME: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 9, 20]);
    static ref OID_LOCAL_KEY_ID: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 9, 21]);
    static ref OID_CERT_TYPE_X509_CERTIFICATE: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 9, 22, 1]);
    static ref OID_CERT_TYPE_SDSI_CERTIFICATE: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 9, 22, 2]);
    static ref OID_PBE_WITH_SHA_AND3_KEY_TRIPLE_DESCBC: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 12, 1, 3]);
    static ref OID_SHA1: ObjectIdentifier = as_oid(&[1, 3, 14, 3, 2, 26]);
    static ref OID_PBE_WITH_SHA1_AND40_BIT_RC2_CBC: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 12, 1, 6]);
    static ref OID_KEY_BAG: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 1]);
    static ref OID_PKCS8_SHROUDED_KEY_BAG: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 2]);
    static ref OID_CERT_BAG: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 3]);
    static ref OID_CRL_BAG: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 4]);
    static ref OID_SECRET_BAG: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 5]);
    static ref OID_SAFE_CONTENTS_BAG: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 6]);
    static ref OID_NIST_SHA256: ObjectIdentifier = as_oid(&[2,16,840,1,101,3,4,2,1]);
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
                println!("OID IS {:?}", oid);
                if oid == *OID_DATA_CONTENT_TYPE {
                    println!("Reading pkcs#7 data");
                    let data = r
                        .next()
                        .read_tagged(yasna::Tag::context(0), |r| r.read_bytes())?;
                    Ok(data)
                } else {
                    return Err(ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
                }
            })?;
            let thing2 = r.next().read_sequence(|r| {
                let a = r.next().read_sequence(|r| {
                    r.next().read_sequence(|r| {
                        let oid = r.next().read_oid()?;
                        println!("oid 2 is {:?}", oid);
                        if oid == *OID_NIST_SHA256 {
                            println!("Reading sha256 nist data");
                        }
                        r.next().read_null()?;
                        println!("Need to read octet string now");
                        Ok(oid)
                    })
                });
                a
            });
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
        println!("Pkcs12 object {:?}", asdf);

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
