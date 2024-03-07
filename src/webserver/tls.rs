use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use pkcs8::DecodePrivateKey;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
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

fn as_oid(s: &'static [u64]) -> yasna::models::ObjectIdentifier {
    yasna::models::ObjectIdentifier::from_slice(s)
}

fn as_oid2(s: &'static str) -> const_oid::ObjectIdentifier {
    const_oid::ObjectIdentifier::from_str(s).unwrap()
}

lazy_static::lazy_static! {
    static ref OID_DATA_CONTENT_TYPE: yasna::models::ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 7, 1]);
    static ref OID_ENCRYPTED_DATA_CONTENT_TYPE: yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 7, 6]);
    static ref OID_PKCS5_PBKDF2: yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 5, 12]);
    static ref OID2_DATA_CONTENT_TYPE: const_oid::ObjectIdentifier = as_oid2("1.2.840.113549.1.7.1");
}

struct Pkcs5Pbes2 {}

impl Pkcs5Pbes2 {
    fn parse(data: &[u8]) -> Result<Self, ASN1Error> {
        yasna::parse_der(data, |r| {
            r.read_sequence(|r| {
                let oid = r.next().read_oid()?;
                println!("OID in pbes2 is {:?}", oid);
                let thing = if oid == *OID_PKCS5_PBKDF2 {
                    r.next().read_sequence(|r| {
                        let d1 = r.next().read_bytes()?;
                        println!("PBKDF2 data1 is {:X?}", d1);
                        let times = r.next().read_u32()?;
                        println!("PBKDF2 times is {}", times);
                        r.next().read_sequence(|r| {
                            let oid = r.next().read_oid()?;
                            println!("PBKDF2 digest is {:?}", oid);
                            r.next().read_null();
                            Ok(42)
                        })?;
                        Ok(42)
                    })?;
                    Ok(42)
                } else {
                    Err(ASN1Error::new(yasna::ASN1ErrorKind::Invalid))
                };
                thing.expect("Failed to read thing");
                Ok(42)
            })?;

            Ok(Self {})
        })
    }
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
    let thing2 = ec.safe_bags(pass).expect("Problem reading bags");
    println!("PFX bags {}:", thing2.len());
    for b in thing2.iter() {
        let data = b.bag.other_bag_data().expect("Expected other bag data");
        let oid = b.bag.oid();
        if oid == *OID_ENCRYPTED_DATA_CONTENT_TYPE {
            println!("Decoding encrypted pkcs 7 data");
            use der::Decode;
            let mut reader = der::SliceReader::new(&data).unwrap();
            let ed: cms::encrypted_data::EncryptedData =
                cms::encrypted_data::EncryptedData::decode(&mut reader)
                    .expect("Failed to decode encrypted data");
            if ed.enc_content_info.content_type == *OID2_DATA_CONTENT_TYPE {
                println!("Need to decode some pkcs7 data");
                if ed.enc_content_info.content_enc_alg.oid == pkcs5::pbes2::PBES2_OID {
                    let parameters = ed.enc_content_info.content_enc_alg.parameters;
                    println!("Need to decrypt with pkcs5 pbes2");
                    if let Some(parameters) = parameters {
                        println!("mystery: {:x?}", parameters);
                        let parameters = Pkcs5Pbes2::parse(parameters.value())
                            .expect("Failed to parse pbes2 parameters");
                    }

                    todo!("Do the thing");
                } else {
                    println!(
                        "Unexpected encryption algorithm: {:?}",
                        ed.enc_content_info.content_enc_alg.oid
                    );
                    todo!("Figure out what to do here");
                }
            } else {
                println!("Data {:?} is unexpected", ed.enc_content_info.content_type);
                todo!("Figure out what to do here");
            }
        } else if oid == *OID_DATA_CONTENT_TYPE {
            println!("Decoding pkcs 7 data");
            todo!("Do the thing");
        } else {
            println!("Unknown data {:?}", oid);
            todo!("Figure out what to do");
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
