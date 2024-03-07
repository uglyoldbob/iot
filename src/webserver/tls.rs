use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use p12::yasna::ASN1Error;
use pkcs5::pbes2::Pbkdf2Params;
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

fn as_oid(s: &'static [u64]) -> p12::yasna::models::ObjectIdentifier {
    p12::yasna::models::ObjectIdentifier::from_slice(s)
}

fn as_oid2(s: &'static str) -> const_oid::ObjectIdentifier {
    const_oid::ObjectIdentifier::from_str(s).unwrap()
}

lazy_static::lazy_static! {
    static ref OID_DATA_CONTENT_TYPE: p12::yasna::models::ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 7, 1]);
    static ref OID_ENCRYPTED_DATA_CONTENT_TYPE: p12::yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 7, 6]);
    static ref OID_PKCS5_PBES2: p12::yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 5, 13]);
    static ref OID_PKCS5_PBKDF2: p12::yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 5, 12]);
    static ref OID_HMAC_SHA256: p12::yasna::models::ObjectIdentifier =
        as_oid(&[1,2,840,113_549,2,9]);
    static ref OID_AES_256_CBC: p12::yasna::models::ObjectIdentifier =
        as_oid(&[2,16,840,1,101,3,4,1,42]);
    static ref OID_PKCS9_FRIENDLY_NAME: p12::yasna::models::ObjectIdentifier =
        as_oid(&[1,2,840,113_549,1,9,20]);
    static ref OID_PKCS9_LOCAL_KEY_ID: p12::yasna::models::ObjectIdentifier =
        as_oid(&[1,2,840,113_549,1,9,21]);
    static ref OID_SHA256: p12::yasna::models::ObjectIdentifier =
        as_oid(&[2,16,840,1,101,3,4,2,1]);
    static ref OID2_DATA_CONTENT_TYPE: const_oid::ObjectIdentifier = as_oid2("1.2.840.113549.1.7.1");
}

#[derive(Debug)]
enum HmacMethod {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl HmacMethod {
    fn to_prf(&self) -> pkcs5::pbes2::Pbkdf2Prf {
        match self {
            HmacMethod::Sha1 => pkcs5::pbes2::Pbkdf2Prf::HmacWithSha1,
            HmacMethod::Sha224 => pkcs5::pbes2::Pbkdf2Prf::HmacWithSha224,
            HmacMethod::Sha256 => pkcs5::pbes2::Pbkdf2Prf::HmacWithSha256,
            HmacMethod::Sha384 => pkcs5::pbes2::Pbkdf2Prf::HmacWithSha384,
            HmacMethod::Sha512 => pkcs5::pbes2::Pbkdf2Prf::HmacWithSha512,
        }
    }
}

#[derive(Debug)]
struct Pbes2Pbkdf2Params {
    salt: Vec<u8>,
    count: u32,
    length: Option<u16>,
    method: HmacMethod,
    scheme: EncryptionScheme,
}

#[derive(Debug)]
enum EncryptionScheme {
    Aes256([u8; 16]),
    Unknown,
}

impl EncryptionScheme {
    fn get_pbes2_scheme<'a>(&'a self) -> Option<pkcs5::pbes2::EncryptionScheme<'a>> {
        match self {
            EncryptionScheme::Aes256(s) => {
                let p = pkcs5::pbes2::EncryptionScheme::Aes256Cbc { iv: s };
                Some(p)
            }
            EncryptionScheme::Unknown => None,
        }
    }
}

impl Pbes2Pbkdf2Params {
    fn new() -> Self {
        Self {
            salt: Vec::new(),
            count: 0,
            length: None,
            method: HmacMethod::Sha512,
            scheme: EncryptionScheme::Unknown,
        }
    }

    fn to_pbkdf2_params<'a>(&'a self) -> pkcs5::pbes2::Pbkdf2Params<'a> {
        pkcs5::pbes2::Pbkdf2Params {
            salt: &self.salt,
            iteration_count: self.count,
            key_length: self.length,
            prf: self.method.to_prf(),
        }
    }
}

#[derive(Debug)]
enum Pbes2Params {
    Pbes2Pbkdf2(Pbes2Pbkdf2Params),
    Unknown,
}

impl Pbes2Params {
    fn decrypt(&self, data: &Vec<u8>, password: &[u8]) -> Vec<u8> {
        match self {
            Pbes2Params::Pbes2Pbkdf2(p) => {
                let pbkdf2 = p.to_pbkdf2_params();
                let parameters = pkcs5::pbes2::Parameters {
                    kdf: pkcs5::pbes2::Kdf::Pbkdf2(pbkdf2),
                    encryption: p.scheme.get_pbes2_scheme().unwrap(),
                };
                parameters
                    .decrypt(password, data)
                    .expect("Failed to decrypt data")
                    .to_vec()
            }
            Pbes2Params::Unknown => {
                panic!("Cannot decrypt unknown algorithm");
            }
        }
    }
}

#[derive(Debug)]
struct Pkcs5Pbes2 {
    params: Pbes2Params,
}

impl Pkcs5Pbes2 {
    fn parse(data: &[u8], pass: &[u8]) -> Result<Self, ASN1Error> {
        Ok(Self {
            params: Pbes2Params::Unknown,
        })
    }

    fn parse_from_reader_seq(r: &mut p12::yasna::BERReaderSeq<'_, '_>) -> Result<Self, ASN1Error> {
        let mut params: Pbes2Params = Pbes2Params::Unknown;
        r.next().read_sequence(|r| {
            let mut lparams = Pbes2Pbkdf2Params::new();
            r.next()
                .read_sequence(|r| {
                    let oid = r.next().read_oid().expect("Failed to read oid1");
                    let thing = if oid == *OID_PKCS5_PBKDF2 {
                        r.next()
                            .read_sequence(|r| {
                                let d1 = r.next().read_bytes().expect("Failed to read pbkdf2 salt");
                                lparams.salt = d1.clone();
                                let times =
                                    r.next().read_u32().expect("Failed to read pbkdf2 times");
                                lparams.count = times;
                                r.next().read_sequence(|r| {
                                    let oid =
                                        r.next().read_oid().expect("Failed to read digest oid");
                                    let hmac = if oid == *OID_HMAC_SHA256 {
                                        HmacMethod::Sha256
                                    } else {
                                        panic!("Unknown digest algorithm {:?}", oid);
                                    };
                                    r.next().read_null().expect("Failed to read null in digest");
                                    lparams.method = hmac;

                                    Ok(oid)
                                })
                            })
                            .expect("Failed to read stuff");
                        Ok(42)
                    } else {
                        Err(ASN1Error::new(p12::yasna::ASN1ErrorKind::Invalid))
                    };
                    thing.expect("Failed to read thing");
                    Ok(42)
                })
                .expect("Failed to read first sequence");
            r.next()
                .read_sequence(|r| {
                    let oid = r.next().read_oid()?;
                    if oid == *OID_AES_256_CBC {
                        let data = r.next().read_bytes()?;
                        let mut data2: [u8; 16] = [0; 16];
                        data2.copy_from_slice(&data[0..16]);
                        lparams.scheme = EncryptionScheme::Aes256(data2);
                    }
                    Ok(42)
                })
                .expect("Failed to read sequence");
            let lparams = Pbes2Params::Pbes2Pbkdf2(lparams);
            params = lparams;
            Ok(42)
        })?;
        Ok(Self { params })
    }
}

#[derive(Debug)]
struct Pkcs12Pkcs7Data {}

impl Pkcs12Pkcs7Data {
    fn parse(data: &[u8], pass: &[u8]) -> Result<Self, ASN1Error> {
        p12::yasna::parse_der(data, |r| {
            let d = r.read_bytes()?;
            let a = p12::yasna::parse_der(&d, |r| {
                r.read_sequence(|r| {
                    r.next().read_sequence(|r| {
                        let oid = r.next().read_oid()?;
                        println!("The oid is {:?}", oid);
                        let data = r.next().read_tagged_der()?;
                        println!("The tagged data is {:X?}", data);
                        let pkey = p12::yasna::parse_der(data.value(), |r| {
                            p12::SafeBagKind::parse(r, oid)
                        })?;
                        println!("The safebag is {:X?}", pkey);
                        if let p12::SafeBagKind::Pkcs8ShroudedKeyBag(pkey) = pkey {
                            if let p12::AlgorithmIdentifier::OtherAlg(pkey) =
                                pkey.encryption_algorithm
                            {
                                if pkey.algorithm_type == *OID_PKCS5_PBES2 {
                                    let pkey_data = pkey.params.unwrap();
                                    println!("Decoding pbes2 data");
                                    let stuff = Pkcs5Pbes2::parse(&pkey_data, pass)?;
                                    println!("BAG STUFF IS {:X?}", stuff);
                                } else {
                                    panic!("Unexpected oid");
                                }
                            }
                        }
                        r.next().read_set_of(|r| {
                            println!("About to read sequence in set");
                            r.read_sequence(|r| {
                                let oid = r.next().read_oid()?;
                                println!("Set oid is {:?}", oid);
                                if oid == *OID_PKCS9_LOCAL_KEY_ID {
                                    r.next().read_set_of(|r| {
                                        let d = r.read_bytes()?;
                                        println!("Data from set local key id is {:X?}", d);
                                        Ok(())
                                    })?;
                                } else if oid == *OID_PKCS9_FRIENDLY_NAME {
                                    r.next().read_set_of(|r| {
                                        let d = r.read_bmp_string()?;
                                        println!("Data from friendly name is {}", d);
                                        Ok(())
                                    })?;
                                }
                                Ok(42)
                            })?;
                            Ok(())
                        })?;
                        Ok(42)
                    })?;
                    Ok(42)
                })?;
                Ok(42)
            })?;
            Ok(Self {})
        })
    }
}

#[derive(Debug)]
struct Pkcs12Pkcs7EncryptedData {
    pw: p12::yasna::models::ObjectIdentifier,
    params: Pbes2Params,
    data: Vec<u8>,
}

impl Pkcs12Pkcs7EncryptedData {
    fn decrypt(&self, pass: &[u8]) -> Option<Vec<u8>> {
        Some(self.params.decrypt(&self.data, pass))
    }

    fn parse(data: &[u8]) -> Result<Self, ASN1Error> {
        p12::yasna::parse_der(data, |r| {
            let mut oid_pw = None;
            let mut params = None;
            let mut data = Vec::new();
            r.read_sequence(|r| {
                let v = r.next().read_u8()?;
                r.next().read_sequence(|r| {
                    let oid = r.next().read_oid()?;
                    if oid == *OID_DATA_CONTENT_TYPE {
                        r.next().read_sequence(|r| {
                            let oid = r.next().read_oid()?;
                            oid_pw = Some(oid.clone());
                            if oid == *OID_PKCS5_PBES2 {
                                let stuff = Pkcs5Pbes2::parse_from_reader_seq(r)?;
                                println!("Decoded stuff is {:X?}", stuff);
                                params = Some(stuff.params);
                            }
                            Ok(42)
                        })?;
                    } else {
                        panic!("Unexpected oid");
                    }
                    let a = r
                        .next()
                        .read_tagged_der()
                        .expect("Could not read bytes here");
                    data = a.value().to_vec();
                    Ok(42)
                })?;

                Ok(42)
            })
            .expect("Failed to read tagged data");

            Ok(Self {
                pw: oid_pw.unwrap(),
                params: params.unwrap(),
                data,
            })
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
            let stuff = Pkcs12Pkcs7EncryptedData::parse(&data)
                .expect("Failed to read pbes2 data the first time");
            let result = stuff.decrypt(pass.as_bytes());
            println!("Decryption result is {:X?}", result);
        } else if oid == *OID_DATA_CONTENT_TYPE {
            println!("Decoding pkcs 7 data");
            let stuff = Pkcs12Pkcs7Data::parse(&data, pass.as_bytes())
                .expect("Failed to read regular data");
            println!("The decoded data is {:?}", stuff);
        } else {
            println!("Unknown data {:?}", oid);
            todo!("Figure out what to do");
        }
    }
    let thing3 = ec.mac_data;
    if let Some(thing3) = thing3 {
        println!("PFX MAC data is {:?}", thing3);
        if let p12::AlgorithmIdentifier::OtherAlg(alg) = thing3.mac.digest_algorithm {
            println!("Encryption oid is {:?}", alg.algorithm_type);
            if alg.algorithm_type == *OID_SHA256 {
                println!("Decrypting with sha-256?");
                todo!("Decode the private key");
            }
        }
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
