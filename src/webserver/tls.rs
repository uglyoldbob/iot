use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use p12::yasna::{self, ASN1ErrorKind};

use der::{Decode, Encode, Reader};
use pkcs5::pbes2::Pbkdf2Params;
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
    static ref OID_PKCS7_DATA_CONTENT_TYPE: yasna::models::ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 7, 1]);
    static ref OID_SHROUDED_KEY_BAG: yasna::models::ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 2]);
    static ref OID_CERT_BAG: yasna::models::ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 3]);
    static ref OID_PKCS7_ENCRYPTED_DATA_CONTENT_TYPE: yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 7, 6]);
    static ref OID_PKCS5_PBES2: yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 5, 13]);
    static ref OID_PKCS5_PBKDF2: yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 5, 12]);
    static ref OID_HMAC_SHA256: yasna::models::ObjectIdentifier =
        as_oid(&[1,2,840,113_549,2,9]);
    static ref OID_AES_256_CBC: yasna::models::ObjectIdentifier =
        as_oid(&[2,16,840,1,101,3,4,1,42]);
    static ref OID_PKCS9_FRIENDLY_NAME: yasna::models::ObjectIdentifier =
        as_oid(&[1,2,840,113_549,1,9,20]);
    static ref OID_PKCS9_LOCAL_KEY_ID: yasna::models::ObjectIdentifier =
        as_oid(&[1,2,840,113_549,1,9,21]);
    static ref OID_SHA256: yasna::models::ObjectIdentifier =
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

    fn from_oid(oid: yasna::models::ObjectIdentifier) -> Option<Self> {
        if oid == *OID_HMAC_SHA256 {
            Some(HmacMethod::Sha256)
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct Pbes2Pbkdf2Params {
    salt: Vec<u8>,
    count: u32,
    length: Option<u16>,
    method: HmacMethod,
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
    fn decrypt(&self, scheme: &EncryptionScheme, data: &Vec<u8>, password: &[u8]) -> Vec<u8> {
        match self {
            Pbes2Params::Pbes2Pbkdf2(p) => {
                let pbkdf2 = p.to_pbkdf2_params();
                let parameters = pkcs5::pbes2::Parameters {
                    kdf: pkcs5::pbes2::Kdf::Pbkdf2(pbkdf2),
                    encryption: scheme.get_pbes2_scheme().unwrap(),
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
    scheme: EncryptionScheme,
}

impl Pkcs5Pbes2 {
    fn decrypt(&self, data: &Vec<u8>, password: &[u8]) -> Vec<u8> {
        self.params.decrypt(&self.scheme, data, password)
    }

    fn parse(r: yasna::BERReader) -> Result<Self, ASN1Error> {
        let mut params: Pbes2Params = Pbes2Params::Unknown;
        let mut scheme = EncryptionScheme::Unknown;
        r.read_multi(|r| {
            r.next().read_sequence(|r| {
                let oid = r.next().read_oid()?;
                if oid == *OID_PKCS5_PBKDF2 {
                    let mut lparams = Pbes2Pbkdf2Params::new();
                    r.next().read_sequence(|r| {
                        let data = r.next().read_bytes()?;
                        lparams.salt = data.clone();
                        let count = r.next().read_u32()?;
                        lparams.count = count;
                        println!("Count {} data {:X?}", count, data);
                        r.next().read_sequence(|r| {
                            let oid = r.next().read_oid()?;
                            println!("The hmac is {:?}", oid);
                            lparams.method = HmacMethod::from_oid(oid).unwrap();
                            r.next().read_null()?;
                            Ok(42)
                        })?;
                        Ok(42)
                    })?;
                    params = Pbes2Params::Pbes2Pbkdf2(lparams);
                    Ok(42)
                } else {
                    panic!("Unknown algorithm: {:?}", oid);
                }
            })?;
            r.next().read_sequence(|r| {
                let oid = r.next().read_oid()?;
                let data = r.next().read_bytes()?;
                if oid == *OID_AES_256_CBC {
                    let mut d: [u8; 16] = [0; 16];
                    d.copy_from_slice(&data);
                    scheme = EncryptionScheme::Aes256(d);
                }
                Ok(42)
            })?;
            Ok(())
        })?;
        Ok(Self { params, scheme })
    }

    fn parse_parameters(data: &[u8]) -> Result<Self, ASN1Error> {
        yasna::parse_der(data, |r| Self::parse(r))
    }
}

#[derive(Debug)]
struct PkiMessage {
    cert: x509_cert::Certificate,
}

impl PkiMessage {
    fn parse(data: &[u8]) -> Result<Self, ASN1Error> {
        let d = yasna::parse_der(data, |r| {
            r.read_sequence(|r| {
                let d = r
                    .next()
                    .read_sequence(|r| {
                        let oid = r.next().read_oid()?;
                        let cert = if oid == *OID_CERT_BAG {
                            let certdata = r
                                .next()
                                .read_tagged(yasna::Tag::context(0), |r| {
                                    let bag = p12::CertBag::parse(r)?;
                                    if let p12::CertBag::X509(x509) = bag {
                                        let mut reader = der::SliceReader::new(&x509).unwrap();
                                        let cert = x509_cert::certificate::Certificate::decode(
                                            &mut reader,
                                        )
                                        .expect("Failed to read x509");
                                        return Ok(cert);
                                    }
                                    Err(ASN1Error::new(yasna::ASN1ErrorKind::Invalid))
                                })
                                .expect("Failed parse 17");
                            certdata
                        } else {
                            panic!("Unexpected oid for certificate");
                        };
                        r.next().read_set_of(|r| {
                            r.read_sequence(|r| {
                                let oid = r.next().read_oid()?;
                                if oid == *OID_PKCS9_LOCAL_KEY_ID {
                                    r.next().read_set_of(|r| {
                                        let d = r.read_bytes()?;
                                        Ok(())
                                    })?;
                                } else if oid == *OID_PKCS9_FRIENDLY_NAME {
                                    r.next().read_set_of(|r| {
                                        let name = r.read_bmp_string()?;
                                        Ok(())
                                    })?;
                                }
                                Ok(42)
                            })?;
                            Ok(())
                        })?;
                        Ok(cert)
                    })
                    .expect("Failed parse 18");
                Ok(d)
            })
        })?;
        Ok(Self { cert: d })
    }
}

#[derive(Debug)]
struct X509Request {
    key: p12::EncryptedPrivateKeyInfo,
}

impl X509Request {
    fn decrypt(&self, pass: &[u8]) -> Option<Vec<u8>> {
        if let p12::AlgorithmIdentifier::OtherAlg(o) = &self.key.encryption_algorithm {
            if o.algorithm_type == *OID_PKCS5_PBES2 {
                let data = o.params.as_ref().unwrap();
                let p =
                    yasna::parse_der(data, |r| r.read_sequence(|r| Pkcs5Pbes2::parse(r.next())))
                        .expect("Failed to decode pbes2");
                let pkey_der = p.decrypt(&self.key.encrypted_data, pass);
                println!("pkey is {}", pkey_der.len());
                for b in pkey_der {
                    print!("{:02X}", b);
                }
                println!("");
                todo!("Parse the pkey_der as der data")
            } else {
                panic!("Unexpected algorithm type for private key");
            }
        }
        None
    }

    fn parse(data: &[u8], pass: &[u8]) -> Result<Self, ASN1Error> {
        yasna::parse_der(data, |r| {
            r.read_sequence(|r| {
                r.next().read_sequence(|r| {
                    let oid = r.next().read_oid()?;
                    let pkey = if oid == *OID_SHROUDED_KEY_BAG {
                        let pkey = r.next().read_tagged(yasna::Tag::context(0), |r| {
                            p12::EncryptedPrivateKeyInfo::parse(r)
                        })?;
                        Ok(Self { key: pkey })
                    } else {
                        Err(ASN1Error::new(yasna::ASN1ErrorKind::Invalid))
                    };
                    let pkey = pkey?;
                    let s = r.next().read_set_of(|r| {
                        let s = r.read_sequence(|r| {
                            let oid = r.next().read_oid().expect("Failed to read oid");
                            println!("Oid5 is {:?}", oid);
                            if oid == *OID_PKCS9_LOCAL_KEY_ID {
                                r.next()
                                    .read_set(|r| {
                                        let d = r
                                            .next(&[yasna::tags::TAG_OCTETSTRING])?
                                            .read_bytes()
                                            .expect("Failed to read local key id");
                                        Ok(())
                                    })
                                    .expect("Failed to read sequence 2");
                            } else if oid == *OID_PKCS9_FRIENDLY_NAME {
                                r.next()
                                    .read_set(|r| {
                                        let d = r
                                            .next(&[yasna::tags::TAG_BMPSTRING])?
                                            .read_bmp_string()
                                            .expect("Failed to read friendly name");
                                        Ok(())
                                    })
                                    .expect("Failed to read sequence 3");
                            } else {
                                panic!("Unexpected oid in public key info");
                            }
                            Ok(())
                        });
                        println!("Sequence return is {:?}", s);
                        s
                    });
                    s?;
                    Ok(pkey)
                })
            })
        })
    }
}

fn safe_bags(ec: &p12::PFX, pass: &[u8]) -> Result<Vec<p12::SafeBag>, ASN1Error> {
    let data = ec.auth_safe.data(pass).unwrap();
    let safe_bags = yasna::parse_ber(&data, |r| r.collect_sequence_of(p12::SafeBag::parse))?;

    let mut result = vec![];
    for safe_bag in safe_bags.iter() {
        result.push(safe_bag.to_owned())
    }
    Ok(result)
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
    let thing2 = safe_bags(&ec, pass.as_bytes()).expect("Problem reading bags");
    println!("PFX bags {}:", thing2.len());

    let mut certificate = None;
    let mut pkey = None;

    for b in thing2.iter() {
        let mob = if let p12::SafeBagKind::OtherBagKind(o) = &b.bag {
            Some(o)
        } else {
            None
        };
        let ob = mob.expect("Expected other bag data");
        if ob.bag_id == *OID_PKCS7_ENCRYPTED_DATA_CONTENT_TYPE {
            if let Ok(bag) = cms::encrypted_data::EncryptedData::from_der(&ob.bag_value) {
                let algorithm = bag.enc_content_info.content_enc_alg;
                let bag_data = bag.enc_content_info.encrypted_content.unwrap();
                if algorithm.oid == pkcs5::pbes2::PBES2_OID {
                    let a = Pkcs5Pbes2::parse_parameters(algorithm.parameters.unwrap().value())
                        .unwrap();
                    let bdv = bag_data.into_bytes();
                    let decrypted = a.decrypt(&bdv, pass.as_bytes());
                    let decrypted_oid = bag.enc_content_info.content_type;
                    if decrypted_oid == *OID2_DATA_CONTENT_TYPE {
                        let cert = PkiMessage::parse(&decrypted)
                            .expect("Failed to parse certificate data");
                        certificate = Some(cert);
                    }
                } else {
                    panic!("Unexpected algorithm {:?}", algorithm.oid);
                }
            }
        } else if ob.bag_id == *OID_PKCS7_DATA_CONTENT_TYPE {
            let bag_data = yasna::parse_der(&ob.bag_value, |r| r.read_bytes())
                .expect("Failed to read bag data");
            let req =
                X509Request::parse(&bag_data, pass.as_bytes()).expect("Failed to read request");
            let p = req
                .decrypt(pass.as_bytes())
                .expect("Failed to decrypt private key");
            println!("The request is {:?}", p);
            pkey = Some(p);
        } else {
            todo!("Handle bag {:X?}", ob.bag_id);
        }
    }
    println!("Certificate is {:?}", certificate);
    todo!("Convert to what is needed");
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
