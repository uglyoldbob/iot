//! A module for loading and parsing tls certificates

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use p12::yasna;

use der::Decode;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::danger::ClientCertVerifier;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use yasna::ASN1Error;

/// A generic error type
type Error = Box<dyn std::error::Error + 'static>;

/// Represents a pkcs12 certificate container on the filesystem
pub struct TlsConfig {
    /// The location of the file
    pub cert_file: PathBuf,
    /// The password of the file
    pub key_password: String,
}

impl TlsConfig {
    /// Create a new tls config, specifying the pkcs12 specs
    /// # Arguments
    /// * cert_file - The location of the pkcs12 document
    /// * pass - The password for the pkcs12 document
    pub fn new<P: Into<PathBuf>, S: Into<String>>(cert_file: P, pass: S) -> Self {
        TlsConfig {
            cert_file: cert_file.into(),
            key_password: pass.into(),
        }
    }
}

/// Create an OID
fn as_oid(s: &'static [u64]) -> yasna::models::ObjectIdentifier {
    yasna::models::ObjectIdentifier::from_slice(s)
}

/// Create a const OID
fn as_oid2(s: &'static str) -> const_oid::ObjectIdentifier {
    const_oid::ObjectIdentifier::from_str(s).unwrap()
}

lazy_static::lazy_static! {
    static ref OID_PKCS7_DATA_CONTENT_TYPE: yasna::models::ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 7, 1]);
    static ref OID_SHROUDED_KEY_BAG: yasna::models::ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 2]);
    static ref OID_CERT_BAG: yasna::models::ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 3]);
    static ref OID_PKCS1_RSA_ENCRYPTION: yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 1, 1]);
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

/// The HMAC method
#[derive(Debug)]
#[allow(dead_code)]
enum HmacMethod {
    /// Sha1 method
    Sha1,
    /// Sha224 method
    Sha224,
    /// Sha256 method
    Sha256,
    /// Sha384 method
    Sha384,
    /// Sha512 method
    Sha512,
}

impl HmacMethod {
    /// Convert to a pkcs5 struct
    fn to_prf(&self) -> pkcs5::pbes2::Pbkdf2Prf {
        match self {
            HmacMethod::Sha1 => pkcs5::pbes2::Pbkdf2Prf::HmacWithSha1,
            HmacMethod::Sha224 => pkcs5::pbes2::Pbkdf2Prf::HmacWithSha224,
            HmacMethod::Sha256 => pkcs5::pbes2::Pbkdf2Prf::HmacWithSha256,
            HmacMethod::Sha384 => pkcs5::pbes2::Pbkdf2Prf::HmacWithSha384,
            HmacMethod::Sha512 => pkcs5::pbes2::Pbkdf2Prf::HmacWithSha512,
        }
    }

    /// Convert from oid to Self, if possible
    fn from_oid(oid: yasna::models::ObjectIdentifier) -> Option<Self> {
        if oid == *OID_HMAC_SHA256 {
            Some(HmacMethod::Sha256)
        } else {
            None
        }
    }
}

/// Represents parameters for the pbkdf2 algorithm
#[derive(Debug)]
struct Pbes2Pbkdf2Params {
    /// The salt of the pbkdf2 algorithm
    salt: Vec<u8>,
    /// Number of iterations
    count: u32,
    /// Length?
    length: Option<u16>,
    /// The hmac method for the pbkdf2
    method: HmacMethod,
}

/// The encryption scheme to use for data
#[derive(Debug)]
enum EncryptionScheme {
    /// Aes 256 with an iv
    Aes256([u8; 16]),
    /// Unknown encryption scheme
    Unknown,
}

impl EncryptionScheme {
    /// Convert to a pkcs5 struct
    fn get_pbes2_scheme(&self) -> Option<pkcs5::pbes2::EncryptionScheme<'_>> {
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
    /// Create a blank Self
    fn new() -> Self {
        Self {
            salt: Vec::new(),
            count: 0,
            length: None,
            method: HmacMethod::Sha512,
        }
    }

    /// Convert to a pkcs5 struct
    fn to_pbkdf2_params(&self) -> pkcs5::pbes2::Pbkdf2Params<'_> {
        pkcs5::pbes2::Pbkdf2Params {
            salt: &self.salt,
            iteration_count: self.count,
            key_length: self.length,
            prf: self.method.to_prf(),
        }
    }
}

/// The parameters for pbes2 encryption
#[derive(Debug)]
enum Pbes2Params {
    /// The pbkdf2 algorithm is used
    Pbes2Pbkdf2(Pbes2Pbkdf2Params),
    /// An unknown algorithm
    Unknown,
}

impl Pbes2Params {
    /// Decrypt the contents of the data
    /// # Arguments
    /// * scheme - The encryption scheme used
    /// * data - The data to deccrypt
    /// * password - The password the data is protected with
    fn decrypt(
        &self,
        scheme: &EncryptionScheme,
        data: &[u8],
        password: &[u8],
    ) -> zeroize::Zeroizing<Vec<u8>> {
        match self {
            Pbes2Params::Pbes2Pbkdf2(p) => {
                let pbkdf2 = p.to_pbkdf2_params();
                let parameters = pkcs5::pbes2::Parameters {
                    kdf: pkcs5::pbes2::Kdf::Pbkdf2(pbkdf2),
                    encryption: scheme.get_pbes2_scheme().unwrap(),
                };
                zeroize::Zeroizing::new(
                    parameters
                        .decrypt(password, data)
                        .expect("Failed to decrypt data")
                        .to_vec(),
                )
            }
            Pbes2Params::Unknown => {
                panic!("Cannot decrypt unknown algorithm");
            }
        }
    }
}

/// Represents data encrypted with pbes2
#[derive(Debug)]
struct Pkcs5Pbes2 {
    /// The pbes2 parameters
    params: Pbes2Params,
    /// The encryption scheme used
    scheme: EncryptionScheme,
}

impl Pkcs5Pbes2 {
    /// Decrypt the contents of the data
    /// # Arguments
    /// * data - The data to deccrypt
    /// * password - The password the data is protected with
    fn decrypt(&self, data: &[u8], password: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
        self.params.decrypt(&self.scheme, data, password)
    }

    /// Parse a Self with the given reader
    /// # Arguments
    /// * r - The BERReader to use for parsing into Self
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
                        r.next().read_sequence(|r| {
                            let oid = r.next().read_oid()?;
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

    /// Parse some der data to produce a Self
    /// # Arguments
    /// * data - The der data to parse
    fn parse_parameters(data: &[u8]) -> Result<Self, ASN1Error> {
        yasna::parse_der(data, |r| Self::parse(r))
    }
}

/// Represents a pki message containg an x509 certificate
#[derive(Debug)]
struct PkiMessage {
    /// The decoded contents of the x509 certificate
    cert: x509_cert::Certificate,
    /// The der representation of the x509 certificate
    der: Vec<u8>,
}

impl PkiMessage {
    /// Return the der contents of an x509 certificate
    fn get_der(&self) -> &Vec<u8> {
        &self.der
    }

    /// Parse some der data into a Self
    /// # Arguments
    /// * data - The der data to parse
    fn parse(data: &[u8]) -> Result<Self, ASN1Error> {
        let mut der_contents = None;
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
                                        der_contents = Some(x509.to_vec());
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
                                        let _d = r.read_bytes()?;
                                        Ok(())
                                    })?;
                                } else if oid == *OID_PKCS9_FRIENDLY_NAME {
                                    r.next().read_set_of(|r| {
                                        let _name = r.read_bmp_string()?;
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
        Ok(Self {
            cert: d,
            der: der_contents.expect("No x509 certificate found"),
        })
    }
}

/// Represents an x509 private key
#[derive(Debug)]
struct X509PrivateKey {
    /// The der contents of the private key
    der: Vec<u8>,
}

impl zeroize::Zeroize for X509PrivateKey {
    fn zeroize(&mut self) {
        self.der.zeroize();
    }
}

impl X509PrivateKey {
    /// Return the der contents of the private key
    fn get_der(&self) -> &Vec<u8> {
        &self.der
    }

    /// Create a new private key struct, containg the der contents of a private key
    fn new(data: &[u8]) -> Self {
        Self { der: data.to_vec() }
    }
}

/// Represents an x509 request structure containing an encrypted private key.
#[derive(Debug)]
struct X509Request {
    /// The encrypted private key
    key: p12::EncryptedPrivateKeyInfo,
}

impl X509Request {
    /// Decrypt the contents of the encrypted private key with the specified password
    /// # Arguments
    /// * pass - The password protecting the private key.
    fn decrypt(&self, pass: &[u8]) -> Option<zeroize::Zeroizing<X509PrivateKey>> {
        if let p12::AlgorithmIdentifier::OtherAlg(o) = &self.key.encryption_algorithm {
            if o.algorithm_type == *OID_PKCS5_PBES2 {
                let data = o.params.as_ref().unwrap();
                let p =
                    yasna::parse_der(data, |r| r.read_sequence(|r| Pkcs5Pbes2::parse(r.next())))
                        .expect("Failed to decode pbes2");
                let pkey_der = p.decrypt(&self.key.encrypted_data, pass);
                let pkey = X509PrivateKey::new(&pkey_der);
                return Some(zeroize::Zeroizing::new(pkey));
            } else {
                panic!("Unexpected algorithm type for private key");
            }
        }
        None
    }

    /// Parse the given der data to produce a Self
    /// # Arguments
    /// * data - The der data to process
    fn parse(data: &[u8]) -> Result<Self, ASN1Error> {
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
                            if oid == *OID_PKCS9_LOCAL_KEY_ID {
                                r.next()
                                    .read_set(|r| {
                                        let _d = r
                                            .next(&[yasna::tags::TAG_OCTETSTRING])?
                                            .read_bytes()
                                            .expect("Failed to read local key id");
                                        Ok(())
                                    })
                                    .expect("Failed to read sequence 2");
                            } else if oid == *OID_PKCS9_FRIENDLY_NAME {
                                r.next()
                                    .read_set(|r| {
                                        let _d = r
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
                        s
                    });
                    s?;
                    Ok(pkey)
                })
            })
        })
    }
}

/// Collect and return the list of safe bags from a pkcs12 PFX container
/// # Arguments
/// * ec - The PFX container object
/// * pass - The password for the container
fn safe_bags(ec: &p12::PFX, pass: &[u8]) -> Result<Vec<p12::SafeBag>, ASN1Error> {
    let data = ec.auth_safe.data(pass).unwrap();
    let safe_bags = yasna::parse_ber(&data, |r| r.collect_sequence_of(p12::SafeBag::parse))?;

    let mut result = vec![];
    for safe_bag in safe_bags.iter() {
        result.push(safe_bag.to_owned())
    }
    Ok(result)
}

/// Check the program config and create a client verifier struct as specified.
/// # Arguments
/// * settings - The program configuration object.
pub fn load_user_cert_data(
    settings: &crate::MainConfiguration,
) -> Option<Arc<dyn ClientCertVerifier>> {
    if let Some(section) = &settings.client_certs {
        println!("Loading client certificate data");
        let mut rcs = RootCertStore::empty();

        for s in section {
            println!("\tClient cert {}", s);
            let mut certbytes = vec![];
            let mut certf = File::open(s)
                .unwrap_or_else(|e| panic!("Failed to open client certificate {}: {}", s, e));
            certf
                .read_to_end(&mut certbytes)
                .unwrap_or_else(|e| panic!("Failed to read client certificate {}: {}", s, e));
            let cder = CertificateDer::from(certbytes);
            rcs.add(cder)
                .unwrap_or_else(|e| panic!("Failed to add client certificate {}: {}", s, e));
        }

        //todo fill out the rcs struct
        let roots = Arc::new(rcs);

        let client_verifier = WebPkiClientVerifier::builder(roots).build().unwrap();
        Some(client_verifier)
    } else {
        println!("Not loading any client certificate information");
        None
    }
}

/// Loads an https certificate from a pkcs12 container, into a format usable by rustls.
/// # Arguments
/// * certfile - The Path for the pkcs12 container
/// * pass - The password for the container
/// * user_certs - The struct used to verify client id with tls.
pub fn load_certificate<P>(
    certfile: P,
    pass: &str,
    user_certs: Option<Arc<dyn ClientCertVerifier>>,
) -> Result<Arc<ServerConfig>, Error>
where
    P: AsRef<Path>,
{
    let mut certbytes = vec![];
    let mut certf = File::open(&certfile)?;
    certf.read_to_end(&mut certbytes)?;

    let ec = p12::PFX::parse(&certbytes).expect("Failed to parse certificate");

    let thing2 = safe_bags(&ec, pass.as_bytes()).expect("Problem reading bags");

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
            let req = X509Request::parse(&bag_data).expect("Failed to read request");
            let p = req
                .decrypt(pass.as_bytes())
                .expect("Failed to decrypt private key");
            pkey = Some(p);
        } else {
            todo!("Handle bag {:X?}", ob.bag_id);
        }
    }

    let certificate = certificate.expect("No certificate loaded for https");
    let pkey = pkey.expect("No private key loaded for https");

    let cert_der = certificate.get_der();

    let pkey_der = pkey.get_der();

    let pkey = PrivatePkcs8KeyDer::from(pkey_der.to_owned());
    let pkey = PrivateKeyDer::Pkcs8(pkey);

    let c1 = CertificateDer::from(cert_der.to_owned());

    let certs = vec![c1];

    let sc: tokio_rustls::rustls::ConfigBuilder<ServerConfig, tokio_rustls::rustls::WantsVerifier> =
        ServerConfig::builder();

    let sc = if let Some(certs) = user_certs {
        sc.with_client_cert_verifier(certs)
    } else {
        sc.with_no_client_auth()
    };
    let sc = sc.with_single_cert(certs, pkey)?;
    Ok(Arc::new(sc))
}
