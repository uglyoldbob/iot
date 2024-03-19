//! Defines how to import and export pkcs12 certificate data

use crate::oid::*;
use p12::yasna;
use p12::yasna::ASN1Error;

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
        if oid == OID_HMAC_SHA256.to_yasna() {
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
                if oid == OID_PKCS5_PBKDF2.to_yasna() {
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
                if oid == OID_AES_256_CBC.to_yasna() {
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
pub struct PkiMessage {
    /// The decoded contents of the x509 certificate
    cert: x509_cert::Certificate,
    /// The der representation of the x509 certificate
    der: Vec<u8>,
}

impl PkiMessage {
    /// Return the der contents of an x509 certificate
    pub fn get_der(&self) -> &Vec<u8> {
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
                        let cert = if oid == OID_CERT_BAG.to_yasna() {
                            let certdata = r
                                .next()
                                .read_tagged(yasna::Tag::context(0), |r| {
                                    let bag = p12::CertBag::parse(r)?;
                                    if let p12::CertBag::X509(x509) = bag {
                                        use der::Decode;
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
                                if oid == OID_PKCS9_LOCAL_KEY_ID.to_yasna() {
                                    r.next().read_set_of(|r| {
                                        let _d = r.read_bytes()?;
                                        Ok(())
                                    })?;
                                } else if oid == OID_PKCS9_FRIENDLY_NAME.to_yasna() {
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
pub struct X509PrivateKey {
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
    pub fn get_der(&self) -> &Vec<u8> {
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
            if o.algorithm_type == OID_PKCS5_PBES2.to_yasna() {
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
                    let pkey = if oid == OID_SHROUDED_KEY_BAG.to_yasna() {
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
                            if oid == OID_PKCS9_LOCAL_KEY_ID.to_yasna() {
                                r.next()
                                    .read_set(|r| {
                                        let _d = r
                                            .next(&[yasna::tags::TAG_OCTETSTRING])?
                                            .read_bytes()
                                            .expect("Failed to read local key id");
                                        Ok(())
                                    })
                                    .expect("Failed to read sequence 2");
                            } else if oid == OID_PKCS9_FRIENDLY_NAME.to_yasna() {
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

/// A struct for pkcs12 certificates containing a certificate and a private key
pub struct Pkcs12 {
    /// The certificate containg the certificate
    pub certificate: PkiMessage,
    /// The private key
    pub pkey: zeroize::Zeroizing<X509PrivateKey>,
}

impl TryFrom<crate::ca::CaCertificate> for Pkcs12 {
    type Error = ();
    fn try_from(value: crate::ca::CaCertificate) -> Result<Self, Self::Error> {
        Err(())
    }
}

impl Pkcs12 {
    /// Load a pkcs12 from the contents of the file specified
    /// # Arguments
    /// * data - The contents of the pkcs12 document
    /// * pass - The password protecting the document
    pub fn load_from_data(data: &[u8], pass: &[u8]) -> Self {
        let ec = p12::PFX::parse(&data).expect("Failed to parse certificate");

        let thing2 = safe_bags(&ec, pass).expect("Problem reading bags");

        let mut certificate = None;
        let mut pkey = None;

        for b in thing2.iter() {
            let mob = if let p12::SafeBagKind::OtherBagKind(o) = &b.bag {
                Some(o)
            } else {
                None
            };
            let ob = mob.expect("Expected other bag data");
            if ob.bag_id == OID_PKCS7_ENCRYPTED_DATA_CONTENT_TYPE.to_yasna() {
                use der::Decode;
                if let Ok(bag) = cms::encrypted_data::EncryptedData::from_der(&ob.bag_value) {
                    let algorithm = bag.enc_content_info.content_enc_alg;
                    let bag_data = bag.enc_content_info.encrypted_content.unwrap();
                    if algorithm.oid == pkcs5::pbes2::PBES2_OID {
                        let a = Pkcs5Pbes2::parse_parameters(algorithm.parameters.unwrap().value())
                            .unwrap();
                        let bdv = bag_data.into_bytes();
                        let decrypted = a.decrypt(&bdv, pass);
                        let decrypted_oid = bag.enc_content_info.content_type;
                        if decrypted_oid == OID_PKCS7_DATA_CONTENT_TYPE.to_const() {
                            let cert = PkiMessage::parse(&decrypted)
                                .expect("Failed to parse certificate data");
                            certificate = Some(cert);
                        }
                    } else {
                        panic!("Unexpected algorithm {:?}", algorithm.oid);
                    }
                }
            } else if ob.bag_id == OID_PKCS7_DATA_CONTENT_TYPE.to_yasna() {
                let bag_data = yasna::parse_der(&ob.bag_value, |r| r.read_bytes())
                    .expect("Failed to read bag data");
                let req = X509Request::parse(&bag_data).expect("Failed to read request");
                let p = req.decrypt(pass).expect("Failed to decrypt private key");
                pkey = Some(p);
            } else {
                todo!("Handle bag {:X?}", ob.bag_id);
            }
        }

        let certificate = certificate.expect("No certificate loaded for https");
        let pkey = pkey.expect("No private key loaded for https");
        Self { certificate, pkey }
    }
}
