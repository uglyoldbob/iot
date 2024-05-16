//! Defines how to import and export pkcs12 certificate data

use crate::oid::*;

use cms::content_info::{CmsVersion, ContentInfo};
use const_oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA};
use const_oid::db::rfc5912::ID_SHA_256;
use der::Decode;
use pkcs12::mac_data::MacData;
use pkcs12::pfx::Version;
use pkcs8::pkcs5::pbes2::{AES_256_CBC_OID, HMAC_WITH_SHA256_OID, PBES2_OID};

/// A bag attribute
#[derive(Debug, Clone)]
pub enum BagAttribute {
    /// The local key id
    LocalKeyId(Vec<u8>),
    /// The firendly name
    FriendlyName(String),
}

impl TryFrom<&cms::cert::x509::attr::Attribute> for BagAttribute {
    type Error = ();
    fn try_from(value: &cms::cert::x509::attr::Attribute) -> Result<Self, Self::Error> {
        if value.oid == OID_PKCS9_LOCAL_KEY_ID.to_const() {
            let id = &value.values.as_slice()[0];
            let val: der::asn1::OctetString = id.decode_as().unwrap();
            return Ok(Self::LocalKeyId(val.as_bytes().to_vec()));
        }
        if value.oid == OID_PKCS9_FRIENDLY_NAME.to_const() {
            let id = &value.values.as_slice()[0];
            let bmp: der::asn1::BmpString = id.decode_as().unwrap();
            let s = std::str::from_utf8(bmp.as_ref()).unwrap();
            return Ok(Self::FriendlyName(s.to_string()));
        }
        panic!("Unsupported bag attribute {:?}", value.oid);
    }
}

impl BagAttribute {
    /// Convert the bag attribute to its der contents
    fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|w| match self {
            BagAttribute::LocalKeyId(id) => {
                w.write_sequence(|w| {
                    w.next().write_oid(&OID_PKCS9_LOCAL_KEY_ID.to_yasna());
                    w.next().write_set(|w| {
                        w.next().write_bytes(id);
                    });
                });
            }
            BagAttribute::FriendlyName(name) => {
                w.write_sequence(|w| {
                    w.next().write_oid(&OID_PKCS9_FRIENDLY_NAME.to_yasna());
                    w.next().write_set(|w| {
                        w.next().write_bmp_string(name);
                    });
                });
            }
        })
        .to_vec()
    }
}

/// A struct for holding the unparsed (encrypted) contents of a pkcs12 document
pub struct ProtectedPkcs12 {
    /// The der contents of the document
    pub contents: Vec<u8>,
    /// The id number of the document
    pub id: u64,
}

/// A struct for pkcs12 certificates containing a certificate and a private key
pub struct Pkcs12 {
    /// The certificate in der format
    pub cert: Vec<u8>,
    /// The private key in der format
    pub pkey: zeroize::Zeroizing<Vec<u8>>,
    /// The extra attributes for the certificate
    pub attributes: Vec<BagAttribute>,
    /// The id for the certificate
    pub id: u64,
}

use hmac::{Hmac, Mac};
/// The type specifier for doing sha256 hmac operations
type HmacSha256 = Hmac<sha2::Sha256>;

/// Builds an encrypted content info, encrypting the specified data before placing into a container
/// # Arguments
/// * enc_scheme - The encryption scheme to use for encrypting the data
/// * data - The data to encrypt and place into the content info
/// * password - The password to use for encrypting the data
fn build_encrypted_content_info(
    enc_scheme: &pkcs5::EncryptionScheme,
    data: &[u8],
    password: &[u8],
) -> ContentInfo {
    use der::Encode;

    let encrypted_data = enc_scheme.encrypt(password, data).unwrap();

    let encrypted1 = der::asn1::OctetString::new(encrypted_data).unwrap();

    let data1_enc_alg = pkcs8::spki::AlgorithmIdentifier {
        oid: PBES2_OID,
        parameters: Some(der::asn1::Any::encode_from(enc_scheme.pbes2().unwrap()).unwrap()),
    };
    let enc_content_info1 = cms::enveloped_data::EncryptedContentInfo {
        content_type: ID_DATA,
        content_enc_alg: data1_enc_alg,
        encrypted_content: Some(encrypted1),
    };
    let ci1 = cms::encrypted_data::EncryptedData {
        version: CmsVersion::V0,
        enc_content_info: enc_content_info1,
        unprotected_attrs: None,
    };
    let ci1_der = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next()
                .write_oid(&Oid::from_const(ID_ENCRYPTED_DATA).to_yasna());
            w.next().write_tagged(yasna::Tag::context(0), |w| {
                w.write_der(&ci1.to_der().unwrap());
            });
        });
    });
    ContentInfo::from_der(&ci1_der).unwrap()
}

/// Build a plain content info for pkcs12 , containing the specified contents
/// # Arguments
/// * data - The contents to put into the content info
fn build_plain_content_info(data: &[u8]) -> ContentInfo {
    let ci1_der = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&Oid::from_const(ID_DATA).to_yasna());
            w.next().write_tagged(yasna::Tag::context(0), |w| {
                w.write_bytes(data);
            });
        });
    });
    ContentInfo::from_der(&ci1_der).unwrap()
}

/// Constructs a shrouded bag for a pkcs12 container, returning the der contents of the bag. This could potentially be replaced with pkcs12::safe_bag::SafeBag
/// # Arguments
/// * enc_scheme - The encryption scheme to use
/// * data - The data to put in the bag
/// * password - The password to use to encrypt the contents of the bag
/// * attributes - The attributes for the bag
fn build_shrouded_bag(
    enc_scheme: &pkcs5::EncryptionScheme,
    data: &[u8],
    password: &[u8],
    attributes: &[BagAttribute],
) -> Vec<u8> {
    use der::Encode;

    let encrypted_data = enc_scheme.encrypt(password, data).unwrap();
    let encrypted_key = pkcs8::EncryptedPrivateKeyInfo {
        encryption_algorithm: enc_scheme.to_owned(),
        encrypted_data: &encrypted_data,
    };

    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_sequence(|w| {
                w.next()
                    .write_oid(&Oid::from_const(pkcs12::PKCS_12_PKCS8_KEY_BAG_OID).to_yasna());
                w.next().write_tagged(yasna::Tag::context(0), |w| {
                    w.write_der(&encrypted_key.to_der().unwrap());
                });
                w.next().write_set(|w| {
                    for a in attributes {
                        w.next().write_der(&a.to_der());
                    }
                });
            });
        });
    })
    .to_vec()
}

/// Build a certificate bag for a pkcs12 container, containing some data. This could potentially be replaced with pkcs12::safe_bag::SafeBag.
/// # Arguments
/// * data - The data to put into the bag
/// * attributes - The attributes for the bag
fn build_cert_bag(data: &[u8], attributes: &[BagAttribute]) -> Vec<u8> {
    use der::Encode;
    let certbag = pkcs12::cert_type::CertBag {
        cert_id: pkcs12::PKCS_12_X509_CERT_OID,
        cert_value: der::asn1::OctetString::new(data).unwrap(),
    };
    let cert_der = certbag.to_der().unwrap();
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_sequence(|w| {
                w.next()
                    .write_oid(&Oid::from_const(pkcs12::PKCS_12_CERT_BAG_OID).to_yasna());
                w.next().write_tagged(yasna::Tag::context(0), |w| {
                    w.write_der(&cert_der);
                });
                w.next().write_set(|w| {
                    for a in attributes {
                        w.next().write_der(&a.to_der());
                    }
                });
            });
        });
    })
    .to_vec()
}

/// Construct an encryption scheme for building a pkcs12 container
/// # Arguments
/// * salt - Should be a randomly generated byte slice
/// * iv - The initial vector for the scheme, should also be randomly generated.
/// * count - The number of iterations for pbkdf2
fn build_encryption_scheme<'a>(
    salt: &'a [u8],
    iv: &'a [u8; 16],
    count: u32,
) -> pkcs5::EncryptionScheme<'a> {
    let prf = pkcs5::pbes2::Pbkdf2Prf::HmacWithSha256;

    let encryption = pkcs5::pbes2::EncryptionScheme::Aes256Cbc { iv };

    let pbkdf2_params = pkcs5::pbes2::Pbkdf2Params {
        salt,
        iteration_count: count,
        key_length: None,
        prf,
    };
    let kdf = pkcs5::pbes2::Kdf::Pbkdf2(pbkdf2_params);
    let enc_parameters = pkcs8::pkcs5::pbes2::Parameters { kdf, encryption };

    let enc_scheme = pkcs5::EncryptionScheme::Pbes2(enc_parameters.clone());
    enc_scheme
}

impl Pkcs12 {
    /// Create a pkcs12 formatted output
    pub fn get_pkcs12(&self, password: &str) -> Vec<u8> {
        use der::Encode;

        /// the default number of iterations for derivinng the mac
        const ITERATIONS: i32 = 2048;

        let mut content_info: Vec<ContentInfo> = Vec::new();

        let salt: [u8; 32] = rand::random();
        let iv: [u8; 16] = rand::random();
        let count = 2048;
        let enc_scheme = build_encryption_scheme(&salt, &iv, count);

        let d1 = build_cert_bag(&self.cert, &self.attributes);
        let ci1 = build_encrypted_content_info(&enc_scheme, &d1, password.as_bytes());
        content_info.push(ci1);
        let shroud_bag = build_shrouded_bag(
            &enc_scheme,
            &self.pkey,
            password.as_bytes(),
            &self.attributes,
        );
        let ci2 = build_plain_content_info(&shroud_bag);
        content_info.push(ci2);

        let content = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                for content in content_info {
                    let der = content.to_der().unwrap();
                    w.next().write_der(&der);
                }
            });
        })
        .to_vec();
        let content_octet = der::asn1::OctetString::new(content).unwrap();
        let content_bytes = content_octet.as_bytes();
        let content = der::asn1::Any::new(der::Tag::OctetString, content_bytes).unwrap();

        let auth_safe = ContentInfo {
            content_type: ID_DATA,
            content,
        };

        let mac_salt: [u8; 8] = rand::random();
        let mac_key = pkcs12::kdf::derive_key_utf8::<sha2::Sha256>(
            password,
            &mac_salt,
            pkcs12::kdf::Pkcs12KeyType::Mac,
            ITERATIONS,
            32,
        )
        .unwrap();

        let mac_data = content_bytes;

        let mut hmac = HmacSha256::new_from_slice(&mac_key).unwrap();
        hmac.update(mac_data);
        let mac_digest = hmac.finalize().into_bytes().to_vec();

        let mac_digest = der::asn1::OctetString::new(mac_digest).unwrap();

        let mac_algorithm_parameters = der::asn1::Any::new(der::Tag::Null, []).unwrap();
        let mac_algorithm_parameters = Some(mac_algorithm_parameters);

        let mac_algorithm = pkcs8::spki::AlgorithmIdentifier {
            oid: ID_SHA_256,
            parameters: mac_algorithm_parameters,
        };

        let mac = pkcs12::digest_info::DigestInfo {
            algorithm: mac_algorithm,
            digest: mac_digest,
        };

        let mac_data = MacData {
            mac,
            mac_salt: der::asn1::OctetString::new(mac_salt).unwrap(),
            iterations: ITERATIONS,
        };
        let mac_data = Some(mac_data);

        let pfx = pkcs12::pfx::Pfx {
            version: Version::V3,
            auth_safe,
            mac_data,
        };
        pfx.to_der().unwrap()
    }

    /// Load a pkcs12 from the contents of the file specified
    /// # Arguments
    /// * data - The contents of the pkcs12 document
    /// * pass - The password protecting the document
    pub fn load_from_data(data: &[u8], pass: &[u8], id: u64) -> Self {
        use der::Encode;

        let mut cert = None;
        let mut pkey = None;
        let mut attributes = Vec::new();

        let pfx = pkcs12::pfx::Pfx::from_der(data).expect("Failed to parse certificate");
        assert_eq!(Version::V3, pfx.version);
        assert_eq!(ID_DATA, pfx.auth_safe.content_type);
        let auth_safes_os =
            der::asn1::OctetString::from_der(&pfx.auth_safe.content.to_der().unwrap()).unwrap();
        let auth_safes =
            pkcs12::authenticated_safe::AuthenticatedSafe::from_der(auth_safes_os.as_bytes())
                .unwrap();

        let auth_safe0 = auth_safes.first().unwrap();
        assert_eq!(ID_ENCRYPTED_DATA, auth_safe0.content_type);
        let enc_data_os = &auth_safe0.content.to_der().unwrap();
        let enc_data =
            cms::encrypted_data::EncryptedData::from_der(enc_data_os.as_slice()).unwrap();
        assert_eq!(ID_DATA, enc_data.enc_content_info.content_type);
        assert_eq!(PBES2_OID, enc_data.enc_content_info.content_enc_alg.oid);
        let enc_params = enc_data
            .enc_content_info
            .content_enc_alg
            .parameters
            .as_ref()
            .unwrap()
            .to_der()
            .unwrap();

        let params = pkcs8::pkcs5::pbes2::Parameters::from_der(&enc_params).unwrap();
        let scheme = pkcs5::EncryptionScheme::from(params.clone());
        let ciphertext_os = enc_data.enc_content_info.encrypted_content.clone().unwrap();
        let mut ciphertext = ciphertext_os.as_bytes().to_vec();
        let plaintext = scheme.decrypt_in_place(pass, &mut ciphertext).unwrap();
        let cert_bags = pkcs12::safe_bag::SafeContents::from_der(plaintext).unwrap();
        for cert_bag in cert_bags {
            match cert_bag.bag_id {
                pkcs12::PKCS_12_CERT_BAG_OID => {
                    let cs: der::asn1::ContextSpecific<pkcs12::cert_type::CertBag> =
                        der::asn1::ContextSpecific::from_der(&cert_bag.bag_value).unwrap();
                    let cb = cs.value;
                    let cert_der = cb.cert_value.as_bytes();
                    cert = Some(cert_der.to_vec());
                }
                _ => panic!(),
            };
        }

        let k = params.kdf.to_der().unwrap();
        let kdf_alg_info = pkcs8::spki::AlgorithmIdentifierOwned::from_der(&k).unwrap();
        assert_eq!(pkcs5::pbes2::PBKDF2_OID, kdf_alg_info.oid);
        let k_params = kdf_alg_info.parameters.unwrap().to_der().unwrap();

        let pbkdf2_params = pkcs12::pbe_params::Pbkdf2Params::from_der(&k_params).unwrap();
        assert_eq!(2048, pbkdf2_params.iteration_count);
        assert_eq!(HMAC_WITH_SHA256_OID, pbkdf2_params.prf.oid);

        let e = params.encryption.to_der().unwrap();
        let enc_alg_info = pkcs8::spki::AlgorithmIdentifierOwned::from_der(&e).unwrap();
        assert_eq!(AES_256_CBC_OID, enc_alg_info.oid);

        // Process second auth safe (from offset 984)
        let auth_safe1 = auth_safes.get(1).unwrap();
        assert_eq!(ID_DATA, auth_safe1.content_type);

        let auth_safe1_auth_safes_os =
            der::asn1::OctetString::from_der(&auth_safe1.content.to_der().unwrap()).unwrap();
        let safe_bags =
            pkcs12::safe_bag::SafeContents::from_der(auth_safe1_auth_safes_os.as_bytes()).unwrap();
        for safe_bag in safe_bags {
            match safe_bag.bag_id {
                pkcs12::PKCS_12_PKCS8_KEY_BAG_OID => {
                    let cs: der::asn1::ContextSpecific<pkcs8::EncryptedPrivateKeyInfo> =
                        der::asn1::ContextSpecific::from_der(&safe_bag.bag_value).unwrap();
                    let ciphertext = cs.value.encrypted_data.to_vec();
                    let plaintext = cs
                        .value
                        .encryption_algorithm
                        .decrypt(pass, &ciphertext)
                        .unwrap();
                    pkey = Some(plaintext.to_vec());
                    let attr = safe_bag.bag_attributes.as_ref().unwrap();
                    let attrs: Vec<BagAttribute> =
                        attr.iter().map(|a| a.try_into().unwrap()).collect();
                    attributes = attrs;
                }
                _ => panic!(),
            };
        }

        // process mac data
        let mac_data = pfx.mac_data.unwrap();
        assert_eq!(ID_SHA_256, mac_data.mac.algorithm.oid);
        assert_eq!(2048, mac_data.iterations);

        Self {
            cert: cert.unwrap(),
            pkey: zeroize::Zeroizing::new(pkey.unwrap()),
            attributes,
            id,
        }
    }
}
