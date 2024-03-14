//! This module stores OID constants

use std::str::FromStr;

use der::Decode;
use p12::yasna;

/// Represents an object identifier used in ASN.1 syntax
#[derive(Clone)]
pub enum Oid {
    /// The oid as represented by yasna
    Yasna(yasna::models::ObjectIdentifier),
    /// The oid as represented by const_oid
    Const(const_oid::ObjectIdentifier),
    /// The oid as represented by ocsp
    Ocsp(ocsp::common::asn1::Oid),
}

impl Oid {
    /// Convert from the yasna oid
    pub fn from_yasna(oid: yasna::models::ObjectIdentifier) -> Self {
        Self::Yasna(oid)
    }

    /// Convert from the const_oid oid
    pub fn from_const(oid: const_oid::ObjectIdentifier) -> Self {
        Self::Const(oid)
    }

    /// Convert from the ocsp oid
    pub fn from_ocsp(oid: ocsp::common::asn1::Oid) -> Self {
        Self::Ocsp(oid)
    }

    /// Get the components of the oid as an array
    pub fn components(&self) -> Vec<u64> {
        match self {
            Self::Yasna(oid) => oid.components().to_vec(),
            Self::Const(oid) => {
                let s = oid.to_string();
                yasna::models::ObjectIdentifier::from_str(&s)
                    .unwrap()
                    .components()
                    .to_vec()
            }
            Self::Ocsp(oid) => {
                let b = oid.to_der_raw().unwrap();
                let yasna: yasna::models::ObjectIdentifier = yasna::decode_der(&b).unwrap();
                yasna.components().to_vec()
            }
        }
    }

    /// Convert to an ocsp oid
    pub fn to_ocsp(&self) -> ocsp::common::asn1::Oid {
        match self {
            Self::Yasna(oid) => {
                let s = oid.to_string();
                ocsp::common::asn1::Oid::new_from_dot(&s).unwrap()
            }
            Self::Const(oid) => {
                let s = oid.to_string();
                ocsp::common::asn1::Oid::new_from_dot(&s).unwrap()
            }
            Self::Ocsp(oid) => oid.to_owned(),
        }
    }

    /// Conver to a yasna oid
    pub fn to_yasna(&self) -> yasna::models::ObjectIdentifier {
        match self {
            Self::Yasna(oid) => oid.to_owned(),
            Self::Const(oid) => {
                let s = oid.to_string();
                yasna::models::ObjectIdentifier::from_str(&s).unwrap()
            }
            Self::Ocsp(oid) => {
                let b = oid.to_der_raw().unwrap();
                yasna::decode_der(&b).unwrap()
            }
        }
    }

    /// Convert to a const oid
    pub fn to_const(&self) -> const_oid::ObjectIdentifier {
        match self {
            Self::Yasna(oid) => {
                let s = oid.to_string();
                const_oid::ObjectIdentifier::from_str(&s).unwrap()
            }
            Self::Const(oid) => oid.to_owned(),
            Self::Ocsp(oid) => {
                let b = oid.to_der_raw().unwrap();
                const_oid::ObjectIdentifier::from_der(&b).unwrap()
            }
        }
    }
}

/// Create an OID
fn as_oid(s: &'static [u64]) -> Oid {
    Oid::Yasna(yasna::models::ObjectIdentifier::from_slice(s))
}

/// Create a const OID
fn as_oid2(s: &'static str) -> Oid {
    Oid::Const(const_oid::ObjectIdentifier::from_str(s).unwrap())
}

lazy_static::lazy_static! {
    /// The oid for pkcs1 ecdsa signing
    pub static ref OID_ECDSA_P256_SHA256_SIGNING: Oid =
        as_oid(&[1, 2, 840, 10_045, 4, 3, 2]);
    /// The oid for sha256 hmac
    pub static ref OID_HMAC_SHA256: Oid =
        as_oid(&[1, 2, 840, 113_549, 2, 9]);
    /// The oid for pbkdf2 encryption
    pub static ref OID_PKCS5_PBKDF2: Oid =
        as_oid(&[1, 2, 840, 113_549, 1, 5, 12]);
    /// The oid for pbes2 encryption
    pub static ref OID_PKCS5_PBES2: Oid =
        as_oid(&[1, 2, 840, 113_549, 1, 5, 13]);
    /// The oid for pkcs1 rsa encryption
    pub static ref OID_PKCS1_SHA256_RSA_ENCRYPTION: Oid =
        as_oid(&[1, 2, 840, 113_549, 1, 1, 11]);
    /// The oid for pkcs7 data content
    pub static ref OID_PKCS7_DATA_CONTENT_TYPE: Oid =
        as_oid(&[1, 2, 840, 113_549, 1, 7, 1]);
    /// The oid for pkcs7 encrypted data
    pub static ref OID_PKCS7_ENCRYPTED_DATA_CONTENT_TYPE: Oid =
        as_oid(&[1, 2, 840, 113_549, 1, 7, 6]);
    /// The oid for the pkcs9 friendly name
    pub static ref OID_PKCS9_FRIENDLY_NAME: Oid =
        as_oid(&[1, 2, 840, 113_549, 1, 9, 20]);
    /// The oid for the pkcs9 local key id
    pub static ref OID_PKCS9_LOCAL_KEY_ID: Oid =
        as_oid(&[1, 2, 840, 113_549, 1, 9, 21]);
    /// The oid for shrouded keybag
    pub static ref OID_SHROUDED_KEY_BAG: Oid =
        as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 2]);
    /// The oid for certificate bag
    pub static ref OID_CERT_BAG: Oid =
        as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 3]);
    /// The oid for aes 256 cbc encryption
    pub static ref OID_AES_256_CBC: Oid =
        as_oid(&[2, 16, 840, 1, 101, 3, 4, 1, 42]);
    /// The oid for sha256 encryption
    pub static ref OID_SHA256: Oid =
        as_oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
    /// The oid used in certificate authorities to indicate the ocsp responder
    pub static ref OID_PKIX_AUTHORITY_INFO_ACCESS: Oid =
        as_oid(&[1, 3, 6, 1, 5, 5, 7, 1, 1]);
    /// The oid used in the authority info access for ocsp url
    pub static ref OID_OCSP: Oid =
        as_oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1]);
    /// The oid for ocsp basic response
    pub static ref OID_OCSP_RESPONSE_BASIC: Oid =
        as_oid2("1.3.6.1.5.5.7.48.1.1");
    /// The oid for sha1
    pub static ref OID_HASH_SHA1: Oid =
        as_oid(&[1, 3, 14, 3, 2, 26]);
}