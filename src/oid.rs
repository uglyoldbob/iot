//! This module stores OID constants

use p12::yasna;

/// Create an OID
fn as_oid(s: &'static [u64]) -> yasna::models::ObjectIdentifier {
    yasna::models::ObjectIdentifier::from_slice(s)
}

/// Create a const OID
fn as_oid2(s: &'static str) -> const_oid::ObjectIdentifier {
    use std::str::FromStr;
    const_oid::ObjectIdentifier::from_str(s).unwrap()
}

/// OID constants
lazy_static::lazy_static! {
    /// The oid for pkcs7 data content
    pub static ref OID_PKCS7_DATA_CONTENT_TYPE: yasna::models::ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 7, 1]);
    /// The oid for shrouded keybag
    pub static ref OID_SHROUDED_KEY_BAG: yasna::models::ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 2]);
    /// The oid for certificate bag
    pub static ref OID_CERT_BAG: yasna::models::ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 3]);
    /// The oid for pkcs1 rsa encryption
    pub static ref OID_PKCS1_RSA_ENCRYPTION: yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 1, 11]);
    /// The oid for pkcs1 ecdsa signing
    pub static ref OID_ECDSA_P256_SHA256_SIGNING: yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 10_045, 4, 3, 2]);
    /// The oid for pkcs7 encrypted data
    pub static ref OID_PKCS7_ENCRYPTED_DATA_CONTENT_TYPE: yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 7, 6]);
    /// The oid for pbes2 encryption
    pub static ref OID_PKCS5_PBES2: yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 5, 13]);
    /// The oid for pbkdf2 encryption
    pub static ref OID_PKCS5_PBKDF2: yasna::models::ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 5, 12]);
    /// The oid for sha256 hmac
    pub static ref OID_HMAC_SHA256: yasna::models::ObjectIdentifier =
        as_oid(&[1,2,840,113_549,2,9]);
    /// The oid for aes 256 cbc encryption
    pub static ref OID_AES_256_CBC: yasna::models::ObjectIdentifier =
        as_oid(&[2,16,840,1,101,3,4,1,42]);
    /// The oid for the pkcs9 friendly name
    pub static ref OID_PKCS9_FRIENDLY_NAME: yasna::models::ObjectIdentifier =
        as_oid(&[1,2,840,113_549,1,9,20]);
    /// The oid for the pkcs9 local key id
    pub static ref OID_PKCS9_LOCAL_KEY_ID: yasna::models::ObjectIdentifier =
        as_oid(&[1,2,840,113_549,1,9,21]);
    /// The oid for sha256 encryption
    pub static ref OID_SHA256: yasna::models::ObjectIdentifier =
        as_oid(&[2,16,840,1,101,3,4,2,1]);
    /// The oid for pkcs7 data
    pub static ref OID2_DATA_CONTENT_TYPE: const_oid::ObjectIdentifier = as_oid2("1.2.840.113549.1.7.1");
    /// The oid used in certificate authorities to indicate the ocsp responder
    pub static ref OID_PKIX_AUTHORITY_INFO_ACCESS: yasna::models::ObjectIdentifier =
        as_oid(&[1,3,6,1,5,5,7,1,1]);
    /// The oid used in the authority info access for ocsp url
    pub static ref OID_OCSP: yasna::models::ObjectIdentifier =
    as_oid(&[1,3,6,1,5,5,7,48,1]);
}
