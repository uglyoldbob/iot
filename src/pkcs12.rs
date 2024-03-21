//! Defines how to import and export pkcs12 certificate data

use crate::oid::*;

use const_oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA};
use const_oid::db::rfc5912::ID_SHA_256;
use pkcs12::pfx::Version;
use pkcs8::pkcs5::pbes2::{AES_256_CBC_OID, HMAC_WITH_SHA256_OID, PBES2_OID, PBKDF2_OID};

/// A struct for pkcs12 certificates containing a certificate and a private key
pub struct Pkcs12 {
    /// The certificate in der format
    pub cert: Vec<u8>,
    /// The private key in der format
    pub pkey: Vec<u8>,
}

impl TryFrom<crate::ca::CaCertificate> for Pkcs12 {
    type Error = ();
    fn try_from(value: crate::ca::CaCertificate) -> Result<Self, Self::Error> {
        use der::Decode;
        let cert = value.certificate_der();
        todo!()
    }
}

impl Pkcs12 {
    /// Create a pkcs12 formatted output
    pub fn get_pkcs12(&self, password: &str) -> Vec<u8> {
        todo!()
    }

    /// Load a pkcs12 from the contents of the file specified
    /// # Arguments
    /// * data - The contents of the pkcs12 document
    /// * pass - The password protecting the document
    pub fn load_from_data(data: &[u8], pass: &[u8]) -> Self {
        use der::Decode;
        use der::Encode;

        let mut cert = None;
        let mut pkey = None;

        let pfx = pkcs12::pfx::Pfx::from_der(&data).expect("Failed to parse certificate");
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
        let plaintext = scheme.decrypt_in_place("", &mut ciphertext).unwrap();
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
                    let mut ciphertext = cs.value.encrypted_data.to_vec();
                    let plaintext = cs
                        .value
                        .encryption_algorithm
                        .decrypt_in_place(pass, &mut ciphertext)
                        .unwrap();
                    pkey = Some(plaintext.to_vec());
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
            pkey: pkey.unwrap(),
        }
    }
}
