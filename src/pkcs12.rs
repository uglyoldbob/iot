//! Defines how to import and export pkcs12 certificate data

use crate::oid::*;

use cms::content_info::{CmsVersion, ContentInfo};
use const_oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA};
use const_oid::db::rfc5912::ID_SHA_256;
use der::Decode;
use pkcs12::mac_data::MacData;
use pkcs12::pfx::Version;
use pkcs8::pkcs5::pbes2::{AES_256_CBC_OID, HMAC_WITH_SHA256_OID, PBES2_OID, PBKDF2_OID};
use sha256::Sha256Digest;

/// A struct for pkcs12 certificates containing a certificate and a private key
pub struct Pkcs12 {
    /// The certificate in der format
    pub cert: Vec<u8>,
    /// The private key in der format
    pub pkey: zeroize::Zeroizing<Vec<u8>>,
}

impl TryFrom<crate::ca::CaCertificate> for Pkcs12 {
    type Error = ();
    fn try_from(value: crate::ca::CaCertificate) -> Result<Self, Self::Error> {
        let cert = value.certificate_der();
        let pkey = value.pkey_der();
        if pkey.is_none() {
            return Err(());
        }
        Ok(Self {
            cert,
            pkey: pkey.unwrap(),
        })
    }
}

use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<sha2::Sha256>;

fn build_encrypted_content_info(data: &[u8], password: &[u8]) -> ContentInfo {
    use der::Encode;
    let data_algorithm_parameters = 42;

    let salt: [u8; 8] = rand::random();
    let iv: [u8; 16] = rand::random();
    let count = 2048;
    let prf = pkcs5::pbes2::Pbkdf2Prf::HmacWithSha256;

    let encryption = pkcs5::pbes2::EncryptionScheme::Aes256Cbc { iv: &iv };

    let pbkdf2_params = pkcs5::pbes2::Pbkdf2Params {
        salt: &salt,
        iteration_count: count,
        key_length: None,
        prf,
    };
    let kdf = pkcs5::pbes2::Kdf::Pbkdf2(pbkdf2_params);
    let enc_parameters = pkcs8::pkcs5::pbes2::Parameters { kdf, encryption };

    let enc_scheme = pkcs5::EncryptionScheme::Pbes2(enc_parameters);
    let encrypted_data = enc_scheme.encrypt(password, data).unwrap();

    let data1_parameters = enc_scheme.to_der().unwrap();
    let encrypted1 = der::asn1::OctetString::new(encrypted_data).unwrap();

    let data1_enc_alg = pkcs8::spki::AlgorithmIdentifier {
        oid: PBES2_OID,
        parameters: Some(der::asn1::Any::new(der::Tag::Sequence, data1_parameters).unwrap()),
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
                w.write_bytes(&ci1.to_der().unwrap());
            });
        });
    });
    println!("Der of ci1 is {:02X?}", ci1_der);
    let ci1 = ContentInfo::from_der(&ci1_der).unwrap();
    ci1
}

fn build_cert_bag(data: &[u8]) -> Vec<u8> {
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
                //TODO optional bag attributes
                //1.2.840.113549.1.9.21 (local key id)
                //1.2.840.113549.1.9.20 (friendly name)
            });
        });
    })
    .to_vec()
}

impl Pkcs12 {
    /// Create a pkcs12 formatted output
    pub fn get_pkcs12(&self, password: &str) -> Vec<u8> {
        use der::Encode;

        const ITERATIONS: i32 = 2048;

        let mut content_info: Vec<ContentInfo> = Vec::new();

        println!("Cert der is {:02X?}", self.cert);
        println!("Pkey der is {:02X?}", self.pkey);

        let d1 = build_cert_bag(&self.cert);
        let ci1 = build_encrypted_content_info(&d1, password.as_bytes());
        content_info.push(ci1);
        let ci2 = build_encrypted_content_info(&self.pkey, password.as_bytes());
        content_info.push(ci2);

        println!("Der of d1 is {:02X?}", d1);

        let content: Vec<u8> = content_info
            .iter()
            .flat_map(|info| info.to_der().unwrap())
            .collect();
        let content_octet = der::asn1::OctetString::new(content).unwrap();
        let content_bytes = content_octet.as_bytes();
        let content = der::asn1::Any::new(der::Tag::OctetString, content_bytes).unwrap();

        let auth_safe = ContentInfo {
            content_type: ID_DATA,
            content,
        };

        let mac_salt: [u8; 32] = rand::random();
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
        hmac.update(&mac_data);
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
    pub fn load_from_data(data: &[u8], pass: &[u8]) -> Self {
        use der::Decode;
        use der::Encode;

        let mut cert = None;
        let mut pkey = None;

        let pfx = pkcs12::pfx::Pfx::from_der(&data).expect("Failed to parse certificate");
        assert_eq!(Version::V3, pfx.version);
        println!("Auth safe is {:02X?}", pfx.auth_safe);
        println!("mac data is {:02X?}", pfx.mac_data);
        assert_eq!(ID_DATA, pfx.auth_safe.content_type);
        let auth_safes_os =
            der::asn1::OctetString::from_der(&pfx.auth_safe.content.to_der().unwrap()).unwrap();
        let auth_safes =
            pkcs12::authenticated_safe::AuthenticatedSafe::from_der(auth_safes_os.as_bytes())
                .unwrap();

        for ci in &auth_safes {
            println!("Contentinfo is {:?}", ci);
        }

        let auth_safe0 = auth_safes.first().unwrap();
        assert_eq!(ID_ENCRYPTED_DATA, auth_safe0.content_type);
        let enc_data_os = &auth_safe0.content.to_der().unwrap();
        let enc_data =
            cms::encrypted_data::EncryptedData::from_der(enc_data_os.as_slice()).unwrap();
        println!("Encrypted data is {:02X?}", enc_data);
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
        println!("Enc params are {:02X?}", params);
        let scheme = pkcs5::EncryptionScheme::from(params.clone());
        let ciphertext_os = enc_data.enc_content_info.encrypted_content.clone().unwrap();
        let mut ciphertext = ciphertext_os.as_bytes().to_vec();
        let plaintext = scheme.decrypt_in_place(pass, &mut ciphertext).unwrap();
        println!("Decrypted data is {:02X?}", plaintext);
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

        println!(
            "Second auth safe bag is {:02X?}",
            &auth_safe1.content.to_der().unwrap()
        );

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
                        .decrypt(pass, &ciphertext)
                        .unwrap();

                    println!("Decoded second bag is {:02X?}", plaintext);

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
            pkey: zeroize::Zeroizing::new(pkey.unwrap()),
        }
    }
}
