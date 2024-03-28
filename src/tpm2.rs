//! Code related to the optional tpm2 hardware module

use ring::aead::{Aad, BoundKey, NonceSequence};
use tss_esapi::structures::CreatePrimaryKeyResult;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct AeadEncryptedData {
    salt: [u8; 8],
    nonce: [u8; 12],
    data: Vec<u8>,
}

pub fn encrypt(data: &[u8], password: &str) -> Vec<u8> {
    let salt: [u8; 8] = rand::random();
    let mut keydata = [0; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(2048).unwrap(),
        &salt,
        password.as_bytes(),
        &mut keydata,
    );

    let nonce: [u8; 12] = rand::random();
    let key = ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &keydata).unwrap();
    let mut seal_key = ring::aead::LessSafeKey::new(key);
    let mut in_out = data.to_owned();
    seal_key
        .seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            Aad::from([]),
            &mut in_out,
        )
        .unwrap();
    let stuff = AeadEncryptedData {
        salt,
        nonce,
        data: in_out,
    };
    bincode::serialize(&stuff).unwrap().to_vec()
}

pub fn decrypt(edata: Vec<u8>, password: &str) -> Vec<u8> {
    let edata: AeadEncryptedData = bincode::deserialize(&edata).unwrap();

    let mut keydata = [0; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(2048).unwrap(),
        &edata.salt,
        password.as_bytes(),
        &mut keydata,
    );
    let key = ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &keydata).unwrap();
    let open_key = ring::aead::LessSafeKey::new(key);
    let mut in_out = edata.data.clone();
    open_key
        .open_in_place(
            ring::aead::Nonce::assume_unique_for_key(edata.nonce),
            Aad::from([]),
            &mut in_out,
        )
        .unwrap()
        .to_vec()
}

pub struct Tpm2 {
    context: tss_esapi::Context,
    pkr: CreatePrimaryKeyResult,
}

impl Tpm2 {
    /// Contruct a new tpm, using the specified node to commmunicate to the tpm hardware
    pub fn new(node: &str) -> Self {
        use std::str::FromStr;
        let dc = tss_esapi::tcti_ldr::DeviceConfig::from_str(node).unwrap();
        let name = tss_esapi::tcti_ldr::TctiNameConf::Device(dc);

        let mut context = tss_esapi::Context::new(name).unwrap();

        let object_attributes = tss_esapi::attributes::ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .expect("Failed to build object attributes");

        let primary_pub = tss_esapi::structures::PublicBuilder::new()
            .with_public_algorithm(
                tss_esapi::interface_types::algorithm::PublicAlgorithm::SymCipher,
            )
            .with_name_hashing_algorithm(
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
            )
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(
                tss_esapi::structures::SymmetricCipherParameters::new(
                    tss_esapi::structures::SymmetricDefinitionObject::AES_128_CFB,
                ),
            )
            .with_symmetric_cipher_unique_identifier(tss_esapi::structures::Digest::default())
            .build()
            .unwrap();

        let pkr = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    tss_esapi::interface_types::reserved_handles::Hierarchy::Owner,
                    primary_pub,
                    None,
                    None,
                    None,
                    None,
                )
            })
            .unwrap();

        Self { context, pkr }
    }

    pub fn decrypt(
        &mut self,
        edata: &[u8],
        private: tss_esapi::structures::Private,
        public: tss_esapi::structures::Public,
    ) -> Result<Vec<u8>, ()> {
        let edata = tss_esapi::structures::PublicKeyRsa::try_from(edata.to_vec()).unwrap();
        let pdata = self
            .context
            .execute_with_nullauth_session(|ctx| {
                let rsa_priv_key = ctx
                    .load(self.pkr.key_handle, private.clone(), public.clone())
                    .unwrap();

                ctx.rsa_decrypt(
                    rsa_priv_key,
                    edata,
                    tss_esapi::structures::RsaDecryptionScheme::Oaep(
                        tss_esapi::structures::HashScheme::new(
                            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha1,
                        ),
                    ),
                    tss_esapi::structures::Data::default(),
                )
            })
            .unwrap();
        Ok(pdata.to_vec())
    }

    pub fn make_rsa(
        &mut self,
    ) -> Result<
        (
            tss_esapi::structures::Private,
            tss_esapi::structures::Public,
        ),
        (),
    > {
        let object_attributes = tss_esapi::attributes::ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            // We need a key that can decrypt values - we don't need to worry
            // about signatures.
            .with_decrypt(true)
            // Note that we don't set the key as restricted.
            .build()
            .expect("Failed to build object attributes");

        let rsa_params = tss_esapi::structures::PublicRsaParametersBuilder::new()
            // The value for scheme may have requirements set by a combination of the
            // sign, decrypt, and restricted flags. For an unrestricted signing and
            // decryption key then scheme must be NULL. For an unrestricted decryption key,
            // NULL, OAEP or RSAES are valid for use.
            .with_scheme(tss_esapi::structures::RsaScheme::Null)
            .with_key_bits(tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048)
            .with_exponent(tss_esapi::structures::RsaExponent::default())
            .with_is_decryption_key(true)
            // We don't require signatures, but some users may.
            // .with_is_signing_key(true)
            .with_restricted(false)
            .build()
            .expect("Failed to build rsa parameters");

        let key_pub = tss_esapi::structures::PublicBuilder::new()
            .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
            )
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(tss_esapi::structures::PublicKeyRsa::default())
            .build()
            .unwrap();

        let (enc_private, public) = self
            .context
            .execute_with_nullauth_session(|ctx| {
                ctx.create(self.pkr.key_handle, key_pub, None, None, None, None)
                    .map(|key| (key.out_private, key.out_public))
            })
            .unwrap();
        Ok((enc_private, public))
    }

    /// Ecnrypt some data
    pub fn encrypt(
        &mut self,
        data: &[u8],
        public: tss_esapi::structures::Public,
    ) -> Result<Vec<u8>, ()> {
        let pdata = tss_esapi::structures::PublicKeyRsa::try_from(data.to_vec()).unwrap();
        let edata = self
            .context
            .execute_with_nullauth_session(|ctx| {
                let rsa_pub_key = ctx
                    .load_external_public(
                        public.clone(),
                        tss_esapi::interface_types::reserved_handles::Hierarchy::Null,
                    )
                    .unwrap();

                ctx.rsa_encrypt(
                    rsa_pub_key,
                    pdata.clone(),
                    tss_esapi::structures::RsaDecryptionScheme::Oaep(
                        tss_esapi::structures::HashScheme::new(
                            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha1,
                        ),
                    ),
                    tss_esapi::structures::Data::default(),
                )
            })
            .unwrap();
        Ok(edata.to_vec())
    }
}
