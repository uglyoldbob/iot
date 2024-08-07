//! Code related to the optional tpm2 hardware module

use ring::aead::Aad;

#[cfg(feature = "tpm2")]
use tss_esapi::structures::{CreatePrimaryKeyResult, Private, Public, SensitiveData};

/// Represents aead encrypted data
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct AeadEncryptedData {
    /// The salt for the aead algorithm
    salt: [u8; 8],
    /// The nonce for the aead encryption algorithm
    nonce: [u8; 12],
    /// Encrypted data
    data: Vec<u8>,
}

/// Retrieve the default path for the tpm2 device node
#[cfg(all(feature = "tpm2", target_os = "linux"))]
#[allow(dead_code)]
pub fn tpm2_path() -> tss_esapi::tcti_ldr::TctiNameConf {
    use std::str::FromStr;
    let node = "/dev/tpmrm0";
    let dc = tss_esapi::tcti_ldr::DeviceConfig::from_str(node).unwrap();

    tss_esapi::tcti_ldr::TctiNameConf::Device(dc)
}

#[cfg(all(feature = "tpm2", target_os = "windows"))]
pub fn tpm2_path() -> tss_esapi::tcti_ldr::TctiNameConf {
    let name = tss_esapi::tcti_ldr::TctiNameConf::Tbs;
    name
}

#[allow(dead_code)]
/// Encrypt some data with the specified password.
pub fn encrypt(data: &[u8], password: &[u8]) -> Vec<u8> {
    let salt: [u8; 8] = rand::random();
    let mut keydata = [0; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(2048).unwrap(),
        &salt,
        password,
        &mut keydata,
    );

    let nonce: [u8; 12] = rand::random();
    let key = ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &keydata).unwrap();
    let seal_key = ring::aead::LessSafeKey::new(key);
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

#[allow(dead_code)]
/// Decrypt some encrypted data with the specified password.
pub fn decrypt(edata: Vec<u8>, password: &[u8]) -> Vec<u8> {
    let edata: AeadEncryptedData = bincode::deserialize(&edata).unwrap();

    let mut keydata = [0; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(2048).unwrap(),
        &edata.salt,
        password,
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
        .expect("Failed to decrypt configuration")
        .to_vec()
}

/// A password, stretched with pbkdf2
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Password {
    /// The salt to append to the password in the pbkdf2 algorithm.
    salt: [u8; 16],
    /// Number of iterations for key stretching
    iterations: std::num::NonZeroU32,
    /// The password
    data: Vec<u8>,
}

impl Password {
    #[allow(dead_code)]
    /// Build a new Self
    pub fn build(password: &[u8], iterations: std::num::NonZeroU32) -> Self {
        let salt: [u8; 16] = rand::random();
        let mut pw = Vec::new();
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            &salt,
            password,
            &mut pw,
        );
        Self {
            salt,
            iterations,
            data: pw,
        }
    }

    #[allow(dead_code)]
    /// Serialize self into data.
    pub fn data(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    #[allow(dead_code)]
    /// Rebuild a Self with the serialized data.
    pub fn rebuild(data: &[u8]) -> Self {
        bincode::deserialize(data).unwrap()
    }

    #[allow(dead_code)]
    /// Retrieve the password
    pub fn password(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(feature = "tpm2")]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
/// Represents a blob of data encrypted by tpm2
pub struct TpmBlob {
    /// The encrypted contents of the blob
    data: Vec<u8>,
    /// The public key for the blob
    public: Public,
}

#[cfg(feature = "tpm2")]
impl TpmBlob {
    #[allow(dead_code)]
    /// Serialize self into a vector
    pub fn data(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    #[allow(dead_code)]
    /// Serialize self from a slice
    pub fn rebuild(data: &[u8]) -> Self {
        bincode::deserialize(data).unwrap()
    }
}

#[cfg(feature = "tpm2")]
/// Represents the context for a usable tpm2 device
pub struct Tpm2 {
    /// The tpm2 context, required for tpm2 operations
    context: tss_esapi::Context,
    /// The result of creating a tpm key
    pkr: CreatePrimaryKeyResult,
}

#[cfg(feature = "tpm2")]
impl Tpm2 {
    /// Contruct a new tpm, using the specified node to commmunicate to the tpm hardware
    #[allow(dead_code)]
    pub fn new(node: tss_esapi::tcti_ldr::TctiNameConf) -> Option<Self> {
        let mut context = tss_esapi::Context::new(node).ok()?;

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

        Some(Self { context, pkr })
    }

    #[allow(dead_code)]
    /// Decrypt the given blob with the tpm
    pub fn decrypt(&mut self, blob: TpmBlob) -> Result<Vec<u8>, ()> {
        let edata = &blob.data;
        let enc_private = Private::from_bytes(edata).unwrap();
        let unsealed = self
            .context
            .execute_with_nullauth_session(|ctx| {
                // When we wish to unseal the data, we must load this object like any other meeting
                // any policy or authValue requirements.
                let sealed_data_object = ctx
                    .load(self.pkr.key_handle, enc_private, blob.public)
                    .unwrap();
                ctx.unseal(sealed_data_object.into())
            })
            .unwrap();
        Ok(unsealed.to_vec())
    }

    #[allow(dead_code)]
    /// Ecnrypt some data into a blob
    pub fn encrypt(&mut self, data: &[u8]) -> Result<TpmBlob, ()> {
        // A sealed data object is a specialised form of a HMAC key. There are strict requirements for
        // the object attributes and algorithms to signal to the TPM that this is a sealed data object.
        let object_attributes = tss_esapi::attributes::ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(true)
            // To access the sealed data we require user auth or policy. In this example we
            // set a null authValue.
            .with_user_with_auth(true)
            // Must be clear (not set). This is because the sensitive data is
            // input from an external source.
            // .with_sensitive_data_origin(true)
            // For sealed data, none of sign, decrypt or restricted can be set. This indicates
            // the created object is a sealed data object.
            // .with_decrypt(false)
            // .with_restricted(false)
            // .with_sign_encrypt(false)
            .build()
            .expect("Failed to build object attributes");

        let key_pub = tss_esapi::structures::PublicBuilder::new()
            // A sealed data object is an HMAC key with a NULL hash scheme.
            .with_public_algorithm(
                tss_esapi::interface_types::algorithm::PublicAlgorithm::KeyedHash,
            )
            .with_name_hashing_algorithm(
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
            )
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(tss_esapi::structures::PublicKeyedHashParameters::new(
                tss_esapi::structures::KeyedHashScheme::Null,
            ))
            .with_keyed_hash_unique_identifier(tss_esapi::structures::Digest::default())
            .build()
            .unwrap();

        let sensitive_data = SensitiveData::from_bytes(data).unwrap();

        let (enc_private, public) = self
            .context
            .execute_with_nullauth_session(|ctx| {
                // Create the sealed data object. The encrypted private component is now encrypted and
                // contains our data. Like any other TPM object, to load this we require the public
                // component as well. Both should be persisted for future use.
                ctx.create(
                    self.pkr.key_handle,
                    key_pub,
                    None,
                    Some(sensitive_data),
                    None,
                    None,
                )
                .map(|key| (key.out_private, key.out_public))
            })
            .unwrap();
        Ok(TpmBlob {
            data: enc_private.to_vec(),
            public,
        })
    }
}
