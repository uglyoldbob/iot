//! Commmon code for both wasm and non-wasm code

pub mod oid;
use oid::*;
use zeroize::Zeroizing;

/// The method that a certificate uses to sign stuff
#[derive(
    Debug,
    Copy,
    Clone,
    prompt::Prompting,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(not(target_arch = "wasm32"), derive(prompt::EguiPrompting))]
pub enum CertificateSigningMethod {
    /// An rsa certificate with sha1
    RsaSha1,
    /// An rsa certificate rsa with sha256
    RsaSha256,
    /// Ecdsa
    EcdsaSha256,
}

impl<T> TryFrom<x509_cert::spki::AlgorithmIdentifier<T>> for CertificateSigningMethod {
    type Error = ();
    fn try_from(value: x509_cert::spki::AlgorithmIdentifier<T>) -> Result<Self, Self::Error> {
        let oid = value.oid;
        if oid == OID_PKCS1_SHA256_RSA_ENCRYPTION.to_const() {
            Ok(Self::RsaSha256)
        } else if oid == OID_PKCS1_SHA1_RSA_ENCRYPTION.to_const() {
            Ok(Self::RsaSha1)
        } else if oid == OID_ECDSA_P256_SHA256_SIGNING.to_const() {
            Ok(Self::EcdsaSha256)
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            service::log::error!("The oid to convert is {:?}", value.oid);
            Err(())
        }
    }
}

impl CertificateSigningMethod {
    /// Convert Self into an Oid
    pub fn oid(&self) -> crate::oid::Oid {
        match self {
            Self::RsaSha1 => OID_PKCS1_SHA1_RSA_ENCRYPTION.to_owned(),
            Self::RsaSha256 => OID_PKCS1_SHA256_RSA_ENCRYPTION.to_owned(),
            Self::EcdsaSha256 => OID_ECDSA_P256_SHA256_SIGNING.to_owned(),
        }
    }

    /// Generate a keypair
    pub fn generate_keypair(&self) -> Option<(rcgen::KeyPair, Option<Zeroizing<Vec<u8>>>)> {
        match self {
            Self::RsaSha1 | Self::RsaSha256 => {
                use pkcs8::EncodePrivateKey;
                let mut rng = rand::thread_rng();
                let bits = 4096;
                let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
                let private_key_der = private_key.to_pkcs8_der().unwrap();
                let pkey = Zeroizing::new(private_key_der.as_bytes().to_vec());
                let key_pair = rcgen::KeyPair::try_from(private_key_der.as_bytes()).unwrap();
                Some((key_pair, Some(pkey)))
            }
            Self::EcdsaSha256 => {
                let keypair = rcgen::KeyPair::generate().ok()?;
                let pkcs8 = keypair.serialize_der();
                let pkey = Zeroizing::new(pkcs8);
                Some((keypair, Some(pkey)))
            }
        }
    }
}