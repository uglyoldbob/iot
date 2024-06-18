//! Code related to the pkcs11 interface for hardware security modules

use std::sync::{Arc, Mutex};

use cert_common::{oid::OID_PKCS1_SHA256_RSA_ENCRYPTION, HttpsSigningMethod};
use cryptoki::context::Pkcs11;
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub enum KeyPair {
    RsaSha256(RsaSha256Keypair),
}

impl KeyPair {
    pub fn keypair(&self) -> rcgen::KeyPair {
        match self {
            KeyPair::RsaSha256(m) => rcgen::KeyPair::from_remote(Box::new(m.clone())).unwrap(),
        }
    }
}

impl rcgen::RemoteKeyPair for KeyPair {
    fn public_key(&self) -> &[u8] {
        match self {
            KeyPair::RsaSha256(m) => m.public_key(),
        }
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        match self {
            KeyPair::RsaSha256(m) => m.sign(msg),
        }
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            KeyPair::RsaSha256(m) => m.algorithm(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RsaSha256Keypair {
    session: Arc<Mutex<cryptoki::session::Session>>,
    public: cryptoki::object::ObjectHandle,
    private: cryptoki::object::ObjectHandle,
    pubkey: Vec<u8>,
    hsm: Arc<crate::hsm2::Hsm>,
}

impl rcgen::RemoteKeyPair for RsaSha256Keypair {
    fn public_key(&self) -> &[u8] {
        &self.pubkey
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let session = self.session.lock().unwrap();
        service::log::debug!("Signing {} bytes for rsa", msg.len());
        let hash = session
            .digest(&cryptoki::mechanism::Mechanism::Sha256, msg)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        let r = session.sign(
            &cryptoki::mechanism::Mechanism::RsaPkcs,
            self.private,
            &hash,
        );
        r.map_err(|_| rcgen::Error::RemoteKeyError)
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        rcgen::SignatureAlgorithm::from_oid(&OID_PKCS1_SHA256_RSA_ENCRYPTION.components()).unwrap()
    }
}

/// Retrieve the default path for the tpm2 device node
#[cfg(target_os = "linux")]
pub fn hsm2_path() -> String {
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so".to_string()
}

#[cfg(target_os = "windows")]
pub fn hsm2_path() -> tss_esapi::tcti_ldr::TctiNameConf {
    "unknown".to_string()
}

#[derive(Debug)]
pub struct Hsm {
    pkcs11: cryptoki::context::Pkcs11,
    so_slot: cryptoki::slot::Slot,
    admin_pin: Zeroizing<String>,
    user_pin: Zeroizing<String>,
}

impl Hsm {
    /// Check to see if the hsm exists
    pub fn check(p: Option<std::path::PathBuf>) -> Result<(), ()> {
        let path = p
            .or_else(|| Some(std::path::PathBuf::from(hsm2_path())))
            .unwrap();
        match cryptoki::context::Pkcs11::new(path) {
            Ok(p) => {
                p.initialize(cryptoki::context::CInitializeArgs::OsThreads)
                    .map_err(|_| ())?;
                Ok(())
            }
            Err(_) => Err(()),
        }
    }

    /// Initialize hsm with slot and pin
    pub fn create(
        p: Option<std::path::PathBuf>,
        admin_pin: Zeroizing<String>,
        user_pin: Zeroizing<String>,
    ) -> Option<Self> {
        let path = p
            .or_else(|| Some(std::path::PathBuf::from(hsm2_path())))
            .unwrap();
        let pkcs11 = cryptoki::context::Pkcs11::new(path).ok()?;
        pkcs11
            .initialize(cryptoki::context::CInitializeArgs::OsThreads)
            .unwrap();
        let so_slot = pkcs11.get_slots_with_token().unwrap().remove(0);
        let so_pin = cryptoki::types::AuthPin::new(admin_pin.as_str().into());
        pkcs11
            .init_token(so_slot, &so_pin, "Initial token")
            .unwrap();
        {
            // open a session
            let session = pkcs11.open_rw_session(so_slot).unwrap();
            // log in the session
            session
                .login(cryptoki::session::UserType::So, Some(&so_pin))
                .unwrap();
            session
                .init_pin(&cryptoki::types::AuthPin::new(user_pin.to_string()))
                .unwrap();
        }
        Some(Self {
            pkcs11,
            so_slot,
            admin_pin,
            user_pin,
        })
    }

    /// Open the hsm
    pub fn open(
        p: Option<std::path::PathBuf>,
        admin_pin: Zeroizing<String>,
        user_pin: Zeroizing<String>,
    ) -> Option<Self> {
        let path = p
            .or_else(|| Some(std::path::PathBuf::from(hsm2_path())))
            .unwrap();
        let pkcs11 = cryptoki::context::Pkcs11::new(path).ok()?;
        pkcs11
            .initialize(cryptoki::context::CInitializeArgs::OsThreads)
            .unwrap();
        let so_slot = pkcs11.get_slots_with_token().unwrap().remove(0);
        Some(Self {
            pkcs11,
            so_slot,
            admin_pin,
            user_pin,
        })
    }

    /// Attempt to get a session as a user
    pub fn get_user_session(&self) -> Option<cryptoki::session::Session> {
        self.pkcs11
            .open_rw_session(self.so_slot)
            .map(|s| {
                s.login(
                    cryptoki::session::UserType::User,
                    Some(&cryptoki::types::AuthPin::new(
                        self.user_pin.as_str().into(),
                    )),
                )
                .unwrap();
                s
            })
            .ok()
    }

    /// Generate a keypair for certificate operations
    pub fn generate_https_keypair(
        self: Arc<Self>,
        method: HttpsSigningMethod,
        keysize: usize,
    ) -> Option<KeyPair> {
        let session = self.get_user_session()?;
        match method {
            HttpsSigningMethod::RsaSha256 => {
                let mechanism = cryptoki::mechanism::Mechanism::RsaPkcsKeyPairGen;
                let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
                let bits: cryptoki::types::Ulong = (keysize as u64).into();
                service::log::debug!("Keysize is {:?}", bits);
                let pub_key_template = vec![
                    cryptoki::object::Attribute::Token(true),
                    cryptoki::object::Attribute::Private(false),
                    cryptoki::object::Attribute::PublicExponent(public_exponent),
                    cryptoki::object::Attribute::ModulusBits(bits),
                    cryptoki::object::Attribute::Encrypt(true),
                ];
                let priv_key_template = vec![
                    cryptoki::object::Attribute::Token(true),
                    cryptoki::object::Attribute::Decrypt(true),
                ];
                let m2 = self
                    .pkcs11
                    .get_mechanism_list(self.so_slot)
                    .expect("Failed to get mechanisms");
                for m in &m2 {
                    let info = self
                        .pkcs11
                        .get_mechanism_info(self.so_slot, *m)
                        .expect("Failed to get mechanism info");
                    service::log::debug!(
                        "Mechanism {} {:?} {} {}",
                        m,
                        m,
                        info.generate(),
                        info.generate_key_pair()
                    );
                }
                let (public, private) = session
                    .generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)
                    .expect("Failed to generate keypair");
                let attrs = session
                    .get_attributes(public, &[cryptoki::object::AttributeType::Modulus])
                    .unwrap();
                let mut rsamod = Vec::new();
                let rsaexp = rsa::BigUint::new(vec![65537 as u32]);
                for attr in &attrs {
                    match attr {
                        cryptoki::object::Attribute::Modulus(v) => {
                            rsamod = v.to_owned();
                        }
                        _ => {
                            service::log::error!("Unexpected attribute");
                        }
                    }
                }
                service::log::debug!("modulus is {:02X?}", rsamod);
                service::log::debug!("rsa exp is {:02X?}", rsaexp);
                let pubkey = rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(&rsamod), rsaexp)
                    .expect("Failed to build public key");

                let pubbytes = rsa::pkcs1::EncodeRsaPublicKey::to_pkcs1_der(&pubkey)
                    .expect("Faiiled to build public key bytes");
                let pubvec = pubbytes.as_bytes().to_vec();
                service::log::debug!("The public key is {:02x?}", pubvec);

                // data to encrypt
                let data = vec![0xFF, 0x55, 0xDD];

                // encrypt something with it
                let encrypted_data = session
                    .encrypt(&cryptoki::mechanism::Mechanism::RsaPkcs, public, &data)
                    .expect("Failed to encrypt sample data");

                // decrypt
                let decrypted_data = session
                    .decrypt(
                        &cryptoki::mechanism::Mechanism::RsaPkcs,
                        private,
                        &encrypted_data,
                    )
                    .expect("Failed to decrypt sample data");

                // The decrypted buffer is bigger than the original one.
                assert_eq!(data, decrypted_data);

                let rkp = RsaSha256Keypair {
                    session: Arc::new(Mutex::new(session)),
                    public,
                    private,
                    pubkey: pubvec,
                    hsm: self,
                };
                Some(KeyPair::RsaSha256(rkp))
            }
            HttpsSigningMethod::EcdsaSha256 => {
                todo!()
            }
        }
    }
}
