//! Code related to the pkcs11 interface for hardware security modules

use cert_common::{CertificateSigningMethod, HttpsSigningMethod};
use zeroize::Zeroizing;

pub struct Pkcs11KeyPair {
    public: cryptoki::object::ObjectHandle,
    private: cryptoki::object::ObjectHandle,
}

impl rcgen::RemoteKeyPair for Pkcs11KeyPair {
    fn public_key(&self) -> &[u8] {
        todo!()
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        todo!()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        todo!()
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
    pub fn get_user_session(&mut self) -> Option<cryptoki::session::Session> {
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
        &mut self,
        session: &mut cryptoki::session::Session,
        method: HttpsSigningMethod,
        keysize: usize,
    ) -> Option<rcgen::KeyPair> {
        match method {
            HttpsSigningMethod::RsaSha256 => {
                let mechanism = cryptoki::mechanism::Mechanism::RsaPkcsKeyPairGen;
                let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];

                let pub_key_template = vec![
                    cryptoki::object::Attribute::Token(true),
                    cryptoki::object::Attribute::Private(false),
                    cryptoki::object::Attribute::PublicExponent(public_exponent),
                    cryptoki::object::Attribute::ModulusBits((keysize as u64).into()),
                    cryptoki::object::Attribute::Encrypt(true),
                ];
                let priv_key_template = vec![
                    cryptoki::object::Attribute::Token(true),
                    cryptoki::object::Attribute::Decrypt(true),
                ];
                let (public, private) = session
                    .generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)
                    .ok()?;
                let attrs = session
                    .get_attributes(public, &[cryptoki::object::AttributeType::PublicKeyInfo])
                    .unwrap();
                service::log::debug!("Attributes are {:?}", attrs);
                if let cryptoki::object::Attribute::PublicKeyInfo(pk) = &attrs[0] {
                    service::log::debug!("The public key is {} {:?}", pk.len(), pk);
                }
                let rkp = Pkcs11KeyPair { public, private };
                rcgen::KeyPair::from_remote(Box::new(rkp)).ok()
            }
            HttpsSigningMethod::EcdsaSha256 => {
                todo!()
            }
        }
    }
}
