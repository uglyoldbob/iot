//! Code related to the pkcs11 interface for hardware security modules

use std::sync::{Arc, Mutex};

use cert_common::{oid::OID_PKCS1_SHA256_RSA_ENCRYPTION, HttpsSigningMethod};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
#[enum_dispatch::enum_dispatch(KeyPairTrait)]
pub enum KeyPair {
    RsaSha256(RsaSha256Keypair),
}

impl KeyPair {
    pub fn load_with_label(hsm: Arc<Hsm>, label: &str) -> Option<Self> {
        let hsm2 = hsm.clone();
        let session = hsm.session.lock().unwrap();
        let objs = session
            .find_objects(&[
                cryptoki::object::Attribute::Label(label.as_bytes().to_vec()),
                cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PUBLIC_KEY),
            ])
            .unwrap();
        service::log::debug!(
            "There are {} objects in the search for public {}",
            objs.len(),
            label
        );
        let public = if objs.len() > 0 { Some(objs[0]) } else { None };
        let objs = session
            .find_objects(&[
                cryptoki::object::Attribute::Label(label.as_bytes().to_vec()),
                cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
            ])
            .unwrap();
        service::log::debug!(
            "There are {} objects in the search for private {}",
            objs.len(),
            label
        );
        let private = if objs.len() > 0 { Some(objs[0]) } else { None };

        let public = public?;
        let private = private?;

        let attr_info = session
            .get_attributes(public, &[cryptoki::object::AttributeType::KeyType])
            .unwrap();
        let ktype = &attr_info[0];
        if let cryptoki::object::Attribute::KeyType(kt) = ktype {
            match kt.to_owned() {
                cryptoki::object::KeyType::RSA => {
                    let pubkey = get_rsa_public_key(&session, public);
                    Some(KeyPair::RsaSha256(RsaSha256Keypair {
                        _public: public,
                        private,
                        pubkey,
                        label: label.to_string(),
                        hsm: hsm2,
                    }))
                }
                _ => None,
            }
        } else {
            None
        }
    }
}

#[enum_dispatch::enum_dispatch]
pub trait KeyPairTrait {
    /// Get an rcgen version of the keypair
    fn keypair(&self) -> rcgen::KeyPair;
    /// Get the label of the key
    fn label(&self) -> String;
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
    _public: cryptoki::object::ObjectHandle,
    private: cryptoki::object::ObjectHandle,
    pubkey: Vec<u8>,
    label: String,
    hsm: Arc<crate::hsm2::Hsm>,
}

impl KeyPairTrait for RsaSha256Keypair {
    fn keypair(&self) -> rcgen::KeyPair {
        rcgen::KeyPair::from_remote(Box::new(self.clone())).unwrap()
    }

    fn label(&self) -> String {
        self.label.clone()
    }
}

impl rcgen::RemoteKeyPair for RsaSha256Keypair {
    fn public_key(&self) -> &[u8] {
        &self.pubkey
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let session = self.hsm.session.lock().unwrap();
        let hash = session
            .digest(&cryptoki::mechanism::Mechanism::Sha256, msg)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        let hashed = crate::ca::rsa_sha256(&hash);
        service::log::debug!(
            "Data to rsa sign is length {} {:02X?}",
            hashed.len(),
            hashed
        );
        let r = session.sign(
            &cryptoki::mechanism::Mechanism::RsaPkcs,
            self.private,
            &hashed,
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
    session: Arc<Mutex<cryptoki::session::Session>>,
}

fn get_rsa_public_key(
    session: &cryptoki::session::Session,
    public: cryptoki::object::ObjectHandle,
) -> Vec<u8> {
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
    let mut rsamod2 = vec![0];
    rsamod2.append(&mut rsamod);
    let pubkey = rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(&rsamod2), rsaexp)
        .expect("Failed to build public key");

    let pubbytes = rsa::pkcs1::EncodeRsaPublicKey::to_pkcs1_der(&pubkey)
        .expect("Faiiled to build public key bytes");
    pubbytes.as_bytes().to_vec()
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

        let session = pkcs11
            .open_rw_session(so_slot)
            .map(|s| {
                s.login(
                    cryptoki::session::UserType::User,
                    Some(&cryptoki::types::AuthPin::new(user_pin.as_str().into())),
                )
                .unwrap();
                s
            })
            .expect("Failed to get user session");

        Some(Self {
            session: Arc::new(Mutex::new(session)),
        })
    }

    /// list certificates
    pub fn list_certificates(&self) {
        let session = self.session.lock().unwrap();

        let mut templates = Vec::new();

        let a = vec![
            cryptoki::object::Attribute::Token(true),
            cryptoki::object::Attribute::Private(false),
            cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PUBLIC_KEY),
            cryptoki::object::Attribute::KeyType(cryptoki::object::KeyType::RSA),
        ];
        templates.push(a);
        for t in &templates {
            let res = session.find_objects(t).expect("Expected to find objects");
            service::log::debug!("There are {} objects", res.len());
            for t2 in res {
                service::log::debug!("Found object {:?}", t2);
            }
        }
    }

    /// Open the hsm
    pub fn open(p: Option<std::path::PathBuf>, user_pin: Zeroizing<String>) -> Option<Self> {
        let path = p
            .or_else(|| Some(std::path::PathBuf::from(hsm2_path())))
            .unwrap();
        let pkcs11 = cryptoki::context::Pkcs11::new(path).ok()?;
        pkcs11
            .initialize(cryptoki::context::CInitializeArgs::OsThreads)
            .unwrap();
        let so_slot = pkcs11.get_slots_with_token().unwrap().remove(0);

        let session = pkcs11
            .open_rw_session(so_slot)
            .map(|s| {
                s.login(
                    cryptoki::session::UserType::User,
                    Some(&cryptoki::types::AuthPin::new(user_pin.as_str().into())),
                )
                .unwrap();
                s
            })
            .expect("Failed to get user session");

        Some(Self {
            session: Arc::new(Mutex::new(session)),
        })
    }

    /// Attempt to get a session as a user
    fn get_user_session(&self) -> Arc<Mutex<cryptoki::session::Session>> {
        self.session.clone()
    }

    /// Generate a keypair for certificate operations
    pub fn generate_https_keypair(
        self: &Arc<Self>,
        name: &str,
        method: HttpsSigningMethod,
        keysize: usize,
    ) -> Option<KeyPair> {
        let session = self.get_user_session();
        let session = session.lock().unwrap();
        match method {
            HttpsSigningMethod::RsaSha256 => {
                let mechanism = cryptoki::mechanism::Mechanism::RsaPkcsKeyPairGen;
                let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
                let bits: cryptoki::types::Ulong = (keysize as u64).into();
                let pub_key_template = vec![
                    cryptoki::object::Attribute::Token(true),
                    cryptoki::object::Attribute::Private(false),
                    cryptoki::object::Attribute::PublicExponent(public_exponent),
                    cryptoki::object::Attribute::ModulusBits(bits),
                    cryptoki::object::Attribute::Encrypt(true),
                    cryptoki::object::Attribute::Label(name.as_bytes().to_vec()),
                ];
                let priv_key_template = vec![
                    cryptoki::object::Attribute::Token(true),
                    cryptoki::object::Attribute::Decrypt(true),
                    cryptoki::object::Attribute::Label(name.as_bytes().to_vec()),
                ];
                let (public, private) = session
                    .generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)
                    .expect("Failed to generate keypair");
                let pubvec = get_rsa_public_key(&session, public);

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
                    _public: public,
                    private,
                    pubkey: pubvec,
                    hsm: self.clone(),
                    label: name.to_string(),
                };
                Some(KeyPair::RsaSha256(rkp))
            }
            HttpsSigningMethod::EcdsaSha256 => {
                todo!()
            }
        }
    }
}
