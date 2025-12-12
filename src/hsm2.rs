//! Code related to the pkcs11 interface for hardware security modules

use std::sync::{Arc, Mutex};

use cert_common::{
    oid::{OID_ECDSA_P256_SHA256_SIGNING, OID_PKCS1_SHA256_RSA_ENCRYPTION},
    HttpsSigningMethod,
};
use cryptoki::object::Attribute;
use zeroize::Zeroizing;

/// The trait that security module implements
#[enum_dispatch::enum_dispatch]
pub trait SecurityModuleTrait {
    /// Generate a keypair for certificate operations
    fn generate_https_keypair(
        &self,
        name: &str,
        method: HttpsSigningMethod,
        keysize: usize,
    ) -> Option<KeyPair>;
    /// list certificates
    fn list_certificates(&self);
    /// Load the cert with the given label
    fn load_with_label(&self, label: &str) -> Option<KeyPair>;
}

/// The keypair for a certificate in the hsm module
#[derive(Clone, Debug)]
#[enum_dispatch::enum_dispatch(KeyPairTrait)]
pub enum KeyPair {
    /// An rsa sha256 keypair
    RsaSha256(RsaSha256Keypair),
    /// An ecdsa sha256 keypair
    EcdsaSha256(EcdsaSha256Keypair),
}

impl KeyPair {
    /// Attempt to load the cert with the specified label from the given hsm.
    pub fn load_with_label(hsm: Arc<SecurityModule>, label: &str) -> Option<Self> {
        hsm.load_with_label(label)
    }
}

/// A trait used to get rcgen keypairs and labels for keypairs on the hsm
#[enum_dispatch::enum_dispatch]
pub trait KeyPairTrait {
    /// Get an rcgen version of the keypair
    fn keypair(&self) -> rcgen::KeyPair;
    /// Get the label of the key
    fn label(&self) -> String;
    /// Get the https signing algorithm
    fn https_algorithm(&self) -> Option<HttpsSigningMethod>;
}

//TODO try to use enum_dispatch for this impl
impl rcgen::RemoteKeyPair for KeyPair {
    fn public_key(&self) -> &[u8] {
        match self {
            KeyPair::RsaSha256(m) => m.public_key(),
            KeyPair::EcdsaSha256(m) => m.public_key(),
        }
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        match self {
            KeyPair::RsaSha256(m) => m.sign(msg),
            KeyPair::EcdsaSha256(m) => m.sign(msg),
        }
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            KeyPair::RsaSha256(m) => m.algorithm(),
            KeyPair::EcdsaSha256(m) => m.algorithm(),
        }
    }
}

/// ECDSA signature structure for ASN.1 encoding
#[derive(Debug, der::Sequence)]
pub struct EcdsaSignature {
    /// The r component of the ECDSA signature
    pub r: der::asn1::Uint,
    /// The s component of the ECDSA signature
    pub s: der::asn1::Uint,
}

/// An ecdsa sha-256 hsm keypair
#[derive(Clone, Debug)]
pub struct EcdsaSha256Keypair {
    /// The handle for the public key
    _public: cryptoki::object::ObjectHandle,
    /// The handle for the private key
    private: cryptoki::object::ObjectHandle,
    /// The actual public key
    pubkey: Vec<u8>,
    /// The label for the keypair
    label: String,
    /// The reference hsm to commmunicate with
    hsm: Arc<crate::hsm2::HsmInner>,
}

impl KeyPairTrait for EcdsaSha256Keypair {
    fn keypair(&self) -> rcgen::KeyPair {
        rcgen::KeyPair::from_remote(Box::new(self.clone())).unwrap()
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn https_algorithm(&self) -> Option<HttpsSigningMethod> {
        Some(HttpsSigningMethod::EcdsaSha256)
    }
}

impl rcgen::RemoteKeyPair for EcdsaSha256Keypair {
    fn public_key(&self) -> &[u8] {
        &self.pubkey
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let session = self.hsm.session.lock().unwrap();
        let hash = session
            .digest(&cryptoki::mechanism::Mechanism::Sha256, &msg)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;

        let r = session.sign(&cryptoki::mechanism::Mechanism::Ecdsa, self.private, &hash);
        let raw = r.map_err(|e| {
            service::log::error!("The error for ecdsa sign is {:?}", e);
            rcgen::Error::RemoteKeyError
        })?;

        let sig = EcdsaSignature {
            r: der::asn1::Uint::new(&raw[0..32]).unwrap(),
            s: der::asn1::Uint::new(&raw[32..64]).unwrap(),
        };

        use der::Encode;
        let yder = sig.to_der().unwrap();

        Ok(yder)
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        rcgen::SignatureAlgorithm::from_oid(&OID_ECDSA_P256_SHA256_SIGNING.components()).unwrap()
    }
}

/// An rsa sha-256 hsm keypair
#[derive(Clone, Debug)]
pub struct RsaSha256Keypair {
    /// The handle for the public key
    _public: cryptoki::object::ObjectHandle,
    /// The handle for the private key
    private: cryptoki::object::ObjectHandle,
    /// The actual public key
    pubkey: Vec<u8>,
    /// The label for the keypair
    label: String,
    /// The reference hsm to commmunicate with
    hsm: Arc<crate::hsm2::HsmInner>,
}

impl KeyPairTrait for RsaSha256Keypair {
    fn keypair(&self) -> rcgen::KeyPair {
        rcgen::KeyPair::from_remote(Box::new(self.clone())).unwrap()
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn https_algorithm(&self) -> Option<HttpsSigningMethod> {
        Some(HttpsSigningMethod::RsaSha256)
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
        let hashed = crate::utility::rsa_sha256(&hash);
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

/// The security module for storing certificates
#[enum_dispatch::enum_dispatch(SecurityModuleTrait)]
pub enum SecurityModule {
    /// A hardware security module is used
    Hardware(Hsm),
    /// Not a hardware security module
    Software(Ssm),
}

#[derive(Clone, Debug)]
struct HsmInner {
    /// A session used to communicate with the hardware
    session: Arc<Mutex<cryptoki::session::Session>>,
}

/// A hardware security module, using pkcs11
#[derive(Debug)]
pub struct Hsm {
    inner: Arc<HsmInner>,
}

/// A software security module
#[derive(Debug)]
pub struct Ssm {}

impl SecurityModuleTrait for Ssm {
    fn generate_https_keypair(
        &self,
        name: &str,
        method: HttpsSigningMethod,
        keysize: usize,
    ) -> Option<KeyPair> {
        todo!()
    }

    fn list_certificates(&self) {
        todo!()
    }

    fn load_with_label(&self, label: &str) -> Option<KeyPair> {
        todo!()
    }
}

/// Get the rsa public key from the hsm
fn get_rsa_public_key(
    session: &cryptoki::session::Session,
    public: cryptoki::object::ObjectHandle,
) -> Vec<u8> {
    let attrs = session
        .get_attributes(public, &[cryptoki::object::AttributeType::Modulus])
        .unwrap();
    let mut rsamod = Vec::new();
    let rsaexp = rsa::BigUint::new(vec![65537_u32]);
    for attr in &attrs {
        match attr {
            cryptoki::object::Attribute::Modulus(v) => {
                v.clone_into(&mut rsamod);
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
        .expect("Failed to build public key bytes");
    pubbytes.as_bytes().to_vec()
}

/// Get the rsa public key from the hsm
fn get_ecdsa_public_key(
    session: &cryptoki::session::Session,
    public: cryptoki::object::ObjectHandle,
) -> Vec<u8> {
    let attrs = session
        .get_attributes(
            public,
            &[
                cryptoki::object::AttributeType::EcParams,
                cryptoki::object::AttributeType::EcPoint,
            ],
        )
        .unwrap();
    let mut ecpoint = Vec::new();
    let mut params = Vec::new();
    for attr in &attrs {
        match attr {
            cryptoki::object::Attribute::EcPoint(d) => {
                ecpoint = d.to_owned();
            }
            cryptoki::object::Attribute::EcParams(p) => {
                params = p.to_owned();
            }
            _ => {
                panic!("Unexpected attribute");
            }
        }
    }

    ecpoint[2..].to_vec()
}

impl SecurityModuleTrait for Hsm {
    fn load_with_label(&self, label: &str) -> Option<KeyPair> {
        let session = self.inner.session.lock().unwrap();
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
        let public = if !objs.is_empty() {
            Some(objs[0])
        } else {
            None
        };
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
        let private = if !objs.is_empty() {
            Some(objs[0])
        } else {
            None
        };

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
                    //TODO Pick the correct rsa keypair instead of assuming sha256
                    Some(KeyPair::RsaSha256(RsaSha256Keypair {
                        _public: public,
                        private,
                        pubkey,
                        label: label.to_string(),
                        hsm: self.inner.clone(),
                    }))
                }
                cryptoki::object::KeyType::EC => {
                    let pubkey = get_ecdsa_public_key(&session, public);
                    //TODO Pick the correct ecdsa keypair instead of assuming sha256
                    Some(KeyPair::EcdsaSha256(EcdsaSha256Keypair {
                        _public: public,
                        private,
                        pubkey,
                        label: label.to_string(),
                        hsm: self.inner.clone(),
                    }))
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn list_certificates(&self) {
        let session = self.inner.session.lock().unwrap();

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

    fn generate_https_keypair(
        &self,
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
                    hsm: self.inner.clone(),
                    label: name.to_string(),
                };
                Some(KeyPair::RsaSha256(rkp))
            }
            HttpsSigningMethod::EcdsaSha256 => {
                let mechanism = cryptoki::mechanism::Mechanism::EccKeyPairGen;

                let pub_key_template = vec![
                    cryptoki::object::Attribute::Token(true),
                    cryptoki::object::Attribute::Label(name.as_bytes().to_vec()),
                    cryptoki::object::Attribute::EcParams(vec![
                        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
                    ]),
                    cryptoki::object::Attribute::Private(false),
                    cryptoki::object::Attribute::Encrypt(true),
                ];
                let priv_key_template = vec![
                    cryptoki::object::Attribute::Token(true),
                    cryptoki::object::Attribute::Label(name.as_bytes().to_vec()),
                    Attribute::Sensitive(true),
                    Attribute::Derive(true),
                    cryptoki::object::Attribute::Private(true),
                    cryptoki::object::Attribute::Decrypt(true),
                ];
                let (public, private) = session
                    .generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)
                    .expect("Failed to generate keypair");
                let pubvec = get_ecdsa_public_key(&session, public);

                let rkp = EcdsaSha256Keypair {
                    _public: public,
                    private,
                    pubkey: pubvec,
                    hsm: self.inner.clone(),
                    label: name.to_string(),
                };
                Some(KeyPair::EcdsaSha256(rkp))
            }
        }
    }
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
        pkcs11.init_token(so_slot, &so_pin, "InitialToken").unwrap();
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
            inner: Arc::new(HsmInner {
                session: Arc::new(Mutex::new(session)),
            }),
        })
    }

    /// Open the hsm
    pub fn open(
        slot_num: usize,
        p: Option<std::path::PathBuf>,
        user_pin: Zeroizing<String>,
    ) -> Option<Self> {
        let path = p
            .or_else(|| Some(std::path::PathBuf::from(hsm2_path())))
            .unwrap();
        let pkcs11 = cryptoki::context::Pkcs11::new(path).ok()?;
        pkcs11
            .initialize(cryptoki::context::CInitializeArgs::OsThreads)
            .unwrap();
        let slots = pkcs11.get_slots_with_token().unwrap();
        if slots.len() < slot_num {
            return None;
        }
        let so_slot = slots[slot_num];

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
            inner: Arc::new(HsmInner {
                session: Arc::new(Mutex::new(session)),
            }),
        })
    }

    /// Attempt to get a session as a user
    fn get_user_session(&self) -> Arc<Mutex<cryptoki::session::Session>> {
        self.inner.session.clone()
    }
}
