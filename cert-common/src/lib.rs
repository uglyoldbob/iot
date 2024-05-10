//! Commmon code for both wasm and non-wasm code

pub mod oid;
use oid::*;
use zeroize::Zeroizing;

/// The ways in which a certificate can be used, the extended form
#[derive(Debug)]
pub enum ExtendedKeyUsage {
    /// The certificate is used to identify a client
    ClientIdentification,
    /// The certificate is used to identify a server
    ServerIdentification,
    /// The certificate is used to sign code
    CodeSigning,
    /// The certificate is used for ocsp signning
    OcspSigning,
    /// The key usage is unrecognized
    Unrecognized(Oid),
}

impl From<Oid> for ExtendedKeyUsage {
    fn from(value: Oid) -> Self {
        if value == *OID_EXTENDED_KEY_USAGE_CLIENT_AUTH {
            ExtendedKeyUsage::ClientIdentification
        } else if value == *OID_EXTENDED_KEY_USAGE_SERVER_AUTH {
            ExtendedKeyUsage::ServerIdentification
        } else if value == *OID_EXTENDED_KEY_USAGE_CODE_SIGNING {
            ExtendedKeyUsage::CodeSigning
        } else if value == *OID_EXTENDED_KEY_USAGE_OCSP_SIGNING {
            ExtendedKeyUsage::OcspSigning
        } else {
            ExtendedKeyUsage::Unrecognized(value)
        }
    }
}

impl ExtendedKeyUsage {
    /// Convert Self to an Oid
    fn to_oid(&self) -> Oid {
        match self {
            ExtendedKeyUsage::ClientIdentification => OID_EXTENDED_KEY_USAGE_CLIENT_AUTH.clone(),
            ExtendedKeyUsage::ServerIdentification => OID_EXTENDED_KEY_USAGE_SERVER_AUTH.clone(),
            ExtendedKeyUsage::CodeSigning => OID_EXTENDED_KEY_USAGE_CODE_SIGNING.clone(),
            ExtendedKeyUsage::OcspSigning => OID_EXTENDED_KEY_USAGE_OCSP_SIGNING.clone(),
            ExtendedKeyUsage::Unrecognized(s) => s.clone(),
        }
    }
}

/// The types of attributes that can be present in a csr
pub enum CsrAttribute {
    /// What the certificate can be used for
    ExtendedKeyUsage(Vec<ExtendedKeyUsage>),
    /// The challenge password
    ChallengePassword(String),
    /// The unstructured name
    UnstructuredName(String),
    /// All others
    Unrecognized(Oid, der::Any),
}

impl CsrAttribute {
    /// Convert self to an `rcgen::CustomAttribute`
    pub fn to_custom_attribute(&self) -> Option<rcgen::CustomAttribute> {
        match self {
            CsrAttribute::ExtendedKeyUsage(oids) => {
                let oid = &OID_CERT_EXTENDED_KEY_USAGE.components();
                let content = yasna::construct_der(|w| {
                    w.write_sequence_of(|w| {
                        for o in oids {
                            w.next().write_oid(&o.to_oid().to_yasna());
                        }
                    });
                });
                Some(rcgen::CustomAttribute::from_oid_content(oid, content))
            }
            CsrAttribute::ChallengePassword(p) => {
                let oid = &OID_PKCS9_CHALLENGE_PASSWORD.components();
                let content = yasna::construct_der(|w| {
                    w.write_set(|w| w.next().write_utf8_string(p));
                });
                Some(rcgen::CustomAttribute::from_oid_content(oid, content))
            }
            CsrAttribute::UnstructuredName(n) => {
                let oid = &OID_PKCS9_UNSTRUCTURED_NAME.components();
                let content = yasna::construct_der(|w| {
                    w.write_set(|w| w.next().write_utf8_string(n));
                });
                Some(rcgen::CustomAttribute::from_oid_content(oid, content))
            }
            CsrAttribute::Unrecognized(_oid, _any) => None,
        }
    }

    /// Convert self to an `rcgen::CustomExtension`
    pub fn to_custom_extension(&self) -> Option<rcgen::CustomExtension> {
        match self {
            CsrAttribute::ExtendedKeyUsage(oids) => {
                let oid = &OID_CERT_EXTENDED_KEY_USAGE.components();
                let content = yasna::construct_der(|w| {
                    w.write_sequence_of(|w| {
                        for o in oids {
                            w.next().write_oid(&o.to_oid().to_yasna());
                        }
                    });
                });
                Some(rcgen::CustomExtension::from_oid_content(oid, content))
            }
            CsrAttribute::ChallengePassword(p) => {
                let oid = &OID_PKCS9_CHALLENGE_PASSWORD.components();
                let content = yasna::construct_der(|w| {
                    w.write_set(|w| w.next().write_utf8_string(p));
                });
                Some(rcgen::CustomExtension::from_oid_content(oid, content))
            }
            CsrAttribute::UnstructuredName(n) => {
                let oid = &OID_PKCS9_UNSTRUCTURED_NAME.components();
                let content = yasna::construct_der(|w| {
                    w.write_set(|w| w.next().write_utf8_string(n));
                });
                Some(rcgen::CustomExtension::from_oid_content(oid, content))
            }
            CsrAttribute::Unrecognized(_oid, _any) => None,
        }
    }

    #[allow(dead_code)]
    /// Build a Self with a list of Oid
    pub fn build_extended_key_usage(usage: Vec<Oid>) -> Self {
        let ks = usage.iter().map(|o| o.clone().into()).collect();
        Self::ExtendedKeyUsage(ks)
    }

    #[allow(dead_code)]
    /// Build a self with the specified oid and data
    pub fn with_oid_and_any(oid: Oid, any: der::Any) -> Self {
        if oid == *OID_PKCS9_UNSTRUCTURED_NAME {
            let n = any.decode_as().unwrap();
            Self::UnstructuredName(n)
        } else if oid == *OID_PKCS9_CHALLENGE_PASSWORD {
            let n = any.decode_as().unwrap();
            Self::ChallengePassword(n)
        } else if oid == *OID_CERT_EXTENDED_KEY_USAGE {
            let oids: Vec<der::asn1::ObjectIdentifier> = any.decode_as().unwrap();
            let oids = oids.iter().map(|o| Oid::from_const(*o).into()).collect();
            Self::ExtendedKeyUsage(oids)
        } else if oid == *OID_PKCS9_EXTENSION_REQUEST {
            use der::Encode;
            let params = yasna::parse_der(&any.to_der().unwrap(), |r| {
                r.read_sequence(|r| {
                    r.next().read_sequence(|r| {
                        let _oid = r.next().read_oid();
                        r.next().read_bytes()
                    })
                })
            })
            .unwrap();
            let oids: Vec<yasna::models::ObjectIdentifier> =
                yasna::parse_der(&params, |r| r.collect_sequence_of(|r| r.read_oid())).unwrap();
            let oids = oids
                .iter()
                .map(|o| Oid::from_yasna(o.clone()).into())
                .collect();
            Self::ExtendedKeyUsage(oids)
        } else {
            Self::Unrecognized(oid, any)
        }
    }
}

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