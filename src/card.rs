//! Smartcard related code and definitions

use card::PivCardWriter;

#[derive(Clone, Debug)]
pub struct KeyPair {
    public_key: Vec<u8>,
    algorithm: card::AuthenticateAlgorithm,
    pin: Vec<u8>,
}

pub enum Error {
    CardError(card::Error),
    Timeout,
}

impl rcgen::RemoteKeyPair for KeyPair {
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self.algorithm {
            card::AuthenticateAlgorithm::TripleDes => todo!(),
            card::AuthenticateAlgorithm::Rsa1024 | card::AuthenticateAlgorithm::Rsa2048 => {
                rcgen::SignatureAlgorithm::from_oid(
                    &cert_common::oid::OID_PKCS1_SHA256_RSA_ENCRYPTION.components(),
                )
                .unwrap()
            }
            card::AuthenticateAlgorithm::Aes128 => todo!(),
            card::AuthenticateAlgorithm::Aes192 => todo!(),
            card::AuthenticateAlgorithm::EccP256 => todo!(),
            card::AuthenticateAlgorithm::Aes256 => todo!(),
            card::AuthenticateAlgorithm::EccP384 => todo!(),
            card::AuthenticateAlgorithm::CipherSuite2 => todo!(),
            card::AuthenticateAlgorithm::CipherSuite7 => todo!(),
        }
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.sign_with_pin(msg)
    }
}

impl KeyPair {
    /// Create an rcgen keypair from the smartcard keypair
    pub fn rcgen(&self) -> rcgen::KeyPair {
        rcgen::KeyPair::from_remote(Box::new(self.clone())).unwrap()
    }

    /// Sign data
    pub fn sign_with_pin(&self, data: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        use sha2::Digest;
        service::log::debug!("Signing data len {} {:02X?}", data.len(), data);
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let hashed = crate::ca::pkcs15_sha256(&hash);

        service::log::debug!(
            "Signing hdata len {} with pin {:02X?} {:02X?}",
            hashed.len(),
            self.pin,
            hashed
        );
        for (i, v) in hashed.iter().enumerate() {
            service::log::debug!("{}: {}", i, v);
        }
        println!("Checking for public key {:02X?}", self.public_key);
        let a = card::with_piv_and_public_key(
            card::Slot::CardAuthentication,
            &self.public_key,
            |mut reader| {
                let r = reader.sign_data(card::Slot::CardAuthentication, &self.pin, hashed);
                r
            },
            std::time::Duration::from_secs(10),
        );
        match a {
            Ok(Ok(a)) => {
                Ok(a)
            }
            _ => {
                println!("Result of sign is {:?}", a);
                Err(rcgen::Error::RemoteKeyError)
            }
        }
    }

    /// Create a new self
    pub fn generate_with_smartcard(pin: Vec<u8>) -> Option<Self> {
        let algorithm = card::AuthenticateAlgorithm::Rsa2048;
        service::log::info!("Waiting for the next smartcard to be inserted");
        let pubkey = card::with_next_valid_piv_card(|reader| {
            let mut writer = card::PivCardWriter::extend(reader);
            writer.generate_keypair_with_management(
                &card::MANAGEMENT_KEY_DEFAULT,
                algorithm,
                card::Slot::CardAuthentication,
                card::KeypairPinPolicy::Once,
            )?;
            writer.reader.get_public_key(card::Slot::CardAuthentication)
        });
        Some(Self {
            public_key: pubkey.ok()?.to_der(),
            algorithm,
            pin,
        })
    }

    pub fn save_cert_to_card(&self, cert: &[u8]) -> Result<(), Error> {
        service::log::debug!("Saving cert data to card: {} {:02X?}", cert.len(), cert);
        match card::with_piv_and_public_key(
            card::Slot::CardAuthentication,
            &self.public_key,
            |reader| {
                let mut writer = card::PivCardWriter::extend(reader);
                writer.maybe_store_x509_cert(card::MANAGEMENT_KEY_DEFAULT, cert, 1)
            },
            std::time::Duration::from_secs(10),
        ) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(Error::CardError(e)),
            _ => Err(Error::Timeout),
        }
    }
}
