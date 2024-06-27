//! Smartcard related code and definitions

#[derive(Clone, Debug)]
pub struct KeyPair {
    public_key: Vec<u8>,
}

impl KeyPair {
    /// Wait for the card with the proper public key
    pub fn wait_for_card(&self) {
        loop {
            todo!();
        }
    }

    /// Wait for the addition of a new smart card to the system
    fn wait_for_new_card() {
        todo!();
    }

    /// Sign the given data with the smartcard key
    pub fn sign(&self, data: &[u8]) -> Option<Vec<u8>> {
        todo!();
    }

    /// Create an rcgen keypair from the smartcard keypair
    pub fn rcgen(&self) -> rcgen::KeyPair {
        todo!();
    }

    /// Create a new self
    pub fn new() -> Self {
        Self::wait_for_new_card();
        Self {
            public_key: Vec::new(),
        }
    }
}
