use tokio_native_tls::native_tls::Identity;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

type Error = Box<dyn std::error::Error + 'static>;

pub struct TlsConfig {
    pub key_file: PathBuf,
    pub key_password: String
}

impl TlsConfig {
    pub fn new<P:Into<PathBuf>, S:Into<String>>(key_file: P, pass: S) -> Self {
        TlsConfig{
            key_file: key_file.into(),
            key_password: pass.into()
        }
    }
}

pub fn load_private_key<P>(file: P, pass: &str) -> Result<Identity, Error>
where
    P: AsRef<Path>,
{
    let mut bytes = vec![];
    let mut f = File::open(file)?;
    f.read_to_end(&mut bytes)?;
    let key = Identity::from_pkcs12(&bytes, pass)?;
    Ok(key)
}


pub fn tls_acceptor(i: Identity) -> tokio_native_tls::TlsAcceptor {
    tokio_native_tls::native_tls::TlsAcceptor::builder(i).build()
        .unwrap().into()
}

