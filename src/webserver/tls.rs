//! A module for loading and parsing tls certificates

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use p12::yasna;

use der::Decode;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::danger::ClientCertVerifier;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use yasna::ASN1Error;

/// A generic error type
type Error = Box<dyn std::error::Error + 'static>;

/// Represents a pkcs12 certificate container on the filesystem
pub struct TlsConfig {
    /// The location of the file
    pub cert_file: PathBuf,
    /// The password of the file
    pub key_password: String,
}

impl TlsConfig {
    /// Create a new tls config, specifying the pkcs12 specs
    /// # Arguments
    /// * cert_file - The location of the pkcs12 document
    /// * pass - The password for the pkcs12 document
    pub fn new<P: Into<PathBuf>, S: Into<String>>(cert_file: P, pass: S) -> Self {
        TlsConfig {
            cert_file: cert_file.into(),
            key_password: pass.into(),
        }
    }
}

/// Check the program config and create a client verifier struct as specified.
/// # Arguments
/// * settings - The program configuration object.
pub fn load_user_cert_data(
    settings: &crate::MainConfiguration,
) -> Option<Arc<dyn ClientCertVerifier>> {
    if let Some(section) = &settings.client_certs {
        println!("Loading client certificate data");
        let mut rcs = RootCertStore::empty();

        for s in section {
            println!("\tClient cert {}", s);
            let mut certbytes = vec![];
            let mut certf = File::open(s)
                .unwrap_or_else(|e| panic!("Failed to open client certificate {}: {}", s, e));
            certf
                .read_to_end(&mut certbytes)
                .unwrap_or_else(|e| panic!("Failed to read client certificate {}: {}", s, e));
            let cder = CertificateDer::from(certbytes);
            rcs.add(cder)
                .unwrap_or_else(|e| panic!("Failed to add client certificate {}: {}", s, e));
        }

        //todo fill out the rcs struct
        let roots = Arc::new(rcs);

        let client_verifier = WebPkiClientVerifier::builder(roots)
            .allow_unauthenticated()
            .build()
            .unwrap();
        Some(client_verifier)
    } else {
        println!("Not loading any client certificate information");
        None
    }
}

/// Loads an https certificate from a pkcs12 container, into a format usable by rustls.
/// # Arguments
/// * certfile - The Path for the pkcs12 container
/// * pass - The password for the container
/// * user_certs - The struct used to verify client id with tls.
pub fn load_certificate<P>(
    certfile: P,
    pass: &str,
    user_certs: Option<Arc<dyn ClientCertVerifier>>,
) -> Result<Arc<ServerConfig>, Error>
where
    P: AsRef<Path>,
{
    let mut certbytes = vec![];
    let mut certf = File::open(&certfile)?;
    certf.read_to_end(&mut certbytes)?;

    let pkcs12 = crate::pkcs12::Pkcs12::load_from_data(&certbytes, pass.as_bytes());

    let cert_der = pkcs12.certificate.get_der();

    let pkey_der = pkcs12.pkey.get_der();

    let pkey = PrivatePkcs8KeyDer::from(pkey_der.to_owned());
    let pkey = PrivateKeyDer::Pkcs8(pkey);

    let c1 = CertificateDer::from(cert_der.to_owned());

    let certs = vec![c1];

    let sc: tokio_rustls::rustls::ConfigBuilder<ServerConfig, tokio_rustls::rustls::WantsVerifier> =
        ServerConfig::builder();

    let sc = if let Some(certs) = user_certs {
        sc.with_client_cert_verifier(certs)
    } else {
        sc.with_no_client_auth()
    };
    let sc = sc.with_single_cert(certs, pkey)?;
    Ok(Arc::new(sc))
}
