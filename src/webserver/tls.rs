//! A module for loading and parsing tls certificates

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};

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
pub fn load_user_cert_data(settings: &crate::MainConfiguration) -> Option<RootCertStore> {
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

        Some(rcs)
    } else {
        println!("Not loading any client certificate information");
        None
    }
}

/// Loads an https certificate from a pkcs12 container, into a format usable by rustls.
/// # Arguments
/// * certfile - The Path for the pkcs12 container
/// * pass - The password for the container
/// * rcs - The root cert store of client certificate root authorities. If this is set, it will replace the normal root authority. Useful for larger setups with multiple servers.
/// * require_cert - Set to true when the https should require a valid certificate instead of making it optional.
pub fn load_certificate<P>(
    certfile: P,
    pass: &str,
    rcs: Option<RootCertStore>,
    pki: &Arc<futures::lock::Mutex<crate::ca::PkiInstance>>,
    require_cert: bool,
) -> Result<Arc<ServerConfig>, Error>
where
    P: AsRef<Path>,
{
    let mut certbytes = vec![];
    let mut certf = File::open(&certfile)?;
    certf.read_to_end(&mut certbytes)?;

    let pkcs12 = crate::pkcs12::Pkcs12::load_from_data(&certbytes, pass.as_bytes(), 0);

    let cert_der = pkcs12.cert;

    let pkey_der: &Vec<u8> = pkcs12.pkey.as_ref();

    let pkey = PrivatePkcs8KeyDer::from(pkey_der.to_owned());
    let pkey = PrivateKeyDer::Pkcs8(pkey);

    let c1 = CertificateDer::from(cert_der.to_owned());

    let certs = vec![c1];

    let sc: tokio_rustls::rustls::ConfigBuilder<ServerConfig, tokio_rustls::rustls::WantsVerifier> =
        ServerConfig::builder();

    let mut rcs2 = if rcs.is_none() {
        RootCertStore::empty()
    } else {
        rcs.clone().unwrap()
    };

    if rcs.is_none() {
        let client_cert_der = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let pki = pki.lock().await;
                let cert = match std::ops::Deref::deref(&pki) {
                    crate::ca::PkiInstance::Pki(pki) => todo!(),
                    crate::ca::PkiInstance::Ca(ca) => ca.root_ca_cert().unwrap(),
                };
                cert.certificate_der()
            })
        });
        rcs2.add(client_cert_der.into()).unwrap();
    }

    //todo fill out the rcs struct
    let roots = Arc::new(rcs2);

    let client_verifier = if !require_cert {
        WebPkiClientVerifier::builder(roots)
            .allow_unauthenticated()
            .build()
            .unwrap()
    } else {
        WebPkiClientVerifier::builder(roots).build().unwrap()
    };

    let sc = sc.with_client_cert_verifier(client_verifier);
    let sc = sc.with_single_cert(certs, pkey)?;
    Ok(Arc::new(sc))
}
