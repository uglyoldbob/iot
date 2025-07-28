//! A module for loading and parsing tls certificates

use std::fs::File;
use std::io::Read;
use std::sync::Arc;

use cert_common::CertificateSigningMethod;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};

use crate::ca::HttpsCertificate;

/// A generic error type
type Error = Box<dyn std::error::Error + 'static>;

/// Loads an https certificate from a pkcs12 container, into a format usable by rustls.
/// # Arguments
/// * certfile - The Path for the pkcs12 container
/// * pass - The password for the container
/// * rcs - The root cert store of client certificate root authorities. If this is set, it will replace the normal root authority. Useful for larger setups with multiple servers.
/// * require_cert - Set to true when the https should require a valid certificate instead of making it optional.
pub fn load_certificate(
    https: &HttpsCertificate,
    rcs: Option<RootCertStore>,
    pki: &Arc<futures::lock::Mutex<crate::ca::PkiInstance>>,
    require_cert: bool,
) -> Result<Arc<ServerConfig>, Error> {
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    let pkey_der = https
        .get_private()
        .expect("Access to the https private is required right now");
    let pkey = PrivatePkcs8KeyDer::from(pkey_der.to_owned());
    let pkey = PrivateKeyDer::Pkcs8(pkey);
    let cert_der = &https.cert;
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
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let pki = pki.lock().await;
                match std::ops::Deref::deref(&pki) {
                    crate::ca::PkiInstance::Pki(pki) => {
                        for ca in pki.get_client_certifiers().await {
                            if let CertificateSigningMethod::Https(_m) = ca.sign_method() {
                                let cert = ca.root_cert_ref().unwrap();
                                let cert_der = cert.contents().unwrap(); //TODO remove this unwrap
                                rcs2.add(cert_der.into()).unwrap();
                            }
                        }
                    }
                    crate::ca::PkiInstance::Ca(ca) => {
                        if let CertificateSigningMethod::Https(_m) = ca.config.sign_method {
                            let cert = ca.root_ca_cert().unwrap();
                            let cert_der = cert.contents().unwrap(); //TODO remove this unwrap
                            rcs2.add(cert_der.into()).unwrap();
                        }
                    }
                };
            })
        });
    }

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
