#[path = "ca/ca_common.rs"]
mod ca_common;

use crate::oid::*;
pub use ca_common::*;
use zeroize::Zeroizing;

impl Ca {
    pub async fn init(settings: &crate::MainConfiguration) -> Self {
        let mut ca = Self::load(settings).await;

        let table = settings.ca.as_ref().unwrap();

        match ca.load_root_ca_cert(&table.root_password).await {
            Ok(_cert) => {}
            Err(e) => {
                if let CertificateLoadingError::DoesNotExist = e {
                    if let Some(table) = &settings.ca {
                        if table.generate {
                            use pkcs8::EncodePrivateKey;
                            println!("Generating a root certificate for ca operations");

                            let mut rng = rand::thread_rng();
                            let bits = 4096;
                            let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
                            let private_key_der = private_key.to_pkcs8_der().unwrap();
                            let key_pair =
                                rcgen::KeyPair::try_from(private_key_der.as_bytes()).unwrap();

                            let san: Vec<String> = table.san.to_owned();
                            let mut certparams = rcgen::CertificateParams::new(san);
                            certparams.key_pair = Some(key_pair);
                            certparams.alg = rcgen::SignatureAlgorithm::from_oid(
                                &OID_PKCS1_SHA256_RSA_ENCRYPTION.components(),
                            )
                            .unwrap();
                            certparams.distinguished_name = rcgen::DistinguishedName::new();

                            let cn = &table.common_name;
                            let days = table.days;
                            let chain_length = table.chain_length;

                            certparams
                                .distinguished_name
                                .push(rcgen::DnType::CommonName, cn);
                            certparams.not_before = time::OffsetDateTime::now_utc();
                            certparams.not_after =
                                certparams.not_before + time::Duration::days(days as i64);
                            let basic_constraints =
                                rcgen::BasicConstraints::Constrained(chain_length);
                            certparams.is_ca = rcgen::IsCa::Ca(basic_constraints);

                            let pkix = PkixAuthorityInfoAccess::new(Self::get_ocsp_urls(settings));
                            let ocsp_data = pkix.der;
                            let ocsp = rcgen::CustomExtension::from_oid_content(
                                &OID_PKIX_AUTHORITY_INFO_ACCESS.components(),
                                ocsp_data,
                            );
                            certparams.custom_extensions.push(ocsp);
                            let cert = rcgen::Certificate::from_params(certparams).unwrap();
                            let cert_der = cert.serialize_der().unwrap();
                            let key_der = cert.get_key_pair().serialize_der();

                            let cacert = CaCertificate::from_existing(
                                CertificateSigningMethod::Ecdsa,
                                ca.medium.clone(),
                                &cert_der,
                                Some(Zeroizing::from(key_der)),
                                "root".to_string(),
                            );
                            cacert.save_to_medium(&table.root_password).await;
                            ca.root_cert = Ok(cacert);
                            ca.init_request_id().await;
                            println!("Generating OCSP responder certificate");
                            let ocsp_names = Self::get_ocsp_urls(settings);
                            let mut key_usage_oids = Vec::new();
                            key_usage_oids.push(OID_EXTENDED_KEY_USAGE_OCSP_SIGNING.to_owned());
                            let mut extensions = Vec::new();
                            extensions.push(
                                CsrAttribute::build_extended_key_usage(key_usage_oids)
                                    .to_custom_extension(),
                            );

                            let id = ca.get_new_request_id().await.unwrap();
                            let ocsp_csr = ca.generate_signing_request(
                                CertificateSigningMethod::RsaSha256,
                                "ocsp".to_string(),
                                "OCSP Responder".to_string(),
                                ocsp_names,
                                extensions,
                                id,
                            );
                            let mut ocsp_cert =
                                ca.root_cert.as_ref().unwrap().sign_csr(ocsp_csr).unwrap();
                            ocsp_cert.medium = ca.medium.clone();
                            ocsp_cert.save_to_medium(&table.ocsp_password).await;
                            ca.ocsp_signer = Ok(ocsp_cert);

                            let mut key_usage_oids = Vec::new();
                            key_usage_oids.push(OID_EXTENDED_KEY_USAGE_CLIENT_AUTH.to_owned());
                            let mut extensions = Vec::new();
                            extensions.push(
                                CsrAttribute::build_extended_key_usage(key_usage_oids)
                                    .to_custom_extension(),
                            );

                            println!("Generating administrator certificate");
                            let id = ca.get_new_request_id().await.unwrap();
                            let admin_csr = ca.generate_signing_request(
                                CertificateSigningMethod::RsaSha256,
                                "admin".to_string(),
                                "Administrator".to_string(),
                                Vec::new(),
                                extensions,
                                id,
                            );
                            let mut admin_cert =
                                ca.root_cert.as_ref().unwrap().sign_csr(admin_csr).unwrap();
                            admin_cert.medium = ca.medium.clone();
                            admin_cert.save_to_medium(&table.admin_password).await;
                            ca.admin = Ok(admin_cert);
                        }
                    }
                }
            }
        }
        ca
    }
}
