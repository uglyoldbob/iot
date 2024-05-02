mod utils;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    let mut params: rcgen::CertificateParams = Default::default();
    params.not_before = rcgen::date_time_ymd(1975, 1, 1);
    params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Crab widgits SE");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Master Cert");
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("crabs.crabs".try_into().unwrap()),
        rcgen::SanType::DnsName("localhost".try_into().unwrap()),
    ];

    let key_pair = rcgen::KeyPair::generate();
    if let Ok(key_pair) = key_pair {
        if let Ok(cert) = params.self_signed(&key_pair) {
            let pem_serialized = cert.pem();
            if let Ok(pem) = pem::parse(&pem_serialized) {
                let der_serialized = pem.contents();
                alert("Decoded some data");
            }
        }
    }
    alert("I am groot!");
}
