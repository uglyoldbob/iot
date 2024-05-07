mod utils;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

fn get_value_from_input_by_name(d: &web_sys::Document, name: &str) -> Option<String> {
    if let Some(t1) = d.get_element_by_id(name) {
        let jsval : wasm_bindgen::JsValue = t1.value_of().into();
        if let Ok(hie) = web_sys::HtmlInputElement::try_from(jsval) {
            Some(hie.value())
        }
        else {
            None
        }
    }
    else {
        None
    }
}

#[wasm_bindgen]
pub fn generate_csr_rsa_sha256() {
    let mut params: rcgen::CertificateParams = Default::default();

    let w = web_sys::window().unwrap();
    let d = w.document().unwrap();
    if let Some(t1) = get_value_from_input_by_name(&d, "name") {
        alert(&t1);
    }
    else {
        alert("No name");
    }
    if let Some(t1) = get_value_from_input_by_name(&d, "email") {
        alert(&t1);
    }
    else {
        alert("No email");
    }

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
                alert(&format!("Decoded some data {}", der_serialized.len()));
            }
        }
    }
}
