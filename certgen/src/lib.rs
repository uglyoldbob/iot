mod utils;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

fn get_html_input_by_name(d: &web_sys::Document, name: &str) -> Option<web_sys::HtmlInputElement> {
    if let Some(t1) = d.get_element_by_id(name) {
        let jsval : wasm_bindgen::JsValue = t1.value_of().into();
        web_sys::HtmlInputElement::try_from(jsval).ok()
    }
    else {
        None
    }
}

fn get_value_from_input_by_name(d: &web_sys::Document, name: &str) -> Option<String> {
    if let Some(t1) = get_html_input_by_name(d, name) {
        Some(t1.value())
    }
    else {
        None
    }
}

fn get_checked_from_input_by_name(d: &web_sys::Document, name: &str) -> Option<bool> {
    if let Some(t1) = get_html_input_by_name(d, name) {
        Some(t1.checked())
    }
    else {
        None
    }
}

#[wasm_bindgen]
pub fn generate_csr_rsa_sha256() {
    crate::utils::set_panic_hook();
    let mut params: rcgen::CertificateParams = Default::default();

    let w = web_sys::window().unwrap();
    let d = w.document().unwrap();
    let name = get_value_from_input_by_name(&d, "name");
    let email = get_value_from_input_by_name(&d, "email");
    let phone = get_value_from_input_by_name(&d, "phone");
    let private_key_password = get_value_from_input_by_name(&d, "password");

    let client_id = get_checked_from_input_by_name(&d, "usage-client");
    let code_usage = get_checked_from_input_by_name(&d, "usage-code");
    let server_id = get_checked_from_input_by_name(&d, "usage-server");

    let cname = get_value_from_input_by_name(&d, "cname");
    let country = get_value_from_input_by_name(&d, "country");
    let state = get_value_from_input_by_name(&d, "state");
    let locality = get_value_from_input_by_name(&d, "locality");
    let organization = get_value_from_input_by_name(&d, "organization");
    let ou = get_value_from_input_by_name(&d, "organization-unit");
    let cpassword = get_value_from_input_by_name(&d, "challenge-pass");
    let challenge_name = get_value_from_input_by_name(&d, "challenge-name");

    let mut good_name = false;

    params.distinguished_name = rcgen::DistinguishedName::new();
    if let Some(cname) = cname {
        if !cname.is_empty() {
            good_name = true;
            params.distinguished_name.push(rcgen::DnType::CommonName, cname);
        }
    }
    if let Some(country) = country {
        if !country.is_empty() {
            good_name = true;
            params.distinguished_name.push(rcgen::DnType::CountryName, country);
        }
    }
    if let Some(state) = state {
        if !state.is_empty() {
            good_name = true;
            params.distinguished_name.push(rcgen::DnType::StateOrProvinceName, state);
        }
    }
    if let Some(locality) = locality {
        if !locality.is_empty() {
            good_name = true;
            params.distinguished_name.push(rcgen::DnType::LocalityName, locality);
        }
    }
    if let Some(organization) = organization {
        if !organization.is_empty() {
            good_name = true;
            params.distinguished_name.push(rcgen::DnType::OrganizationName, organization);
        }
    }
    if let Some(ou) = ou {
        if !ou.is_empty() {
            good_name = true;
            params.distinguished_name.push(rcgen::DnType::OrganizationalUnitName, ou);
        }
    }

    // These values are ignored
    params.not_before = rcgen::date_time_ymd(1975, 1, 1);
    params.not_after = rcgen::date_time_ymd(4096, 1, 1);

    //TODO implement these items
    /*
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("crabs.crabs".try_into().unwrap()),
        rcgen::SanType::DnsName("localhost".try_into().unwrap()),
    ];
    */
    let signing = cert_common::CertificateSigningMethod::RsaSha256;
    if let Some((key_pair, private)) = signing.generate_keypair() {
        if let Ok(cert) = params.self_signed(&key_pair) {
            let pem_serialized = cert.pem();
            if let Ok(pem) = pem::parse(&pem_serialized) {
                let der_serialized = pem.contents();
                alert(&format!("Decoded some data {}", der_serialized.len()));
            }
        }
    }
}
