mod utils;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

/// Present this file to the user
fn download_file(d: &mut web_sys::Document, file: &web_sys::Blob, filename: &str) -> Result<(),()> {
    let anchor = d.create_element("a").map_err(|_|())?;
    let jsval_anchor : wasm_bindgen::JsValue = anchor.value_of().into();
    let anchor : web_sys::HtmlAnchorElement = jsval_anchor.into();
    let url = web_sys::Url::create_object_url_with_blob(file).map_err(|_|())?;
    anchor.set_href(&url);
    anchor.set_download(filename);
    let body = d.body().ok_or(())?;
    let body_node : web_sys::Node = body.into();
    body_node.append_child(&anchor.clone().into());
    anchor.click();
    body_node.remove_child(&anchor.into());
    web_sys::Url::revoke_object_url(&url);
    Ok(())
}

/// Build a file with the specified data
fn build_file(data: &[u8]) -> web_sys::File {
    let mut u8array = js_sys::Uint8Array::new_with_length(data.len() as u32);
    u8array.copy_from(&data);
    let array = js_sys::Array::new();
    array.push(&u8array.buffer());
    let mut foptions = web_sys::FilePropertyBag::new();
    foptions.type_("application/octet-stream");
    let file = web_sys::File::new_with_blob_sequence_and_options(&array, "whatever.bin", &foptions).unwrap();
    file
}

/// Build a file with the specified data
fn build_blob(data: &[u8]) -> web_sys::Blob {
    let mut u8array = js_sys::Uint8Array::new_with_length(data.len() as u32);
    u8array.copy_from(&data);
    let array = js_sys::Array::new();
    array.push(&u8array.buffer());
    let mut foptions = web_sys::BlobPropertyBag::new();
    foptions.type_("application/octet-stream");
    let file = web_sys::Blob::new_with_blob_sequence_and_options(&array, &foptions).unwrap();
    file
}

/// Retrieve an htmlElement by name
fn get_html_element_by_name(d: &web_sys::Document, name: &str) -> Option<web_sys::HtmlElement> {
    if let Some(t1) = d.get_element_by_id(name) {
        let jsval : wasm_bindgen::JsValue = t1.value_of().into();
        web_sys::HtmlElement::try_from(jsval).ok()
    }
    else {
        None
    }
}

/// Retrieve the htmlInputElement specified by name from the given document
fn get_html_input_by_name(d: &web_sys::Document, name: &str) -> Option<web_sys::HtmlInputElement> {
    if let Some(t1) = d.get_element_by_id(name) {
        let jsval : wasm_bindgen::JsValue = t1.value_of().into();
        web_sys::HtmlInputElement::try_from(jsval).ok()
    }
    else {
        None
    }
}

/// Retrieve the htmlInputElement specified by name from the given document, getting the value of what is in the input element
fn get_value_from_input_by_name(d: &web_sys::Document, name: &str) -> Option<String> {
    if let Some(t1) = get_html_input_by_name(d, name) {
        Some(t1.value())
    }
    else {
        None
    }
}

/// Retrieve the htmlInputElement specified by name from the given document, getting the checked value of the input element
fn get_checked_from_input_by_name(d: &web_sys::Document, name: &str) -> Option<bool> {
    if let Some(t1) = get_html_input_by_name(d, name) {
        Some(t1.checked())
    }
    else {
        None
    }
}

fn hide(collection: &web_sys::HtmlCollection) {
    let quantity = collection.length();

}

fn generate_csr(signing: cert_common::CertificateSigningMethod)
{
    let mut params: rcgen::CertificateParams = Default::default();

    let w = web_sys::window().unwrap();
    let mut d = w.document().unwrap();

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

    let elements_form = d.get_elements_by_class_name("cert-gen-stuff");
    let loading_form = d.get_elements_by_class_name("cert_generating");

    if let Some((key_pair, private)) = signing.generate_keypair() {
        if let Ok(cert) = params.serialize_request(&key_pair) {
            if let Ok(pem_serialized) = cert.pem() {
                if let Some(csr) = get_html_input_by_name(&d, "csr") {
                    csr.set_value(&pem_serialized);
                }
                if let Ok(pem) = pem::parse(&pem_serialized) {
                    let der_serialized = pem.contents();
                    if let Some(private) = private {
                        let data: &[u8] = private.as_ref();
                        use der::Decode;
                        let private_key = pkcs8::PrivateKeyInfo::from_der(data).unwrap();
                        let rng = rand::thread_rng();
                        if let Some(private_key_password) = private_key_password {
                            let protected = private_key.encrypt(rng, private_key_password).unwrap();
                            let epki = pkcs8::EncryptedPrivateKeyInfo::from_der(protected.as_bytes()).unwrap();
                            let file = build_file(protected.as_bytes());
                            download_file(&mut d, &file, "testing.bin");
                        }
                    }
                }
            }
            if let Some(button) = get_html_element_by_name(&d, "submit") {
                button.click();
            }
        }
    }
}

#[wasm_bindgen]
pub fn generate_csr_rsa_sha256() {
    crate::utils::set_panic_hook();
    wasm_logger::init(wasm_logger::Config::default());
    generate_csr(cert_common::CertificateSigningMethod::RsaSha256);
}
