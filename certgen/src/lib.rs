mod utils;
mod timeout;

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

/// Present this file to the user
fn download_file(d: &web_sys::Document, file: &web_sys::Blob, filename: &str) -> Result<(),()> {
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

fn show(collection: &web_sys::HtmlCollection) {
    let quantity = collection.length();
    for i in 0..quantity {
        let e = collection.get_with_index(i);
        if let Some(e) = e {
            let jsval : wasm_bindgen::JsValue = e.value_of().into();
            let el = web_sys::HtmlElement::try_from(jsval).ok();
            if let Some(el) = el {
                let style = el.style();
                style.set_property("display", "block");
            }
        }
    }
}

fn hide(collection: &web_sys::HtmlCollection) {
    let quantity = collection.length();
    for i in 0..quantity {
        let e = collection.get_with_index(i);
        if let Some(e) = e {
            let jsval : wasm_bindgen::JsValue = e.value_of().into();
            let el = web_sys::HtmlElement::try_from(jsval).ok();
            if let Some(el) = el {
                let style = el.style();
                style.set_property("display", "none");
            }
        }
    }
}

fn do_csr_work(w: &web_sys::Window, d: &web_sys::Document, form: &CsrFormData, params: &rcgen::CertificateParams, signing: cert_common::CertificateSigningMethod) {
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
                        let protected = private_key.encrypt(rng, &form.private_key_password).unwrap();
                        let epki = pkcs8::EncryptedPrivateKeyInfo::from_der(protected.as_bytes()).unwrap();
                        let file = build_file(protected.as_bytes());
                        download_file(&d, &file, "testing.bin");
                    }
                }
            }
            if let Some(button) = get_html_element_by_name(&d, "submit") {
                button.click();
            }
        }
    }
}

fn generate_csr_with_form(w: &web_sys::Window, d: &web_sys::Document, form: &CsrFormData, signing: cert_common::CertificateSigningMethod)
{
    let mut params: rcgen::CertificateParams = Default::default();

    params.distinguished_name = rcgen::DistinguishedName::new();
    if !form.cname.is_empty() {
        params.distinguished_name.push(rcgen::DnType::CommonName, &form.cname);
    }
    if !form.country.is_empty() {
        params.distinguished_name.push(rcgen::DnType::CountryName, &form.country);
    }
    if !form.state.is_empty() {
        params.distinguished_name.push(rcgen::DnType::StateOrProvinceName, &form.state);
    }
    if !form.locality.is_empty() {
        params.distinguished_name.push(rcgen::DnType::LocalityName, &form.locality);
    }
    if !form.organization.is_empty() {
        params.distinguished_name.push(rcgen::DnType::OrganizationName, &form.organization);
    }
    if !form.ou.is_empty() {
        params.distinguished_name.push(rcgen::DnType::OrganizationalUnitName, &form.ou);
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

    show(&loading_form);
    hide(&elements_form);

    do_csr_work(w, d, form, &params, signing);
}

struct CsrFormData {
    name: String,
    email: String,
    phone: String,
    private_key_password: Zeroizing<String>,
    client_id: bool,
    code_usage: bool,
    server_id: bool,
    cname: String,
    country: String,
    state: String,
    locality: String,
    organization: String,
    ou: String,
    cpassword: Zeroizing<String>,
    challenge_name: String,
}

fn validate_form(d: &web_sys::Document) -> Result<CsrFormData, String> {
    let name = get_value_from_input_by_name(&d, "name").ok_or("Missing form value")?;
    let email = get_value_from_input_by_name(&d, "email").ok_or("Missing form value")?;
    let phone = get_value_from_input_by_name(&d, "phone").ok_or("Missing form value")?;
    let private_key_password = get_value_from_input_by_name(&d, "password").ok_or("Missing form value")?;

    let client_id = get_checked_from_input_by_name(&d, "usage-client").ok_or("Missing form value")?;
    let code_usage = get_checked_from_input_by_name(&d, "usage-code").ok_or("Missing form value")?;
    let server_id = get_checked_from_input_by_name(&d, "usage-server").ok_or("Missing form value")?;

    let cname = get_value_from_input_by_name(&d, "cname").ok_or("Missing form value")?;
    let country = get_value_from_input_by_name(&d, "country").ok_or("Missing form value")?;
    let state = get_value_from_input_by_name(&d, "state").ok_or("Missing form value")?;
    let locality = get_value_from_input_by_name(&d, "locality").ok_or("Missing form value")?;
    let organization = get_value_from_input_by_name(&d, "organization").ok_or("Missing form value")?;
    let ou = get_value_from_input_by_name(&d, "organization-unit").ok_or("Missing form value")?;
    let cpassword = get_value_from_input_by_name(&d, "challenge-pass").ok_or("Missing form value")?;
    let challenge_name = get_value_from_input_by_name(&d, "challenge-name").ok_or("Missing form value")?;

    let form = CsrFormData {
        name,
        email,
        phone,
        private_key_password: Zeroizing::new(private_key_password),
        client_id,
        code_usage,
        server_id,
        cname,
        country,
        state,
        locality,
        organization,
        ou,
        cpassword: Zeroizing::new(cpassword),
        challenge_name,
    };

    let mut good_name = false;

    if !form.cname.is_empty() {
        good_name = true;
    }
    if !form.country.is_empty() {
        good_name = true;
    }
    if !form.state.is_empty() {
        good_name = true;
    }
    if !form.locality.is_empty() {
        good_name = true;
    }
    if !form.organization.is_empty() {
        good_name = true;
    }
    if !form.ou.is_empty() {
        good_name = true;
    }
    if !good_name {
        alert("All Certificate Information is blank");
        Err("All certificate information is blank".to_string())
    }
    else {
        Ok(form)
    }
}

#[wasm_bindgen]
pub fn testing() -> timeout::TimeoutHandle1 {
    crate::utils::set_panic_hook();
    wasm_logger::init(wasm_logger::Config::default());
    
    let w = web_sys::window().unwrap();
    let mut d = w.document().unwrap();

    let cb : wasm_bindgen::closure::Closure<dyn FnMut(String)> = wasm_bindgen::closure::Closure::new(|a| {
        log::debug!("Stuff {}", a);
        alert("Stuff");
    });

    let args = js_sys::Array::new();
    args.push(&("asdf".to_string().into()));

    w.set_timeout_with_callback_and_timeout_and_arguments(cb.as_ref().unchecked_ref(), 1, &args);
    timeout::TimeoutHandle1::new(cb)
}

fn generate_csr(signing: cert_common::CertificateSigningMethod) {
    let w = web_sys::window().unwrap();
    let d = w.document().unwrap();

    let form = validate_form(&d);

    match form {
        Ok(form) => generate_csr_with_form(&w, &d, &form, signing),
        Err(e) => log::debug!("{}", e),
    }
}

#[wasm_bindgen]
pub fn generate_csr_rsa_sha256() {
    crate::utils::set_panic_hook();
    wasm_logger::init(wasm_logger::Config::default());

    generate_csr(cert_common::CertificateSigningMethod::RsaSha256);
}
