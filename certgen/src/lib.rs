mod timeout;
mod utils;

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn show_advanced() {
    let w = web_sys::window().unwrap();
    let d = w.document().unwrap();
    let advanced = d.get_elements_by_class_name("advanced");
    let regular = d.get_elements_by_class_name("regular");
    show(&advanced);
    hide(&regular);
}

#[wasm_bindgen]
pub fn show_regular() {
    let w = web_sys::window().unwrap();
    let d = w.document().unwrap();
    let advanced = d.get_elements_by_class_name("advanced");
    let regular = d.get_elements_by_class_name("regular");
    hide(&advanced);
    show(&regular);
}

/// Present this file to the user
fn download_file(d: &web_sys::Document, file: &web_sys::Blob, filename: &str) -> Result<(), ()> {
    let anchor = d.create_element("a").map_err(|_| ())?;
    let jsval_anchor: wasm_bindgen::JsValue = anchor.value_of().into();
    let anchor: web_sys::HtmlAnchorElement = jsval_anchor.into();
    let url = web_sys::Url::create_object_url_with_blob(file).map_err(|_| ())?;
    anchor.set_href(&url);
    anchor.set_download(filename);
    let body = d.body().ok_or(())?;
    let body_node: web_sys::Node = body.into();
    body_node.append_child(&anchor.clone().into());
    anchor.click();
    body_node.remove_child(&anchor.into());
    web_sys::Url::revoke_object_url(&url);
    Ok(())
}

/// Build a file with the specified data
fn build_file(data: &[u8]) -> web_sys::File {
    let u8array = js_sys::Uint8Array::new_with_length(data.len() as u32);
    u8array.copy_from(&data);
    let array = js_sys::Array::new();
    array.push(&u8array.buffer());
    let mut foptions = web_sys::FilePropertyBag::new();
    foptions.type_("application/octet-stream");
    let file = web_sys::File::new_with_blob_sequence_and_options(&array, "whatever.bin", &foptions)
        .unwrap();
    file
}

/// Build a file with the specified data
fn build_blob(data: &[u8]) -> web_sys::Blob {
    let u8array = js_sys::Uint8Array::new_with_length(data.len() as u32);
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
        let jsval: wasm_bindgen::JsValue = t1.value_of().into();
        web_sys::HtmlElement::try_from(jsval).ok()
    } else {
        None
    }
}

/// Retrieve the htmlInputElement specified by name from the given document
fn get_html_input_by_name(d: &web_sys::Document, name: &str) -> Option<web_sys::HtmlInputElement> {
    if let Some(t1) = d.get_element_by_id(name) {
        let jsval: wasm_bindgen::JsValue = t1.value_of().into();
        web_sys::HtmlInputElement::try_from(jsval).ok()
    } else {
        None
    }
}

/// Retrieve the htmlElement specified by name from the given document, getting the value of what is in the input element
fn get_value_from_element_by_name(d: &web_sys::Document, name: &str) -> Option<String> {
    if let Some(t1) = get_html_element_by_name(d, name) {
        Some(t1.inner_text())
    } else {
        None
    }
}

/// Retrieve the htmlInputElement specified by name from the given document, getting the value of what is in the input element
fn get_value_from_input_by_name(d: &web_sys::Document, name: &str) -> Option<String> {
    if let Some(t1) = get_html_input_by_name(d, name) {
        Some(t1.value())
    } else {
        None
    }
}

/// Retrieve the htmlInputElement specified by name from the given document, getting the checked value of the input element
fn get_checked_from_input_by_name(d: &web_sys::Document, name: &str) -> Option<bool> {
    if let Some(t1) = get_html_input_by_name(d, name) {
        Some(t1.checked())
    } else {
        None
    }
}

fn show(collection: &web_sys::HtmlCollection) {
    let quantity = collection.length();
    for i in 0..quantity {
        let e = collection.get_with_index(i);
        if let Some(e) = e {
            let jsval: wasm_bindgen::JsValue = e.value_of().into();
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
            let jsval: wasm_bindgen::JsValue = e.value_of().into();
            let el = web_sys::HtmlElement::try_from(jsval).ok();
            if let Some(el) = el {
                let style = el.style();
                style.set_property("display", "none");
            }
        }
    }
}

#[wasm_bindgen]
pub struct CsrWork {
    private_key_password: Zeroizing<String>,
    params: rcgen::CertificateParams,
    signing: cert_common::HttpsSigningMethod,
}

fn do_csr_work(work: CsrWork) {
    let CsrWork {
        private_key_password,
        params,
        signing,
    } = work;

    let w = web_sys::window().unwrap();
    let d = w.document().unwrap();

    if let Some((key_pair, private)) = signing.generate_keypair(4096) {
        if let Ok(cert) = params.serialize_request(&key_pair) {
            if let Ok(pem_serialized) = cert.pem() {
                if let Some(csr) = get_html_input_by_name(&d, "csr") {
                    csr.set_value(&pem_serialized);
                }
                if let Some(private) = private {
                    let data: &[u8] = private.as_ref();
                    use der::Decode;
                    let private_key = pkcs8::PrivateKeyInfo::from_der(data).unwrap();
                    let rng = rand::thread_rng();
                    let protected = private_key.encrypt(rng, &private_key_password).unwrap();
                    let file = build_file(protected.as_bytes());
                    download_file(&d, &file, "testing.bin");
                }
            }
            if let Some(button) = get_html_element_by_name(&d, "submit") {
                button.click();
            }
        }
    }
}

fn generate_csr_with_form(
    w: &web_sys::Window,
    d: &web_sys::Document,
    form: CsrFormData,
    signing: cert_common::HttpsSigningMethod,
) -> timeout::TimeoutHandleCsrWork {
    let mut params: rcgen::CertificateParams = Default::default();

    let CsrFormData {
        private_key_password,
        client_id,
        code_usage,
        server_id,
        cname,
        country,
        state,
        locality,
        organization,
        ou,
        cpassword,
        challenge_name,
    } = form;

    params.distinguished_name = rcgen::DistinguishedName::new();
    if !cname.is_empty() {
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, &cname);
    }
    if !country.is_empty() {
        params
            .distinguished_name
            .push(rcgen::DnType::CountryName, &country);
    }
    if !state.is_empty() {
        params
            .distinguished_name
            .push(rcgen::DnType::StateOrProvinceName, &state);
    }
    if !locality.is_empty() {
        params
            .distinguished_name
            .push(rcgen::DnType::LocalityName, &locality);
    }
    if !organization.is_empty() {
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, &organization);
    }
    if !ou.is_empty() {
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationalUnitName, &ou);
    }

    // These values are ignored
    params.not_before = rcgen::date_time_ymd(1975, 1, 1);
    params.not_after = rcgen::date_time_ymd(4096, 1, 1);

    if client_id {
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    }
    if code_usage {
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::CodeSigning);
    }
    if server_id {
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    }

    if !cpassword.is_empty() {
        let s: &String = &cpassword;
        let attr = cert_common::CsrAttribute::ChallengePassword(s.to_owned());
        if let Some(a) = attr.to_custom_attribute() {
            params.extra_attributes.push(a);
        }
    }
    if !challenge_name.is_empty() {
        let attr = cert_common::CsrAttribute::UnstructuredName(challenge_name);
        if let Some(a) = attr.to_custom_attribute() {
            params.extra_attributes.push(a);
        }
    }

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

    let work = CsrWork {
        private_key_password,
        params,
        signing,
    };

    let cb: wasm_bindgen::closure::Closure<dyn FnMut(CsrWork)> =
        wasm_bindgen::closure::Closure::new(|w| {
            do_csr_work(w);
        });

    let args = js_sys::Array::new();
    args.push(&(work.into()));

    w.set_timeout_with_callback_and_timeout_and_arguments(cb.as_ref().unchecked_ref(), 1, &args);
    timeout::TimeoutHandleCsrWork::new(cb)
}

struct CsrFormData {
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

    if name.is_empty() {
        return Err("Name is empty".to_string());
    }
    if email.is_empty() {
        return Err("Email is empty".to_string());
    }
    if phone.is_empty() {
        return Err("Phone is empty".to_string());
    }

    let private_key_password =
        get_value_from_input_by_name(&d, "password").ok_or("Missing form value")?;

    let client_id =
        get_checked_from_input_by_name(&d, "usage-client").ok_or("Missing form value")?;
    let code_usage =
        get_checked_from_input_by_name(&d, "usage-code").ok_or("Missing form value")?;
    let server_id =
        get_checked_from_input_by_name(&d, "usage-server").ok_or("Missing form value")?;

    let cname = get_value_from_input_by_name(&d, "cname").ok_or("Missing form value")?;
    let country = get_value_from_input_by_name(&d, "country").ok_or("Missing form value")?;
    let state = get_value_from_input_by_name(&d, "state").ok_or("Missing form value")?;
    let locality = get_value_from_input_by_name(&d, "locality").ok_or("Missing form value")?;
    let organization =
        get_value_from_input_by_name(&d, "organization").ok_or("Missing form value")?;
    let ou = get_value_from_input_by_name(&d, "organization-unit").ok_or("Missing form value")?;
    let cpassword =
        get_value_from_input_by_name(&d, "challenge-pass").ok_or("Missing form value")?;
    let challenge_name =
        get_value_from_input_by_name(&d, "challenge-name").ok_or("Missing form value")?;

    let mut good_name = false;

    if !cname.is_empty() {
        good_name = true;
    }
    if !country.is_empty() {
        good_name = true;
    }
    if !state.is_empty() {
        good_name = true;
    }
    if !locality.is_empty() {
        good_name = true;
    }
    if !organization.is_empty() {
        good_name = true;
    }
    if !ou.is_empty() {
        good_name = true;
    }

    let form = CsrFormData {
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

    if !good_name {
        alert("All Certificate Information is blank");
        Err("All certificate information is blank".to_string())
    } else {
        Ok(form)
    }
}

fn generate_csr(
    signing: cert_common::HttpsSigningMethod,
) -> Option<timeout::TimeoutHandleCsrWork> {
    let w = web_sys::window().unwrap();
    let d = w.document().unwrap();

    let form = validate_form(&d);

    match form {
        Ok(form) => Some(generate_csr_with_form(&w, &d, form, signing)),
        Err(e) => {
            log::debug!("{}", e);
            None
        }
    }
}

#[wasm_bindgen]
pub fn generate_csr_rsa_sha256() -> Option<timeout::TimeoutHandleCsrWork> {
    crate::utils::set_panic_hook();
    wasm_logger::init(wasm_logger::Config::default());
    generate_csr(cert_common::HttpsSigningMethod::RsaSha256)
}

#[wasm_bindgen]
pub fn generate_csr_ecdsa_sha256() -> Option<timeout::TimeoutHandleCsrWork> {
    crate::utils::set_panic_hook();
    wasm_logger::init(wasm_logger::Config::default());
    generate_csr(cert_common::HttpsSigningMethod::EcdsaSha256)
}

/// Retrieve the contents of the specified file in a nice Vec<u8>, if possible.
async fn get_file_contents(file: web_sys::File) -> Option<Vec<u8>> {
    let r = file
        .stream()
        .get_reader()
        .dyn_into::<web_sys::ReadableStreamDefaultReader>();
    if let Ok(r) = r {
        let mut data: Vec<u8> = Vec::new();
        loop {
            let chunk = wasm_bindgen_futures::JsFuture::from(r.read()).await;
            if let Ok(c) = chunk {
                let obj = js_sys::Object::try_from(&c).unwrap();
                let entries = js_sys::Object::entries(&obj);
                let a1 = entries.get(0);
                let a2 = entries.get(1);
                let a1 = js_sys::Array::try_from(a1).unwrap();
                let a2 = js_sys::Array::try_from(a2).unwrap();
                let a1a = a1.get(0);
                let a1b = a1.get(1);
                if let Some(s) = a1a.as_string() {
                    if s.as_str() == "done" {
                        if a1b.as_bool().unwrap() {
                            break;
                        }
                    }
                }
                let a2a = a2.get(0);
                let a2b = a2.get(1);
                if let Some(s) = a2a.as_string() {
                    if s.as_str() == "value" {
                        let chunk = js_sys::Uint8Array::try_from(a2b).unwrap();
                        let data_len = data.len();
                        data.resize(data_len + chunk.length() as usize, 0);
                        chunk.copy_to(&mut data[data_len..]);
                    }
                }
            }
        }
        Some(data)
    } else {
        None
    }
}

#[wasm_bindgen]
pub fn build_cert() {
    crate::utils::set_panic_hook();
    wasm_logger::init(wasm_logger::Config::default());
    let w = web_sys::window().unwrap();
    let d = w.document().unwrap();

    let private_key_password =
        get_value_from_input_by_name(&d, "password").ok_or("Missing form value");

    let certificate_password =
        get_value_from_input_by_name(&d, "cert-password").ok_or("Missing form value");

    let cert_url = get_value_from_element_by_name(&d, "get_request");
    log::debug!("Url is {:?}", cert_url);

    if let Some(button) = get_html_input_by_name(&d, "file-selector") {
        button.click();

        let button2 = button.clone();
        let cb = cert_common::WasmClosureAsync!({
            let files = button2.files();
            if let Some(f) = files {
                if let Some(file) = f.item(0) {
                    if let Some(url) = cert_url {
                        let mut ri = web_sys::RequestInit::new();
                        ri.method("get");
                        ri.mode(web_sys::RequestMode::NoCors);
                        ri.referrer_policy(web_sys::ReferrerPolicy::NoReferrer);
                        let cert_fetch = w.fetch_with_str_and_init(&url, &ri);
                        let cert_a = wasm_bindgen_futures::JsFuture::from(cert_fetch);
                        let cert = cert_a.await.unwrap();
                        let rsp = web_sys::Response::try_from(cert).unwrap();
                        let tp = rsp.text().unwrap();
                        let tp_a = wasm_bindgen_futures::JsFuture::from(tp);
                        let t = tp_a.await.unwrap();
                        let cert_pem = t.as_string().unwrap();
                        log::debug!("The cert is {}", cert_pem);
                        let pem = pem::parse(cert_pem).unwrap();
                        if let Some(doc) = get_file_contents(file).await {
                            let secret = pkcs8::EncryptedPrivateKeyInfo::try_from(doc.as_ref());
                            if let Ok(secret) = secret {
                                if let Ok(password) = private_key_password {
                                    let sd = secret.decrypt(password);
                                    if let Ok(sd) = sd {
                                        let pri_key =
                                            pkcs8::PrivateKeyInfo::try_from(sd.as_bytes()).unwrap();
                                        log::debug!("Decoded the key {:02x?}", pri_key);
                                        let pkcs12 = cert_common::pkcs12::Pkcs12 {
                                            cert: pem.into_contents(),
                                            pkey: Zeroizing::new(sd.as_bytes().to_vec()),
                                            attributes: vec![
                                                cert_common::pkcs12::BagAttribute::LocalKeyId(
                                                    vec![42; 16],
                                                ), //TODO
                                                cert_common::pkcs12::BagAttribute::FriendlyName(
                                                    "User Certificate".to_string(),
                                                ), //TODO
                                            ],
                                            id: 42,
                                        };
                                        let p12 = pkcs12.get_pkcs12(&certificate_password.unwrap());
                                        let file = build_file(&p12);
                                        download_file(&d, &file, "certificate.p12");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let cref = cb.as_ref().borrow();
        let c2 = cref.as_ref().unwrap();
        let func: &js_sys::Function = c2.as_ref().unchecked_ref();

        let mut options = web_sys::AddEventListenerOptions::new();
        options.once(true);
        button.add_event_listener_with_callback_and_add_event_listener_options(
            "change", func, &options,
        );
    }
}
