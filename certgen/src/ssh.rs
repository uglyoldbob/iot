//! Code for handling ssh certificate generation on the client side

use crate::timeout;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[derive(Default)]
/// The parameters needed to build an ssh certificate
pub struct SshParams {}

#[wasm_bindgen]
/// The elements needed to build an ssh certificate
pub struct SshWork {
    /// the password to protect the private key
    private_key_password: Zeroizing<String>,
    /// the parameters to generate the certificate
    params: SshParams,
    /// the method to sign the certificate with
    signing: cert_common::SshSigningMethod,
}

/// The data entered by the user for submitting a certificate signing request
struct SshFormData {
    /// The password to protect the private key
    private_key_password: Zeroizing<String>,
    /// The certificate will be used to identify a client
    client_id: bool,
    /// The certificate will be used to sign code
    code_usage: bool,
    /// The certificate will be used to identify a server
    server_id: bool,
    /// cname of the certificate
    cname: String,
    /// Country field for the certificate
    country: String,
    /// State field for the certificate
    state: String,
    /// Locality field for the certificate
    locality: String,
    /// organization field for the certificate
    organization: String,
    /// organization unit fiedl for the certificate
    ou: String,
    /// the challenge password for the certificate request
    cpassword: Zeroizing<String>,
    /// the challenge name for the certificate request
    challenge_name: String,
}

/// Do the work required to build a certificate request
fn do_ssh_work(work: SshWork) {
    let SshWork {
        private_key_password,
        params,
        signing,
    } = work;

    let w = web_sys::window().unwrap();
    let d = w.document().unwrap();

    if let Some(keypair) = signing.generate_keypair(4096) {
        todo!();
    }
}

/// Parse data gathered from the web page form, building an SshWork struct to be processed.
fn generate_ssh_with_form(
    w: &web_sys::Window,
    d: &web_sys::Document,
    form: SshFormData,
    signing: cert_common::SshSigningMethod,
) -> timeout::TimeoutHandleSshWork {
    let mut params: SshParams = Default::default();

    let SshFormData {
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

    //TODO fill out the params

    let elements_form = d.get_elements_by_class_name("cert-gen-stuff");
    let loading_form = d.get_elements_by_class_name("cert_generating");

    crate::show(&loading_form);
    crate::hide(&elements_form);

    let work = SshWork {
        private_key_password,
        params,
        signing,
    };

    let cb: wasm_bindgen::closure::Closure<dyn FnMut(SshWork)> =
        wasm_bindgen::closure::Closure::new(|w| {
            do_ssh_work(w);
        });

    let args = js_sys::Array::new();
    args.push(&(work.into()));

    let _ = w.set_timeout_with_callback_and_timeout_and_arguments(
        cb.as_ref().unchecked_ref(),
        1,
        &args,
    );
    timeout::TimeoutHandleSshWork::new(cb)
}

/// Validate the contents of the form submitted by the user for ssh
fn validate_ssh_form(d: &web_sys::Document) -> Result<SshFormData, String> {
    let name = crate::get_value_from_input_by_name(d, "name").ok_or("Missing form value")?;
    let email = crate::get_value_from_input_by_name(d, "email").ok_or("Missing form value")?;
    let phone = crate::get_value_from_input_by_name(d, "phone").ok_or("Missing form value")?;

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
        crate::get_value_from_input_by_name(d, "password").ok_or("Missing form value")?;

    let client_id =
        crate::get_checked_from_input_by_name(d, "usage-client").ok_or("Missing form value")?;
    let code_usage =
        crate::get_checked_from_input_by_name(d, "usage-code").ok_or("Missing form value")?;
    let server_id =
        crate::get_checked_from_input_by_name(d, "usage-server").ok_or("Missing form value")?;

    let cname = crate::get_value_from_input_by_name(d, "cname").ok_or("Missing form value")?;
    let country = crate::get_value_from_input_by_name(d, "country").ok_or("Missing form value")?;
    let state = crate::get_value_from_input_by_name(d, "state").ok_or("Missing form value")?;
    let locality =
        crate::get_value_from_input_by_name(d, "locality").ok_or("Missing form value")?;
    let organization =
        crate::get_value_from_input_by_name(d, "organization").ok_or("Missing form value")?;
    let ou =
        crate::get_value_from_input_by_name(d, "organization-unit").ok_or("Missing form value")?;
    let cpassword =
        crate::get_value_from_input_by_name(d, "challenge-pass").ok_or("Missing form value")?;
    let challenge_name =
        crate::get_value_from_input_by_name(d, "challenge-name").ok_or("Missing form value")?;

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

    let form = SshFormData {
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
        crate::alert("All Certificate Information is blank");
        Err("All certificate information is blank".to_string())
    } else {
        Ok(form)
    }
}

/// Generate an ssh certificate of the type specified
fn generate_ssh(signing: cert_common::SshSigningMethod) -> Option<timeout::TimeoutHandleSshWork> {
    let w = web_sys::window().unwrap();
    let d = w.document().unwrap();

    let form = validate_ssh_form(&d);

    match form {
        Ok(form) => Some(generate_ssh_with_form(&w, &d, form, signing)),
        Err(e) => {
            log::debug!("{}", e);
            None
        }
    }
}

#[wasm_bindgen]
/// Generates a request for an ssh rsa certificate
pub fn generate_ssh_rsa() -> Option<timeout::TimeoutHandleSshWork> {
    crate::utils::set_panic_hook();
    wasm_logger::init(wasm_logger::Config::default());
    generate_ssh(cert_common::SshSigningMethod::Rsa)
}

#[wasm_bindgen]
/// Generates a request for an ssh ed25519 certificate
pub fn generate_ed25519_rsa() -> Option<timeout::TimeoutHandleSshWork> {
    crate::utils::set_panic_hook();
    wasm_logger::init(wasm_logger::Config::default());
    generate_ssh(cert_common::SshSigningMethod::Ed25519)
}
