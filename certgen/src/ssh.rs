//! Code for handling ssh certificate generation on the client side

use crate::timeout;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen]
/// The elements needed to build an ssh certificate
pub struct SshWork {
    /// the password to protect the private key
    private_key_password: Zeroizing<String>,
    /// the method to sign the certificate with
    signing: cert_common::SshSigningMethod,
}

/// The data entered by the user for submitting a certificate signing request
struct SshFormData {
    /// The password to protect the private key
    private_key_password: Zeroizing<String>,
    /// How the certificate will be used
    use_type: String,
}

/// Do the work required to build a certificate request
fn do_ssh_work(work: SshWork) {
    let SshWork {
        private_key_password,
        signing,
    } = work;

    let w = web_sys::window().unwrap();
    let d = w.document().unwrap();

    if let Some(key) = signing.generate_keypair(4096) {
        let public_key = key.public_key();

        let p = public_key.to_openssh().unwrap();
        let file = crate::build_file(p.as_bytes());
        let _ = crate::download_file(&d, &file, "ssh.pub");

        let pkey = key
            .encrypt(&mut rand::thread_rng(), private_key_password)
            .unwrap();
        let file2 = crate::build_file(pkey.to_bytes().unwrap().as_ref());
        let _ = crate::download_file(&d, &file2, "ssh");
        if let Some(button) = crate::get_html_element_by_name(&d, "submit") {
            button.click();
        }
    }
}

/// Parse data gathered from the web page form, building an SshWork struct to be processed.
fn generate_ssh_with_form(
    w: &web_sys::Window,
    d: &web_sys::Document,
    form: SshFormData,
    signing: cert_common::SshSigningMethod,
) -> timeout::TimeoutHandleSshWork {
    let SshFormData {
        private_key_password,
        use_type,
    } = form;

    let _use_type: u32 = use_type.parse().unwrap();
    let elements_form = d.get_elements_by_class_name("cert-gen-stuff");
    let loading_form = d.get_elements_by_class_name("cert_generating");

    crate::show(&loading_form);
    crate::hide(&elements_form);

    let work = SshWork {
        private_key_password,
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

    let _comment = crate::get_value_from_input_by_name(d, "comment").ok_or("Missing form value")?;

    let use_type =
        crate::get_value_from_input_by_name(d, "usage-type").ok_or("Missing form value")?;

    let principals =
        crate::get_value_from_input_by_name(d, "principals").ok_or("Missing form value")?;

    let _cpassword =
        crate::get_value_from_input_by_name(d, "challenge-pass").ok_or("Missing form value")?;
    let _challenge_name =
        crate::get_value_from_input_by_name(d, "challenge-name").ok_or("Missing form value")?;

    let mut good_name = false;

    if !principals.is_empty() {
        good_name = true;
    }

    let form = SshFormData {
        private_key_password: Zeroizing::new(private_key_password),
        use_type,
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
