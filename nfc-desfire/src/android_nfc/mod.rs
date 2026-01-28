use ::jni::objects::GlobalRef;
use ::jni::sys::_jobject;
#[cfg(target_os = "android")]
use egui_winit::winit;
use jni_min_helper::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use winit::platform::android::activity::AndroidApp;

pub enum RegistrationStep {
    GotUrl(String),
    CheckCertificate(String),
    CreatingCsr,
    SubmitCsr(String, String, Vec<u8>),
    WaitingForApproval(String),
    AlreadyRegistered,
}

lazy_static::lazy_static! {
    pub static ref NxpNfcInstance : Arc<Mutex<Option<NxpNfcLib>>> = Arc::new(Mutex::new(None));
    pub static ref Application : Arc<Mutex<Option<AndroidApp>>> = Arc::new(Mutex::new(None));
    pub static ref RegisterData : Arc<Mutex<Option<RegistrationStep>>> = Arc::new(Mutex::new(None));
}

fn get_context<'a>() -> Result<jni::objects::JObject<'a>, std::io::Error> {
    let mut ac = Application.lock().unwrap();
    let ac: Option<&mut AndroidApp> = ac.as_mut();
    if let Some(ac) = ac {
        let context = unsafe {
            jni::objects::JObject::from_raw(ac.activity_as_ptr() as *mut jni::sys::_jobject)
        };
        Ok(context)
    } else {
        Err(std::io::Error::other("Context not created yet"))
    }
}

pub fn start_registration(url: String) {
    let mut rd = RegisterData.lock().unwrap();
    rd.replace(RegistrationStep::GotUrl(url));
}

fn generate_keypair() -> (rcgen::KeyPair, zeroize::Zeroizing<Vec<u8>>) {
    use pkcs8::EncodePrivateKey;
    use rand::rngs::OsRng;
    let mut rng = OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 4096).unwrap();
    let private_key_der = private_key.to_pkcs8_der().unwrap();
    let pkey = zeroize::Zeroizing::new(private_key_der.as_bytes().to_vec());
    let key_pair = rcgen::KeyPair::try_from(private_key_der.as_bytes()).unwrap();
    (key_pair, pkey)
}

fn generate_csr(action: String) {
    let name = "Test name 1";
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = params.not_before + time::Duration::days(30);
    //params.custom_extensions.append(&mut extensions);
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut rng = OsRng;
    let mut sn = [0u8; 20];
    rng.fill_bytes(&mut sn);
    let keypair = generate_keypair();
    let req = params
        .serialize_request(&keypair.0)
        .expect("Failed to generate csr");
    //req.params.serial_number = Some(rcgen::SerialNumber::from_slice(&sn));
    let der = req.pem().expect("Failed to build pem for csr");
    let mut rd = RegisterData.lock().unwrap();
    rd.replace(RegistrationStep::SubmitCsr(action, der, keypair.1.to_vec()));
}

/// Decode a hex string to a vec of bytes
pub fn decode_hex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// Encode a vec of bytes to a hex string with no separators
pub fn encode_hex(d: &[u8]) -> String {
    let serhex: Vec<String> = d.iter().map(|e| format!("{:02x}", e)).collect();
    serhex.join("")
}

pub fn get_client(app: &super::DemoApp) -> Option<reqwest::blocking::Client> {
    if let Ok(settings) = &app.settings {
        if let Some(id) = settings.get_identity() {
            let client = reqwest::blocking::ClientBuilder::new().identity(id);
            if let Ok(client) = client
                .danger_accept_invalid_hostnames(true)
                .use_rustls_tls()
                .build()
            {
                return Some(client);
            }
        }
    }
    None
}

pub fn handle_register(app: &mut super::DemoApp, ui: &mut eframe::egui::Ui) -> bool {
    let mut rd = RegisterData.lock().unwrap();
    let rd = rd.as_mut();
    if let Some(a) = rd {
        match a {
            RegistrationStep::GotUrl(b) => {
                let mut save_config = false;
                if let Some(c) = b.strip_prefix("registerscheme://") {
                    let c2 = c.to_owned();
                    log::error!("Need to register with {c}");
                    *a = RegistrationStep::CheckCertificate(c.to_string());
                    let settings = app.settings.as_mut().expect("No settings found");
                    settings.server_url.replace(c2);
                    save_config = true;
                }
                if save_config {
                    app.save_config().expect("Failed to save config");
                }
            }
            RegistrationStep::CheckCertificate(action) => {
                let settings = app.settings.as_mut().expect("No settings found");
                let action2 = action.to_owned();
                log::error!("Checking for certificate and csr");
                if settings.get_cert().is_none() {
                    if settings.csr_der.is_none() {
                        std::thread::spawn(|| {
                            generate_csr(action2);
                        });
                        *a = RegistrationStep::CreatingCsr;
                    } else {
                        *a = RegistrationStep::WaitingForApproval(action.clone());
                    }
                } else {
                    *a = RegistrationStep::AlreadyRegistered;
                }
            }
            RegistrationStep::CreatingCsr => {
                ui.label("Creating CSR. This will take a while.");
            }
            RegistrationStep::SubmitCsr(url, csr, pkey) => {
                ui.label(format!("Need to submit generated csr {csr:x?}"));
                let settings = app.settings.as_mut().expect("No settings found");
                settings.cert_keypair.replace(pkey.to_owned());
                let client = reqwest::blocking::ClientBuilder::new();
                if let Ok(client) = client
                    .danger_accept_invalid_hostnames(true)
                    .use_rustls_tls()
                    .build()
                {
                    let mut form = HashMap::new();
                    form.insert("csr", csr.to_owned());
                    form.insert("name", "Android User".to_string());
                    form.insert("email", "test@example.com".to_string());
                    form.insert("phone", "867-5309".to_string());
                    form.insert("smartcard", "1".to_string());
                    settings.csr_der.replace(csr.to_owned());
                    let res = client
                        .post(format!("https://{}?action=register_android", url))
                        .form(&form)
                        .send();
                    log::error!("The submission result is {:?}", res);
                    if let Ok(r) = res {
                        let b = r.bytes().expect("Unable to read response").to_vec();
                        if let Ok(d) = String::from_utf8(b) {
                            log::error!("Response is {d}");
                            let h = url_encoded_data::UrlEncodedData::parse_str(&d);
                            let serial = h.get("serial");
                            if let Some(serial) = serial {
                                if let Some(serial) = serial.first() {
                                    if let Ok(serial) = decode_hex(serial) {
                                        log::error!("The serial is {:02x?}", serial);
                                        settings.cert_serial.replace(serial);
                                    }
                                }
                            }
                        }
                    }
                    *a = RegistrationStep::WaitingForApproval(url.clone());
                }
                app.save_config().expect("Failed to save config");
            }
            RegistrationStep::WaitingForApproval(action) => {
                let action2 = action.to_owned();
                let mut save_config = false;
                let settings = app.settings.as_mut().expect("No settings found");
                if ui.button("Delete CSR").clicked() {
                    settings.csr_der.take();
                    *a = RegistrationStep::CheckCertificate(action2.clone());
                }
                if let Some(serial) = &settings.cert_serial {
                    if ui.button("Check status").clicked() {
                        let url = format!(
                            "https://{}&action=register_android&check=1&type=pem&serial={}",
                            action2,
                            encode_hex(serial)
                        );
                        let client = reqwest::blocking::ClientBuilder::new();
                        if let Ok(client) = client
                            .danger_accept_invalid_hostnames(true)
                            .use_rustls_tls()
                            .build()
                        {
                            let res = client.get(url).send();
                            log::error!("Check returned {res:?}");
                            if let Ok(r) = res {
                                if let Ok(data) = r.bytes() {
                                    let data = data.to_vec();
                                    if let Ok(s) = str::from_utf8(&data) {
                                        log::error!("Status is {s}");
                                        let cert = s.to_string();
                                        settings.certificate.replace(cert);
                                        *a = RegistrationStep::AlreadyRegistered;
                                        save_config = true;
                                    }
                                }
                            }
                        }
                    }
                }
                ui.label(format!(
                    "Waiting for approval of login details: cert serial {0:x?}",
                    settings.cert_serial
                ));
                if save_config {
                    app.save_config().expect("Failed to save config");
                }
            }
            RegistrationStep::AlreadyRegistered => {
                ui.label("Currently registered");
            }
        }
        true
    } else {
        false
    }
}

/// Maps unexpected JNI errors to `std::io::Error`.
/// (`From<jni::errors::Error>` cannot be implemented for `std::io::Error`
/// here because of the orphan rule). Side effect: `jni_last_cleared_ex()`.
#[inline(always)]
pub(crate) fn jerr(env: &mut jni::JNIEnv, err: jni::errors::Error) -> std::io::Error {
    use ::jni::errors::Error::*;
    if let JavaException = err {
        let err = jni_min_helper::jni_clear_ex(err);
        jni_min_helper::jni_last_cleared_ex()
            .ok_or(JavaException)
            .and_then(|ex| Ok((ex.get_class_name(env)?, ex.get_throwable_msg(env)?)))
            .map(|(cls, msg)| {
                if cls.contains("SecurityException") {
                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg)
                } else if cls.contains("IllegalArgumentException") {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
                } else {
                    std::io::Error::other(format!("{cls}: {msg}"))
                }
            })
            .unwrap_or(std::io::Error::other(err))
    } else {
        std::io::Error::other(err)
    }
}

fn get_class<'a, 'b>(
    env: &'a mut jni::JNIEnv<'b>,
    context: jni::objects::JObject,
    name: &str,
) -> Result<jni::objects::JClass<'b>, std::io::Error> {
    let context2 = unsafe { jni::objects::JObject::from_raw(context.as_raw()) };
    let activity_class = env.get_object_class(context2).map_err(|e| jerr(env, e))?;
    let get_class_loader_method = env
        .get_method_id(
            activity_class,
            "getClassLoader",
            "()Ljava/lang/ClassLoader;",
        )
        .map_err(|e| jerr(env, e))?;
    let context2 = unsafe { jni::objects::JObject::from_raw(context.as_raw()) };

    let loader = try_call_object_method(env, context2, get_class_loader_method, &[])?;
    let loader_class: jni::objects::JObject = env
        .find_class("java/lang/ClassLoader")
        .map_err(|e| jerr(env, e))?
        .into();
    let lcc: jni::objects::JClass = loader_class.into();
    let load_class_method = env
        .get_method_id(lcc, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;")
        .map_err(|e| jerr(env, e))?;
    //com/nxp/nfclib/NxpNfcLib
    //com/moron/ModdedNativeActivity
    let name: jni::objects::JObject = env.new_string(name).map_err(|e| jerr(env, e))?.into();
    let session_class: jni::objects::JClass = try_call_object_method(
        env,
        loader,
        load_class_method,
        &[jni::objects::JValue::Object(&name).to_jni()],
    )?
    .into();
    Ok(session_class)
}

#[ouroboros::self_referencing]
pub struct Java {
    app: AndroidApp,
    java: jni::JavaVM,
    #[borrows(java)]
    #[not_covariant]
    env: jni::JNIEnv<'this>,
}

impl Java {
    /// Use the java environment with a closure that returns a type. Generally used to make calls to java code.
    pub fn use_env<T, F: FnOnce(&mut jni::JNIEnv, jni::objects::JObject) -> T>(
        &mut self,
        f: F,
    ) -> T {
        let context = unsafe {
            jni::objects::JObject::from_raw(
                self.borrow_app().activity_as_ptr() as *mut jni::sys::_jobject
            )
        };
        self.with_env_mut(|a| f(a, context))
    }

    /// Retrieve a clone of the androidapp object
    pub fn get_app(&self) -> AndroidApp {
        self.borrow_app().clone()
    }

    /// Make a new java object using the androidapp object
    pub fn make(app: &AndroidApp) -> Self {
        {
            let mut ac = Application.lock().unwrap();
            *ac = Some(app.clone());
        }
        let vm = unsafe {
            jni::JavaVM::from_raw(app.vm_as_ptr() as *mut *const jni::sys::JNIInvokeInterface_)
        }
        .unwrap();
        JavaBuilder {
            app: app.clone(),
            java: vm,
            env_builder: |java: &jni::JavaVM| java.attach_current_thread_permanently().unwrap(),
        }
        .build()
    }
}

fn try_call_object_method<'a, 'b>(
    env: &mut jni::JNIEnv<'a>,
    obj: jni::objects::JObject<'b>,
    method_id: jni::objects::JMethodID,
    args: &[jni::sys::jvalue],
) -> Result<jni::objects::JObject<'a>, std::io::Error> {
    // XXX: Wow, it's pretty terrible that any function call that returns an object requires allocating a String for the JavaType...
    let e = match unsafe {
        env.call_method_unchecked(obj, method_id, jni::signature::ReturnType::Object, args)
    } {
        Err(jni::errors::Error::JavaException) => {
            env.exception_describe().map_err(|e| jerr(env, e))?;
            env.exception_clear().map_err(|e| jerr(env, e))?;
            Err(std::io::Error::other(anyhow::anyhow!("JNI: Exception")))
        }
        Err(err) => Err(std::io::Error::other(err)),
        Ok(ok) => Ok(ok),
    };
    match e? {
        jni::objects::JValueGen::Object(o) => Ok(o),
        _ => Err(std::io::Error::other(anyhow::anyhow!(
            "JNI: unexpected return type"
        ))),
    }
}

pub struct TapLinx {
    java: Arc<Mutex<Java>>,
}

impl TapLinx {
    pub fn make_new(app: &AndroidApp) -> Self {
        let java = Java::make(app);
        let java = Arc::new(Mutex::new(java));
        Self::new(java)
    }

    /// constructs a new Self with the protected java instance
    fn new(java: Arc<Mutex<Java>>) -> Self {
        let s = Self { java };
        s
    }

    /// Get the taplinx version
    pub fn get_version(&self) -> Result<String, std::io::Error> {
        let mut java = self.java.lock().unwrap();
        java.use_env(|env, context| {
            let session_class = get_class(env, context, "com/nxp/nfclib/NxpNfcLib")?;
            let ver = env
                .call_static_method(
                    session_class,
                    "getTaplinxVersion",
                    "()Ljava/lang/String;",
                    &[],
                )
                .map_err(|e| jerr(env, e))?;
            let ver = ver.l().map_err(|e| jerr(env, e))?;
            let ver = ver.get_string(env).map_err(|e| jerr(env, e))?;
            Ok::<String, std::io::Error>(ver)
        })
    }

    /// Get the taplinx instance
    pub fn load_instance(&mut self) -> Result<(), std::io::Error> {
        let mut java = self.java.lock().unwrap();
        java.use_env(|env, context| {
            let session_class = get_class(env, context, "com/nxp/nfclib/NxpNfcLib")?;
            let ver = env
                .call_static_method(
                    session_class,
                    "getInstance",
                    "()Lcom/nxp/nfclib/NxpNfcLib;",
                    &[],
                )
                .get_object(env)
                .map_err(|e| jerr(env, e))?;
            let ver = env.new_global_ref(&ver).map_err(|e| jerr(env, e))?;
            let i = NxpNfcLib { inner: ver.into() };
            {
                let mut m = NxpNfcInstance.lock().unwrap();
                *m = Some(i);
            }
            Ok::<(), std::io::Error>(())
        })
    }

    /// Register the activity
    pub fn register_activity(&mut self, key: &str, keyo: &str) -> Result<(), std::io::Error> {
        let mut m = NxpNfcInstance.lock().unwrap();
        let m: Option<&mut NxpNfcLib> = m.as_mut();
        if let Some(i) = m {
            let mut java = self.java.lock().unwrap();
            let r = i.register_activity(&mut java, key, keyo);
            log::error!("REGISTERED ACTIVITY {:?}", r);
            r
        } else {
            Err(std::io::Error::other("NxpNfcLib not created yet"))
        }
    }
}

pub struct NxpNfcLib {
    /// The NxpNfcLib java object
    inner: GlobalRef,
}

#[derive(Debug)]
pub enum CardType {
    DesFireEv1,
    DesFireEv2,
    DesFireEv3,
    DesFireEv3C,
    DesFireLight,
    ICodeDna,
    ICodeSLI,
    ICodeSLIL,
    ICodeSLIS,
    ICodeSLIX,
    ICodeSLIX2,
    ICodeSLIXL,
    ICodeSLIXS,
    MifareClassic,
    MifareClassicV2,
    MifareIdentity,
    MifareUltralightAes,
    Ntag203x,
    Ntag210,
    Ntag210u,
    Ntag212,
    Ntag213,
    Ntag213f,
    Ntag213TagTamper,
    Ntag215,
    NTag216,
    Ntag216f,
    Ntag223Dna,
    Ntag223DnaStatusDefect,
    Ntag224Dna,
    Ntag224DnaStatusDefect,
    Ntag413Dna,
    Ntag424Dna,
    Ntag424DnaTagTamper,
    Ntag5Boost,
    Ntag5Link,
    Ntag5Switch,
    NtagI2c2k,
    NtagI2cPlus1k,
    NtagI2cPlus2k,
    PlusEv1Sl0,
    PlusEv1Sl1,
    PlusEv1Sl3,
    PlusEv2Sl0,
    PlusEv2Sl1,
    PlusEv2Sl3,
    PlusSl0,
    PlusSl1,
    PlusSl3,
    UltraLight,
    UltraLightC,
    UltraLightEv1_11,
    UltraLightEv1_21,
    UltraLigthNano40,
    UltraLigthNano48,
    Unknown,
}

impl From<&str> for CardType {
    fn from(value: &str) -> Self {
        match value {
            "DESFireEV1" => Self::DesFireEv1,
            _ => Self::Unknown,
        }
    }
}

impl CardType {
    pub fn process(
        &self,
        env: &mut jni::JNIEnv,
        lib: &mut NxpNfcLib,
    ) -> Result<(), std::io::Error> {
        match self {
            Self::DesFireEv1 => {
                let cm = lib.get_custom_modules(env)?;
                let factory = DesfireFactory::get_instance(env)?;
                let ev1 = factory.get_desfire_ev1(env, cm)?;
                log::error!("Got desfire ev1 object");
                Ok(())
            }
            _ => Err(std::io::Error::other(format!(
                "Unhandled card type {:?}",
                self
            ))),
        }
    }
}

impl NxpNfcLib {
    /// Call registerActivity with the original context and the specified keys
    /// key is the online key
    /// keyo is the offline key
    pub fn register_activity(
        &self,
        java: &mut Java,
        key: &str,
        keyo: &str,
    ) -> Result<(), std::io::Error> {
        java.use_env(|env, context| {
            let context2 = unsafe { jni::objects::JObject::from_raw(context.as_raw()) };
            let arg = key.new_jobject(env).map_err(|e| jerr(env, e)).unwrap();
            let arg2 = keyo.new_jobject(env).map_err(|e| jerr(env, e)).unwrap();
            env.call_method(
                self.inner.as_obj(),
                "registerActivity",
                "(Landroid/app/Activity;Ljava/lang/String;Ljava/lang/String;)V",
                &[(&context2).into(), (&arg).into(), (&arg2).into()],
            )
            .map_err(|e| jerr(env, e))?;
            Ok(())
        })
    }

    /// Get custom modules
    pub fn get_custom_modules<'a>(
        &self,
        env: &'a mut jni::JNIEnv,
    ) -> Result<GlobalRef, std::io::Error> {
        let ver = env
            .call_method(
                self.inner.as_obj(),
                "getCustomModules",
                "()Lcom/nxp/nfclib/CustomModules;",
                &[],
            )
            .get_object(env)
            .map_err(|e| jerr(env, e))?;
        let ver = env.new_global_ref(&ver).map_err(|e| jerr(env, e))?;
        Ok(ver)
    }

    pub fn get_card_type_from_tag(
        &mut self,
        env: &mut jni::JNIEnv,
        tag: jni::objects::JObject,
    ) -> Result<CardType, std::io::Error> {
        let context = get_context()?;
        let ct = env
            .call_method(
                self.inner.as_obj(),
                "getCardType",
                "(Landroid/nfc/Tag;)Lcom/nxp/nfclib/CardType;",
                &[(&tag).into()],
            )
            .get_object(env)
            .map_err(|e| jerr(env, e))?;
        let ver = env
            .call_method(ct, "name", "()Ljava/lang/String;", &[])
            .map_err(|e| jerr(env, e))?;
        let ver = ver.l().map_err(|e| jerr(env, e))?;
        let ver = ver.get_string(env).map_err(|e| jerr(env, e))?;
        log::error!("Card enum is {}", ver);
        Ok(ver.as_str().into())
    }

    pub fn get_card_type(
        &mut self,
        env: &mut jni::JNIEnv,
        intent: jni::objects::JObject,
    ) -> Result<CardType, std::io::Error> {
        let ct = env
            .call_method(
                self.inner.as_obj(),
                "getCardType",
                "(Landroid/content/Intent;)Lcom/nxp/nfclib/CardType;",
                &[(&intent).into()],
            )
            .get_object(env)
            .map_err(|e| jerr(env, e))?;
        let ver = env
            .call_method(ct, "name", "()Ljava/lang/String;", &[])
            .map_err(|e| jerr(env, e))?;
        let ver = ver.l().map_err(|e| jerr(env, e))?;
        let ver = ver.get_string(env).map_err(|e| jerr(env, e))?;
        log::error!("Card enum is {}", ver);
        Ok(ver.as_str().into())
    }
}

pub struct DesfireFactory {
    inner: GlobalRef,
}

impl DesfireFactory {
    pub fn get_instance(env: &mut jni::JNIEnv) -> Result<Self, std::io::Error> {
        let context = get_context()?;
        let class = get_class(env, context, "com/nxp/nfclib/desfire/DESFireFactory")?;
        let ver = env
            .call_static_method(
                class,
                "getInstance",
                "()Lcom/nxp/nfclib/desfire/DESFireFactory;",
                &[],
            )
            .get_object(env)
            .map_err(|e| jerr(env, e))?;
        let ver = env.new_global_ref(&ver).map_err(|e| jerr(env, e))?;
        Ok(Self { inner: ver })
    }

    pub fn get_desfire_ev1(
        &self,
        env: &mut jni::JNIEnv,
        cm: GlobalRef,
    ) -> Result<GlobalRef, std::io::Error> {
        let ver = env
            .call_method(
                self.inner.as_obj(),
                "getDESFire",
                "(Lcom/nxp/nfclib/CustomModules;)Lcom/nxp/nfclib/desfire/IDESFireEV1;",
                &[(&cm).into()],
            )
            .get_object(env)
            .map_err(|e| jerr(env, e))?;
        env.new_global_ref(&ver).map_err(|e| jerr(env, e))
    }
}
