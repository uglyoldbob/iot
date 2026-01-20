use ::jni::objects::GlobalRef;
use ::jni::sys::_jobject;
#[cfg(target_os = "android")]
use egui_winit::winit;
use jni_min_helper::*;
use std::sync::Arc;
use std::sync::Mutex;
use winit::platform::android::activity::AndroidApp;

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
    instance: Option<NxpNfcLib>,
}

impl TapLinx {
    pub fn make_new(app: &AndroidApp) -> Self {
        let java = Java::make(app);
        let java = Arc::new(Mutex::new(java));
        Self::new(java)
    }

    /// constructs a new Self with the protected java instance
    fn new(java: Arc<Mutex<Java>>) -> Self {
        let s = Self {
            java,
            instance: None,
        };
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
            self.instance = Some(i);
            Ok::<(), std::io::Error>(())
        })
    }

    /// Register the activity
    pub fn register_activity(&mut self, key: &str, keyo: &str) -> Result<(), std::io::Error> {
        if let Some(i) = &mut self.instance {
            let mut java = self.java.lock().unwrap();
            let r = i.register_activity(&mut java, key, keyo);
            log::info!("REGISTERED ACTIVITY {:?}", r);
            r
        } else {
            Err(std::io::Error::other("NxpNfcLib not created yet"))
        }
    }
}

pub struct NxpNfcLib {
    /// The NxpNfcLib java object
    inner: jni::objects::GlobalRef,
}

impl NxpNfcLib {
    pub fn register_activity(&self, java: &mut Java, key: &str, keyo: &str) -> Result<(), std::io::Error> {
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
}
