//! Desfire related cards

use jni::objects::{JObject, JValue};

pub struct Ev1 {
    /// This is the com/nxp/nfclib/desfire/IDESFireEV1 object
    inner: jni::objects::GlobalRef,
}

/// The default encryption key for the entire card
static DEFAULT_PICC_KEY: &[u8] = &[0; 16];

impl Ev1 {
    pub fn new(g: jni::objects::GlobalRef) -> Self {
        Self { inner: g }
    }

    fn make_keydata<'a, 'b>(
        env: &'a mut jni::JNIEnv<'b>,
        keytype: &jni::objects::JObject<'a>,
        key: &[u8],
    ) -> Result<jni::objects::JObject<'b>, std::io::Error> {
        let keydata_obj = env
            .new_object("com/nxp/nfclib/defaultimpl/KeyData", "()V", &[])
            .map_err(|e| super::jerr(env, e))?;
        let key_array = env
            .byte_array_from_slice(key)
            .map_err(|e| super::jerr(env, e))?;
        let secret_key_class = env
            .find_class("javax/crypto/spec/SecretKeySpec")
            .map_err(|e| super::jerr(env, e))?;
        let aes_str = env.new_string("AES");
        let aes_str = aes_str.map_err(|e| super::jerr(env, e))?;
        let secret_key_obj = env
            .new_object(
                secret_key_class,
                "([BLjava/lang/String;)V",
                &[
                    JValue::Object(&JObject::from(key_array)),
                    JValue::Object(&aes_str.into()),
                ],
            )
            .map_err(|e| super::jerr(env, e))?;
        env.call_method(
            &keydata_obj,
            "setKey",
            "(Ljava/security/Key;)V",
            &[jni::objects::JValue::Object(&secret_key_obj)],
        )
        .map_err(|e| super::jerr(env, e))?;
        Ok(keydata_obj)
    }
}

impl super::CardTrait for Ev1 {
    fn select_application(
        &self,
        env: &mut jni::JNIEnv,
        app: Option<&[u8]>,
    ) -> Result<(), std::io::Error> {
        let app = app.unwrap_or(&[0; 3]);
        let picc_aid = env
            .byte_array_from_slice(app)
            .map_err(|e| super::jerr(env, e))?;

        env.call_method(
            self.inner.as_obj(),
            "selectApplication",
            "([B)V",
            &[JValue::Object(&JObject::from(picc_aid))],
        )
        .map_err(|e| super::jerr(env, e))?;
        Ok(())
    }

    fn authenticate(
        &self,
        env: &mut jni::JNIEnv,
        auth: &str,
        keytype: &str,
        key: Option<&[u8]>,
    ) -> Result<(), std::io::Error> {
        let key = key.unwrap_or(DEFAULT_PICC_KEY);

        let auth_type_class = env
            .find_class("com/nxp/nfclib/desfire/IDESFireEV1$AuthType")
            .map_err(|e| super::jerr(env, e))?;
        let aes = env
            .get_static_field(
                auth_type_class,
                auth,
                "Lcom/nxp/nfclib/desfire/IDESFireEV1$AuthType;",
            )
            .map_err(|e| super::jerr(env, e))?
            .l()
            .map_err(|e| super::jerr(env, e))?;

        let key_type_class = env
            .find_class("com/nxp/nfclib/KeyType")
            .map_err(|e| super::jerr(env, e))?;
        let keytype = env
            .get_static_field(key_type_class, keytype, "Lcom/nxp/nfclib/KeyType;")
            .map_err(|e| super::jerr(env, e))?
            .l()
            .map_err(|e| super::jerr(env, e))?;

        let key = Self::make_keydata(env, &keytype, key)?;

        env.call_method(self.inner.as_obj(),
            "authenticate", 
            "(ILcom/nxp/nfclib/desfire/IDESFireEV1$AuthType;Lcom/nxp/nfclib/KeyType;Lcom/nxp/nfclib/interfaces/IKeyData;)V", 
            &[jni::objects::JValue::Int(0),
                jni::objects::JValue::Object(&aes),
                jni::objects::JValue::Object(&keytype),
                jni::objects::JValue::Object(&key),
            ]).map_err(|e| super::jerr(env, e))?;
        Ok(())
    }
}
