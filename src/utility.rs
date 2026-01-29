//! A collection of random utility functions and structures

use std::{collections::HashMap, convert::Infallible, sync::Arc};

use crate::{ca::SimplifiedPkiConfigurationEnum, main_config::PageDelivery};

/// Decode a hex string to a vec of bytes
pub fn decode_hex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// Build a base64 encoded toml string from an object
pub fn build_toml_string(doc: impl serde::Serialize) -> String {
    use base64::Engine;
    let c = toml::to_string(&doc).unwrap();
    base64::prelude::BASE64_STANDARD_NO_PAD.encode(c)
}

/// Decode an object from the output of `build_toml_string`
pub fn decode_toml_string<T: serde::de::DeserializeOwned>(v: &str) -> Option<T> {
    use base64::Engine;
    let d = base64::prelude::BASE64_STANDARD_NO_PAD.decode(v).ok()?;
    let d = String::from_utf8(d).ok()?;
    toml::from_str::<T>(&d).ok()
}

/// Encode a vec of bytes to a hex string with no separators
pub fn encode_hex(d: &[u8]) -> String {
    let serhex: Vec<String> = d.iter().map(|e| format!("{:02x}", e)).collect();
    serhex.join("")
}

/// Generate a password of the specified length
pub fn generate_password(len: usize) -> String {
    use rand::Rng;
    /// The characters to pick from for a randomly generated password
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789\
                            `~!@#$%^&*()-_=+[]{}\\|;:'\",<.>/?";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Hash and convert to der format
pub fn rsa_sha256(hash: &[u8]) -> Vec<u8> {
    let mut hash = hash.to_vec();
    // convert to der format, indicating sha-256 hash present
    let mut der_hash = vec![
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    der_hash.append(&mut hash);
    der_hash
}

/// apply pkcs1.5 padding to pkcs1 hash, suitable for signing.
/// # Arguments
/// * total_size - Size in bits
/// * hash - The hash needs to be in der format.
pub fn pkcs15_sha256(total_size: usize, hash: &[u8]) -> Vec<u8> {
    // convert to der format, indicating sha-256 hash present
    let mut der_hash = rsa_sha256(hash);

    let plen = total_size - der_hash.len() - 3;
    let mut p = vec![0xff; plen];

    let mut total = Vec::new();
    total.append(&mut vec![0, 1]);
    total.append(&mut p);
    total.push(0);
    total.append(&mut der_hash);
    total
}

pub struct DroppingProcess {
    c: std::process::Child,
}

impl Drop for DroppingProcess {
    fn drop(&mut self) {
        self.c.kill();
        self.c.wait();
    }
}

/// Runs the java smartcard simulator
pub fn run_smartcard_sim() -> Option<DroppingProcess> {
    let mut p = std::process::Command::new("java");
    let a = p.args([
        "-classpath", 
        "jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar:javacard-sdk/jc305u3_kit/lib/api_classic.jar:PivApplet/bin", 
        "com.licel.jcardsim.remote.VSmartCard", 
        "jcardsim.cfg"]).spawn();
    if let Ok(a) = a {
        let mut b = std::process::Command::new("opensc-tool");
        let mut p = b.args([
            "--card-driver",
            "default",
            "--send-apdu",
            "80b80000120ba000000308000010000100050000020F0F7f",
        ]);
        std::thread::sleep(std::time::Duration::from_secs(5));
        let asdf = p
            .output()
            .expect("Failed to initialize smartcard simulator");
        service::log::info!(
            "Initialize output is {}",
            String::from_utf8(asdf.stdout).unwrap()
        );
        Some(DroppingProcess { c: a })
    } else {
        None
    }
}

#[cfg(target_family = "windows")]
pub struct Luid {
    luid: winapi::shared::ntdef::LUID,
}

#[cfg(target_family = "windows")]
impl Luid {
    pub fn new(
        system: Option<&str>,
        privilege: &str,
    ) -> Result<Self, winapi::shared::minwindef::DWORD> {
        let mut luid = winapi::shared::ntdef::LUID {
            LowPart: 0,
            HighPart: 0,
        };
        let arg1 = service::get_optional_utf16(system);
        let arg2 = service::get_utf16(privilege);
        let rv = unsafe {
            winapi::um::winbase::LookupPrivilegeValueW(
                arg1,
                arg2.as_ptr(),
                &mut luid as *mut winapi::shared::ntdef::LUID,
            )
        };
        if rv == 0 {
            let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
            service::log::error!("Error is {} {}", rv, err);
            return Err(err);
        }
        service::log::debug!("LUID Lookup is {:?} {:?}", luid.LowPart, luid.HighPart);
        Ok(Self { luid })
    }
}

#[cfg(target_family = "windows")]
pub struct TokenPrivileges {
    tp: winapi::um::winnt::TOKEN_PRIVILEGES,
}

#[cfg(target_family = "windows")]
impl TokenPrivileges {
    pub fn enable(luid: Luid) -> Self {
        let tp = winapi::um::winnt::TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [winapi::um::winnt::LUID_AND_ATTRIBUTES {
                Luid: luid.luid,
                Attributes: winapi::um::winnt::SE_PRIVILEGE_ENABLED,
            }],
        };
        Self { tp }
    }

    pub fn remove(luid: Luid) -> Self {
        let tp = winapi::um::winnt::TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [winapi::um::winnt::LUID_AND_ATTRIBUTES {
                Luid: luid.luid,
                Attributes: winapi::um::winnt::SE_PRIVILEGE_REMOVED,
            }],
        };
        Self { tp }
    }
}

#[cfg(target_family = "windows")]
pub struct TokenContainer(winapi::shared::ntdef::HANDLE);

#[cfg(target_family = "windows")]
unsafe impl Send for TokenContainer {}

#[cfg(target_family = "windows")]
pub struct Token {
    token: std::sync::Mutex<TokenContainer>,
}

#[cfg(target_family = "windows")]
impl Token {
    pub fn new_thread(
        access: winapi::shared::minwindef::DWORD,
    ) -> Result<Self, winapi::shared::minwindef::DWORD> {
        let thread_handle = unsafe { winapi::um::processthreadsapi::GetCurrentThread() };
        let mut handle = unsafe { winapi::um::processthreadsapi::GetCurrentThread() };
        let rv = unsafe {
            winapi::um::processthreadsapi::OpenThreadToken(
                thread_handle,
                access,
                0,
                &mut handle as winapi::um::winnt::PHANDLE,
            )
        };
        if rv == 0 {
            let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
            service::log::warn!("Error getting thread token is {} {}", rv, err);
            return Err(err);
        }
        Ok(Self {
            token: std::sync::Mutex::new(TokenContainer(handle)),
        })
    }

    pub fn new_process(
        access: winapi::shared::minwindef::DWORD,
    ) -> Result<Self, winapi::shared::minwindef::DWORD> {
        let process_handle = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
        let mut handle = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
        let rv = unsafe {
            winapi::um::processthreadsapi::OpenProcessToken(
                process_handle,
                access,
                &mut handle as winapi::um::winnt::PHANDLE,
            )
        };
        if rv == 0 {
            let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
            service::log::error!("Error getting process token is {} {}", rv, err);
            return Err(err);
        }
        Ok(Self {
            token: std::sync::Mutex::new(TokenContainer(handle)),
        })
    }
}

#[cfg(target_family = "windows")]
pub struct TokenPrivilegesEnabled {
    token: Token,
    prev: Vec<u8>,
}

#[cfg(target_family = "windows")]
impl TokenPrivilegesEnabled {
    pub fn new(
        token: Token,
        tp: TokenPrivileges,
    ) -> Result<Self, winapi::shared::minwindef::DWORD> {
        use std::ops::DerefMut;
        let mut len_required: winapi::shared::minwindef::DWORD = 0;
        let mut tp = tp.tp.clone();
        let mut t3 = token.token.lock().unwrap();
        let token2 = t3.deref_mut().0;
        let r = unsafe {
            winapi::um::securitybaseapi::AdjustTokenPrivileges(
                token2,
                0,
                &mut tp as *mut winapi::um::winnt::TOKEN_PRIVILEGES,
                0,
                std::ptr::null_mut(),
                &mut len_required as *mut winapi::shared::minwindef::DWORD,
            )
        };
        if r != 0 {
            service::log::error!("Error enabling token privileges is {}", unsafe {
                winapi::um::errhandlingapi::GetLastError()
            });
        }
        let prev = vec![0; len_required as usize];
        drop(t3);
        Ok(Self { token, prev })
    }
}

/// Represents the ways user certs can make it to us
pub enum UserCert {
    /// The user certs came directly from tls, could be a user certificate or a load balancer (reverse proxy) certificate.
    HttpsCert(x509_cert::Certificate),
    /// The user certs came from http headers
    ProxyCert(x509_cert::Certificate),
}

/// A list of all the `UserCert` that the current page knows about.
pub struct UserCerts {
    pub inner: Vec<UserCert>,
}

impl UserCerts {
    /// Build a new blank list
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Return a list of all certs, regardless of how the made it here
    pub fn all_certs(&self) -> Vec<&x509_cert::Certificate> {
        self.inner
            .iter()
            .map(|c| match c {
                UserCert::HttpsCert(a) => a,
                UserCert::ProxyCert(a) => a,
            })
            .collect()
    }
}

/// Represents the contents of a post request
#[derive(Clone)]
pub struct PostContent {
    /// The body of a request, containing some content
    body: Option<hyper::body::Bytes>,
    /// The headers, for extracting the multipart
    headers: hyper::header::HeaderMap,
}

impl PostContent {
    /// Construct a Self with the given body and headers.
    pub fn new(body: Option<hyper::body::Bytes>, headers: hyper::header::HeaderMap) -> Self {
        Self { body, headers }
    }

    /// Just get the post content
    #[allow(dead_code)]
    pub fn content(&self) -> Option<Vec<u8>> {
        self.body.as_ref().map(|d| d.to_vec())
    }

    /// Convert the post content to an ocsp request if possible.
    pub fn ocsp(&self) -> Option<ocsp::request::OcspRequest> {
        let b = self.body.as_ref()?;
        ocsp::request::OcspRequest::parse(b.as_ref()).ok()
    }

    /// Convert the post content to form data if possible
    pub fn form(&self) -> Option<url_encoded_data::UrlEncodedData<'_>> {
        if let Some(body) = self.body.as_ref() {
            let s = std::str::from_utf8(body).ok()?;
            Some(url_encoded_data::UrlEncodedData::parse_str(s))
        } else {
            None
        }
    }

    /// Convert the post content to a multipart request if possible.
    #[allow(dead_code)]
    pub fn multipart(&self) -> Option<multer::Multipart<'_>> {
        let body = self.body.as_ref()?;
        let boundary = self.headers.get("Content-Type")?;
        let b = boundary.to_str().ok()?;
        let boundary = multer::parse_boundary(b).ok()?;
        let data = futures_util::stream::once(async move {
            Result::<multer::bytes::Bytes, Infallible>::Ok(body.clone())
        });
        Some(multer::Multipart::new(data, boundary))
    }
}

impl std::io::Read for PostContent {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let b = match self.body.as_ref() {
            None => {
                return Ok(0);
            }
            Some(a) => a,
        };
        buf.copy_from_slice(b);
        Ok(b.len())
    }
}

/// Represents the context necessary to render a webpage
pub struct WebPageContext {
    /// What kind of method was used to deliver the page?
    pub delivery: PageDelivery,
    /// Was https used to access the page?
    pub https: bool,
    /// The domain that was used to access the request
    pub domain: String,
    /// The actual page requested
    pub page: std::path::PathBuf,
    /// The proxy sub-directory
    pub proxy: String,
    /// The map of all post arguments
    pub post: PostContent,
    /// The map of all get arguments
    pub get: HashMap<String, String>,
    /// The login cookie
    pub logincookie: Option<String>,
    /// The optional mysql server connection
    pub pool: Option<mysql::PooledConn>,
    /// The list of user certificates presented by the user
    pub user_certs: UserCerts,
    /// The application settings
    pub pki_type: SimplifiedPkiConfigurationEnum,
    /// The pki object
    pub pki: Arc<futures::lock::Mutex<crate::ca::PkiInstance>>,
}
