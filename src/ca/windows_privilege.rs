//! Windows specific helper code

use std::sync::Mutex;

pub struct Luid {
    luid: winapi::shared::ntdef::LUID,
}

impl Luid {
    pub fn new(system: Option<&str>, privilege: &str) -> Result<Self, winapi::shared::minwindef::DWORD> {
        let mut luid = winapi::shared::ntdef::LUID {
            LowPart: 0,
            HighPart: 0,
        };
        let arg1 = service::get_optional_utf16(system);
        let arg2 = service::get_utf16(privilege);
        let rv = unsafe { winapi::um::winbase::LookupPrivilegeValueW(arg1, arg2.as_ptr(), &mut luid as *mut winapi::shared::ntdef::LUID) };
        if rv == 0 {
            let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
            println!("Error is {} {}", rv, err);
            return Err(err);
        }
        println!("LUID Lookup is {:?} {:?}", luid.LowPart, luid.HighPart);
        Ok ( Self {
            luid,
        })
    }
}

pub struct TokenPrivileges {
    tp: winapi::um::winnt::TOKEN_PRIVILEGES,
}

impl TokenPrivileges {
    pub fn enable(luid: Luid) -> Self {
        let tp = winapi::um::winnt::TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [winapi::um::winnt::LUID_AND_ATTRIBUTES {
                Luid: luid.luid,
                Attributes: winapi::um::winnt::SE_PRIVILEGE_ENABLED,
            }],
        };
        Self {
            tp,
        }
    }

    pub fn remove(luid: Luid) -> Self {
        let tp = winapi::um::winnt::TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [winapi::um::winnt::LUID_AND_ATTRIBUTES {
                Luid: luid.luid,
                Attributes: winapi::um::winnt::SE_PRIVILEGE_REMOVED,
            }],
        };
        Self {
            tp,
        }
    }
}

pub struct TokenContainer(winapi::shared::ntdef::HANDLE);

unsafe impl Send for TokenContainer {}

pub struct Token {
    token: std::sync::Mutex<TokenContainer>,
}

impl Token {
    pub fn new_thread(access: winapi::shared::minwindef::DWORD) -> Result<Self, winapi::shared::minwindef::DWORD> {
        let thread_handle = unsafe { winapi::um::processthreadsapi::GetCurrentThread() };
        let mut handle = unsafe { winapi::um::processthreadsapi::GetCurrentThread() };
        let rv = unsafe { winapi::um::processthreadsapi::OpenThreadToken(
            thread_handle,
            access,
            0,
            &mut handle as winapi::um::winnt::PHANDLE,
        )};
        if rv == 0 {
            let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
            println!("Error getting thread token is {} {}", rv, err);
            return Err(err);
        }
        Ok(Self {
            token: Mutex::new(TokenContainer(handle)),
        })
    }

    pub fn new_process(access: winapi::shared::minwindef::DWORD) -> Result<Self, winapi::shared::minwindef::DWORD> {
        let process_handle = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
        let mut handle = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
        let rv = unsafe { winapi::um::processthreadsapi::OpenProcessToken(
            process_handle,
            access,
            &mut handle as winapi::um::winnt::PHANDLE,
        ) };
        if rv == 0 {
            let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
            println!("Error getting process token is {} {}", rv, err);
            return Err(err);
        }
        Ok(Self {
            token: Mutex::new(TokenContainer(handle)),
        })
    }
}

pub struct TokenPrivilegesEnabled {
    token: Token,
    prev: Vec<u8>,
}

impl TokenPrivilegesEnabled {
    pub fn new(token: Token,
        tp: TokenPrivileges,
    ) -> Result<Self, winapi::shared::minwindef::DWORD> {
        use std::ops::DerefMut;
        let mut len_required : winapi::shared::minwindef::DWORD = 0;
        let mut tp = tp.tp.clone();
        let mut t3 = token.token.lock().unwrap();
        let token2 = t3.deref_mut().0;
        let r = unsafe { winapi::um::securitybaseapi::AdjustTokenPrivileges(
            token2,
            0,
            &mut tp as *mut winapi::um::winnt::TOKEN_PRIVILEGES,
            0,
            std::ptr::null_mut(),
            &mut len_required as *mut winapi::shared::minwindef::DWORD,
        ) };
        if r != 0 {
            println!("Error is {}", unsafe { winapi::um::errhandlingapi::GetLastError() });
        }
        let prev = vec![0; len_required as usize];
        drop(t3);
        Ok(Self {
            token,
            prev,
        })
    }
}