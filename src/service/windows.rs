//! The windows specific code for service handling

use std::os::windows::ffi::OsStrExt;

use winapi::shared::minwindef::DWORD;
use winapi::um::winsvc::CloseServiceHandle;
use winapi::um::winsvc::OpenSCManagerW;
use winapi::um::winsvc::OpenServiceW;
use winapi::um::winsvc::SC_HANDLE;

pub fn get_utf16(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub struct ServiceHandle {
    handle: SC_HANDLE,
}

impl ServiceHandle {
    pub fn get_handle(&self) -> SC_HANDLE {
        self.handle
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { CloseServiceHandle(self.handle) };
        }
    }
}

pub struct ServiceController {
    handle: SC_HANDLE,
}

impl ServiceController {
    pub fn get_handle(&self) -> SC_HANDLE {
        self.handle
    }

    pub fn open(access: DWORD) -> Option<Self> {
        let handle = unsafe { OpenSCManagerW(std::ptr::null_mut(), std::ptr::null_mut(), access) };
        if handle.is_null() {
            None
        } else {
            Some(Self { handle })
        }
    }

    pub fn open_service(&self, name: &str, access: DWORD) -> Option<ServiceHandle> {
        let handle = unsafe { OpenServiceW(self.handle, get_utf16(name).as_ptr(), access) };
        if handle.is_null() {
            None
        } else {
            Some(ServiceHandle { handle })
        }
    }
}
