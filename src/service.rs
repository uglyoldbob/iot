//! Contains code for establishing a service

use std::path::PathBuf;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
use winapi::shared::minwindef::DWORD;

pub struct Service {
    name: String,
    display: String,
    description: String,
    binary: PathBuf,
    #[cfg(target_os = "windows")]
    pub desired_access: DWORD,
    #[cfg(target_os = "windows")]
    pub service_type: DWORD,
    #[cfg(target_os = "windows")]
    pub start_type: DWORD,
    #[cfg(target_os = "windows")]
    pub error_control: DWORD,
    #[cfg(target_os = "windows")]
    pub tag_id: DWORD,
    #[cfg(target_os = "windows")]
    pub load_order_group: String,
    #[cfg(target_os = "windows")]
    pub dependencies: String,
    #[cfg(target_os = "windows")]
    pub account_name: String,
    #[cfg(target_os = "windows")]
    pub password: String,
    #[cfg(target_os = "windows")]
    pub service_status: winapi::um::winsvc::SERVICE_STATUS,
    #[cfg(target_os = "windows")]
    pub status_handle: winapi::um::winsvc::SERVICE_STATUS_HANDLE,
    #[cfg(target_os = "windows")]
    pub controls_accepted: DWORD,
}

impl Service {
    /// Construct a new self
    pub fn new(name: String, display: String, description: String, binary: PathBuf) -> Self {
        Self {
            name,
            display,
            description,
            binary,
            desired_access: winapi::um::winsvc::SERVICE_ALL_ACCESS,
            service_type: winapi::um::winnt::SERVICE_WIN32_OWN_PROCESS,
            start_type: winapi::um::winnt::SERVICE_AUTO_START,
            error_control: winapi::um::winnt::SERVICE_ERROR_NORMAL,
            tag_id: 0,
            load_order_group: "".to_string(),
            dependencies: "".to_string(),
            account_name: "".to_string(),
            password: "".to_string(),
            service_status: winapi::um::winsvc::SERVICE_STATUS {
                dwServiceType: winapi::um::winnt::SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: winapi::um::winsvc::SERVICE_STOPPED,
                dwControlsAccepted: 0,
                dwWin32ExitCode: 0,
                dwServiceSpecificExitCode: 0,
                dwCheckPoint: 0,
                dwWaitHint: 0,
            },
            status_handle: std::ptr::null_mut(),
            controls_accepted: winapi::um::winsvc::SERVICE_ACCEPT_STOP,
        }
    }

    /// Does the service already exist?
    #[cfg(target_os = "linux")]
    pub fn exists(&self) -> bool {
        let systemd_path = PathBuf::from("/etc/systemd/system");
        let pb = systemd_path.join(format!("{}.service", self.name));
        pb.exists()
    }

    /// Does the service already exist?
    #[cfg(target_os = "windows")]
    pub fn exists(&self) -> bool {
        let service_manager =
            windows::ServiceController::open(winapi::um::winsvc::SC_MANAGER_ALL_ACCESS)
                .unwrap_or_else(|| panic!("Unable to get service controller")); //TODO REMOVE RIGHTS NOT REQUIRED
        let service =
            service_manager.open_service(&self.name, winapi::um::winsvc::SERVICE_ALL_ACCESS);
        service.is_some()
    }

    /// Create the service
    #[cfg(target_os = "windows")]
    pub fn create(&mut self) -> Result<(), ()> {
        let service_manager =
            windows::ServiceController::open(winapi::um::winsvc::SC_MANAGER_ALL_ACCESS); //TODO REMOVE RIGHTS NOT REQUIRED
        if let Some(service_manager) = service_manager {
            let service = unsafe {
                winapi::um::winsvc::CreateServiceW(
                    service_manager.get_handle(),
                    windows::get_utf16(self.name.as_str()).as_ptr(),
                    windows::get_utf16(self.display.as_str()).as_ptr(),
                    self.desired_access,
                    self.service_type,
                    self.start_type,
                    self.error_control,
                    windows::get_utf16(self.binary.to_str().unwrap()).as_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if service.is_null() {
                return Err(());
            }
            let mut description = windows::get_utf16(self.description.as_str());

            let mut sd = winapi::um::winsvc::SERVICE_DESCRIPTIONW {
                lpDescription: description.as_mut_ptr(),
            };

            let p_sd = &mut sd as *mut _ as *mut winapi::ctypes::c_void;
            unsafe {
                winapi::um::winsvc::ChangeServiceConfig2W(
                    service,
                    winapi::um::winsvc::SERVICE_CONFIG_DESCRIPTION,
                    p_sd,
                )
            };
            unsafe { winapi::um::winsvc::CloseServiceHandle(service) };
            Ok(())
        } else {
            Err(())
        }
    }

    /// Create the service
    #[cfg(target_os = "linux")]
    pub fn create(&mut self) {
        let mut con = String::new();
        con.push_str(&format!(
            "[Unit]
Description=Iot Certificate Authority and Iot Manager

[Service]
User={2}
WorkingDirectory={0}
ExecStart=/usr/bin/rust-iot --name={1}

[Install]
WantedBy=multi-user.target
        ",
            config_path.display(),
            name,
            username
        ));
        println!("Saving service file as {}", pb.display());
        let mut fpw = tokio::fs::File::create(pb).await.unwrap();
        fpw.write_all(con.as_bytes())
            .await
            .expect("Failed to write service file");
    }

    /// Delete the service
    #[cfg(target_os = "windows")]
    pub fn delete(&mut self) -> Result<(), ()> {
        let service_manager =
            windows::ServiceController::open(winapi::um::winsvc::SC_MANAGER_ALL_ACCESS); //TODO REMOVE RIGHTS NOT REQUIRED
        if let Some(service_manager) = service_manager {
            let service = service_manager
                .open_service(&self.name, winapi::um::winsvc::SERVICE_ALL_ACCESS)
                .unwrap();
            if unsafe {
                winapi::um::winsvc::ControlService(
                    service.get_handle(),
                    winapi::um::winsvc::SERVICE_CONTROL_STOP,
                    &mut self.service_status,
                )
            } != 0
            {
                while unsafe {
                    winapi::um::winsvc::QueryServiceStatus(
                        service.get_handle(),
                        &mut self.service_status,
                    )
                } != 0
                {
                    if self.service_status.dwCurrentState
                        != winapi::um::winsvc::SERVICE_STOP_PENDING
                    {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            }

            if unsafe { winapi::um::winsvc::DeleteService(service.get_handle()) } == 0 {
                return Err(());
            }
            Ok(())
        } else {
            Err(())
        }
    }
}
