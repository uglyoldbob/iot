use std::{
    io::Read,
    sync::{Arc, Mutex},
};

use crate::{
    egui_multiwin_dynamic::{
        multi_window::NewWindowRequest,
        tracked_window::{RedrawResponse, TrackedWindow},
    },
    main_config::MainConfigurationAnswers,
};
use egui_multiwin::egui_glow::EguiGlow;
use interprocess::local_socket::ToFsName;
use userprompt::EguiPrompting;

use crate::AppCommon;

/// A message sent to the async code
pub enum Message {
    /// The async code should send a reply then exit
    Exit,
    /// Erase the piv card
    ErasePivCard,
    /// Generate a keypair
    GenerateKeypair,
    /// Submit csr
    SubmitCsr {
        /// The csr in pem format
        csr: String,
        /// The server to submit to
        server: String,
        /// The name for contact regarding the csr
        name: String,
        /// The email for the contact regarding the csr
        email: String,
        /// The phone number for the contact regarding the csr
        phone: String,
    },
    /// Check on a status of a submitted csr, includes server url where to check
    CheckCsrStatus {
        /// The url to query
        server: String,
        /// The serial of the certificate
        serial: Vec<u8>,
    },
    /// Write certificate to smartcard
    WriteCertificate(String),
}

/// A multi-state status for an element
enum Status {
    /// The status is in the idle state
    Idle,
    /// The status is waiting on something to happen
    Waiting,
    /// The status is now known
    Known(bool),
}

enum EraseStatus {
    Idle,
    Confirming,
    Erasing,
    Success,
    Failed,
}

/// Potential status for a submitted csr
enum CsrStatus {
    /// The csr is invalid
    Invalid,
    /// Waiting for signed certificate
    WaitingForCertificate,
    /// Received the certificate
    ReceivedCertificate(String),
    /// The csr was rejected
    Rejected(String),
}

/// A response from the async code
pub enum Response {
    /// The async code is about to exit
    Done,
    /// The card was erased with the given status, true if successful
    Erased(bool),
    /// A keypair generated
    KeypairGenerated(Option<rcgen::KeyPair>),
    /// Csr Submit status, request serial if it was successfully submitted
    CsrSubmitStatus(Option<Vec<u8>>),
    /// Csr status
    CsrStatus(CsrStatus),
    /// The status of saving the certificate to the card
    CertificateStored(Result<(), card::Error>),
    /// The newly created certificate in pem format
    CertificateCreated(String),
}

#[derive(Default)]
struct CsrFormData {
    /// The name of the person
    name: String,
    /// The email of the person
    email: String,
    /// The phone of the person
    phone: String,
    /// The country for the user
    country: String,
    /// The state for the user
    state: String,
    /// locality for the user
    locality: String,
    /// Organization for the user
    organization: String,
    /// organizational unit for the user
    ou: String,
    /// The card will be used for identifying the user (false might be dumb here)
    client_id: bool,
    /// The card will be used to sign code
    code_usage: bool,
    /// The challenge password
    cpassword: String,
    /// The challenge name
    challenge_name: String,
}

/// The struct for the root window
pub struct RootWindow {
    /// We are expecting a response from the async
    expecting_response: bool,
    /// The erase status of the smartcard
    erase_status: EraseStatus,
    /// The keypair of the smartcard
    keypair: Option<rcgen::KeyPair>,
    /// Waiting on the keypair to be generated
    keypair_generating: bool,
    /// Notes to present to the user
    notes: Vec<String>,
    /// The optional smartcard simulator
    simulator: Option<crate::utility::DroppingProcess>,
    /// The csr form data
    csr_data: CsrFormData,
    /// The ca index selected
    selected_ca_index: usize,
    /// Has a csr been submitted
    csr_submitted: Status,
    /// The submitted csr serial
    csr_serial: Option<Vec<u8>>,
    /// The csr status
    csr_status: Option<CsrStatus>,
}

impl RootWindow {
    /// Create a request for a new window
    pub fn request() -> NewWindowRequest {
        NewWindowRequest::new(
            super::MyWindows::SmartcardRoot(RootWindow {
                expecting_response: false,
                erase_status: EraseStatus::Idle,
                keypair: None,
                keypair_generating: false,
                notes: Vec::new(),
                simulator: None,
                csr_data: CsrFormData::default(),
                selected_ca_index: 0,
                csr_submitted: Status::Idle,
                csr_serial: None,
                csr_status: None,
            }),
            egui_multiwin::winit::window::WindowBuilder::new()
                .with_resizable(true)
                .with_inner_size(egui_multiwin::winit::dpi::LogicalSize {
                    width: 800.0,
                    height: 600.0,
                })
                .with_title("Certificate Authority Smartcard Manager"),
            egui_multiwin::tracked_window::TrackedWindowOptions {
                vsync: false,
                shader: None,
            },
            egui_multiwin::multi_window::new_id(),
        )
    }

    /// Send the csr to the server
    fn send_request(&self, pem: &String, srv: &String) {}

    /// Update the given certificateparams object with the fields input by the user.
    fn build_params(&self, params: &mut rcgen::CertificateParams) {
        params.distinguished_name = rcgen::DistinguishedName::new();
        if !self.csr_data.name.is_empty() {
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, &self.csr_data.name);
        }
        if !self.csr_data.country.is_empty() {
            params
                .distinguished_name
                .push(rcgen::DnType::CountryName, &self.csr_data.country);
        }
        if !self.csr_data.state.is_empty() {
            params
                .distinguished_name
                .push(rcgen::DnType::StateOrProvinceName, &self.csr_data.state);
        }
        if !self.csr_data.locality.is_empty() {
            params
                .distinguished_name
                .push(rcgen::DnType::LocalityName, &self.csr_data.locality);
        }
        if !self.csr_data.organization.is_empty() {
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, &self.csr_data.organization);
        }
        if !self.csr_data.ou.is_empty() {
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationalUnitName, &self.csr_data.ou);
        }

        // These values are ignored
        params.not_before = rcgen::date_time_ymd(1975, 1, 1);
        params.not_after = rcgen::date_time_ymd(4096, 1, 1);

        if self.csr_data.client_id {
            params
                .extended_key_usages
                .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        }
        if self.csr_data.code_usage {
            params
                .extended_key_usages
                .push(rcgen::ExtendedKeyUsagePurpose::CodeSigning);
        }

        if !self.csr_data.cpassword.is_empty() {
            let s: &String = &self.csr_data.cpassword;
            let attr = cert_common::CsrAttribute::ChallengePassword(s.to_owned());
            if let Some(a) = attr.to_custom_attribute() {
                params.extra_attributes.push(a);
            }
        }
        if !self.csr_data.challenge_name.is_empty() {
            let attr =
                cert_common::CsrAttribute::UnstructuredName(self.csr_data.challenge_name.clone());
            if let Some(a) = attr.to_custom_attribute() {
                params.extra_attributes.push(a);
            }
        }
    }
}

/// Receive a string from a local socket stream, sent length first, 4 bytes, le, then bytes of utf8
fn receive_string(
    stream: &mut interprocess::local_socket::prelude::LocalSocketStream,
) -> Option<String> {
    let mut asdf = [0, 0, 0, 0];
    if stream.read_exact(&mut asdf).is_ok() {
        let total_len = u32::from_le_bytes(asdf);
        if total_len != 0 {
            let mut m: Vec<u8> = vec![0; total_len as usize];
            stream.read_exact(&mut m).unwrap();
            Some(String::from_utf8(m).unwrap())
        } else {
            None
        }
    } else {
        None
    }
}

impl TrackedWindow for RootWindow {
    fn is_root(&self) -> bool {
        true
    }

    fn can_quit(&mut self, c: &mut crate::AppCommon) -> bool {
        let _ = c.send.blocking_send(Message::Exit);
        true
    }

    fn set_root(&mut self, _root: bool) {}

    fn redraw(
        &mut self,
        c: &mut AppCommon,
        egui: &mut EguiGlow,
        _window: &egui_multiwin::winit::window::Window,
        _clipboard: &mut egui_multiwin::arboard::Clipboard,
    ) -> RedrawResponse {
        let mut quit = false;

        let windows_to_create = vec![];

        if self.expecting_response {
            egui.egui_ctx.request_repaint();
            match c.recv.try_recv() {
                Ok(response) => {
                    self.expecting_response = false;
                    match response {
                        Response::Erased(s) => {
                            if s {
                                self.erase_status = EraseStatus::Success;
                            } else {
                                self.erase_status = EraseStatus::Failed;
                            }
                        }
                        Response::KeypairGenerated(s) => {
                            self.notes.push("Keypair generated".to_string());
                            self.keypair = s;
                            self.keypair_generating = false;
                        }
                        Response::CsrSubmitStatus(s) => {
                            self.csr_submitted = Status::Known(s.is_some());
                            self.csr_serial = s;
                        }
                        Response::CsrStatus(s) => {
                            self.csr_status = Some(s);
                        }
                        Response::CertificateCreated(cert) => {
                            c.send.blocking_send(Message::WriteCertificate(cert));
                            self.expecting_response = true;
                        }
                        Response::CertificateStored(s) => {
                            if s.is_ok() {
                                self.notes.push("Certificate saved to card".to_string());
                            }
                        }
                        Response::Done => {
                            quit = true;
                        }
                    }
                }
                Err(_) => {}
            }
        }

        egui_multiwin::egui::CentralPanel::default().show(&egui.egui_ctx, |ui| {
            egui_multiwin::egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    {
                        egui_multiwin::egui::ComboBox::from_label(
                            "Select a server to register with",
                        )
                        .selected_text(format!("{:?}", c.config.ca_urls[self.selected_ca_index]))
                        .show_ui(ui, |ui| {
                            for (i, e) in c.config.ca_urls.iter().enumerate() {
                                ui.selectable_value(&mut self.selected_ca_index, i, e);
                            }
                        });
                    }
                    let server_url = &c.config.ca_urls[self.selected_ca_index];
                    ui.label(server_url);
                    match &self.simulator {
                        Some(sim) => {
                            if ui.button("End simulator").clicked() {
                                self.simulator.take();
                            }
                        }
                        None => {
                            if ui.button("Start simulator").clicked() {
                                self.simulator = crate::utility::run_smartcard_sim();
                            }
                        }
                    }
                    if card::is_card_present().is_some() {
                        ui.label("Card is present");
                        match self.erase_status {
                            EraseStatus::Idle => {
                                if ui.button("Erase card").clicked() {
                                    self.erase_status = EraseStatus::Confirming;
                                }
                            }
                            EraseStatus::Confirming => {
                                ui.label("Are you sure you want to erase the smartcard?");
                                if ui.button("No").clicked() {
                                    self.erase_status = EraseStatus::Idle;
                                }
                                if ui.button("Yes").clicked() {
                                    if c.send.blocking_send(Message::ErasePivCard).is_ok() {
                                        self.expecting_response = true;
                                        self.erase_status = EraseStatus::Erasing;
                                    }
                                }
                            }
                            EraseStatus::Erasing => {
                                ui.label("Erasing smartcard");
                            }
                            EraseStatus::Success => {
                                ui.label("Successfully erased smartcard");
                            }
                            EraseStatus::Failed => {
                                ui.label("Failed to erase smartcard");
                            }
                        }
                        if !self.keypair_generating {
                            if ui.button("Generate a keypair").clicked() {
                                c.send.blocking_send(Message::GenerateKeypair);
                                self.expecting_response = true;
                                self.keypair_generating = true;
                            }
                        }
                        match self.csr_submitted {
                            Status::Waiting => {
                                ui.label("Submitting csr for user");
                            }
                            Status::Known(true) => {
                                if let Some(s) = &self.csr_status {
                                    match s {
                                        CsrStatus::Invalid => {
                                            ui.label("The csr was invalid for some reasion");
                                        }
                                        CsrStatus::WaitingForCertificate => {
                                            ui.label("Waiting for certificate");
                                        }
                                        CsrStatus::ReceivedCertificate(cs) => {
                                            ui.label(format!(
                                                "The certificate was accepted: {}",
                                                cs
                                            ));
                                            if ui.button("Write certificate to smartcard").clicked()
                                            {
                                                c.send.blocking_send(Message::WriteCertificate(
                                                    cs.to_owned(),
                                                ));
                                                self.expecting_response = true;
                                            }
                                        }
                                        CsrStatus::Rejected(r) => {
                                            ui.label(format!(
                                                "The certificate was rejected: {}",
                                                r
                                            ));
                                        }
                                    }
                                }
                                ui.label("CSR submitted for signing");
                                if let Some(serial) = &self.csr_serial {
                                    if ui.button("Check CSR status").clicked() {
                                        c.send.blocking_send(Message::CheckCsrStatus {
                                            server: c.config.ca_urls[self.selected_ca_index]
                                                .clone(),
                                            serial: serial.clone(),
                                        });
                                        self.expecting_response = true;
                                    }
                                }
                            }
                            Status::Idle | Status::Known(false) => {
                                if let Some(kp) = &self.keypair {
                                    ui.label("Cardholder Name");
                                    ui.text_edit_singleline(&mut self.csr_data.name);
                                    ui.label("Cardholder email");
                                    ui.text_edit_singleline(&mut self.csr_data.email);
                                    ui.label("Cardholder phone");
                                    ui.text_edit_singleline(&mut self.csr_data.phone);
                                    ui.label("Cardholder country");
                                    ui.text_edit_singleline(&mut self.csr_data.country);
                                    ui.label("Cardholder state");
                                    ui.text_edit_singleline(&mut self.csr_data.state);
                                    ui.label("Cardholder locality");
                                    ui.text_edit_singleline(&mut self.csr_data.locality);
                                    ui.label("Cardholder organization");
                                    ui.text_edit_singleline(&mut self.csr_data.organization);
                                    ui.label("Cardholder organizational unit");
                                    ui.text_edit_singleline(&mut self.csr_data.ou);
                                    ui.label("Challenge password");
                                    let mut te =
                                        egui_multiwin::egui::widgets::TextEdit::singleline(
                                            &mut self.csr_data.cpassword,
                                        )
                                        .password(true);
                                    ui.add(te);
                                    ui.label("Challenge name");
                                    ui.text_edit_singleline(&mut self.csr_data.challenge_name);
                                    ui.checkbox(
                                        &mut self.csr_data.client_id,
                                        "Client identification",
                                    );
                                    ui.checkbox(&mut self.csr_data.code_usage, "Code signing");
                                    if ui.button("Generate CSR for cardholder").clicked() {
                                        let mut csrp = rcgen::CertificateParams::new(vec![self
                                            .csr_data
                                            .name
                                            .clone()]);
                                        if let Ok(mut csrp) = csrp {
                                            self.build_params(&mut csrp);
                                            let pem = csrp.serialize_request(kp);
                                            if let Ok(pem) = pem {
                                                match pem.pem() {
                                                    Ok(pem) => {
                                                        c.send.blocking_send(Message::SubmitCsr {
                                                            csr: pem,
                                                            server: c.config.ca_urls
                                                                [self.selected_ca_index]
                                                                .clone(),
                                                            name: self.csr_data.name.clone(),
                                                            email: self.csr_data.email.clone(),
                                                            phone: self.csr_data.phone.clone(),
                                                        });
                                                        self.expecting_response = true;
                                                    }
                                                    Err(e) => {
                                                        self.notes.push(format!(
                                                            "Failed to build csr pem: {:?}",
                                                            e
                                                        ));
                                                    }
                                                }
                                            } else {
                                                self.notes.push(format!(
                                                    "Failed to build csr: {:?}",
                                                    pem.err()
                                                ));
                                            }
                                        } else {
                                            self.notes.push(format!(
                                                "Failed to build csr params: {:?}",
                                                csrp.err()
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        ui.label("Card is not present");
                        self.keypair = None;
                        self.csr_data = CsrFormData::default();
                        self.csr_submitted = Status::Idle;
                        self.csr_serial = None;
                        self.csr_status = None;
                        self.notes.clear();
                    }
                    if ui.button("Clear notes").clicked() {
                        self.notes.clear();
                    }
                    ui.label("NOTES:");
                    for m in &self.notes {
                        ui.label(m);
                    }
                });
        });
        RedrawResponse {
            quit,
            new_windows: windows_to_create,
        }
    }
}
