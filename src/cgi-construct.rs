//! This is the page for constructing a configuration for the pki instance to run on cgi pages.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(unused_extern_crates)]
#![allow(unused)]
//For the html crate
#![recursion_limit = "512"]

mod ca;
mod hsm2;
mod tpm2;
mod utility;
mod webserver;

mod main_config;
use crate::ca::{
    CaCertificateStorageBuilder, CaCertificateStorageBuilderAnswers, CertificateTypeAnswers,
    ProxyConfig,
};
use cert_common::{CertificateSigningMethod, HttpsSigningMethod, SshSigningMethod};
pub use main_config::{DatabaseSettings, MainConfiguration, SecurityModuleConfiguration};

use std::{collections::HashMap, str::FromStr};

use base64::Engine;

use crate::{
    ca::{PkiConfigurationAnswers, StandaloneCaConfigurationAnswers},
    hsm2::SecurityModule,
    main_config::MainConfigurationAnswers,
};

fn build_toml_string(doc: &MainConfigurationAnswers) -> String {
    let c = toml::to_string(doc).unwrap();
    base64::prelude::BASE64_STANDARD_NO_PAD.encode(c)
}

#[derive(strum::FromRepr, Debug, PartialEq)]
#[repr(usize)]
enum BuildStep {
    Beginning,
    GetSecurityModuleType,
    GetHardwareSecurityOptions,
    ApplyHardwareSecurityOptions,
    GetSoftwareSecurityOptions,
    ApplySoftwareSecurityOptions,
    GetPublicNames,
    ApplyPublicNames,
    GetDatabaseConfig,
    ApplyDatabaseConfig,
    GetProxyConfig,
    ApplyProxyConfig,
    GetTpm2Config,
    ApplyTpm2Config,
    GetSigningMethod,
    GetHttpsSigning,
    GetSshSigning,
    ApplyHttpsSigningMethod,
    ApplySshSigningMethod,
    GetCertStoragePath,
    ApplyCertStoragePath,
    GetAdminType,
    GetExternalAdminCsr,
    ApplyExternalAdminCsr,
    GetSoftAdminCsr,
    ApplySoftAdminCsr,
    GetRemainingOptions,
    ApplyRemainingOptions,
    Finalize,
}

#[tokio::main]
async fn main() {
    cgi::handle_async(async |request: cgi::Request| -> cgi::Response {
        let mut html = html::root::Html::builder();

        let get_map = {
            let mut get_map = HashMap::new();
            let get_data = request.headers().get("x-cgi-query-string");
            if let Some(get_data) = get_data {
                let get_data = get_data.to_str().unwrap();
                let get_split = get_data.split('&');
                for get_elem in get_split {
                    let mut ele_split = get_elem.split('=').take(2);
                    let i1 = ele_split.next().unwrap_or_default();
                    let i2 = ele_split.next().unwrap_or_default();
                    get_map.insert(i1.to_owned(), i2.to_owned());
                }
            }
            get_map
        };

        let post_map = {
            let mut get_map = HashMap::new();
            if let Some(c) = request.headers().get("x-cgi-content-type") {
                if let Ok(c) = c.to_str() {
                    if "application/x-www-form-urlencoded" == c {
                        let body = request.body();
                        let a: String = String::from_utf8(body.clone()).unwrap();
                        let get_data = a;
                        let get_data = get_data;
                        let get_split = get_data.split('&');
                        for get_elem in get_split {
                            let mut ele_split = get_elem.split('=').take(2);
                            let i1 = ele_split.next().unwrap_or_default();
                            let i2 = ele_split.next().unwrap_or_default();
                            let s = urlencoding::decode(i2).unwrap().into_owned().to_string();
                            get_map.insert(i1.to_owned(), s);
                        }
                    }
                }
            }
            get_map
        };

        let example = MainConfigurationAnswers::default();
        let example = toml::to_string(&example).unwrap();

        let toml_plain = post_map
            .get("object")
            .map(|a| base64::prelude::BASE64_STANDARD_NO_PAD.decode(a).ok())
            .unwrap_or(None)
            .map(|t| String::from_utf8(t).ok())
            .flatten();
        let toml_decoded = toml_plain
            .clone()
            .map(|t| toml::from_str::<MainConfigurationAnswers>(&t).ok())
            .flatten();
        let toml_value = match &toml_decoded {
            Some(a) => a.clone(),
            None => MainConfigurationAnswers::default(),
        };
        let mut toml = toml_value;

        let step = post_map
            .get("step")
            .map(|a| a.parse::<usize>().ok())
            .flatten()
            .unwrap_or(0);
        html.head(|h| h.title(|t| t.text("CA Builder")));
        let Some(step) = BuildStep::from_repr(step) else {
            return cgi::html_response(500, "Invalid step");
        };
        match step {
            BuildStep::Beginning => {
                html.body(|b| {
                    b.text(format!("{:#?}<br />\n", request));
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text(format!("TOML EXAMPLE {:#?}<br />\n", example));
                    b.text(format!("GET IS {:#?}<br />\n", get_map));
                    b.text(format!("POST IS {:#?}<br />\n", post_map));
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::GetSecurityModuleType as usize))
                        });
                        f.text("Name of CA");
                        f.line_break(|a| a);
                        f.input(|i| i.name("name"));
                        f.line_break(|a| a);
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.button(|b| b.text("Start"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::GetSecurityModuleType => {
                let Some(p) = post_map.get("name") else {
                    return cgi::html_response(500, "Missing argument");
                };
                toml.pki = ca::PkiConfigurationEnumAnswers::Ca {
                    pki_name: p.clone(),
                    config: Box::new(StandaloneCaConfigurationAnswers::default()),
                };

                html.body(|b| {
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text("Select the security module type");
                    b.line_break(|lb| lb);
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden").name("step").value(format!(
                                "{}",
                                BuildStep::GetHardwareSecurityOptions as usize
                            ))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.button(|b| b.text("Hardware"))
                    });
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden").name("step").value(format!(
                                "{}",
                                BuildStep::GetSoftwareSecurityOptions as usize
                            ))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.button(|b| b.text("Software"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::GetSoftwareSecurityOptions => {
                html.body(|b| {
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text("Select the security module options");
                    b.line_break(|lb| lb);
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden").name("step").value(format!(
                                "{}",
                                BuildStep::ApplySoftwareSecurityOptions as usize
                            ))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.text("Path for software security module files");
                        f.line_break(|a| a);
                        f.input(|i| i.name("hsm_path"));
                        f.line_break(|a| a);
                        f.button(|b| b.type_("submit").text("Next"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::GetHardwareSecurityOptions => {
                html.body(|b| {
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text("Select the security module options");
                    b.line_break(|lb| lb);
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden").name("step").value(format!(
                                "{}",
                                BuildStep::ApplyHardwareSecurityOptions as usize
                            ))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.text("Path override for hardware security module library");
                        f.line_break(|a| a);
                        f.input(|i| i.name("hsm_path"));
                        f.line_break(|a| a);
                        f.text("HSM pin");
                        f.line_break(|a| a);
                        f.input(|i| i.type_("password").name("hsm_pin"));
                        f.line_break(|a| a);
                        f.input(|i| i.type_("password").name("hsm_pin2"));
                        f.line_break(|a| a);
                        f.text("Slot for hardware security module");
                        f.line_break(|a| a);
                        f.input(|i| i.name("hsm_slot").type_("number"));
                        f.line_break(|a| a);
                        f.button(|b| b.type_("submit").text("Next"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::ApplySoftwareSecurityOptions => {
                let Some(hsm_path) = post_map.get("hsm_path") else {
                    return cgi::html_response(500, "Missing argument");
                };
                if let ca::PkiConfigurationEnumAnswers::Ca { pki_name, config } = &mut toml.pki {
                    let h =
                        SecurityModuleConfiguration::Software(std::path::PathBuf::from(hsm_path));
                    config.hsm_config = h;
                    html.body(|b| {
                        b.text("Applied software security module settings");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::GetPublicNames as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                }
            }
            BuildStep::ApplyHardwareSecurityOptions => {
                let Some(hsm_path) = post_map.get("hsm_path") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Some(hsm_pin) = post_map.get("hsm_pin") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Some(hsm_pin2) = post_map.get("hsm_pin2") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Some(hsm_slot) = post_map.get("hsm_slot") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let hsm_slot = if !hsm_slot.is_empty() {
                    let Ok(hsm_slot) = hsm_slot.parse::<usize>() else {
                        return cgi::html_response(500, "Invalid hsm_slot");
                    };
                    Some(hsm_slot)
                } else {
                    None
                };
                if hsm_pin != hsm_pin2 {
                    html.body(|b| {
                        b.text("Hardware security module pins don't match");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::GetSecurityModuleType as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Try again"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                } else {
                    if let ca::PkiConfigurationEnumAnswers::Ca { pki_name, config } = &mut toml.pki
                    {
                        let h = SecurityModuleConfiguration::Hardware {
                            hsm_path_override: if !hsm_path.is_empty() {
                                Some(std::path::PathBuf::from(hsm_path))
                            } else {
                                None
                            },
                            hsm_pin: hsm_pin.clone(),
                            hsm_pin2: hsm_pin2.clone(),
                            hsm_slot,
                        };
                        config.hsm_config = h;
                        html.body(|b| {
                            b.text("Applied hardware security module settings");
                            b.line_break(|lb| lb);
                            b.form(|f| {
                                f.method("POST");
                                f.input(|i| {
                                    i.type_("hidden")
                                        .name("step")
                                        .value(format!("{}", BuildStep::GetPublicNames as usize))
                                });
                                f.input(|i| {
                                    i.type_("hidden")
                                        .name("object")
                                        .value(build_toml_string(&toml))
                                });
                                f.button(|b| b.type_("submit").text("Next"))
                            });
                            b.line_break(|lb| lb);
                            b
                        });
                    }
                }
            }
            BuildStep::GetPublicNames => {
                html.body(|b| {
                    b.text(format!("{:#?}<br />\n", request));
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text(format!("TOML EXAMPLE {:#?}<br />\n", example));
                    b.text(format!("GET IS {:#?}<br />\n", get_map));
                    b.text(format!("POST IS {:#?}<br />\n", post_map));
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::ApplyPublicNames as usize))
                        });
                        f.text("Public Names of CA (like example.com/asdf)");
                        f.line_break(|a| a);
                        f.text_area(|i| i.name("names"));
                        f.line_break(|a| a);
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.button(|b| b.text("Next"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::ApplyPublicNames => {
                let Some(names) = post_map.get("names") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let names = names
                    .lines()
                    .map(|a| ca::ComplexName::from_str(a))
                    .filter(|a| a.is_ok())
                    .map(|a| a.unwrap())
                    .collect();
                if let ca::PkiConfigurationEnumAnswers::Ca { pki_name, config } = &mut toml.pki {
                    config.public_names = names;
                    html.body(|b| {
                        b.text("Applied public names");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::GetDatabaseConfig as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                } else {
                    html.body(|b| {
                        b.text(format!("Invalid object: {:#?}\n<br />\n", toml));
                        b
                    });
                }
            }
            BuildStep::GetDatabaseConfig => {
                html.body(|b| {
                    b.text(format!("{:#?}<br />\n", request));
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text(format!("TOML EXAMPLE {:#?}<br />\n", example));
                    b.text(format!("GET IS {:#?}<br />\n", get_map));
                    b.text(format!("POST IS {:#?}<br />\n", post_map));
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::ApplyDatabaseConfig as usize))
                        });
                        f.text("Database username");
                        f.line_break(|a| a);
                        f.input(|i| i.name("db_username"));
                        f.line_break(|a| a);
                        f.text("Database password");
                        f.line_break(|a| a);
                        f.input(|i| i.name("db_password").type_("password"));
                        f.line_break(|a| a);
                        f.text("Database name");
                        f.line_break(|a| a);
                        f.input(|i| i.name("db_name"));
                        f.line_break(|a| a);
                        f.text("Database url");
                        f.line_break(|a| a);
                        f.input(|i| i.name("db_url"));
                        f.line_break(|a| a);
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.button(|b| b.text("Next"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::ApplyDatabaseConfig => {
                let Some(db_username) = post_map.get("db_username") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Some(db_password) = post_map.get("db_password") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Some(db_name) = post_map.get("db_name") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Some(db_url) = post_map.get("db_url") else {
                    return cgi::html_response(500, "Missing argument");
                };
                if let ca::PkiConfigurationEnumAnswers::Ca { pki_name, config } = &mut toml.pki {
                    config.database = Some(DatabaseSettings {
                        username: db_username.clone(),
                        password: userprompt::Password2::new(db_password.clone()),
                        name: db_name.clone(),
                        url: db_url.clone(),
                    });
                    html.body(|b| {
                        b.text("Applied database settings");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::GetProxyConfig as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                }
            }
            BuildStep::GetProxyConfig => {
                html.body(|b| {
                    b.text(format!("{:#?}<br />\n", request));
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text(format!("TOML EXAMPLE {:#?}<br />\n", example));
                    b.text(format!("GET IS {:#?}<br />\n", get_map));
                    b.text(format!("POST IS {:#?}<br />\n", post_map));
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::ApplyProxyConfig as usize))
                        });
                        f.text("Proxy: http port (blank if not applicable)");
                        f.line_break(|a| a);
                        f.input(|i| i.name("proxy_http"));
                        f.line_break(|a| a);
                        f.text("Proxy: https port (blank if not applicable)");
                        f.line_break(|a| a);
                        f.input(|i| i.name("proxy_https"));
                        f.line_break(|a| a);
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.button(|b| b.text("Next"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::ApplyProxyConfig => {
                let Some(http) = post_map.get("proxy_http") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Some(https) = post_map.get("proxy_https") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let http = if !http.is_empty() {
                    let Ok(v) = http.parse::<u16>() else {
                        return cgi::html_response(500, "Invalid http port");
                    };
                    Some(v)
                } else {
                    None
                };
                let https = if !https.is_empty() {
                    let Ok(v) = https.parse::<u16>() else {
                        return cgi::html_response(500, "Invalid https port");
                    };
                    Some(v)
                } else {
                    None
                };
                if let ca::PkiConfigurationEnumAnswers::Ca { pki_name, config } = &mut toml.pki {
                    if http.is_some() || https.is_some() {
                        config.proxy_config = Some(ProxyConfig {
                            http_port: http,
                            https_port: https,
                        });
                    }
                    #[cfg(feature = "tpm2")]
                    html.body(|b| {
                        b.text("Applied proxy settings");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::GetTpm2Config as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                    #[cfg(not(feature = "tpm2"))]
                    html.body(|b| {
                        b.text("Applied proxy settings");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::GetSigningMethod as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                }
            }
            BuildStep::GetTpm2Config => {
                html.body(|b| {
                    b.text(format!("{:#?}<br />\n", request));
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text(format!("TOML EXAMPLE {:#?}<br />\n", example));
                    b.text(format!("GET IS {:#?}<br />\n", get_map));
                    b.text(format!("POST IS {:#?}<br />\n", post_map));
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::ApplyTpm2Config as usize))
                        });
                        f.text("TPM2 configuration");
                        f.line_break(|a| a);
                        f.text("TPM2 Required?");
                        f.line_break(|a| a);
                        f.input(|i| i.name("tpm2_required").type_("checkbox"));
                        f.line_break(|a| a);
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.button(|b| b.text("Next"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::ApplyTpm2Config => {
                #[cfg(feature = "tpm2")]
                let tpm2_required = post_map
                    .get("tpm2_required")
                    .map(|a| a.to_string())
                    .unwrap_or("off".to_string());
                if let ca::PkiConfigurationEnumAnswers::Ca { pki_name, config } = &mut toml.pki {
                    #[cfg(feature = "tpm2")]
                    {
                        config.tpm2_required = match tpm2_required.as_str() {
                            "on" => true,
                            _ => false,
                        };
                    }
                    html.body(|b| {
                        b.text("Applied tpm2 settings");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::GetSigningMethod as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                }
            }
            BuildStep::GetSigningMethod => {
                html.body(|b| {
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text("Select the signing method");
                    b.line_break(|lb| lb);
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::GetHttpsSigning as usize))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.button(|b| b.text("HTTPS"))
                    });
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::GetSshSigning as usize))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.button(|b: &mut html::forms::builders::ButtonBuilder| b.text("SSH"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::GetHttpsSigning => {
                html.body(|b| {
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text("Select the HTTPS signing method");
                    b.line_break(|lb| lb);
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::ApplyHttpsSigningMethod as usize))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.input(|i| i.type_("hidden").name("method").value("RsaSha256"));
                        f.button(|b| b.text("RsaSha256"))
                    });
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::ApplyHttpsSigningMethod as usize))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.input(|i| i.type_("hidden").name("method").value("EcdsaSha256"));
                        f.button(|b| b.text("EcdsaSha256"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::ApplyHttpsSigningMethod => {
                let Some(method) = post_map.get("method") else {
                    return cgi::html_response(500, "Missing argument");
                };
                if let ca::PkiConfigurationEnumAnswers::Ca { pki_name, config } = &mut toml.pki {
                    match method.as_str() {
                        "RsaSha256" => {
                            config.sign_method =
                                CertificateSigningMethod::Https(HttpsSigningMethod::RsaSha256);
                        }
                        "EcdsaSha256" => {
                            config.sign_method =
                                CertificateSigningMethod::Https(HttpsSigningMethod::EcdsaSha256);
                        }
                        _ => {
                            return cgi::html_response(500, "Invalid signing method");
                        }
                    }
                    html.body(|b| {
                        b.text("Applied https signing method settings");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::GetCertStoragePath as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                }
            }
            BuildStep::GetSshSigning => {
                html.body(|b| {
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text("Select the SSH signing method");
                    b.line_break(|lb| lb);
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::ApplySshSigningMethod as usize))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.input(|i| i.type_("hidden").name("method").value("Rsa"));
                        f.button(|b| b.text("Rsa"))
                    });
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::ApplySshSigningMethod as usize))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.input(|i| i.type_("hidden").name("method").value("Ed25519"));
                        f.button(|b| b.text("Ed25519"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::ApplySshSigningMethod => {
                let Some(method) = post_map.get("method") else {
                    return cgi::html_response(500, "Missing argument");
                };
                if let ca::PkiConfigurationEnumAnswers::Ca { pki_name, config } = &mut toml.pki {
                    match method.as_str() {
                        "Rsa" => {
                            config.sign_method =
                                CertificateSigningMethod::Ssh(SshSigningMethod::Rsa);
                        }
                        "Ed25519" => {
                            config.sign_method =
                                CertificateSigningMethod::Ssh(SshSigningMethod::Ed25519);
                        }
                        _ => {
                            return cgi::html_response(500, "Invalid signing method");
                        }
                    }
                    html.body(|b: &mut html::root::builders::BodyBuilder| {
                        b.text("Applied ssh signing method settings");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::GetCertStoragePath as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                }
            }
            BuildStep::GetCertStoragePath => {
                html.body(|b| {
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text("Select the path for certificates");
                    b.line_break(|lb| lb);
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::ApplyCertStoragePath as usize))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.text("Path for generated certificates");
                        f.line_break(|a| a);
                        f.input(|i| i.name("cert_path"));
                        f.line_break(|a| a);
                        f.button(|b| b.type_("submit").text("Next"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::ApplyCertStoragePath => {
                let Some(cert_path) = post_map.get("cert_path") else {
                    return cgi::html_response(500, "Missing argument");
                };
                if let ca::PkiConfigurationEnumAnswers::Ca { pki_name, config } = &mut toml.pki {
                    config.path = CaCertificateStorageBuilderAnswers::Sqlite(
                        std::path::PathBuf::from(cert_path).into(),
                    );
                    html.body(|b: &mut html::root::builders::BodyBuilder| {
                        b.text("Applied certificate path settings");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::GetAdminType as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                }
            }
            BuildStep::GetAdminType => {
                html.body(|b| {
                    b.text("Configure the admin certificate type");
                    b.line_break(|lb| lb);
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::GetExternalAdminCsr as usize))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.button(|b| b.type_("submit").text("External"))
                    });
                    b.line_break(|lb| lb);
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::GetSoftAdminCsr as usize))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.button(|b| b.type_("submit").text("Soft Internal"))
                    });
                    b
                });
            }
            BuildStep::GetExternalAdminCsr => {
                html.body(|b| {
                    b.text("Configure the external admin certificate");
                    b.line_break(|lb| lb);
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::ApplyExternalAdminCsr as usize))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.button(|b| b.type_("submit").text("Next"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::ApplyExternalAdminCsr => {
                if let ca::PkiConfigurationEnumAnswers::Ca { pki_name, config } = &mut toml.pki {
                    config.admin_access_password =
                        userprompt::Password2::new("fhuieahvehuioqerg".to_string());
                    config.admin_cert = CertificateTypeAnswers::External;
                    html.body(|b: &mut html::root::builders::BodyBuilder| {
                        b.text("Applied external admin certificate settings");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::GetRemainingOptions as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                }
            }
            BuildStep::GetSoftAdminCsr => {
                html.body(|b| {
                    b.text("Configure the admin certificate options");
                    b.line_break(|lb| lb);
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::ApplySoftAdminCsr as usize))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.text("Admin access password - used to access the admin certificate");
                        f.line_break(|a| a);
                        f.input(|i| i.name("admin_access_password").type_("password"));
                        f.line_break(|a| a);
                        f.text("Admin access password again");
                        f.line_break(|a| a);
                        f.input(|i| i.name("admin_access_password2").type_("password"));
                        f.line_break(|a| a);
                        f.text("Admin password");
                        f.line_break(|a| a);
                        f.input(|i| i.name("admin_password").type_("password"));
                        f.line_break(|a| a);
                        f.text("Admin password again");
                        f.line_break(|a| a);
                        f.input(|i| i.name("admin_password2").type_("password"));
                        f.line_break(|a| a);
                        f.button(|b| b.type_("submit").text("Next"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::ApplySoftAdminCsr => {
                let Some(admin_access_password) = post_map.get("admin_access_password") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Some(admin_access_password2) = post_map.get("admin_access_password2") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Some(admin_password) = post_map.get("admin_password") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Some(admin_password2) = post_map.get("admin_password2") else {
                    return cgi::html_response(500, "Missing argument");
                };
                if admin_access_password != admin_access_password2 {
                    return cgi::html_response(500, "Admin access passwords do not match");
                }
                if admin_password != admin_password2 {
                    return cgi::html_response(500, "Admin passwords do not match");
                }
                if let ca::PkiConfigurationEnumAnswers::Ca { pki_name, config } = &mut toml.pki {
                    config.admin_access_password =
                        userprompt::Password2::new(admin_access_password.clone());
                    config.admin_cert = CertificateTypeAnswers::Soft {
                        password: userprompt::Password2::new(admin_password.clone()),
                    };
                    html.body(|b: &mut html::root::builders::BodyBuilder| {
                        b.text("Applied soft admin certificate settings");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::GetRemainingOptions as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Next"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                }
            }
            BuildStep::GetRemainingOptions => {
                html.body(|b| {
                    b.text(format!("TOML PLAIN {:#?}<br />\n", toml_plain));
                    b.text(format!("TOML CONFIG {:#?}<br />\n", toml));
                    b.text("Configure the authority");
                    b.line_break(|lb| lb);
                    b.form(|f| {
                        f.method("POST");
                        f.input(|i| {
                            i.type_("hidden")
                                .name("step")
                                .value(format!("{}", BuildStep::ApplyRemainingOptions as usize))
                        });
                        f.input(|i| {
                            i.type_("hidden")
                                .name("object")
                                .value(build_toml_string(&toml))
                        });
                        f.text("Common Name");
                        f.line_break(|a| a);
                        f.input(|i| i.name("common_name"));
                        f.line_break(|a| a);
                        f.text("Length in days");
                        f.line_break(|a| a);
                        f.input(|i| i.name("length_days"));
                        f.line_break(|a| a);
                        f.text("Maximum chain length");
                        f.line_break(|a| a);
                        f.input(|i| i.name("max_chain_length"));
                        f.line_break(|a| a);
                        f.text("Admin access password - used to access the admin certificate");
                        f.line_break(|a| a);
                        f.input(|i| i.name("admin_access_password").type_("password"));
                        f.line_break(|a| a);
                        f.text("Admin access password again");
                        f.line_break(|a| a);
                        f.input(|i| i.name("admin_access_password2").type_("password"));
                        f.line_break(|a| a);
                        f.text("Admin password");
                        f.line_break(|a| a);
                        f.input(|i| i.name("admin_password").type_("password"));
                        f.line_break(|a| a);
                        f.text("Admin password again");
                        f.line_break(|a| a);
                        f.input(|i| i.name("admin_password2").type_("password"));
                        f.line_break(|a| a);
                        f.text("OCSP signature required?");
                        f.line_break(|a| a);
                        f.input(|i| i.name("ocsp_signature").type_("checkbox"));
                        f.line_break(|a| a);
                        f.button(|b| b.type_("submit").text("Next"))
                    });
                    b.line_break(|lb| lb);
                    b
                });
            }
            BuildStep::ApplyRemainingOptions => {
                let Some(common_name) = post_map.get("common_name") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Some(length_days) = post_map.get("length_days") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Ok(length_days) = length_days.parse::<u32>() else {
                    return cgi::html_response(500, "Invalid number of days");
                };
                let Some(max_chain_length) = post_map.get("max_chain_length") else {
                    return cgi::html_response(500, "Missing argument");
                };
                let Ok(max_chain_length) = max_chain_length.parse::<u8>() else {
                    return cgi::html_response(500, "Invalid maximum chain length");
                };
                let ocsp_signature = post_map
                    .get("ocsp_signature")
                    .map(|a| a.to_string())
                    .unwrap_or("off".to_string());
                if let ca::PkiConfigurationEnumAnswers::Ca { pki_name, config } = &mut toml.pki {
                    config.common_name = common_name.clone();
                    config.days = length_days;
                    config.chain_length = max_chain_length;
                    config.ocsp_signature = match ocsp_signature.as_str() {
                        "on" => true,
                        _ => false,
                    };
                    html.body(|b: &mut html::root::builders::BodyBuilder| {
                        b.text("Applied remaining settings");
                        b.line_break(|lb| lb);
                        b.form(|f| {
                            f.method("POST");
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("step")
                                    .value(format!("{}", BuildStep::Finalize as usize))
                            });
                            f.input(|i| {
                                i.type_("hidden")
                                    .name("object")
                                    .value(build_toml_string(&toml))
                            });
                            f.button(|b| b.type_("submit").text("Finish"))
                        });
                        b.line_break(|lb| lb);
                        b
                    });
                }
            }
            BuildStep::Finalize => {
                let main_config = MainConfiguration::provide_answers(&toml);
                let config_data = toml::to_string(&main_config).unwrap();
                #[cfg(feature = "tpm2")]
                let (pw, econfig) = {
                    #[cfg(feature = "tpm2")]
                    let mut tpm2 = tpm2::Tpm2::new(tpm2::tpm2_path());
                    let (pw, econfig) = if let Some(tpm2) = &mut tpm2 {
                        let password2: [u8; 32] = rand::random();

                        let protected_password = tpm2::Password::build(
                            &password2,
                            std::num::NonZeroU32::new(2048).unwrap(),
                        );

                        let password_combined = protected_password.password();

                        let econfig: Vec<u8> =
                            tpm2::encrypt(config_data.as_bytes(), password_combined);

                        let epdata = protected_password.data();
                        let tpmblob: tpm2::TpmBlob = tpm2.encrypt(&epdata).unwrap();

                        (tpmblob.data(), econfig)
                    } else {
                        service::log::error!("TPM2 NOT DETECTED!!!");
                        if main_config.tpm2_required() {
                            return cgi::html_response(
                                500,
                                "TPM2 not detected and i was told to require it",
                            );
                        }
                        let (pw, config_encrypted) =
                            main_config::do_encryption_without_tpm2(config_data, "default").await;
                        (pw, config_encrypted)
                    };

                    (pw, econfig)
                };
                #[cfg(not(feature = "tpm2"))]
                let (pw, econfig) = {
                    let (pw, config_encrypted) =
                        main_config::do_encryption_without_tpm2(config_data, "default").await;
                    (pw, config_encrypted)
                };
                use std::io::Write;
                let mut zip_contents2 = Vec::new();
                let mut zip_contents = std::io::Cursor::new(&mut zip_contents2);
                let mut zip = zip::ZipWriter::new(&mut zip_contents);
                zip.start_file(
                    "default-credentials.bin",
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Stored)
                        .unix_permissions(0o600),
                );
                zip.write_all(pw.as_bytes());
                zip.start_file(
                    "config.bin",
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Stored)
                        .unix_permissions(0o600),
                );
                zip.write_all(&econfig);
                if let Ok(a) = zip.finish() {
                    return cgi::binary_response(200, "application/zip", zip_contents2);
                } else {
                    html.body(|b: &mut html::root::builders::BodyBuilder| {
                        b.text("FAILED creating settings");
                        b.line_break(|lb| lb);
                        b
                    });
                }
            }
        }
        let html = html.build();
        cgi::html_response(200, html.to_string())
    })
    .await
}
