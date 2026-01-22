//! Code for the desfire applet

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct Ev1 {}

impl super::AppletTrait for Ev1 {
    fn name(&self) -> &str {
        "desfire_ev1"
    }

    fn groups(&self) -> Vec<&str> {
        vec!["admin", "manager"]
    }
}
