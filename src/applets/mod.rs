//! Code for the individual applets managed by the iot manager

mod desfire;

/// The main trait for each individual applet to implement
#[enum_dispatch::enum_dispatch]
pub trait AppletTrait {
    /// Get the applet name
    fn name(&self) -> &str;
    /// Get a list of groups for the applet
    fn groups(&self) -> Vec<&str>;
}

/// The individual applet instance type
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, strum::EnumIter)]
#[enum_dispatch::enum_dispatch(AppletTrait)]
pub enum AppletInstance {
    /// The applet for managing desfire_ev1 tags.
    DesfireEv1(desfire::Ev1),
}
