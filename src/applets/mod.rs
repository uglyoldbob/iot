//! Code for the individual applets managed by the iot manager

mod desfire;

/// The main trait for each individual applet to implement
#[enum_dispatch::enum_dispatch]
pub trait AppletTrait {
    /// Get the applet name
    fn name(&self) -> &str;
    /// Get a list of groups for the applet
    fn groups(&self) -> Vec<&str>;
    /// Build the html form for modifying the data
    fn html_form<F: FnOnce(&mut html::forms::builders::FormBuilder)>(
        &self,
        html: &mut html::root::builders::HtmlBuilder,
        fbm: F,
    );
    /// Apply changes from the html form
    fn apply_form_data(&mut self, data: url_encoded_data::UrlEncodedData);
    /// Get list of all tables
    fn table_names(&self) -> Vec<&str>;
}

/// The individual applet instance type
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, strum::EnumIter)]
#[enum_dispatch::enum_dispatch(AppletTrait)]
pub enum AppletInstance {
    /// The applet for managing desfire_ev1 tags.
    DesfireEv1(desfire::Ev1),
}
