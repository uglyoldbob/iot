//! Code for the individual applets managed by the iot manager

use std::collections::HashMap;

use crate::ca::Ca;

mod desfire;

/// Defines the types of variables that can exist for a column of a table
pub enum FieldType {
    /// Integer type
    Integer,
    /// String type
    Text,
    /// Binary data type
    Blob,
}

/// A field for an applet table
pub struct AppletTableField {
    /// The type for the field
    pub ty: FieldType,
    /// True if this is the primary key.
    pub primary_key: bool,
    /// The default value, if applicable
    pub default: Option<String>,
}

/// Defines a table for an applet
pub struct AppletTable {
    /// The subname of the table
    pub name: String,
    /// The fields for the table
    pub fields: Vec<(String, AppletTableField)>,
}

/// The main trait for each individual applet to implement
#[enum_dispatch::enum_dispatch]
pub trait AppletTrait {
    /// Get the applet name
    fn name(&self) -> &str;
    /// Get a list of the admin groups for the applet (there might be only one - that's fine)
    fn admin_groups(&self) -> Vec<&str>;
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
    fn table_setup(&self) -> Vec<AppletTable>;
    /// Run the applet
    async fn run_applet(
        &self,
        html: &mut html::root::builders::HtmlBuilder,
        appletid: i64,
        userid: i64,
        ca: &mut Ca,
        s: &crate::utility::WebPageContext,
    );
}

/// The individual applet instance type
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, strum::EnumIter)]
#[enum_dispatch::enum_dispatch(AppletTrait)]
pub enum AppletInstance {
    /// The applet for managing desfire_ev1 tags.
    DesfireEv1(desfire::Ev1),
}
