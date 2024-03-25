#[path = "ca_construct.rs"]
mod ca;
mod main_config;
pub mod oid;
pub mod pkcs12;
pub use main_config::MainConfiguration;

#[tokio::main]
async fn main() {
    println!("This program constructs a new iot instance");
}
