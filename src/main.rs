use log::{info};

use network::client;
mod network { pub mod client; }
use logging::logger;
mod logging { pub mod logger; }

fn main() {
    match logger::init(){
        Ok(_result) => {
            info!("Logging initialized");
        }
        Err(_e) => {
            println!("Logging module failed to initialize!");
        }
    }
    let success: bool = client::connect("localhost", 9000);
    println!("{}",success)
}
