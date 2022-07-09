use log::{info};

use network::client;
mod network { pub mod client; }
use logging::logger;
mod logging { pub mod logger; }
use cryptography::eckeypair;

use crate::cryptography::eckeypair::exportprivatekey;
mod cryptography { pub mod eckeypair; }

fn main() {
    match logger::init(){
        Ok(_result) => {
            info!("Logging initialized");
        }
        Err(_e) => {
            println!("Logging module failed to initialize!");
        }
    }
    let success: bool = client::connect("localhost", 4004);
    println!("{}",success);
    let new_key = eckeypair::createnewkeypair();
    println!("private eckey = {:?}", new_key.private_key());
    let privatekey = exportprivatekey(new_key);
    println!("{}", privatekey)
}
