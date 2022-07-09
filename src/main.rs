use log::{info};
use std::fs::File;

use network::client;
mod network { pub mod client; }
use logging::logger;
mod logging { pub mod logger; }
use cryptography::eckeypair;

use crate::cryptography::eckeypair::{exportprivatekey, exportpubkey};
mod cryptography { pub mod eckeypair; }
use util::filehandler;
mod util { pub mod filehandler; }

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
    let privatekey = exportprivatekey(&new_key);
    println!("{}", privatekey);
    exportpubkey(&new_key);
    init_wallet_keys();
}

fn init_wallet_keys() {
    match filehandler::openfile("WalletKeys.dat"){
        Ok(result) => {
            info!("WalletKeys.dat found.");
        }
        Err(_e) => {
            info!("No WalletKey.dat found, creating a new one!");
            let result = filehandler::createfile("WalletKeys.dat");
        }
    }
}
