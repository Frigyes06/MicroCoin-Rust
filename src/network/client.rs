use std::net::{TcpStream};
use log::{info, warn};

pub fn connect(hostname:&str, port:u16) -> bool {           //tcp connect function
    let host = format!("{}{}{}", hostname, ":", port);          //makes string from hostname and port for the tcp function
    match TcpStream::connect(&host) {
        Ok(_stream) => {
            info!("connected to: {}", hostname);
        }
        Err(e) => {
            warn!("Failed to connect: {}", e);
            return false;
        }
    }
    return true;
}