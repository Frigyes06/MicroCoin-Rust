use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};
use log::{info, warn};

pub fn Connect(mut hostname:&str, port:u16){                //tcp connect function
    let host = format!("{}{}{}", hostname, ":", port);   //makes string from hostname and port for the tcp function
    match TcpStream::connect(&host) {
        Ok(mut stream) => {
            info!("connected to: {}", hostname);
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
            warn!("Failed to connect: {}", e);
        }
    }
}