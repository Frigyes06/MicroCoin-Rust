use std::{fs::File, io::Stdout};
use std::io::{prelude::*, Error};
use std::path::Path;
use log::{info, warn};

pub fn openfile(file_name: &str) ->  Result<File, Error>{
    let path = Path::new(file_name);
    let display = path.display();
    let mut file = match File::open(&path) {
        Err(why) => {
            warn!("couldn't open {}: {}", display, why);
            return Err(why);
        }
        Ok(file) => file,
    };
    return Ok(file);
}

pub fn createfile(file_name: &str) -> Result<File, Error> {
    let path = Path::new(file_name);
    let display = path.display();

    // Open a file in write-only mode, returns `io::Result<File>`
    let mut file = match File::create(&path) {
        Err(why) => {
            warn!("couldn't create {}: {}", display, why);
            return Err(why);
    }
        Ok(file) => return Ok(file),
    };
}