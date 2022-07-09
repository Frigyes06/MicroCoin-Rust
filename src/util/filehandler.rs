use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use log::{info, warn};

pub fn openfile(file_name: &str) ->  Result<File, std::io::Error>{
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

pub fn createfile(file_name: &str) -> Result {
    
}