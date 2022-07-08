use net::client;
mod net { pub mod client; }

fn main() {
    let success = client::Connect("localhost", 9000);
    println!("{}",success)
}
