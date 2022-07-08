use net::client;
mod net { pub mod client; }

fn main() {
    client::Connect("localhost", 9000);
}
