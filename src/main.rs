#![allow(unused)]
use codecrafters_dns_server::{server::DNSServer};


fn main() {
    let server = DNSServer::new("127.0.0.1:2053");
    match server.run() {
        Ok(()) => {println!("Should not reach here");}
        Err(e) => {println!("Failed to start Server");}
    }
}
