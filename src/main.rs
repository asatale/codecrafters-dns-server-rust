use codecrafters_dns_server::server::DNSServer;
use std::process;

#[tokio::main]
async fn main() {
    let mut server = DNSServer::new("127.0.0.1:2053");
    match server.run().await {
        Ok(()) => {println!("Should not reach here");}
        Err(e) => {
            eprintln!("Problem parsing arguments: {e}");
            process::exit(1);
        }
    }
}
