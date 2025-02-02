use codecrafters_dns_server::server::DNSServer;
use std::{process, env};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let forwarder = match args.len() {
        3 => {
            if args[1] == "--resolver" {
                args[2].clone()
            } else {
                String::new()
            }
        },
        _ => {
            String::new()
        }
    };

    let mut server = DNSServer::new("127.0.0.1:2053", &forwarder);
    match server.run().await {
        Ok(()) => {println!("Should not reach here");}
        Err(e) => {
            eprintln!("Problem parsing arguments: {e}");
            process::exit(1);
        }
    }
}
