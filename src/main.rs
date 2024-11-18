use std::net::UdpSocket;
use codecrafters_dns_server::{Header, Question};


fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buffer = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buffer) {
            Ok((_, source)) => {
                let buf = Vec::from(buffer);
                let header = Header::from_bytes(&buf);
                let rsp_hdr= Header::new(header.id(),
                                        true,
                                            header.opcode(),
                                            false,
                                            false,
                                            header.rd(),
                                            false,
                                            0,
                                            1,
                                            0,
                                            0,
                                            0);
                let mut response = rsp_hdr.to_bytes();
                let question = Question::new("codecrafters.io", 1, 1);
                response.append(&mut question.to_bytes());
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
