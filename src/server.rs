use std::net::UdpSocket;
use std::net::Ipv4Addr;
use anyhow::Error;
use anyhow::Result;

use crate::message::{ Class, DNSRequest, DNSResponse, Header, Question, RRecord, Type};
const DEFAULT_TTL: u32 = 3600;


pub struct DNSServer {
    pub listen_addr: String,
}

impl DNSServer {

    pub fn new(addr: &str) -> Self {
        DNSServer {
            listen_addr: String::from(addr),
        }
    }

    pub fn run(&self) -> Result<()> {
        let udp_socket = UdpSocket::bind(&self.listen_addr).expect("Failed to bind to address");
        let mut buffer = [0; 512];
        loop {
            match udp_socket.recv_from(&mut buffer) {
                Ok((_, source)) => {
                    let buf = Vec::from(buffer);
                    //print_hex(&buf);
                    let request = DNSRequest::from_bytes(&buf).unwrap();
                    //println!("Received {}", request);
                    let mut answers = Vec::<RRecord>::new();
                    let mut questions= Vec::<Question>::new();
                    for q in request.questions {
                        if q.qtype() == Type::A && q.qclass() == Class::IN {
                            questions.push(Question::new(&q.qname(), q.qtype(), q.qclass()));
                            let ip = Ipv4Addr::new(127, 0, 0, 1);
                            let rdata = Vec::<u8>::from_iter(ip.octets());
                            let answer = RRecord::new(q.qname(), Type::A, Class::IN, DEFAULT_TTL, rdata);
                            answers.push(answer);
                        }
                    }
    
                    let response_header =
                        Header::new_response_from_request(request.header, false, answers.len() as u16, 0, 0);
    
                    let response = DNSResponse::new(
                        response_header,
                        questions,
                        answers,
                        Vec::<RRecord>::new(),
                        Vec::<RRecord>::new(),
                    );
                    //println!("Sending {}", response);
                    let response = response.to_bytes().unwrap();
                    //print_hex(&response);
    
                    udp_socket
                        .send_to(&response, source)
                        .expect("Failed to send response");
                }
                Err(e) => {
                    return Err(Error::new(e));
                }
            }
        }    
    }
}

