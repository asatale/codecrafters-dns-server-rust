use std::net::Ipv4Addr;
use core::net::SocketAddr;
use tokio::net::UdpSocket;
use anyhow::Error;
use anyhow::Result;

use crate::message::{ Class, DNSRequest, DNSResponse, Header, Question, RRecord, Type};
const DEFAULT_TTL: u32 = 3600;


pub struct DNSServer {
    pub listen_addr: String,
    conn: Option<UdpSocket>
}

impl DNSServer {
    pub fn new(addr: &str) -> Self {
        DNSServer {
            listen_addr: String::from(addr),
            conn: None
        }
    }

    pub async fn run(&mut self) -> Result<()> {

        match &self.conn {
            Some(_conn) => return Err(Error::msg("Server already running")),
            None => {
                self.conn = Some(UdpSocket::bind(&self.listen_addr).await?);
            }
        }

        let conn = self.conn.as_ref().expect("Socket not available");

        loop {
            let mut buf = [0u8; 512];
            match conn.recv_from(&mut buf).await {
                Ok((size, remote)) => {
                    let msg_buf = Vec::from(&buf[..size]);
                    self.process_request(msg_buf, &remote).await?;
                },
                Err(_e) => {
                    return Err(Error::msg("Error receiving data from socket"));
                }
            }
        }    
    }

    pub async fn process_request(&self, buf: Vec<u8>, remote_add: &SocketAddr) -> Result<()> {

        let request = DNSRequest::from_bytes(&buf).unwrap();
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

        let response = response.to_bytes().unwrap();
        let conn = self.conn.as_ref().expect("Socket not available");
        conn.send_to(&response, remote_add).await?;
        Ok(())
    }
}

