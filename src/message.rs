#![allow(unused)]
use std::{error::Error, fmt::Debug, str::FromStr};


const DNS_HEADER_SIZE: usize = 12;
const MAX_LABEL_LENGTH: usize = 255;
const RESOURCE_RECORD_MIN_SIZE: usize = 10;


fn print_hex(bytes: &Vec<u8>) {
    println!("{} bytes", bytes.len());
    for (idx, v) in bytes.iter().enumerate() {
        let idx = idx+1;
        print!("{:#04x} ", v);
        if idx % 16 == 0 {
            println!("");
        }
    }
}

#[derive(Debug)]
pub enum ErrorCondition {
    SerializationErr(&'static str),
    DeserializationErr(&'static str),
}

impl std::fmt::Display for ErrorCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ErrorCondition::SerializationErr(msg) => {
                write!(f, "Serialization Error: {}", msg)
            }
            ErrorCondition::DeserializationErr(msg) => {
                write!(f, "Deserialization Error: {}", msg)
            }
        }
    }
}

impl Error for ErrorCondition {}

#[derive(Debug, PartialEq, Eq)]
pub enum Type {
    A = 1,       // a host address
    NS = 2,      // an authoritative name server
    MD = 3,      // a mail destination (Obsolete - use MX)
    MF = 4,      //  a mail forwarder (Obsolete - use MX)
    CNAME = 5,   //the canonical name for an alias
    SOA = 6,     // marks the start of a zone of authority
    MB = 7,      // a mailbox domain name (EXPERIMENTAL)
    MG = 8,      // a mail group member (EXPERIMENTAL)
    MR = 9,      // a mail rename domain name (EXPERIMENTAL)
    NULL = 10,   // a null RR (EXPERIMENTAL)
    WKS = 11,    // a well known service description
    PTR = 12,    // a domain name pointer
    HINFO = 13,  // host information
    MINFO = 14,  // mailbox or mail list information
    MX = 15,     // mail exchange
    TXT = 16,    // text strings
    AXFR = 252,  // A request for a transfer of an entire zone
    MAILB = 253, // A request for mailbox-related records (MB, MG or MR)
    MAILA = 254, // A request for mail agent RRs (Obsolete - see MX)
    _ALL_ = 255, // A request for all records
}
impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let msg: &str = match self {
            Type::A => "a host address",
            Type::NS => "an authoritative name server",
            Type::MD => "a mail destination (Obsolete - use MX)",
            Type::MF => "a mail forwarder (Obsolete - use MX)",
            Type::CNAME => "the canonical name for an alias",
            Type::SOA => "marks the start of a zone of authority",
            Type::MB => "a mailbox domain name (EXPERIMENTAL)",
            Type::MG => "a mail group member (EXPERIMENTAL)",
            Type::MR => "a mail rename domain name (EXPERIMENTAL)",
            Type::NULL => "a null RR (EXPERIMENTAL)",
            Type::WKS => "a well known service description",
            Type::PTR => "a domain name pointer",
            Type::HINFO => "host information",
            Type::MINFO => "mailbox or mail list information",
            Type::MX => "mail exchange",
            Type::TXT => "text strings",
            Type::AXFR => "A request for a transfer of an entire zone",
            Type::MAILB => "A request for mailbox-related records (MB, MG or MR)",
            Type::MAILA => "A request for mail agent RRs (Obsolete - see MX)",
            Type::_ALL_ => "A request for all records",
        };
        write!(f, "Type<{}>", msg)
    }
}

impl Type {
    fn from_bytes(bytes: &[u8], offset:usize) -> Result<(Type, usize), ErrorCondition> {
        let inet_type = match u16::from_be_bytes([bytes[offset], bytes[offset+1]]) {
            1 => Type::A,
            2 => Type::NS,
            3 => Type::MD,
            4 => Type::MF,
            5 => Type::CNAME,
            6 => Type::SOA,
            7 => Type::MB,
            8 => Type::MG,
            9 => Type::MR,
            10 => Type::NULL,
            11 => Type::WKS,
            12 => Type::PTR,
            13 => Type::HINFO,
            14 => Type::MINFO,
            15 => Type::MX,
            16 => Type::TXT,
            252 => Type::AXFR,
            253 => Type::MAILB,
            254 => Type::MAILA,
            255 => Type::_ALL_,
            _ => {
                return Err(ErrorCondition::DeserializationErr("Error in parsing ResourceType"));
            }
        };
        Ok((inet_type, offset+2))
    }
    fn to_bytes(&self) -> Result<[u8; 2], ErrorCondition> {
        let num: u16 = match self {
            Type::A => 1,
            Type::NS => 2,
            Type::MD => 3,
            Type::MF => 4,
            Type::CNAME => 5,
            Type::SOA => 6,
            Type::MB => 7,
            Type::MG => 8,
            Type::MR => 9,
            Type::NULL => 10,
            Type::WKS => 11,
            Type::PTR => 12,
            Type::HINFO => 13,
            Type::MINFO => 14,
            Type::MX => 15,
            Type::TXT => 16,
            Type::AXFR => 252,
            Type::MAILB => 253,
            Type::MAILA => 254,
            Type::_ALL_ => 255,
        };
        Ok(u16::to_be_bytes(num))
    }
}

#[derive(Debug,PartialEq, Eq)]
pub enum Class {
    IN = 1,      // the Internet
    CS = 2,      // the CSNET class (Obsolete)
    CH = 3,      // the CHAOS class
    HS = 4,      // Hesiod
    _ANY_ = 255, // Any class
}
impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let msg: &str = match self {
            Class::IN => "the Internet",
            Class::CS => "the CSNET class (obsolete)",
            Class::CH => "the CHAOS class",
            Class::HS => "Hesiod",
            Class::_ANY_ => "Any Class",
        };
        write!(f, "Class<{}>", msg)
    }
}
impl Class {
    pub fn from_bytes(bytes: &[u8], offset: usize) -> Result<(Class, usize), ErrorCondition> {
        let class=    match u16::from_be_bytes([bytes[offset], bytes[offset+1]]) {
            1 => Class::IN,
            2 => Class::CS,
            3 => Class::CH,
            4 => Class::HS,
            255 => Class::_ANY_,
            _ => {
                return Err(
                    ErrorCondition::DeserializationErr("Received Unknown class value"));
            }
        };
        Ok((class, offset+2))
    }
    pub fn to_bytes(&self) -> Result<[u8; 2], ErrorCondition> {
        let num: u16 = match self {
            Class::IN => 1,
            Class::CS => 2,
            Class::CH => 3,
            Class::HS => 4,
            Class::_ANY_ => 255,
        };
        Ok(u16::to_be_bytes(num))
    }
}

#[derive(Debug)]
struct DomainName {
    name: String,
}


impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ name: {}}}", self.name)
    }
}

impl DomainName {
    fn new(name: &str) -> DomainName {
        DomainName {
            name: String::from_str(name).unwrap(),
        }
    }
    fn from_bytes(bytes: &[u8], offset: usize) -> Result<(DomainName, usize), ErrorCondition> {
        fn increment_by(offset: usize, step: usize, max: usize) -> Result<usize, ErrorCondition> {
            if (offset + step) < max {
                return Ok(offset + step);
            }
            Err(ErrorCondition::DeserializationErr(
                "Short buffer while parsing DomainName",
            ))
        }

        let mut name = String::new();
        let mut offset = offset;
        let buf_length = bytes.len();
        let mut orig_offset = 0;


        while bytes[offset] != 0 {
            let len = (bytes[offset] as u8).to_le();
            // Check for compression
            if (len & 0xC0 as u8) == 0xC0 {
                // if first two bits are set then it represents compression
                offset = increment_by(offset, 1, buf_length)?;
                let ptr = (bytes[offset] as u8).to_le();
                orig_offset = offset;
                // set offset to new compression pointer
                offset = ptr as usize;
            } else {
                offset = increment_by(offset, 1, buf_length)?;
                for i in 0..len {
                    name.push(bytes[offset + i as usize] as char);
                }
                offset = increment_by(offset, len as usize, buf_length)?;
                name.push('.');
            }
        }

        if orig_offset != 0 {
            offset = orig_offset;
        }

        Ok((DomainName::new(&name), offset+1))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, ErrorCondition> {
        let mut bytes = Vec::new();
        for label in self.name.split('.') {
            if label.len() > MAX_LABEL_LENGTH {
                return Err(ErrorCondition::SerializationErr(
                    "Label length more max permitted",
                ));
            }
            if label.len() != 0 {
                bytes.push(label.len() as u8);
                bytes.append(&mut Vec::from(label.as_bytes()));
            }
        }
        bytes.push(0 as u8);
        Ok(bytes)
    }
}


#[derive(Debug)]
pub struct Header {
    id: u16,       // Identifier assigned by the program that generates any kind of query.
    pub bitfield: u16, // QR, Opcode, AA flag, TC flag, RD flag, RA flag, Z, RCODE.
    qdcount: u16,  // Number of entries in the question section.
    ancount: u16,  // Number of resource records in the answer section.
    nscount: u16,  // Number of name server resource records in the authority records section.
    arcount: u16,  // Number of resource records in the additional records section.
}

impl Header {
    pub fn new(
        id: u16,
        qr: bool,
        opcode: u8,
        aa: bool,
        tc: bool,
        rd: bool,
        ra: bool,
        rcode: u8,
        qdcount: u16,
        ancount: u16,
        nscount: u16,
        arcount: u16,
    ) -> Header {
        Header {
            id,
            bitfield: (qr as u16) << 15
                | (opcode as u16) << 11
                | (aa as u16) << 10
                | (tc as u16) << 9
                | (rd as u16) << 8
                | (ra as u16) << 7
                | rcode as u16,
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }
    pub fn new_response_from_request(
        request_header: Header,
        authorative_response: bool,
        answers: u16,
        nameservers: u16,
        additional: u16,
    ) -> Self {
        let mut rcode = 0; // No Error
        let request_opcode = request_header.opcode();
        if request_opcode != 0 { // Not a standard query
            rcode = 4; // Not implemented
        }

        Header::new(
            request_header.id(),
            true,
            request_opcode,
            authorative_response,
            false, // Truncated
            request_header.rd(),
            false,  // Recursion available
            rcode,
            request_header.qdcount(),
            answers,
            nameservers,
            additional,
        )
    }
    pub fn from_bytes(bytes: &[u8], offset: usize) -> Result<Header, ErrorCondition> {
        let bytes = &bytes[offset..];
        if bytes.len() < 12 {
            return Err(ErrorCondition::SerializationErr(
                "Short buffer in parsing header",
            ));
        }
        Ok(Header {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            bitfield: u16::from_be_bytes([bytes[2], bytes[3]]),
            qdcount: u16::from_be_bytes([bytes[4], bytes[5]]),
            ancount: u16::from_be_bytes([bytes[6], bytes[7]]),
            nscount: u16::from_be_bytes([bytes[8], bytes[9]]),
            arcount: u16::from_be_bytes([bytes[10], bytes[11]]),
        })
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, ErrorCondition> {
        Ok(Vec::from([
            self.id.to_be_bytes()[0],
            self.id.to_be_bytes()[1],
            self.bitfield.to_be_bytes()[0],
            self.bitfield.to_be_bytes()[1],
            self.qdcount.to_be_bytes()[0],
            self.qdcount.to_be_bytes()[1],
            self.ancount.to_be_bytes()[0],
            self.ancount.to_be_bytes()[1],
            self.nscount.to_be_bytes()[0],
            self.nscount.to_be_bytes()[1],
            self.arcount.to_be_bytes()[0],
            self.arcount.to_be_bytes()[1],
        ]))
    }
    pub fn id(&self) -> u16 {
        self.id
    }
    pub fn qr(&self) -> bool {
        self.bitfield & 0x8000 != 0
    }
    pub fn opcode(&self) -> u8 {
        let b = self.bitfield & 0x7800;
        let b = (b >> 11) as u8;
        b
    }
    pub fn aa(&self) -> bool {
        self.bitfield & 0x0400 != 0
    }
    pub fn tc(&self) -> bool {
        self.bitfield & 0x0200 != 0
    }
    pub fn rd(&self) -> bool {
        self.bitfield & 0x0100 != 0
    }
    pub fn ra(&self) -> bool {
        self.bitfield & 0x0080 != 0
    }
    pub fn rcode(&self) -> u8 {
        (self.bitfield & 0x000F).try_into().unwrap()
    }
    pub fn qdcount(&self) -> u16 {
        self.qdcount
    }
    pub fn ancount(&self) -> u16 {
        self.ancount
    }
    pub fn nscount(&self) -> u16 {
        self.nscount
    }
    pub fn arcount(&self) -> u16 {
        self.arcount
    }
}

impl std::fmt::Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let qr_flag = if self.qr() { "Response" } else { "Query" };
        let opcode = match self.opcode() {
            0 => "Standard Query",
            1 => "Inverse Query",
            2 => "Server Status Request",
            _ => "Reserved",
        };
        let aa_flag = if self.aa() {
            "Authoritative"
        } else {
            "Non-authoritative"
        };
        let tc_flag = if self.tc() {
            "Truncated"
        } else {
            "Not truncated"
        };
        let rd_flag = if self.rd() {
            "Recursion Desired"
        } else {
            "Recursion Not Desired"
        };
        let ra_flag = if self.ra() {
            "Recursion Available"
        } else {
            "Recursion Not Available"
        };
        let rcode = match self.rcode() {
            0 => "No Error",
            1 => "Format Error",
            2 => "Server Failure",
            3 => "Name Error",
            4 => "Not Implemented",
            5 => "Refused",
            _ => "Reserved",
        };

        write!(f, "Header {{ id: {}, qr: {}, opcode: {}, aa: {}, tc: {}, rd: {}, ra: {}, rcode: {}, qdcount: {}, ancount: {}, nscount: {}, arcount: {} }}",
            self.id(),
            qr_flag,
            opcode,
            aa_flag,
            tc_flag,
            rd_flag,
            ra_flag,
            rcode,
            self.qdcount(),
            self.ancount(),
            self.nscount(),
            self.arcount()
        )
    }
}

#[derive(Debug)]
pub struct Question {
    qname: DomainName,
    qtype: Type,
    qclass: Class,
}

impl std::fmt::Display for Question {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Question {{ qname: {}, qt: {},  qc: {} }}",
            self.qname, self.qtype, self.qclass
        )
    }
}

impl Question {
    pub fn new(qname: &str, qtype: Type, qclass: Class) -> Question {
        Question {
            qname: DomainName::new(qname),
            qtype,
            qclass,
        }
    }

    pub fn from_bytes(bytes: &[u8], offset: usize) -> Result<(Question, usize), ErrorCondition> {
        let (qname, offset) = DomainName::from_bytes(bytes, offset)?;
        let (qtype, offset) = Type::from_bytes(bytes, offset)?;
        let (qclass, offset) = Class::from_bytes(bytes, offset)?;

        Ok((
            Question {
                qname,
                qtype: qtype,
                qclass: qclass,
            },
            offset,
        ))
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, ErrorCondition> {
        let mut bytes = self.qname.to_bytes()?;
        let qtype = self.qtype.to_bytes()?;
        let qclass = self.qclass.to_bytes()?;

        bytes.append(&mut Vec::from(qtype));
        bytes.append(&mut Vec::from(qclass));

        Ok(bytes)
    }
    pub fn qname(&self) -> String {
        self.qname.name.clone()
    }
    pub fn qtype(&self) -> Type {
        match self.qtype {
            Type::A => Type::A,
            Type::NS => Type::NS,
            Type::MD => Type::MD,
            Type::MF => Type::MF,
            Type::CNAME => Type::CNAME,
            Type::SOA => Type::SOA,
            Type::MB => Type::MB,
            Type::MG => Type::MG,
            Type::MR => Type::MR,
            Type::NULL => Type::NULL,
            Type::WKS => Type::WKS,
            Type::PTR => Type::PTR,
            Type::HINFO => Type::HINFO,
            Type::MINFO => Type::MINFO,
            Type::MX => Type::MX,
            Type::TXT => Type::TXT,
            Type::AXFR => Type::AXFR,
            Type::MAILB => Type::MAILB,
            Type::MAILA => Type::MAILA,
            Type::_ALL_ => Type::_ALL_
        }
    }
    pub fn qclass(&self) -> Class {
        match self.qclass {
            Class::IN => Class::IN,
            Class::CS => Class::CS,
            Class::CH => Class::CH,
            Class::HS => Class::HS,
            Class::_ANY_ => Class::_ANY_
        }
    }

}

#[derive(Debug)]
pub struct RRecord {
    name: DomainName,
    rtype: Type,
    class: Class,
    ttl: u32,
    rdata: Vec<u8>,
}

impl std::fmt::Display for RRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RR {{ name: {}, type: {},  class: {}, ttl: {}, rdata: {:?} }}",
            self.name, self.rtype, self.class, self.ttl, self.rdata
        )
    }
}

impl RRecord {
    pub fn new(name: String, rtype: Type, class: Class, ttl: u32, rdata: Vec<u8>) -> RRecord {
        RRecord {
            name: DomainName::new(&name),
            rtype: rtype,
            class: class,
            ttl: ttl,
            rdata: rdata.clone(),
        }
    }

    pub fn from_bytes(bytes: &[u8], offset: usize) -> Result<(RRecord, usize), ErrorCondition> {
        let (domain_name, offset) = DomainName::from_bytes(bytes, offset)?;
        if bytes.len() - offset < RESOURCE_RECORD_MIN_SIZE {
            return Err(ErrorCondition::DeserializationErr("Short buffer parsing"));
        }
        let (rrtype, offset) = Type::from_bytes(bytes, offset)?;
        let (rclass, offset) = Class::from_bytes(bytes, offset)?;

        let (ttl_bytes, rest) = bytes[offset..].split_at(std::mem::size_of::<u32>());
        let ttl: u32 = u32::from_be_bytes(ttl_bytes.try_into().unwrap());
        let offset = offset + 4;

        let (rd_len_bytes, rest) = rest.split_at(std::mem::size_of::<u16>());
        let rd_len: usize = u16::from_be_bytes(rd_len_bytes.try_into().unwrap()) as usize;
        let offset = offset + 2;

        if rest.len() < rd_len {
            return Err(ErrorCondition::DeserializationErr("Short buffer parsing"));
        }
        let offset = offset + rd_len;

        let rdata: Vec<u8> = Vec::from(rest);
        let rrecord = RRecord::new(domain_name.name, rrtype, rclass, ttl, rdata);
        Ok((rrecord, offset))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ErrorCondition> {
        let mut bytes = self.name.to_bytes()?;
        let rrtype = self.rtype.to_bytes()?;
        let rclass = self.class.to_bytes()?;
        let ttl = u32::to_be_bytes(self.ttl);
        let rdlen = u16::to_be_bytes(self.rdata.len() as u16);
        let mut rdata = self.rdata.clone();

        bytes.append(&mut Vec::from(rrtype));
        bytes.append(&mut Vec::from(rclass));
        bytes.append(&mut Vec::from(ttl));
        bytes.append(&mut Vec::from(rdlen));
        bytes.append(&mut rdata);

        Ok(bytes)
    }
}

#[derive(Debug)]
pub struct DNSRequest {
    pub header: Header,
    pub questions: Vec<Question>,
    pub additional: Vec<RRecord>,
}

impl std::fmt::Display for DNSRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut qstring = String::new();
        for q in &self.questions {
            qstring.push_str(&format!("{}", q));
        }
        write!(
            f,
            "DNS_Request {{ header: {}, question: {}}}",
            self.header, qstring
        )
    }
}

impl DNSRequest {
    pub fn new(header: Header, question: Vec<Question>, additional: Vec<RRecord>) -> DNSRequest {
        DNSRequest {
            header: header,
            questions: question,
            additional: additional,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<DNSRequest, ErrorCondition> {
        let mut offset = 0;
        let header = Header::from_bytes(bytes, offset)?;
        offset += DNS_HEADER_SIZE;

        let mut questions = Vec::<Question>::new();
        for _i in 0..header.qdcount() {
            let (question, skip) = Question::from_bytes(bytes, offset).unwrap();
            offset = skip;
            questions.push(question);
        }
        let mut additional = Vec::<RRecord>::new();
        for _i in 0..header.arcount() {
            match RRecord::from_bytes(bytes, offset) {
                Ok(r) => {
                    additional.push(r.0);
                    offset = r.1;
                }
                Err(e) => {
                    println!("Err in handling additional record");
                }
            }
        }

        Ok(DNSRequest {
            header: header,
            questions: questions,
            additional: Vec::<RRecord>::new()
        })
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, ErrorCondition> {
        assert!(self.header.qdcount == self.questions.len() as u16);
        let mut bytes = self.header.to_bytes()?;
        for q in &self.questions {
            let mut question = q.to_bytes()?;
            bytes.append(&mut question);
        }
        Ok(bytes)
    }
}

#[derive(Debug)]
pub struct DNSResponse {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<RRecord>,
    pub authority: Vec<RRecord>,
    pub additional: Vec<RRecord>,
}

impl std::fmt::Display for DNSResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut qstring = String::new();
        for q in &self.questions {
            qstring.push_str(&format!("{}", q));
        }

        let mut astring = String::new();
        for a in &self.answers {
            astring.push_str(&format!("{}", a));
        }

        let mut austring = String::new();
        for au in &self.authority {
            austring.push_str(&format!("{}", au));
        }

        let mut adstring = String::new();
        for ad in &self.additional {
            adstring.push_str(&format!("{}", ad));
        }
        write!(
            f,
            "DNS_Response {{ header: {}, question: {}, answers: {}, authority: {}, additional: {}}}",
            self.header, qstring, astring, austring, adstring
        )
    }
}

impl DNSResponse {
    pub fn new(
        header: Header,
        question: Vec<Question>,
        answer: Vec<RRecord>,
        authority: Vec<RRecord>,
        additional: Vec<RRecord>,
    ) -> DNSResponse {
        DNSResponse {
            header: header,
            questions: question,
            answers: answer,
            authority: authority,
            additional: additional,
        }
    }

    pub fn from_bytes(bytes: &[u8], offset:usize) -> Result<DNSResponse, ErrorCondition> {
        let header = Header::from_bytes(bytes, offset)?;
        let mut offset = offset + DNS_HEADER_SIZE;

        let mut questions = Vec::<Question>::new();
        for _i in 0..header.qdcount() {
            let (question, skip) = Question::from_bytes(bytes, offset).unwrap();
            offset = skip;
            questions.push(question);
        }

        let mut answers = Vec::<RRecord>::new();
        for _i in 0..header.ancount() {
            let (answer, skip) = RRecord::from_bytes(bytes, offset).unwrap();
            offset = skip;
            answers.push(answer);
        }

        let mut nsservers = Vec::<RRecord>::new();
        for _i in 0..header.nscount() {
            let (ns, skip) = RRecord::from_bytes(bytes, offset).unwrap();
            offset = skip;
            nsservers.push(ns);
        }

        let mut additional = Vec::<RRecord>::new();
        for _i in 0..header.nscount() {
            let (ad, skip) = RRecord::from_bytes(bytes, offset).unwrap();
            offset = skip;
            additional.push(ad);
        }
        Ok(DNSResponse {
            header: header,
            questions: questions,
            answers: answers,
            authority: nsservers,
            additional: additional,
        })
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, ErrorCondition> {
        assert!(self.header.qdcount == self.questions.len() as u16);
        let mut bytes = self.header.to_bytes()?;
        for q in &self.questions {
            let mut question = q.to_bytes()?;
            bytes.append(&mut question);
        }
        for an in &self.answers {
            let mut answer = an.to_bytes()?;
            bytes.append(&mut answer);
        }
        for ns in &self.authority {
            let mut nsserver = ns.to_bytes()?;
            bytes.append(&mut nsserver);
        }
        for ad in &self.additional {
            let mut addtional = ad.to_bytes()?;
            bytes.append(&mut addtional);
        }
        Ok(bytes)
    }
}

