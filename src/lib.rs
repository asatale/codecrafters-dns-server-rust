use std::{error::Error, fmt::Debug, str::FromStr};

const DNS_HEADER_SIZE: usize = 12;
const MAX_LABEL_LENGTH: usize = 255;
const RESOURCE_RECORD_MIN_SIZE: usize = 10;

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
    fn from_bytes(bytes: &[u8]) -> Result<Type, ErrorCondition> {
        match u16::from_be_bytes([bytes[0], bytes[1]]) {
            1 => Ok(Type::A),
            2 => Ok(Type::NS),
            3 => Ok(Type::MD),
            4 => Ok(Type::MF),
            5 => Ok(Type::CNAME),
            6 => Ok(Type::SOA),
            7 => Ok(Type::MB),
            8 => Ok(Type::MG),
            9 => Ok(Type::MR),
            10 => Ok(Type::NULL),
            11 => Ok(Type::WKS),
            12 => Ok(Type::PTR),
            13 => Ok(Type::HINFO),
            14 => Ok(Type::MINFO),
            15 => Ok(Type::MX),
            16 => Ok(Type::TXT),
            252 => Ok(Type::AXFR),
            253 => Ok(Type::MAILB),
            254 => Ok(Type::MAILA),
            255 => Ok(Type::_ALL_),
            _ => Err(ErrorCondition::DeserializationErr(
                "Error in parsing ResourceType",
            )),
        }
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Class, ErrorCondition> {
        match u16::from_be_bytes([bytes[0], bytes[1]]) {
            1 => Ok(Class::IN),
            2 => Ok(Class::CS),
            3 => Ok(Class::CH),
            4 => Ok(Class::HS),
            255 => Ok(Class::_ANY_),
            _ => Err(ErrorCondition::DeserializationErr(
                "Received Unknown class value",
            )),
        }
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
    fn from_bytes(bytes: &[u8]) -> Result<(DomainName, usize), ErrorCondition> {
        fn increment_by(offset: usize, step: usize, max: usize) -> Result<usize, ErrorCondition> {
            if (offset + step) < max {
                return Ok(offset + step);
            }
            Err(ErrorCondition::DeserializationErr(
                "Short buffer while parsing DomainName",
            ))
        }

        let mut name = String::new();
        let mut offset = 0;
        let buf_length = bytes.len();

        while bytes[offset] != 0 {
            let len = (bytes[offset] as u8).to_le();
            offset = increment_by(offset, 1, buf_length)?;
            for i in 0..len {
                name.push(bytes[offset + i as usize] as char);
            }
            offset = increment_by(offset, len as usize, buf_length)?;
            if bytes[offset] == 0 {
                break;
            }
            name.push('.');
        }
        Ok((DomainName::new(&name), offset + 1))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, ErrorCondition> {
        let mut bytes = Vec::new();
        for label in self.name.split('.') {
            if label.len() > MAX_LABEL_LENGTH {
                return Err(ErrorCondition::SerializationErr(
                    "Label length more max permitted",
                ));
            }
            bytes.push(label.len() as u8);
            bytes.append(&mut Vec::from(label.as_bytes()));
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Header, ErrorCondition> {
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

    pub fn from_bytes(bytes: &[u8]) -> Result<(Question, usize), ErrorCondition> {
        let (qname, offset) = DomainName::from_bytes(bytes)?;

        if bytes.len() - offset < 4 {
            // Assert for presence of additional 4 bytes for type and class
            return Err(ErrorCondition::DeserializationErr(
                "Short buffer parsing Question",
            ));
        }
        Ok((
            Question {
                qname,
                qtype: Type::from_bytes(&bytes[offset..offset + 2])?,
                qclass: Class::from_bytes(&bytes[offset + 2..offset + 4])?,
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

    pub fn from_bytes(bytes: &[u8]) -> Result<(RRecord, usize), ErrorCondition> {
        let (domain_name, offset) = DomainName::from_bytes(bytes)?;
        if bytes.len() - offset < RESOURCE_RECORD_MIN_SIZE {
            return Err(ErrorCondition::DeserializationErr("Short buffer parsing"));
        }
        let rrtype = Type::from_bytes(&bytes[offset..])?;
        let offset = offset + 2;

        let rclass = Class::from_bytes(&bytes[offset + 2..])?;
        let offset = offset + 2;

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
    pub fn new(header: Header, question: Vec<Question>) -> DNSRequest {
        DNSRequest {
            header: header,
            questions: question,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<DNSRequest, ErrorCondition> {
        let header = Header::from_bytes(bytes)?;
        let bytes = &bytes[DNS_HEADER_SIZE..];
        let mut questions = Vec::<Question>::new();
        let mut skip = 0;
        for _i in 0..header.qdcount() {
            let bytes = &bytes[skip..];
            let (question, offset) = Question::from_bytes(bytes).unwrap();
            skip = offset;
            questions.push(question);
        }
        Ok(DNSRequest {
            header: header,
            questions: questions,
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

    pub fn from_bytes(bytes: &[u8]) -> Result<DNSResponse, ErrorCondition> {
        let header = Header::from_bytes(bytes)?;
        let bytes = &bytes[DNS_HEADER_SIZE..];
        let mut skip = 0;

        let mut questions = Vec::<Question>::new();
        for _i in 0..header.qdcount() {
            let bytes = &bytes[skip..];
            let (question, offset) = Question::from_bytes(bytes).unwrap();
            skip = offset;
            questions.push(question);
        }

        let mut answers = Vec::<RRecord>::new();
        for _i in 0..header.ancount() {
            let bytes = &bytes[skip..];
            let (answer, offset) = RRecord::from_bytes(bytes).unwrap();
            skip = offset;
            answers.push(answer);
        }

        let mut nsservers = Vec::<RRecord>::new();
        for _i in 0..header.nscount() {
            let bytes = &bytes[skip..];
            let (ns, offset) = RRecord::from_bytes(bytes).unwrap();
            skip = offset;
            nsservers.push(ns);
        }

        let mut additional = Vec::<RRecord>::new();
        for _i in 0..header.nscount() {
            let bytes = &bytes[skip..];
            let (ad, offset) = RRecord::from_bytes(bytes).unwrap();
            skip = offset;
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
