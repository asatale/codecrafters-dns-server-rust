use std::fmt::Debug;

pub struct Header {
    _id: u16,          // Identifier assigned by the program that generates any kind of query.
    _bitfield: u16,    // QR, Opcode, AA flag, TC flag, RD flag, RA flag, Z, RCODE.
    pub _qdcount: u16, // Number of entries in the question section.
    pub _ancount: u16, // Number of resource records in the answer section.
    pub _nscount: u16, // Number of name server resource records in the authority records section.
    pub _arcount: u16, // Number of resource records in the additional records section.
}

impl Header {

    pub fn new(id: u16, qr: bool, opcode: u8, aa: bool, tc: bool, rd: bool, ra: bool, rcode: u8, qdcount: u16, ancount: u16, nscount: u16, arcount: u16) -> Header {
        Header {
            _id: id,
            _bitfield: (qr as u16) << 15 | (opcode as u16) << 11 | (aa as u16) << 10 | (tc as u16) << 9 | (rd as u16) << 8 | (ra as u16) << 7 | rcode as u16,
            _qdcount: qdcount,
            _ancount: ancount,
            _nscount: nscount,
            _arcount: arcount,
        }
    }
    pub fn from_bytes(bytes: [u8; 12]) -> Header {
        Header {
            _id: u16::from_be_bytes([bytes[0], bytes[1]]),
            _bitfield: u16::from_be_bytes([bytes[2], bytes[3]]),
            _qdcount: u16::from_be_bytes([bytes[4], bytes[5]]),
            _ancount: u16::from_be_bytes([bytes[6], bytes[7]]),
            _nscount: u16::from_be_bytes([bytes[8], bytes[9]]),
            _arcount: u16::from_be_bytes([bytes[10], bytes[11]]),
        }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        [
            self._id.to_be_bytes()[0],
            self._id.to_be_bytes()[1],
            self._bitfield.to_be_bytes()[0],
            self._bitfield.to_be_bytes()[1],
            self._qdcount.to_be_bytes()[0],
            self._qdcount.to_be_bytes()[1],
            self._ancount.to_be_bytes()[0],
            self._ancount.to_be_bytes()[1],
            self._nscount.to_be_bytes()[0],
            self._nscount.to_be_bytes()[1],
            self._arcount.to_be_bytes()[0],
            self._arcount.to_be_bytes()[1],
        ]
    }

    pub fn id(&self) -> u16 {
        self._id
    }

    pub fn qr(&self) -> bool {
        self._bitfield & 0x8000 != 0
    }

    pub fn opcode(&self) -> u8 {
        (self._bitfield & 0x7800 >> 11).try_into().unwrap()
    }

    pub fn aa(&self) -> bool {
        self._bitfield & 0x0400 != 0
    }

    pub fn tc(&self) -> bool {
        self._bitfield & 0x0200 != 0
    }

    pub fn rd(&self) -> bool {
        self._bitfield & 0x0100 != 0
    }

    pub fn ra(&self) -> bool {
        self._bitfield & 0x0080 != 0
    }

    pub fn rcode(&self) -> u8 {
        (self._bitfield & 0x000F).try_into().unwrap()
    }

    pub fn qdcount(&self) -> u16 {
        self._qdcount
    }

    pub fn ancount(&self) -> u16 {
        self._ancount
    }

    pub fn nscount(&self) -> u16 {
        self._nscount
    }

    pub fn arcount(&self) -> u16 {
        self._arcount
    }
}

impl Debug for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let qr_flag = if self.qr() { "Response" } else { "Query" };
        let opcode = match self.opcode() {
            0 => "Standard Query",
            1 => "Inverse Query",
            2 => "Server Status Request",
            _ => "Reserved",
        };
        let aa_flag = if self.aa() { "Authoritative" } else { "Non-authoritative" };
        let tc_flag = if self.tc() { "Truncated" } else { "Not truncated" };
        let rd_flag = if self.rd() { "Recursion Desired" } else { "Recursion Not Desired" };
        let ra_flag = if self.ra() { "Recursion Available" } else { "Recursion Not Available" };
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