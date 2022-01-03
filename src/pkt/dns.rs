#![allow(unused)]
use super::{Serialize, AsBytes};

pub(crate) mod opcode {
    pub const QUERY: u8 = 0;
    pub const IQUERY: u8 = 1;
    pub const STATUS: u8 = 2;
}

pub(crate) mod flags {
    pub const RESPONSE: u16 = 0x8000;

    pub fn from_opcode(opcode: u8) -> u16 {
        ((opcode & 7) as u16) << 14
    }
}

pub(crate) mod rrtype {
    pub const A: u8 = 1;
    pub const NS: u8 = 2;
    pub const MD: u8 = 3;
    pub const MF: u8 = 4;
    pub const CDNS_NAME: u8 = 5;
    pub const SOA: u8 = 6;
    pub const MB: u8 = 7;
    pub const MG: u8 = 8;
    pub const NMR: u8 = 9;
    pub const NULL: u8 = 10;
    pub const WKS: u8 = 11;
    pub const PTR: u8 = 12;
    pub const HINFO: u8 = 13;
    pub const MINFO: u8 = 14;
    pub const MX: u8 = 15;
    pub const TXT: u8 = 16;
    pub const AXFR: u8 = 252;
    pub const MAILB: u8 = 253;
    pub const MAILA: u8 = 254;
    pub const ALL: u8 = 255;
}

pub(crate) mod class {
    pub const IN: u8 = 1;
    pub const CS: u8 = 2;
    pub const CH: u8 = 3;
    pub const HS: u8 = 4;
    pub const ANY: u8 = 255;
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub(crate) struct dns_hdr {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}
impl Serialize for dns_hdr {}

impl Default for dns_hdr {
    fn default() -> Self {
        Self {
            id: 0,
            flags: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
}

impl dns_hdr {
    pub fn id(&mut self, id: u16) -> &mut Self {
        self.id = id.to_be();
        self
    }

    pub fn flags(&mut self, flags: u16) -> &mut Self {
        self.flags = flags.to_be();
        self
    }

    pub fn qdcount(&mut self, qdcount: u16) -> &mut Self {
        self.qdcount = qdcount.to_be();
        self
    }

    pub fn ancount(&mut self, ancount: u16) -> &mut Self {
        self.ancount = ancount.to_be();
        self
    }

    pub fn nscount(&mut self, nscount: u16) -> &mut Self {
        self.nscount = nscount.to_be();
        self
    }

    pub fn arcount(&mut self, arcount: u16) -> &mut Self {
        self.arcount = arcount.to_be();
        self
    }
}
