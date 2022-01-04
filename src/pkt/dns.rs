#![allow(unused)]
use super::{Serialize, AsBytes};

pub(crate) mod opcode {
    pub const QUERY: u8 = 0;
    pub const IQUERY: u8 = 1;
    pub const STATUS: u8 = 2;
}

pub(crate) mod rcode {
    pub const NOERROR: u8 = 0;
    pub const FORMERROR: u8 = 1;
    pub const SERVFAIL: u8 = 2;
    pub const NXDOMAIN: u8 = 3;
    pub const NOTIMP: u8 = 4;
    pub const REFUSED: u8 = 5;
    pub const YXDOMAIN: u8 = 6;
    pub const XRRSET: u8 = 7;
    pub const NOTAUTH: u8 = 8;
    pub const NOTZONE: u8 = 9;
}

pub(crate) mod flags {
    /// Response message
    pub const RESPONSE: u16 = 0x8000;

    /// Authoritative answer
    pub const AA: u16 = 0x0400;

    /// Truncation
    pub const TC: u16 = 0x0200;

    /// Recursion desired
    pub const RD: u16 = 0x0100;

    /// Recursion available
    pub const RA: u16 = 0x0080;

    pub fn from_opcode(opcode: u8) -> u16 {
        ((opcode & 7) as u16) << 14
    }

    pub fn from_rcode(opcode: u8) -> u16 {
        (opcode & 0xf) as u16
    }
}

pub(crate) mod rrtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const MD: u16 = 3;
    pub const MF: u16 = 4;
    pub const CDNS_NAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const MB: u16 = 7;
    pub const MG: u16 = 8;
    pub const NMR: u16 = 9;
    pub const NULL: u16 = 10;
    pub const WKS: u16 = 11;
    pub const PTR: u16 = 12;
    pub const HINFO: u16 = 13;
    pub const MINFO: u16 = 14;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AXFR: u16 = 252;
    pub const MAILB: u16 = 253;
    pub const MAILA: u16 = 254;
    pub const ALL: u16 = 255;
}

pub(crate) mod class {
    pub const IN: u16 = 1;
    pub const CS: u16 = 2;
    pub const CH: u16 = 3;
    pub const HS: u16 = 4;
    pub const ANY: u16 = 255;
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct dns_hdr {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}
impl Serialize for dns_hdr {}

impl dns_hdr {
    pub fn builder() -> DnsHdrBuilder {
        DnsHdrBuilder::default()
    }

    pub fn set_id(&mut self, id: u16) -> &mut Self {
        self.id = id.to_be();
        self
    }

    pub fn set_flags(&mut self, flags: u16) -> &mut Self {
        self.flags = flags.to_be();
        self
    }

    pub fn set_qdcount(&mut self, qdcount: u16) -> &mut Self {
        self.qdcount = qdcount.to_be();
        self
    }

    pub fn set_ancount(&mut self, ancount: u16) -> &mut Self {
        self.ancount = ancount.to_be();
        self
    }

    pub fn set_nscount(&mut self, nscount: u16) -> &mut Self {
        self.nscount = nscount.to_be();
        self
    }

    pub fn set_arcount(&mut self, arcount: u16) -> &mut Self {
        self.arcount = arcount.to_be();
        self
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct DnsHdrBuilder {
    hdr: dns_hdr,
}

impl DnsHdrBuilder {
    pub fn build(self) -> dns_hdr {
        self.hdr
    }

    pub fn id(mut self, id: u16) -> Self {
        self.hdr.set_id(id);
        self
    }

    pub fn flags(mut self, flags: u16) -> Self {
        self.hdr.set_flags(flags);
        self
    }

    pub fn qdcount(mut self, qdcount: u16) -> Self {
        self.hdr.set_qdcount(qdcount);
        self
    }

    pub fn ancount(mut self, ancount: u16) -> Self {
        self.hdr.set_ancount(ancount);
        self
    }

    pub fn nscount(mut self, nscount: u16) -> Self {
        self.hdr.set_nscount(nscount);
        self
    }

    pub fn arcount(mut self, arcount: u16) -> Self {
        self.hdr.set_arcount(arcount);
        self
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct DnsFlags {
    flags: u16,
}

impl DnsFlags {
    pub fn build(self) -> u16 {
        self.flags
    }

    pub fn response(mut self, flag: bool) -> Self {
        if flag {
            self.flags |= flags::RESPONSE;
        } else {
            self.flags &= !flags::RESPONSE;
        }
        self
    }

    pub fn opcode(mut self, opcode: u8) -> Self {
        self.flags |= flags::from_opcode(opcode);
        self
    }

    pub fn aa(mut self, flag: bool) -> Self {
        if flag {
            self.flags |= flags::AA;
        } else {
            self.flags &= !flags::AA;
        }
        self
    }

    pub fn tc(mut self, flag: bool) -> Self {
        if flag {
            self.flags |= flags::TC;
        } else {
            self.flags &= !flags::TC;
        }
        self
    }

    pub fn rd(mut self, flag: bool) -> Self {
        if flag {
            self.flags |= flags::RD;
        } else {
            self.flags &= !flags::RD;
        }
        self
    }

    pub fn ra(mut self, flag: bool) -> Self {
        if flag {
            self.flags |= flags::RA;
        } else {
            self.flags &= !flags::RA;
        }
        self
    }

    pub fn rcode(mut self, opcode: u8) -> Self {
        self.flags |= flags::from_rcode(opcode);
        self
    }
}

pub(crate) struct DnsName {
    buf: Vec<u8>,
}

impl DnsName {
    pub fn new() -> Self {
        DnsName {
            buf: Vec::new(),
        }
    }

    pub fn from(name: &[u8]) -> Self {
        let mut ret = Self {
            buf: Vec::with_capacity(name.len() + 1),
        };

        for part in name.split(|x| *x == b'.') {
            ret.push(part);
        }

        ret.finish();

        ret
    }

    pub fn root() -> Self {
        DnsName {
            buf: vec!(0),
        }
    }

    pub fn push(&mut self, component: &[u8]) {
        self.buf.push(component.len() as u8);
        self.buf.extend(component);
    }

    pub fn finish(&mut self) {
        self.buf.push(0);
    }
}

impl Default for DnsName {
    fn default() -> Self {
        Self::root()
    }
}

impl AsRef<[u8]> for DnsName {
    fn as_ref(&self) -> &[u8] {
        self.buf.as_ref()
    }
}
