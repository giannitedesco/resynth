#![allow(unused)]

use std::net::Ipv4Addr;

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct ip_hdr {
    pub ihl_version: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub csum: u16,
    pub saddr: u32,
    pub daddr: u32,
}

impl ip_hdr {
    pub fn init(&mut self) -> &mut Self {
        self.ihl_version = 0x45;
        self.tot_len = (std::mem::size_of::<Self>() as u16).to_be();
        self.ttl = 64;
        self
    }

    pub fn tot_len(&mut self, tot_len: u16) -> &mut Self {
        self.tot_len = tot_len.to_be();
        self
    }

    pub fn id(&mut self, id: u16) -> &mut Self {
        self.id = id.to_be();
        self
    }

    pub fn ttl(&mut self, ttl: u8) -> &mut Self {
        self.ttl = ttl;
        self
    }

    pub fn protocol(&mut self, protocol: u8) -> &mut Self {
        self.protocol = protocol;
        self
    }

    pub fn saddr(&mut self, addr: Ipv4Addr) -> &mut Self {
        let ip: u32 = addr.into();
        self.saddr = ip.to_be();
        self
    }

    pub fn daddr(&mut self, addr: Ipv4Addr) -> &mut Self {
        let ip: u32 = addr.into();
        self.daddr = ip.to_be();
        self
    }
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct udp_hdr {
    pub sport: u16,
    pub dport: u16,
    pub len: u16,
    pub csum: u16,
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct tcp_hdr {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub doff: u8,
    pub flags: u8,
    pub win: u16,
    pub csum: u16,
    pub urp: u16,
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;
pub const TCP_ECE: u8 = 0x40;
pub const TCP_CWR: u8 = 0x80;

impl tcp_hdr {
    pub fn init(&mut self) -> &mut Self {
        let sz = std::mem::size_of::<Self>() as u8;
        self.doff = (sz >> 2) << 4;
        self.win = 1024u16.to_be();
        self
    }

    pub fn sport(&mut self, sport: u16) -> &mut Self {
        self.sport = sport.to_be();
        self
    }

    pub fn dport(&mut self, dport: u16) -> &mut Self {
        self.dport = dport.to_be();
        self
    }

    pub fn seq(&mut self, seq: u32) -> &mut Self {
        self.seq = seq.to_be();
        self
    }

    pub fn syn(&mut self) -> &mut Self {
        self.flags |= TCP_SYN;
        self
    }

    pub fn push(&mut self) -> &mut Self {
        self.flags |= TCP_PSH;
        self
    }

    pub fn fin(&mut self) -> &mut Self {
        self.flags |= TCP_FIN;
        self
    }

    pub fn rst(&mut self) -> &mut Self {
        self.flags |= TCP_RST;
        self
    }

    pub fn ack(&mut self, ack: u32) -> &mut Self {
        self.ack = ack.to_be();
        self.flags |= TCP_ACK;
        self
    }
}
