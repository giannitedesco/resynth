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

impl udp_hdr {
    pub fn sport(&mut self, sport: u16) -> &mut Self {
        self.sport = sport.to_be();
        self
    }

    pub fn dport(&mut self, dport: u16) -> &mut Self {
        self.dport = dport.to_be();
        self
    }

    pub fn len(&mut self, len: u16) -> &mut Self {
        self.len = len.to_be();
        self
    }
}

pub const ICMP_ECHOREPLY: u8 = 0;       /* Echo Reply */
pub const ICMP_DEST_UNREACH: u8 = 3;    /* Destination Unreachable */
pub const ICMP_SOURCE_QUENCH: u8 = 4;   /* Source Quench */
pub const ICMP_REDIRECT: u8 = 5;        /* Redirect (change route) */
pub const ICMP_ECHO: u8 = 8;            /* Echo Request */
pub const ICMP_TIME_EXCEEDED: u8 = 11;  /* Time Exceeded */
pub const ICMP_PARAMETERPROB: u8 = 12;  /* Parameter Problem */
pub const ICMP_TIMESTAMP: u8 = 13;      /* Timestamp Request */
pub const ICMP_TIMESTAMPREPLY: u8 = 14; /* Timestamp Reply */
pub const ICMP_INFO_REQUEST: u8 = 15;   /* Information Request */
pub const ICMP_INFO_REPLY: u8 = 16;     /* Information Reply */
pub const ICMP_ADDRESS: u8 = 17;        /* Address Mask Request */
pub const ICMP_ADDRESSREPLY: u8 = 18;   /* Address Mask Reply */

/* For ICMP_DEST_UNREACH */
pub const ICMP_NET_UNREACH: u8 = 0;
pub const ICMP_HOST_UNREACH: u8 = 1;
pub const ICMP_PROT_UNREACH: u8 = 2;
pub const ICMP_PORT_UNREACH: u8 = 3;
pub const ICMP_FRAG_NEEDED: u8 = 4;
pub const ICMP_SR_FAILED: u8 = 5;
pub const ICMP_NET_UNKNOWN: u8 = 7;
pub const ICMP_HOST_UNKNOWN: u8 = 8;
pub const ICMP_NET_ANO: u8 = 9;
pub const ICMP_HOST_ANO: u8 = 10;
pub const ICMP_NET_UNR_TOS: u8 = 11;
pub const ICMP_HOST_UNR_TOS: u8 = 12;
pub const ICMP_PKT_FILTERED: u8 = 13;
pub const ICMP_PREC_VIOLATION: u8 = 14;
pub const ICMP_PREC_CUTOFF: u8 = 15;

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct icmp_hdr {
    pub typ: u8,
    pub code: u8,
    pub csum: u16,
}

impl icmp_hdr {
    pub fn typ(&mut self, typ: u8) -> &mut Self {
        self.typ = typ;
        self
    }

    pub fn code(&mut self, code: u8) -> &mut Self {
        self.code = code;
        self
    }

    pub fn csum(&mut self, csum: u16) -> &mut Self {
        self.csum = csum.to_be();
        self
    }
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct icmp_echo_hdr {
    pub id: u16,
    pub seq: u16,
}

impl icmp_echo_hdr {
    pub fn id(&mut self, id: u16) -> &mut Self {
        self.id = id.to_be();
        self
    }

    pub fn seq(&mut self, seq: u16) -> &mut Self {
        self.seq = seq.to_be();
        self
    }
}
