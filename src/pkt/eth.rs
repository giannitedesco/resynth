#![allow(unused)]

use std::net::Ipv4Addr;

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub(crate) struct eth_addr {
    octets: [u8; 6],
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub(crate) struct eth_hdr {
    pub dst: eth_addr,
    pub src: eth_addr,
    pub proto: u16,
}

impl eth_hdr {
    pub fn dst_from_ip(&mut self, addr: Ipv4Addr) -> &mut Self {
        let ip = addr.octets();
        self.dst.octets = [0x00, 0x02, ip[0], ip[1], ip[2], ip[3]];
        self
    }

    pub fn src_from_ip(&mut self, addr: Ipv4Addr) -> &mut Self {
        let ip = addr.octets();
        self.src.octets = [0x00, 0x02, ip[0], ip[1], ip[2], ip[3]];
        self
    }

    pub fn proto(&mut self, proto: u16) -> &mut Self {
        self.proto = proto.to_be();
        self
    }
}
