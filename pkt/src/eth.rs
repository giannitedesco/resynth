use std::net::Ipv4Addr;

use bytemuck::{Pod, Zeroable};

pub mod ethertype {
    pub const VLAN: u16 = 0x8100;
    pub const FABRICPATH: u16 = 0x8903;

    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86dd;

    pub const PPTP: u16 = 0x880b;
    pub const GRETAP: u16 = 0x6558;
    pub const ERSPAN_1_2: u16 = 0x88be;
    pub const ERSPAN_3: u16 = 0x22eb;
}

#[repr(C, packed(1))]
#[derive(Pod, Zeroable, Debug, Copy, Clone, Default)]
pub struct eth_addr {
    octets: [u8; 6],
}

impl eth_addr {
    pub fn new(octets: [u8; 6]) -> Self {
        Self { octets }
    }
}

impl From<Ipv4Addr> for eth_addr {
    fn from(addr: Ipv4Addr) -> Self {
        let ip = addr.octets();

        Self {
            octets: [0x02, 0x00, ip[0], ip[1], ip[2], ip[3]],
        }
    }
}

impl<'a> AsRef<[u8]> for &'a eth_addr {
    fn as_ref(&self) -> &'a [u8] {
        &self.octets[..]
    }
}

#[repr(C, packed(1))]
#[derive(Pod, Zeroable, Debug, Copy, Clone, Default)]
pub struct eth_hdr {
    pub dst: eth_addr,
    pub src: eth_addr,
    pub proto: u16,
}

pub const BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

impl eth_hdr {
    pub fn new(src: eth_addr, dst: eth_addr, proto: u16) -> Self {
        Self {
            dst,
            src,
            proto: proto.to_be(),
        }
    }

    pub fn with_proto(proto: u16) -> Self {
        Self {
            src: Default::default(),
            dst: Default::default(),
            proto: proto.to_be(),
        }
    }

    pub fn dst_from_ip(&mut self, addr: Ipv4Addr) -> &mut Self {
        self.dst = addr.into();
        self
    }

    pub fn src_from_ip(&mut self, addr: Ipv4Addr) -> &mut Self {
        self.dst = addr.into();
        self
    }

    pub fn set_proto(&mut self, proto: u16) -> &mut Self {
        self.proto = proto.to_be();
        self
    }

    pub fn set_broadcast(&mut self) -> &mut Self {
        self.dst.octets = BROADCAST;
        self
    }
}
