use std::net::SocketAddrV4;

use pkt::{Packet, AsBytes, vxlan::vxlan_hdr};

use super::UdpDgram;

#[derive(Debug, PartialEq, Eq)]
pub struct VxlanFlow {
    cl: SocketAddrV4,
    sv: SocketAddrV4,
    vni: u32,
}

pub struct VxlanDgram {
    outer: UdpDgram,
}

impl VxlanDgram {
    fn new(src: SocketAddrV4, dst: SocketAddrV4, vni: u32) -> Self {
        Self {
            outer: UdpDgram::with_capacity(
                src,
                dst,
                std::mem::size_of::<vxlan_hdr>(),
            ).push(
                vxlan_hdr::with_vni(vni).as_bytes()
            ),
        }
    }

    fn push(mut self, bytes: &[u8]) -> Self {
        self.outer = self.outer.push(bytes);
        self
    }
}

impl From<VxlanDgram> for Packet {
    fn from(dgram: VxlanDgram) -> Self {
        dgram.outer.into()
    }
}

impl VxlanFlow {
    pub fn new(cl: SocketAddrV4, sv: SocketAddrV4, vni: u32) -> Self {
        //println!("trace: vxlan:flow({:?}, {:?}, {:#x})", cl, sv, vni);
        Self {
            cl,
            sv,
            vni,
        }
    }

    fn dgram(&self) -> VxlanDgram {
        VxlanDgram::new(self.cl, self.sv, self.vni)
    }

    pub fn encap(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: vxlan:encap({} bytes)", bytes.len());
        self.dgram().push(bytes).into()
    }
}
