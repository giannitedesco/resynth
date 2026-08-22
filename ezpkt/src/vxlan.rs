use std::net::SocketAddrV4;

use pkt::{Packet, vxlan::vxlan_hdr};

use bytemuck::bytes_of;

use super::UdpDgram;

#[derive(Debug, PartialEq, Eq)]
pub struct VxlanFlow {
    cl: SocketAddrV4,
    sv: SocketAddrV4,
    vni: u32,
    raw: bool,
}

pub struct VxlanDgram {
    outer: UdpDgram,
}

impl VxlanDgram {
    fn new(src: SocketAddrV4, dst: SocketAddrV4, vni: u32, raw: bool) -> Self {
        Self {
            outer: UdpDgram::with_capacity(std::mem::size_of::<vxlan_hdr>(), raw)
                .src(src)
                .dst(dst)
                .push(bytes_of(&vxlan_hdr::with_vni(vni))),
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
    pub fn new(cl: SocketAddrV4, sv: SocketAddrV4, vni: u32, raw: bool) -> Self {
        //println!("trace: vxlan:flow({:?}, {:?}, {:#x})", cl, sv, vni);
        Self { cl, sv, vni, raw }
    }

    fn dgram(&self) -> VxlanDgram {
        VxlanDgram::new(self.cl, self.sv, self.vni, self.raw)
    }

    pub fn encap<T: AsRef<[u8]>>(&mut self, bytes: T) -> Packet {
        //println!("trace: vxlan:encap({} bytes)", bytes.len());
        self.dgram().push(bytes.as_ref()).into()
    }
}
