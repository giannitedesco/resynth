use std::net::Ipv4Addr;

use pkt::Packet;
use pkt::eth::ethertype;
use pkt::gre::GreFlags;

use crate::GreFrame;

#[derive(Copy, Clone, Debug)]
pub struct Erspan1Frame {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    raw: bool,
}

impl Erspan1Frame {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, raw: bool) -> Self {
        Self { src, dst, raw }
    }

    pub fn raw(mut self, raw: bool) -> Self {
        self.raw = raw;
        self
    }

    pub fn src(mut self, src: Ipv4Addr) -> Self {
        self.src = src;
        self
    }

    pub fn dst(mut self, dst: Ipv4Addr) -> Self {
        self.dst = dst;
        self
    }

    pub fn encap<T: AsRef<[u8]>>(self, payload: T) -> Packet {
        let p = payload.as_ref();

        GreFrame::new(
            self.src,
            self.dst,
            GreFlags::default(),
            ethertype::ERSPAN_1_2,
            self.raw,
            p.len(),
        )
        .push(p)
        .into()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Erspan1Flow {
    cl: Ipv4Addr,
    sv: Ipv4Addr,
    raw: bool,
    session_id: u16,
}

impl Erspan1Flow {
    pub fn new(cl: Ipv4Addr, sv: Ipv4Addr, raw: bool) -> Self {
        //println!("trace: vxlan:flow({:?}, {:?}, {:#x})", cl, sv, ethertype);
        Self {
            cl,
            sv,
            raw,
            session_id: 0,
        }
    }

    fn dgram(&mut self) -> Erspan1Frame {
        Erspan1Frame::new(self.cl, self.sv, self.raw)
    }

    pub fn encap(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: vxlan:encap({} bytes)", bytes.len());
        self.dgram().encap(bytes)
    }
}
