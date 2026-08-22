use std::net::Ipv4Addr;

use pkt::Packet;
use pkt::erspan2::{Erspan2, erspan2_hdr};
use pkt::eth::ethertype;
use pkt::gre::GreFlags;

use crate::GreFrame;

#[derive(Copy, Clone, Debug)]
pub struct Erspan2Frame {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    raw: bool,
    erspan: Erspan2,
    seq: u32,
}

impl Erspan2Frame {
    pub const OVERHEAD: usize = std::mem::size_of::<erspan2_hdr>();

    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, raw: bool) -> Self {
        Self {
            src,
            dst,
            raw,
            erspan: Default::default(),
            seq: Default::default(),
        }
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

    pub fn erspan(mut self, erspan: Erspan2) -> Self {
        self.erspan = erspan;
        self
    }

    pub fn seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }

    pub fn encap<T: AsRef<[u8]>>(self, payload: T) -> Packet {
        let p = payload.as_ref();

        let gre = GreFrame::new(
            self.src,
            self.dst,
            GreFlags::default().seq(true),
            ethertype::ERSPAN_1_2,
            self.raw,
            Erspan2Frame::OVERHEAD + p.len(),
        );

        gre.seq(self.seq)
            .set_hdr(self.erspan.build())
            .push(payload)
            .into()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Erspan2Flow {
    cl: Ipv4Addr,
    sv: Ipv4Addr,
    raw: bool,
    seq: u32,
    session_id: u16,
}

impl Erspan2Flow {
    pub fn new(cl: Ipv4Addr, sv: Ipv4Addr, raw: bool) -> Self {
        //println!("trace: vxlan:flow({:?}, {:?}, {:#x})", cl, sv, ethertype);
        Self {
            cl,
            sv,
            raw,
            seq: 0,
            session_id: 0,
        }
    }

    fn next_seq(&mut self) -> u32 {
        let ret = self.seq;

        self.seq += 1;

        ret
    }

    fn dgram(&mut self) -> Erspan2Frame {
        Erspan2Frame::new(self.cl, self.sv, self.raw).seq(self.next_seq())
    }

    fn erspan(&self) -> Erspan2 {
        Erspan2::default().session_id(self.session_id)
    }

    pub fn encap(&mut self, bytes: &[u8], port_index: u32) -> Packet {
        let flags = self.erspan().port_index(port_index);

        //println!("trace: vxlan:encap({} bytes)", bytes.len());
        self.dgram().erspan(flags).encap(bytes)
    }
}
