use std::net::Ipv4Addr;

use pkt::Packet;
use pkt::erspan3::{Erspan3, Erspan3Platform, erspan3_hdr};
use pkt::eth::ethertype;
use pkt::gre::GreFlags;

use crate::GreFrame;

#[derive(Copy, Clone, Debug)]
pub struct Erspan3Frame {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    raw: bool,
    erspan: Erspan3,
    seq: u32,
    platform: Option<Erspan3Platform>,
}

impl Erspan3Frame {
    pub const OVERHEAD: usize = std::mem::size_of::<erspan3_hdr>();
    pub const PLATFORM_OVERHEAD: usize = std::mem::size_of::<u64>();

    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, raw: bool) -> Self {
        Self {
            src,
            dst,
            raw,
            erspan: Default::default(),
            seq: Default::default(),
            platform: None,
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

    pub fn erspan(mut self, erspan: Erspan3) -> Self {
        self.erspan = erspan;
        self
    }

    pub fn seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }

    pub fn platform(mut self, platform: Erspan3Platform) -> Self {
        self.platform = Some(platform);
        self
    }

    pub fn encap<T: AsRef<[u8]>>(self, payload: T) -> Packet {
        let p = payload.as_ref();

        let overhead =
            Erspan3Frame::OVERHEAD + self.platform.map_or(0, |_| Erspan3Frame::PLATFORM_OVERHEAD);

        let mut erspan = self.erspan;
        if self.platform.is_some() {
            erspan = erspan.optional(true);
        }

        let gre = GreFrame::new(
            self.src,
            self.dst,
            GreFlags::default().seq(true),
            ethertype::ERSPAN_3,
            self.raw,
            overhead + p.len(),
        );

        let mut frame = gre.seq(self.seq).set_hdr(erspan.build());

        if let Some(plat) = self.platform {
            frame = frame.push(plat.to_be_bytes());
        }

        frame.push(payload).into()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Erspan3Flow {
    cl: Ipv4Addr,
    sv: Ipv4Addr,
    raw: bool,
    seq: u32,
    pub session_id: u16,
    pub hwid: u8,
    pub sgt: u16,
    pub ft: u8,
    pub gra: u8,
    pub d: bool,
    pub platform: Option<Erspan3Platform>,
}

impl Erspan3Flow {
    pub fn new(cl: Ipv4Addr, sv: Ipv4Addr, raw: bool) -> Self {
        Self {
            cl,
            sv,
            raw,
            seq: 0,
            session_id: 0,
            hwid: 0,
            sgt: 0,
            ft: 0,
            gra: 0,
            d: false,
            platform: None,
        }
    }

    fn next_seq(&mut self) -> u32 {
        let ret = self.seq;

        self.seq += 1;

        ret
    }

    fn dgram(&mut self) -> Erspan3Frame {
        let mut frame = Erspan3Frame::new(self.cl, self.sv, self.raw).seq(self.next_seq());
        if let Some(plat) = self.platform {
            frame = frame.platform(plat);
        }
        frame
    }

    fn erspan(&self) -> Erspan3 {
        Erspan3::default()
            .session_id(self.session_id)
            .hwid(self.hwid)
            .sgt(self.sgt)
            .ft(self.ft)
            .gra(self.gra)
            .direction(self.d)
    }

    pub fn encap(&mut self, bytes: &[u8], timestamp: u32) -> Packet {
        let flags = self.erspan().timestamp(timestamp);

        self.dgram().erspan(flags).encap(bytes)
    }
}
