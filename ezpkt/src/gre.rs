use std::net::Ipv4Addr;

use bytemuck::Pod;

use pkt::eth::{eth_hdr, ethertype};
use pkt::gre::{GreFlags, gre_hdr, gre_hdr_seq};
use pkt::ipv4::{ip_hdr, proto};
use pkt::{Hdr, Packet};

/// Helper for creating GRE frames
pub struct GreFrame {
    pub pkt: Packet,
    ip: Hdr<ip_hdr>,
    seq: Option<Hdr<gre_hdr_seq>>,
}

impl GreFrame {
    const RAW_OVERHEAD: usize = std::mem::size_of::<ip_hdr>() + std::mem::size_of::<gre_hdr>();

    const OVERHEAD: usize = std::mem::size_of::<eth_hdr>() + Self::RAW_OVERHEAD;

    pub fn new(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        flags: GreFlags,
        proto: u16,
        raw: bool,
        extra: usize,
    ) -> Self {
        let pkt = if raw {
            Packet::with_capacity(Self::RAW_OVERHEAD + extra)
        } else {
            let pkt = Packet::with_capacity(Self::OVERHEAD + extra);

            pkt.push(eth_hdr::new(src.into(), dst.into(), ethertype::IPV4));

            pkt
        };

        let mut iph: ip_hdr = Default::default();
        iph.set_protocol(proto::GRE)
            .set_tot_len(Self::RAW_OVERHEAD as u16)
            .set_saddr(src)
            .set_daddr(dst)
            .calc_csum();

        let greh = gre_hdr::new(flags, proto);

        let ip = pkt.push(iph);
        let gre = pkt.push(greh);

        let seq = if gre.get(&pkt).get_seq() {
            let seq: Hdr<gre_hdr_seq> = pkt.push_hdr();
            let seq_len = seq.len() as u16;

            ip.mutate(&pkt, |iph| {
                iph.add_tot_len(seq_len);
            });

            Some(seq)
        } else {
            None
        };

        Self { pkt, ip, seq }
    }

    fn update_tot_len(&mut self, more: u16) {
        self.ip.get_mut(&self.pkt).add_tot_len(more).calc_csum();
    }

    pub fn push_hdr<T: Pod>(&mut self) -> Hdr<T> {
        let ret: Hdr<T> = self.pkt.push_hdr();

        self.update_tot_len(Hdr::<T>::size_of() as u16);

        ret
    }

    pub fn set_hdr<T: Pod>(mut self, item: T) -> Self {
        let hdr = self.pkt.push(item);
        self.update_tot_len(hdr.len() as u16);

        self
    }

    pub fn push<T: AsRef<[u8]>>(mut self, bytes: T) -> Self {
        let b = bytes.as_ref();

        self.pkt.push_bytes(b);
        self.update_tot_len(b.len() as u16);

        self
    }

    pub fn seq(self, seq: u32) -> Self {
        if let Some(shdr) = self.seq {
            shdr.get(&self.pkt).seq(seq);
        };
        self
    }
}

impl From<GreFrame> for Packet {
    fn from(seg: GreFrame) -> Self {
        seg.pkt
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct GreFlow {
    cl: Ipv4Addr,
    sv: Ipv4Addr,
    flags: GreFlags,
    ethertype: u16,
    raw: bool,
    seq: u32,
}

impl GreFlow {
    pub fn new(cl: Ipv4Addr, sv: Ipv4Addr, flags: GreFlags, ethertype: u16, raw: bool) -> Self {
        //println!("trace: vxlan:flow({:?}, {:?}, {:#x})", cl, sv, ethertype);
        Self {
            cl,
            sv,
            flags,
            ethertype,
            raw,
            seq: 0,
        }
    }

    fn next_seq(&mut self) -> u32 {
        let ret = self.seq;

        self.seq += 1;

        ret
    }

    fn dgram(&mut self, extra: usize) -> GreFrame {
        GreFrame::new(
            self.cl,
            self.sv,
            self.flags,
            self.ethertype,
            self.raw,
            extra,
        )
        .seq(self.next_seq())
    }

    pub fn encap(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: vxlan:encap({} bytes)", bytes.len());
        self.dgram(bytes.len()).push(bytes).into()
    }
}
