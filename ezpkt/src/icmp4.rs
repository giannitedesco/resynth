use std::net::Ipv4Addr;

use pkt::eth::{eth_hdr, ethertype};
use pkt::ipv4::{ICMP_ECHO, ICMP_ECHOREPLY, icmp_echo_hdr, icmp_hdr, ip_csum, ip_hdr, proto};
use pkt::{Hdr, Packet};

#[derive(Debug, PartialEq, Eq)]
pub struct IcmpFlow {
    cl: Ipv4Addr,
    sv: Ipv4Addr,
    raw: bool,
    id: u16,
    ping_seq: u16,
    pong_seq: u16,
}

/// Helper for creating ICMP datagrams
pub struct IcmpDgram {
    pkt: Packet,
    ip: Hdr<ip_hdr>,
    icmp: Hdr<icmp_hdr>,
    echo: Hdr<icmp_echo_hdr>,
}

impl IcmpDgram {
    const RAW_OVERHEAD: usize = std::mem::size_of::<ip_hdr>()
        + std::mem::size_of::<icmp_echo_hdr>()
        + std::mem::size_of::<icmp_hdr>();

    const OVERHEAD: usize = std::mem::size_of::<eth_hdr>() + Self::RAW_OVERHEAD;

    fn new(src: Ipv4Addr, dst: Ipv4Addr, raw: bool) -> Self {
        let pkt = if raw {
            Packet::with_capacity(Self::RAW_OVERHEAD)
        } else {
            let pkt = Packet::with_capacity(Self::OVERHEAD);

            pkt.push(eth_hdr::new(src.into(), dst.into(), ethertype::IPV4));

            pkt
        };

        let mut iph: ip_hdr = Default::default();
        iph.set_protocol(proto::ICMP)
            .set_tot_len(Self::RAW_OVERHEAD as u16)
            .set_saddr(src)
            .set_daddr(dst)
            .calc_csum();

        let ip = pkt.push(iph);

        let icmp: Hdr<icmp_hdr> = pkt.push_hdr();
        let echo: Hdr<icmp_echo_hdr> = pkt.push_hdr();

        Self {
            pkt,
            ip,
            icmp,
            echo,
        }
    }

    fn push(self, bytes: &[u8]) -> Self {
        self.pkt.push_bytes(bytes);
        self.update_tot_len(bytes.len() as u16)
    }

    fn update_tot_len(self, more: u16) -> Self {
        self.ip.get_mut(&self.pkt).add_tot_len(more);
        self
    }

    fn ping(mut self, id: u16, seq: u16, bytes: &[u8]) -> Self {
        self = self.push(bytes);
        self.icmp.get_mut(&self.pkt).set_typ(ICMP_ECHO);
        self.echo.get_mut(&self.pkt).set_id(id).set_seq(seq);

        let csum = ip_csum(
            &self
                .icmp
                .packet_bytes(&self.pkt, self.icmp.len_from(&self.pkt)),
        );

        self.icmp.get_mut(&self.pkt).set_csum(csum);

        self
    }

    fn pong(mut self, id: u16, seq: u16, bytes: &[u8]) -> Self {
        self = self.push(bytes);
        self.icmp.get_mut(&self.pkt).set_typ(ICMP_ECHOREPLY);
        self.echo.get_mut(&self.pkt).set_id(id).set_seq(seq);

        let csum = ip_csum(
            &self
                .icmp
                .packet_bytes(&self.pkt, self.icmp.len_from(&self.pkt)),
        );
        self.icmp.get_mut(&self.pkt).set_csum(csum);

        self
    }
}

impl From<IcmpDgram> for Packet {
    fn from(seg: IcmpDgram) -> Self {
        seg.pkt
    }
}

impl IcmpFlow {
    pub fn new(cl: Ipv4Addr, sv: Ipv4Addr, raw: bool) -> Self {
        //println!("trace: icmp:flow({:?}, {:?})", cl, sv);
        Self {
            cl,
            sv,
            raw,
            id: 0x1234,
            ping_seq: 0,
            pong_seq: 0,
        }
    }

    fn clnt(&self) -> IcmpDgram {
        IcmpDgram::new(self.cl, self.sv, self.raw)
    }

    fn srvr(&self) -> IcmpDgram {
        IcmpDgram::new(self.sv, self.cl, self.raw)
    }

    pub fn echo(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: icmp:ping({} bytes)", bytes.len());
        let ret = self.clnt().ping(self.id, self.ping_seq, bytes).into();
        self.ping_seq += 1;
        ret
    }

    pub fn echo_reply(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: icmp:pong({} bytes)", bytes.len());
        let ret = self.srvr().pong(self.id, self.pong_seq, bytes).into();
        self.pong_seq += 1;
        ret
    }
}
