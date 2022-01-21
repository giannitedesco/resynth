use std::net::Ipv4Addr;

use pkt::eth::eth_hdr;
use pkt::ipv4::{ip_hdr, icmp_hdr, icmp_echo_hdr, ip_csum, ICMP_ECHOREPLY, ICMP_ECHO};
use pkt::{Packet, Hdr};

#[derive(Debug, PartialEq, Eq)]
pub struct IcmpFlow {
    cl: Ipv4Addr,
    sv: Ipv4Addr,
    id: u16,
    ping_seq: u16,
    pong_seq: u16,
}

const ICMP_DGRAM_OVERHEAD: usize =
    std::mem::size_of::<eth_hdr>()
    + std::mem::size_of::<ip_hdr>()
    + std::mem::size_of::<icmp_echo_hdr>()
    + std::mem::size_of::<icmp_hdr>();

/// Helper for creating ICMP datagrams
pub struct IcmpDgram {
    pkt: Packet,
    ip: Hdr<ip_hdr>,
    icmp: Hdr<icmp_hdr>,
    echo: Hdr<icmp_echo_hdr>,
    tot_len: usize,
}

impl IcmpDgram {
    fn new(src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        let mut pkt = Packet::with_capacity(ICMP_DGRAM_OVERHEAD);

        let eth: Hdr<eth_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(&eth)
            .dst_from_ip(dst)
            .src_from_ip(src)
            .proto(0x0800);

        let ip: Hdr<ip_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(&ip)
            .init()
            .protocol(1)
            .saddr(src)
            .daddr(dst);

        let icmp: Hdr<icmp_hdr> = pkt.push_hdr();

        let echo: Hdr<icmp_echo_hdr> = pkt.push_hdr();

        let tot_len = ip.len() + icmp.len() + echo.len();

        let ret = Self {
            pkt,
            ip,
            icmp,
            echo,
            tot_len,
        };

        ret.update_tot_len()
    }

    fn push(mut self, bytes: &[u8]) -> Self {
        self.pkt.push_bytes(bytes);
        self.tot_len += bytes.len();
        self.update_tot_len()
    }

    fn update_tot_len(mut self) -> Self {
        self.pkt.get_mut_hdr(&self.ip)
            .tot_len(self.tot_len as u16);
        self
    }

    fn ping(mut self, id: u16, seq: u16, bytes: &[u8]) -> Self {
        self = self.push(bytes);
        self.pkt.get_mut_hdr(&self.icmp)
            .typ(ICMP_ECHO);
        self.pkt.get_mut_hdr(&self.echo)
            .id(id)
            .seq(seq);

        let bytes = self.pkt.bytes_after(&self.ip, self.tot_len);
        let csum = ip_csum(bytes);
        self.pkt.get_mut_hdr(&self.icmp).csum(csum);

        self
    }

    fn pong(mut self, id: u16, seq: u16, bytes: &[u8]) -> Self {
        self = self.push(bytes);
        self.pkt.get_mut_hdr(&self.icmp)
            .typ(ICMP_ECHOREPLY);
        self.pkt.get_mut_hdr(&self.echo)
            .id(id)
            .seq(seq);

        let bytes = self.pkt.bytes_after(&self.ip, self.tot_len);
        let csum = ip_csum(bytes);
        self.pkt.get_mut_hdr(&self.icmp).csum(csum);

        self
    }
}

impl From<IcmpDgram> for Packet {
    fn from(seg: IcmpDgram) -> Self{
        seg.pkt
    }
}

impl IcmpFlow {
    pub fn new(cl: Ipv4Addr, sv: Ipv4Addr) -> Self {
        //println!("trace: icmp:flow({:?}, {:?})", cl, sv);
        Self {
            cl,
            sv,
            id: 0x1234,
            ping_seq: 0,
            pong_seq: 0,
        }
    }

    fn clnt(&self) -> IcmpDgram {
        IcmpDgram::new(self.cl, self.sv)
    }

    fn srvr(&self) -> IcmpDgram {
        IcmpDgram::new(self.sv, self.cl)
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
