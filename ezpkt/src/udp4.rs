use std::net::{SocketAddrV4, Ipv4Addr};

use pkt::eth::eth_hdr;
use pkt::ipv4::{ip_hdr, udp_hdr};
use pkt::{Packet, Hdr};

#[derive(Debug, PartialEq, Eq)]
pub struct UdpFlow {
    cl: SocketAddrV4,
    sv: SocketAddrV4,
}

const UDP_DGRAM_OVERHEAD: usize =
    std::mem::size_of::<eth_hdr>()
    + std::mem::size_of::<ip_hdr>()
    + std::mem::size_of::<udp_hdr>();

/// Helper for creating UDP datagrams
pub struct UdpDgram {
    pkt: Packet,
    eth: Hdr<eth_hdr>,
    ip: Hdr<ip_hdr>,
    udp: Hdr<udp_hdr>,
    tot_len: usize,
    dgram_len: usize,
}

impl UdpDgram {
    #[must_use]
    pub fn with_capacity(payload_sz: usize) -> Self {
        let mut pkt = Packet::with_capacity(UDP_DGRAM_OVERHEAD + payload_sz);

        let eth: Hdr<eth_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(eth)
            .proto(0x0800);

        let ip: Hdr<ip_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(ip)
            .init()
            .protocol(17);

        let udp: Hdr<udp_hdr> = pkt.push_hdr();

        let tot_len = ip.len() + udp.len();

        let ret = Self {
            pkt,
            eth,
            ip,
            udp,
            tot_len,
            dgram_len: ::std::mem::size_of::<udp_hdr>(),
        };

        ret.update_tot_len().update_dgram_len()
    }

    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    #[must_use]
    pub fn srcip(mut self, src: Ipv4Addr) -> Self {
        self.pkt.get_mut_hdr(self.ip).saddr(src);
        self
    }

    #[must_use]
    pub fn src(mut self, src: SocketAddrV4) -> Self {
        self.pkt.get_mut_hdr(self.eth).src_from_ip(*src.ip());
        self.pkt.get_mut_hdr(self.ip).saddr(*src.ip());
        self.pkt.get_mut_hdr(self.udp).sport(src.port());
        self
    }

    #[must_use]
    pub fn dst(mut self, dst: SocketAddrV4) -> Self {
        self.pkt.get_mut_hdr(self.eth).dst_from_ip(*dst.ip());
        self.pkt.get_mut_hdr(self.ip).daddr(*dst.ip());
        self.pkt.get_mut_hdr(self.udp).dport(dst.port());
        self
    }

    #[must_use]
    pub fn broadcast(mut self) -> Self {
        self.pkt.get_mut_hdr(self.eth).broadcast();
        self
    }

    #[must_use]
    pub fn push<T: AsRef<[u8]>>(mut self, bytes: T) -> Self {
        let buf = bytes.as_ref();
        self.pkt.push_bytes(buf);
        self.tot_len += buf.len();
        self.dgram_len += buf.len();
        self.update_tot_len().update_dgram_len()
    }

    #[must_use]
    fn update_tot_len(mut self) -> Self {
        self.pkt.get_mut_hdr(self.ip)
            .tot_len(self.tot_len as u16);
        self
    }

    #[must_use]
    fn update_dgram_len(mut self) -> Self {
        self.pkt.get_mut_hdr(self.udp)
            .len(self.dgram_len as u16);
        self
    }
}

impl Default for UdpDgram {
    fn default() -> Self {
        Self::new()
    }
}

impl From<UdpDgram> for Packet {
    fn from(seg: UdpDgram) -> Self {
        seg.pkt
    }
}

impl UdpFlow {
    pub fn new(cl: SocketAddrV4, sv: SocketAddrV4) -> Self {
        //println!("trace: udp:flow({:?}, {:?})", cl, sv);
        Self {
            cl,
            sv,
        }
    }

    fn clnt(&self) -> UdpDgram {
        UdpDgram::new().src(self.cl).dst(self.sv)
    }

    fn srvr(&self) -> UdpDgram {
        UdpDgram::new().src(self.sv).dst(self.cl)
    }

    pub fn client_dgram(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: udp:client({} bytes)", bytes.len());
        self.clnt().push(bytes).into()
    }

    pub fn server_dgram(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: udp:server({} bytes)", bytes.len());
        self.srvr().push(bytes).into()
    }
}
