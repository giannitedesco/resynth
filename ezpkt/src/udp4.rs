use std::net::SocketAddrV4;

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
    ip: Hdr<ip_hdr>,
    udp: Hdr<udp_hdr>,
    tot_len: usize,
    dgram_len: usize,
}

impl UdpDgram {
    fn new(src: SocketAddrV4, dst: SocketAddrV4) -> Self {
        let mut pkt = Packet::with_capacity(UDP_DGRAM_OVERHEAD);

        let eth: Hdr<eth_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(&eth)
            .dst_from_ip(*dst.ip())
            .src_from_ip(*src.ip())
            .proto(0x0800);

        let ip: Hdr<ip_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(&ip)
            .init()
            .protocol(17)
            .saddr(*src.ip())
            .daddr(*dst.ip());

        let udp: Hdr<udp_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(&udp)
            .sport(src.port())
            .dport(dst.port());

        let tot_len = ip.len() + udp.len();

        let ret = Self {
            pkt,
            ip,
            udp,
            tot_len,
            dgram_len: ::std::mem::size_of::<udp_hdr>(),
        };

        ret.update_tot_len().update_dgram_len()
    }

    fn push(mut self, bytes: &[u8]) -> Self {
        self.pkt.push_bytes(bytes);
        self.tot_len += bytes.len();
        self.dgram_len += bytes.len();
        self.update_tot_len().update_dgram_len()
    }

    fn update_tot_len(mut self) -> Self {
        self.pkt.get_mut_hdr(&self.ip)
            .tot_len(self.tot_len as u16);
        self
    }

    fn update_dgram_len(mut self) -> Self {
        self.pkt.get_mut_hdr(&self.udp)
            .len(self.dgram_len as u16);
        self
    }
}

impl From<UdpDgram> for Packet {
    fn from(seg: UdpDgram) -> Self{
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
        UdpDgram::new(self.cl, self.sv)
    }

    fn srvr(&self) -> UdpDgram {
        UdpDgram::new(self.sv, self.cl)
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
