use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;

use pkt::eth::{eth_hdr, ethertype};
use pkt::ipv4::{ip_csum_fold, ip_csum_partial, ip_hdr, ip_pseudo_hdr, proto, udp_hdr};
use pkt::{Hdr, Packet};

#[derive(Debug, PartialEq, Eq)]
pub struct UdpFlow {
    cl: SocketAddrV4,
    sv: SocketAddrV4,
    raw: bool,
}

/// Helper for creating UDP datagrams
pub struct UdpDgram {
    pkt: Packet,
    eth: Option<Hdr<eth_hdr>>,
    ip: Hdr<ip_hdr>,
    udp: Hdr<udp_hdr>,
}

impl UdpDgram {
    const RAW_OVERHEAD: usize = std::mem::size_of::<ip_hdr>() + std::mem::size_of::<udp_hdr>();

    const OVERHEAD: usize = std::mem::size_of::<eth_hdr>() + Self::RAW_OVERHEAD;

    #[must_use]
    pub fn with_capacity(payload_sz: usize, raw: bool) -> Self {
        let pkt = if raw {
            Packet::with_capacity(Self::RAW_OVERHEAD + payload_sz)
        } else {
            Packet::with_capacity(Self::OVERHEAD + payload_sz)
        };

        let eth = if raw {
            None
        } else {
            Some(pkt.push(eth_hdr::with_proto(ethertype::IPV4)))
        };

        let mut iph = ip_hdr::default();
        iph.set_protocol(proto::UDP)
            .set_tot_len(Self::RAW_OVERHEAD as u16)
            .calc_csum();

        let ip = pkt.push(iph);
        let udp = pkt.push(udp_hdr::default());

        Self { pkt, eth, ip, udp }
    }

    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(0, false)
    }

    pub fn raw() -> Self {
        Self::with_capacity(0, true)
    }

    pub fn of_type(raw: bool) -> Self {
        Self::with_capacity(0, raw)
    }

    #[must_use]
    pub fn srcip(self, src: Ipv4Addr) -> Self {
        self.ip.get_mut(&self.pkt).set_saddr(src);

        self
    }

    #[must_use]
    pub fn frag_off(self, frag_off: u16) -> Self {
        self.ip.get_mut(&self.pkt).set_frag_off(frag_off);

        self
    }

    #[must_use]
    pub fn src(self, src: SocketAddrV4) -> Self {
        if let Some(eth) = self.eth {
            eth.get_mut(&self.pkt).src_from_ip(*src.ip());
        }
        self.ip.get_mut(&self.pkt).set_saddr(*src.ip());
        self.udp.get_mut(&self.pkt).set_sport(src.port());
        self
    }

    #[must_use]
    pub fn dst(self, dst: SocketAddrV4) -> Self {
        if let Some(eth) = self.eth {
            eth.get_mut(&self.pkt).dst_from_ip(*dst.ip());
        }
        self.ip.get_mut(&self.pkt).set_daddr(*dst.ip());
        self.udp.get_mut(&self.pkt).set_dport(dst.port());
        self
    }

    #[must_use]
    pub fn broadcast(self) -> Self {
        if let Some(eth) = self.eth {
            eth.get_mut(&self.pkt).set_broadcast();
        }
        self
    }

    #[must_use]
    pub fn push<T: AsRef<[u8]>>(self, bytes: T) -> Self {
        let buf = bytes.as_ref();
        self.pkt.push_bytes(buf);
        self.update_tot_len(buf.len() as u16)
            .update_dgram_len(buf.len() as u16)
    }

    #[must_use]
    fn update_tot_len(self, more: u16) -> Self {
        self.ip.get_mut(&self.pkt).add_tot_len(more).calc_csum();
        self
    }

    #[must_use]
    fn update_dgram_len(self, more: u16) -> Self {
        self.udp.get_mut(&self.pkt).add_len(more);
        self
    }

    fn ip_pseudo_hdr(&self, len: u16) -> ip_pseudo_hdr {
        self.ip.get(&self.pkt).get_pseudo_hdr(len)
    }

    /// Checksum is the TCP header length plus the data length
    fn csum_len(&self) -> u16 {
        self.udp.len_from(&self.pkt) as u16
    }

    #[must_use]
    pub fn csum(self) -> Self {
        let ip_phdr = self.ip_pseudo_hdr(self.csum_len()).csum_partial();
        let udp_hdr = ip_csum_partial(&self.udp.as_bytes(&self.pkt));
        let payload = ip_csum_partial(
            &self
                .udp
                .bytes_after(&self.pkt, self.udp.len_after(&self.pkt)),
        );

        self.udp
            .get_mut(&self.pkt)
            .set_csum(ip_csum_fold(ip_phdr + udp_hdr + payload));

        self
    }

    pub fn udp_hdr_bytes(&self) -> pkt::SliceRef<'_> {
        self.udp.as_bytes(&self.pkt)
    }

    pub fn udp_dgram(&self) -> pkt::PktSlice {
        self.udp.packet(self.udp.len_from(&self.pkt))
    }

    pub fn udp_dgram_bytes(&self) -> pkt::SliceRef<'_> {
        self.udp_dgram().get(&self.pkt)
    }

    pub fn into_udp_dgram(self) -> Vec<u8> {
        let pktslice = self.udp_dgram();
        let pkt: Packet = self.into();

        // XXX: This is more efficient if there is no headroom
        pkt.into_vec_from(pktslice)
    }
}

impl Default for UdpDgram {
    fn default() -> Self {
        Self::new()
    }
}

impl From<UdpDgram> for Rc<Packet> {
    fn from(seg: UdpDgram) -> Self {
        Rc::new(seg.pkt)
    }
}

impl From<UdpDgram> for Packet {
    fn from(seg: UdpDgram) -> Self {
        seg.pkt
    }
}

impl UdpFlow {
    pub fn new(cl: SocketAddrV4, sv: SocketAddrV4, raw: bool) -> Self {
        //println!("trace: udp:flow({:?}, {:?})", cl, sv);
        Self { cl, sv, raw }
    }

    fn clnt(&self) -> UdpDgram {
        UdpDgram::of_type(self.raw).src(self.cl).dst(self.sv)
    }

    fn srvr(&self) -> UdpDgram {
        UdpDgram::of_type(self.raw).src(self.sv).dst(self.cl)
    }

    pub fn client_dgram(&mut self, bytes: &[u8]) -> UdpDgram {
        //println!("trace: udp:client({} bytes)", bytes.len());
        self.clnt().push(bytes)
    }

    pub fn server_dgram(&mut self, bytes: &[u8]) -> UdpDgram {
        //println!("trace: udp:server({} bytes)", bytes.len());
        self.srvr().push(bytes)
    }
}
