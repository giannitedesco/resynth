use bytemuck::{Pod, pod_read_unaligned};
use pkt::Packet;
use pkt::eth::{eth_hdr, ethertype};
use pkt::ipv4::{ip_csum, ip_csum_fold, ip_csum_partial, ip_hdr};

mod gre;
mod icmp4;
mod tcp4;

/// An Ethernet frame holding an IPv4 datagram, read back through pkt's headers
struct Frame(Vec<u8>);

impl Frame {
    const IP_OFF: usize = std::mem::size_of::<eth_hdr>();

    /// A header of type `T` at `off` bytes into the frame
    fn hdr<T: Pod>(&self, off: usize) -> T {
        pod_read_unaligned(&self.0[off..off + std::mem::size_of::<T>()])
    }

    fn eth(&self) -> eth_hdr {
        self.hdr(0)
    }

    fn ip(&self) -> ip_hdr {
        assert_eq!(self.eth().get_proto(), ethertype::IPV4);
        self.hdr(Self::IP_OFF)
    }

    /// Where the IP payload starts, after the IP header and any options
    fn l4_off(&self) -> usize {
        Self::IP_OFF + ((self.ip().get_ihl_version() & 0xf) as usize) * 4
    }

    /// The header of type `T` at `off` bytes into the IP payload
    fn l4<T: Pod>(&self, off: usize) -> T {
        self.hdr(self.l4_off() + off)
    }

    /// Everything after the IP header, up to the IP total length
    fn ip_payload(&self) -> &[u8] {
        &self.0[self.l4_off()..Self::IP_OFF + self.ip().get_tot_len() as usize]
    }

    /// Whether the IP header checksum is correct
    fn ip_csum_ok(&self) -> bool {
        ip_csum(&self.0[Self::IP_OFF..self.l4_off()]) == 0
    }

    /// Whether the TCP or UDP checksum is correct, over the pseudo-header and the IP payload
    fn l4_csum_ok(&self) -> bool {
        let l4 = self.ip_payload();
        let phdr = self.ip().get_pseudo_hdr(l4.len() as u16);

        ip_csum_fold(phdr.csum_partial() + ip_csum_partial(l4)) == 0
    }
}

impl From<&Packet> for Frame {
    fn from(pkt: &Packet) -> Self {
        Self(pkt.to_vec())
    }
}
