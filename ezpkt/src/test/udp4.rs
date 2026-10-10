use std::net::{Ipv4Addr, SocketAddrV4};

use pkt::Packet;
use pkt::eth::{BROADCAST, eth_addr};
use pkt::ipv4::udp_hdr;

use super::Frame;
use crate::{UdpDgram, UdpFlow};

const CL: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
const SV: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 9);

/// The source and destination set the ethernet, IP and UDP addresses
#[test]
fn test_addresses() {
    let pkt: Packet = UdpDgram::new().src(CL).dst(SV).push(b"hello").into();
    let frame = Frame::from(&pkt);
    let udp: udp_hdr = frame.l4(0);

    assert_eq!(frame.eth().get_src(), eth_addr::from(*CL.ip()));
    assert_eq!(frame.eth().get_dst(), eth_addr::from(*SV.ip()));
    assert_eq!(frame.ip().get_saddr(), *CL.ip());
    assert_eq!(frame.ip().get_daddr(), *SV.ip());
    assert_eq!(udp.get_sport(), CL.port());
    assert_eq!(udp.get_dport(), SV.port());
    assert!(frame.ip_csum_ok());
}

#[test]
fn test_broadcast() {
    let pkt: Packet = UdpDgram::new()
        .src(CL)
        .dst(SV)
        .broadcast()
        .push(b"hello")
        .into();

    assert_eq!(Frame::from(&pkt).eth().get_dst(), eth_addr::new(BROADCAST));
}

/// Setting frag_off after the payload used to leave a stale IP header checksum
#[test]
fn test_frag_off_ip_csum() {
    let mut flow = UdpFlow::new(CL, SV, false);

    for dgram in [
        flow.client_dgram(b"hello").frag_off(1),
        flow.server_dgram(b"hello").frag_off(1),
    ] {
        let pkt: Packet = dgram.into();
        let frame = Frame::from(&pkt);

        assert_eq!(frame.ip().get_frag_off(), 1);
        assert!(frame.ip_csum_ok());
    }
}

/// Overriding the source IP after the payload used to leave a stale IP header checksum
#[test]
fn test_srcip_ip_csum() {
    let pkt: Packet = UdpDgram::new()
        .src(CL)
        .dst(SV)
        .push(b"hello")
        .srcip(Ipv4Addr::UNSPECIFIED)
        .into();
    let frame = Frame::from(&pkt);

    assert_eq!(frame.ip().get_saddr(), Ipv4Addr::UNSPECIFIED);
    assert!(frame.ip_csum_ok());
}
