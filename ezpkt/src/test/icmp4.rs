use std::net::Ipv4Addr;

use pkt::ipv4::{icmp_echo_hdr, icmp_hdr, ip_csum};

use super::Frame;
use crate::IcmpFlow;

fn flow() -> IcmpFlow {
    IcmpFlow::new(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        false,
    )
}

/// Echoes with a payload used to have a stale IP header checksum
#[test]
fn test_echo_ip_csum() {
    let mut flow = flow();

    for pkt in [flow.echo(b"abcdefgh"), flow.echo_reply(b"abcdefgh")] {
        let frame = Frame::from(&pkt);

        assert_eq!(frame.ip().get_tot_len(), 20 + 8 + 8);
        assert!(frame.ip_csum_ok());
        assert_eq!(ip_csum(frame.ip_payload()), 0, "ICMP checksum");
    }
}

/// The echo sequence number wraps after 65536 echoes, which used to panic in debug builds
#[test]
fn test_seq_wraps() {
    let mut flow = flow();

    for _ in 0..=u16::MAX {
        flow.echo(b"");
        flow.echo_reply(b"");
    }

    for pkt in [flow.echo(b""), flow.echo_reply(b"")] {
        let frame = Frame::from(&pkt);
        let echo: icmp_echo_hdr = frame.l4(std::mem::size_of::<icmp_hdr>());

        assert_eq!(echo.get_seq(), 0);
    }
}
