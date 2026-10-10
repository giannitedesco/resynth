use std::net::Ipv4Addr;

use pkt::Packet;
use pkt::gre::{GreFlags, gre_hdr, gre_hdr_seq};

use super::Frame;
use crate::{Erspan2Flow, Erspan3Flow, GreFlow};

const CL: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 1);
const SV: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 2);

/// The GRE sequence number of each frame, checking the sequence flag and the IP checksum
fn seqs(pkts: impl IntoIterator<Item = Packet>) -> Vec<u32> {
    pkts.into_iter()
        .map(|pkt| {
            let frame = Frame::from(&pkt);
            let gre: gre_hdr = frame.l4(0);

            assert!(gre.get_seq());
            assert!(frame.ip_csum_ok());

            frame
                .l4::<gre_hdr_seq>(std::mem::size_of::<gre_hdr>())
                .get_seq()
        })
        .collect()
}

/// GRE sequence numbers used to always be zero
#[test]
fn test_gre_seq() {
    let mut flow = GreFlow::new(CL, SV, GreFlags::default().seq(true), 0x0800, false);

    assert_eq!(seqs((0..3).map(|_| flow.encap(b"hello"))), [0, 1, 2]);
}

/// ERSPAN II and III count in the GRE sequence number, which was always zero too
#[test]
fn test_erspan_gre_seq() {
    let mut flow = Erspan2Flow::new(CL, SV, false);
    assert_eq!(seqs((0..3).map(|_| flow.encap(b"hello", 0))), [0, 1, 2]);

    let mut flow = Erspan3Flow::new(CL, SV, false);
    assert_eq!(seqs((0..3).map(|_| flow.encap(b"hello", 0))), [0, 1, 2]);
}
