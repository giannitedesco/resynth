use std::net::Ipv4Addr;

use pkt::Packet;
use pkt::ipv4::ip_hdr;

use super::Frame;
use crate::{IpDgram, IpFrag};

fn frag(payload: &[u8]) -> IpFrag {
    let mut hdr = ip_hdr::default();
    hdr.set_protocol(253)
        .set_saddr(Ipv4Addr::new(10, 0, 0, 1))
        .set_daddr(Ipv4Addr::new(10, 0, 0, 2));

    IpFrag::new(hdr, payload.to_vec())
}

/// The payload, fragment offset and MF flag of a fragment, checking its IP checksum
fn parts(pkt: &Packet) -> (Vec<u8>, u16, bool) {
    let frame = Frame::from(pkt);
    let ip = frame.ip();

    assert!(frame.ip_csum_ok());

    (frame.ip_payload().to_vec(), ip.get_frag_off(), ip.get_mf())
}

const PAYLOAD: &[u8] = b"0123456789abcdef0123456789abcdef";

/// The offset and length are in 8-byte blocks, so this is bytes 8 to 23
#[test]
fn test_fragment() {
    assert_eq!(
        parts(&frag(PAYLOAD).fragment(1, 2, false)),
        (b"89abcdef01234567".to_vec(), 1, true)
    );
}

/// A fragment that reaches the end of the payload clears MF
#[test]
fn test_fragment_to_end() {
    assert_eq!(
        parts(&frag(PAYLOAD).fragment(2, 8, false)),
        (b"0123456789abcdef".to_vec(), 2, false)
    );
}

#[test]
fn test_tail() {
    assert_eq!(
        parts(&frag(PAYLOAD).tail(3, false)),
        (b"89abcdef".to_vec(), 3, false)
    );
}

#[test]
fn test_datagram() {
    assert_eq!(
        parts(&frag(PAYLOAD).datagram(false)),
        (PAYLOAD.to_vec(), 0, false)
    );
}

/// A fragment offset past the end of the payload used to panic. It's an empty fragment there.
#[test]
fn test_fragment_past_end() {
    assert_eq!(
        parts(&frag(b"01234567").fragment(2, 1, false)),
        (Vec::new(), 2, false)
    );
}

/// A payload too long for the total length wraps it, rather than panicking in debug builds
#[test]
fn test_dgram_tot_len_wraps() {
    let pkt: Packet = IpDgram::new(ip_hdr::default(), &[0; 65516], false).into();

    assert_eq!(Frame::from(&pkt).ip().get_tot_len(), 0);
}
