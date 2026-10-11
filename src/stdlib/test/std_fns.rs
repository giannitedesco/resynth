use pkt::ipv4::udp_hdr;

use super::{bytes, frames, hdr};

/// A string literal of `n` bytes
fn payload(n: usize) -> String {
    format!("\"{}\"", "x".repeat(n))
}

/// Length prefixes wrap around, as documented
#[test]
fn len_u8_wraps() {
    let buf = bytes(&format!("import std;\nstd::len_u8({});", payload(256)));
    assert_eq!(buf[0], 0);
    assert_eq!(buf.len(), 257);
}

/// adjust: used to overflow and panic in debug builds
#[test]
fn len_adjust_wraps() {
    let buf = bytes(&format!(
        "import std;\nstd::len_u8(adjust: 1, {});",
        payload(255)
    ));
    assert_eq!(buf[0], 0);

    let buf = bytes(&format!(
        "import std;\nstd::len_be16(adjust: 1, {});",
        payload(65535)
    ));
    assert_eq!(buf[..2], [0, 0]);

    let buf = bytes(&format!(
        "import std;\nstd::len_le32(adjust: 0xffffffff, {});",
        payload(1)
    ));
    assert_eq!(buf[..4], [0, 0, 0, 0]);
}

/// ipv4::udp::hdr's len used to overflow and panic in debug builds
#[test]
fn udp_hdr_len_wraps() {
    let udp: udp_hdr = hdr(&bytes("import ipv4;\nipv4::udp::hdr(1, 2, len: 65535);"));
    assert_eq!(udp.get_len(), 7);
}

/// ipv4::datagram's total length used to overflow and panic in debug builds
#[test]
fn ip_datagram_tot_len_wraps() {
    let dgram = frames(&format!(
        "import ipv4;\nipv4::datagram(10.0.0.1, 10.0.0.2, {});",
        payload(65516)
    ));
    assert_eq!(dgram[0].ip().get_tot_len(), 0);
}
