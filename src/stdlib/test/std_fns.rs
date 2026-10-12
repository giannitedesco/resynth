use std::net::Ipv4Addr;

use pkt::ipv4::udp_hdr;

use crate::val::Val;

use super::{Call, hdr, s};

/// A string of `n` bytes
fn payload(n: usize) -> Val {
    s("x".repeat(n))
}

/// Length prefixes wrap around, as documented
#[test]
fn len_u8_wraps() {
    let buf = Call::func("std::len_u8").extra(payload(256)).bytes();
    assert_eq!(buf[0], 0);
    assert_eq!(buf.len(), 257);
}

/// adjust: used to overflow and panic in debug builds
#[test]
fn len_adjust_wraps() {
    let buf = Call::func("std::len_u8")
        .named("adjust", 1u64)
        .extra(payload(255))
        .bytes();
    assert_eq!(buf[0], 0);

    let buf = Call::func("std::len_be16")
        .named("adjust", 1u64)
        .extra(payload(65535))
        .bytes();
    assert_eq!(buf[..2], [0, 0]);

    let buf = Call::func("std::len_le32")
        .named("adjust", 0xffffffffu64)
        .extra(payload(1))
        .bytes();
    assert_eq!(buf[..4], [0, 0, 0, 0]);
}

/// ipv4::udp::hdr's len used to overflow and panic in debug builds
#[test]
fn udp_hdr_len_wraps() {
    let udp: udp_hdr = hdr(&Call::func("ipv4::udp::hdr")
        .arg(1u64)
        .arg(2u64)
        .named("len", 65535u64)
        .bytes());
    assert_eq!(udp.get_len(), 7);
}

/// ipv4::datagram's total length used to overflow and panic in debug builds
#[test]
fn ip_datagram_tot_len_wraps() {
    let dgram = Call::func("ipv4::datagram")
        .arg(Val::Ip4(Ipv4Addr::new(10, 0, 0, 1)))
        .arg(Val::Ip4(Ipv4Addr::new(10, 0, 0, 2)))
        .extra(payload(65516))
        .frames();
    assert_eq!(dgram[0].ip().get_tot_len(), 0);
}
