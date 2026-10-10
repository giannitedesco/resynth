use std::net::Ipv4Addr;

use bytemuck::bytes_of;

use crate::eth::{eth_addr, eth_hdr};

const DST: [u8; 6] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15];
const SRC: [u8; 6] = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25];

/// The documented example. The address used to be 00:02:..., which isn't locally administered.
#[test]
fn test_addr_from_ip() {
    let addr = eth_addr::from(Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!((&addr).as_ref(), [0x02, 0x00, 0xc0, 0x00, 0x02, 0x01]);
}

/// Destination, then source, then the big-endian ethertype
#[test]
fn test_new() {
    let hdr = eth_hdr::new(eth_addr::new(SRC), eth_addr::new(DST), 0x0800);
    assert_eq!(bytes_of(&hdr), [&DST[..], &SRC, &[0x08, 0x00]].concat());
}

#[test]
fn test_with_proto() {
    let hdr = eth_hdr::with_proto(0x86dd);
    assert_eq!(bytes_of(&hdr)[12..], [0x86, 0xdd]);
}

#[test]
fn test_set_proto() {
    let mut hdr = eth_hdr::default();
    hdr.set_proto(0x0806);
    assert_eq!(bytes_of(&hdr), [&[0; 12][..], &[0x08, 0x06]].concat());
}

#[test]
fn test_dst_from_ip() {
    let ip = Ipv4Addr::new(10, 0, 0, 2);
    let mut hdr = eth_hdr::default();
    hdr.dst_from_ip(ip);
    assert_eq!(bytes_of(&hdr), [2, 0, 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
}

/// This used to set the destination
#[test]
fn test_src_from_ip() {
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    let mut hdr = eth_hdr::default();
    hdr.src_from_ip(ip);
    assert_eq!(bytes_of(&hdr), [0, 0, 0, 0, 0, 0, 2, 0, 10, 0, 0, 1, 0, 0]);
}

/// Broadcast sets the destination only
#[test]
fn test_set_broadcast() {
    let mut hdr = eth_hdr::new(eth_addr::new(SRC), eth_addr::new(DST), 0x0800);
    hdr.set_broadcast();
    assert_eq!(
        bytes_of(&hdr),
        [&[0xff; 6][..], &SRC, &[0x08, 0x00]].concat()
    );
}
