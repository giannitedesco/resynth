use bytemuck::{Zeroable, bytes_of, pod_read_unaligned};

use crate::gre::{GreFlags, gre_hdr, gre_hdr_key, gre_hdr_seq, gre_hdr_sum};

/// The first two bytes of a GRE header with these flags
fn flag_bytes(flags: GreFlags) -> [u8; 2] {
    let hdr = gre_hdr::new(flags, 0);
    [bytes_of(&hdr)[0], bytes_of(&hdr)[1]]
}

/// Each flag lands in its own bits, RFC 2784 and RFC 2637 section 4.1
#[test]
fn test_flags() {
    let dfl = GreFlags::default;

    assert_eq!(flag_bytes(dfl().csum(true)), [0x80, 0x00]);
    assert_eq!(flag_bytes(dfl().routing(true)), [0x40, 0x00]);
    assert_eq!(flag_bytes(dfl().key(true)), [0x20, 0x00]);
    assert_eq!(flag_bytes(dfl().seq(true)), [0x10, 0x00]);
    assert_eq!(flag_bytes(dfl().source_routing(true)), [0x08, 0x00]);
    assert_eq!(flag_bytes(dfl().ack(true)), [0x00, 0x80]);
}

/// Recursion control and flags are separate fields, but the recursion count used to fill both
#[test]
fn test_recursion_and_flags() {
    let dfl = GreFlags::default;

    assert_eq!(flag_bytes(dfl().recursion(5)), [0x05, 0x00]);
    assert_eq!(flag_bytes(dfl().flags(0x9)), [0x00, 0x48]);
    assert_eq!(flag_bytes(dfl().ver(5)), [0x00, 0x05]);
}

/// Values too wide for a field don't spill into the next one
#[test]
fn test_field_widths() {
    let dfl = GreFlags::default;

    assert_eq!(flag_bytes(dfl().recursion(0xff)), [0x07, 0x00]);
    assert_eq!(flag_bytes(dfl().flags(0xff)), [0x00, 0x78]);
    assert_eq!(flag_bytes(dfl().ver(0xff)), [0x00, 0x07]);
}

#[test]
fn test_new() {
    let hdr = gre_hdr::new(GreFlags::default().seq(true).ver(1), 0x88be);
    assert_eq!(bytes_of(&hdr), [0x10, 0x01, 0x88, 0xbe]);
}

#[test]
fn test_set_flags_and_proto() {
    let mut hdr = gre_hdr::default();
    hdr.flags(GreFlags::default().key(true)).proto(0x6558);
    assert_eq!(bytes_of(&hdr), [0x20, 0x00, 0x65, 0x58]);

    hdr.flags(0x8001u16);
    assert_eq!(bytes_of(&hdr), [0x80, 0x01, 0x65, 0x58]);
}

#[test]
fn test_getters() {
    let hdr: gre_hdr = pod_read_unaligned(&[0xb0, 0x01, 0x88, 0xbe]);

    assert_eq!(hdr.get_flags(), 0xb001);
    assert!(hdr.get_csum());
    assert!(hdr.get_key());
    assert!(hdr.get_seq());
    assert_eq!(hdr.get_ver(), 1);

    let hdr: gre_hdr = pod_read_unaligned(&[0x00, 0x00, 0x88, 0xbe]);

    assert!(!hdr.get_csum());
    assert!(!hdr.get_key());
    assert!(!hdr.get_seq());
}

/// The optional fields are big-endian, in the order checksum, key, sequence number
#[test]
fn test_optional_fields() {
    let sum = gre_hdr_sum::zeroed().csum(0x1234).rsvd(0x5678);
    assert_eq!(bytes_of(&sum), [0x12, 0x34, 0x56, 0x78]);

    let key = gre_hdr_key::zeroed().key(0x0102_0304);
    assert_eq!(bytes_of(&key), [0x01, 0x02, 0x03, 0x04]);

    let seq = gre_hdr_seq::zeroed().seq(0x0506_0708);
    assert_eq!(bytes_of(&seq), [0x05, 0x06, 0x07, 0x08]);
}
