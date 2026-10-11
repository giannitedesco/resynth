use bytemuck::{Zeroable, bytes_of, pod_read_unaligned};

use crate::dns::{DnsFlags, DnsName, dns_hdr};

/// Construct a root name
#[test]
fn test_name_root() {
    let n = DnsName::root();
    assert_eq!(b"\x00", n.as_ref());
}

/// Construct a compression pointer
#[test]
fn test_ptr() {
    let n = DnsName::compression_pointer(0x4bad);
    assert_eq!(b"\xcb\xad", n.as_ref());
}

/// Partial name construction
#[test]
fn test_partial() {
    let mut n = DnsName::new();
    n.push(b"www");
    n.push(b"evildoer");
    n.push(b"n3t");
    assert_eq!(b"\x03www\x08evildoer\x03n3t", n.as_ref());
}

/// Partial name construction
#[test]
fn test_complete() {
    let mut n = DnsName::new();
    n.push(b"www");
    n.push(b"evildoer");
    n.push(b"n3t");
    n.finish();
    assert_eq!(b"\x03www\x08evildoer\x03n3t\x00", n.as_ref());
}

/// Name parsing
#[test]
fn test_parse() {
    let n = DnsName::from(b"www.evildoer.n3t");
    assert_eq!(b"\x03www\x08evildoer\x03n3t\x00", n.as_ref());
}

/// A final dot is the root label of a fully-qualified name
#[test]
fn test_trailing_dot() {
    let n = DnsName::from(b"www.evildoer.n3t.");
    assert_eq!(b"\x03www\x08evildoer\x03n3t\x00", n.as_ref());
}

/// The empty name is the root
#[test]
fn test_parse_empty() {
    let n = DnsName::from(b"");
    assert_eq!(b"\x00", n.as_ref());
}

/// A lone dot is the root
#[test]
fn test_parse_dot() {
    let n = DnsName::from(b".");
    assert_eq!(b"\x00", n.as_ref());
}

/// Only one trailing dot is the root, a second is an empty label
#[test]
fn test_two_trailing_dots() {
    let n = DnsName::from(b"n3t..");
    assert_eq!(b"\x03n3t\x00\x00", n.as_ref());
}

/// An empty label in the middle is kept
#[test]
fn test_empty_label() {
    let n = DnsName::from(b"www..n3t");
    assert_eq!(b"\x03www\x00\x03n3t\x00", n.as_ref());
}

/// Pushing raw bytes
#[test]
fn test_push_raw() {
    let mut n = DnsName::new();
    n.push(b"www");
    n.push(b"evildoer");
    n.push(b"n3t");
    n.push_raw(b"\xf0\x0f");
    n.finish();
    assert_eq!(b"\x03www\x08evildoer\x03n3t\xf0\x0f\x00", n.as_ref());
}

/// ID, flags, then the four section counts, RFC 1035 section 4.1.1
#[test]
fn test_hdr_getters() {
    let hdr: dns_hdr = pod_read_unaligned(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    assert_eq!(hdr.get_id(), 0x0102);
    assert_eq!(hdr.get_flags(), 0x0304);
    assert_eq!(hdr.get_qdcount(), 0x0506);
    assert_eq!(hdr.get_ancount(), 0x0708);
    assert_eq!(hdr.get_nscount(), 0x090a);
    assert_eq!(hdr.get_arcount(), 0x0b0c);
}

/// Pushing a dotted name pushes each label, and no root
#[test]
fn test_push_dotted() {
    let mut n = DnsName::new();
    n.push_dotted(b"www.evildoer");
    assert_eq!(b"\x03www\x08evildoer", n.as_ref());
}

/// One trailing dot stands for the root, so it pushes nothing
#[test]
fn test_push_dotted_trailing_dot() {
    let mut n = DnsName::new();
    n.push_dotted(b"www.evildoer.");
    assert_eq!(b"\x03www\x08evildoer", n.as_ref());
}

/// The root pushes nothing, written either way
#[test]
fn test_push_dotted_root() {
    for root in [&b""[..], b"."] {
        let mut n = DnsName::new();
        n.push_dotted(root);
        assert_eq!(b"", n.as_ref());
    }
}

/// Each flag lands in its own bits, RFC 1035 section 4.1.1 and RFC 4035 section 3.2
#[test]
fn test_flags() {
    let dfl = DnsFlags::default;

    assert_eq!(dfl().response(true).build(), 0x8000);
    assert_eq!(dfl().opcode(0x5).build(), 0x2800);
    assert_eq!(dfl().aa(true).build(), 0x0400);
    assert_eq!(dfl().tc(true).build(), 0x0200);
    assert_eq!(dfl().rd(true).build(), 0x0100);
    assert_eq!(dfl().ra(true).build(), 0x0080);
    assert_eq!(dfl().z(true).build(), 0x0040);
    assert_eq!(dfl().ad(true).build(), 0x0020);
    assert_eq!(dfl().cd(true).build(), 0x0010);
    assert_eq!(dfl().rcode(0x5).build(), 0x0005);
}

/// Values too wide for a field don't spill into the next one
#[test]
fn test_flags_field_widths() {
    assert_eq!(DnsFlags::default().opcode(0xff).build(), 0x7800);
    assert_eq!(DnsFlags::default().rcode(0xff).build(), 0x000f);
}

/// Clearing a flag keeps the others
#[test]
fn test_flags_clear() {
    let all = DnsFlags::default()
        .response(true)
        .aa(true)
        .tc(true)
        .rd(true)
        .ra(true)
        .z(true)
        .ad(true)
        .cd(true);

    assert_eq!(all.response(false).build(), 0x07f0);
    assert_eq!(all.aa(false).build(), 0x83f0);
    assert_eq!(all.tc(false).build(), 0x85f0);
    assert_eq!(all.rd(false).build(), 0x86f0);
    assert_eq!(all.ra(false).build(), 0x8770);
    assert_eq!(all.z(false).build(), 0x87b0);
    assert_eq!(all.ad(false).build(), 0x87d0);
    assert_eq!(all.cd(false).build(), 0x87e0);
}

/// ID, flags, then the four section counts, RFC 1035 section 4.1.1
#[test]
fn test_hdr_setters() {
    let mut hdr = dns_hdr::zeroed();
    hdr.set_id(0x0102)
        .set_flags(0x0304)
        .set_qdcount(0x0506)
        .set_ancount(0x0708)
        .set_nscount(0x090a)
        .set_arcount(0x0b0c);

    assert_eq!(bytes_of(&hdr), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
}
