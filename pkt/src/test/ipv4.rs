use std::net::Ipv4Addr;

use bytemuck::{Zeroable, bytes_of, pod_read_unaligned};

use crate::ipv4::{
    ICMP_ECHO, ICMP_ECHOREPLY, icmp_echo_hdr, icmp_hdr, ip_csum, ip_csum_fold, ip_csum_partial,
    ip_hdr, ip_pseudo_hdr, proto, tcp_hdr, udp_hdr,
};

const SRC: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 1);
const DST: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 199);

/// A zeroed header with `bytes` at offset `off`
fn zeroed_with<const N: usize>(off: usize, bytes: &[u8]) -> [u8; N] {
    let mut ret = [0; N];
    ret[off..off + bytes.len()].copy_from_slice(bytes);
    ret
}

/// The bytes of an IPv4 header after `f` has set fields of a zeroed one
fn ip(f: impl FnOnce(&mut ip_hdr)) -> [u8; 20] {
    let mut hdr = ip_hdr::zeroed();
    f(&mut hdr);
    bytes_of(&hdr).try_into().unwrap()
}

/// The RFC 1071 section 3 example
#[test]
fn test_csum_rfc1071() {
    let buf = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    assert_eq!(ip_csum_partial(&buf), 0x2ddf0);
    assert_eq!(ip_csum(&buf), !0xddf2);
}

/// An odd byte at the end is padded with a zero
#[test]
fn test_csum_odd_length() {
    assert_eq!(ip_csum(&[0x12, 0x34, 0x56]), !0x6834);
}

/// A buffer that includes its own correct checksum sums to zero
#[test]
fn test_csum_fold_verifies() {
    let mut buf = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7, 0, 0];
    let csum = ip_csum(&buf);
    buf[8..].copy_from_slice(&csum.to_be_bytes());
    assert_eq!(ip_csum_fold(ip_csum_partial(&buf)), 0);
}

#[test]
fn test_protocol_numbers() {
    assert_eq!(proto::ICMP, 1);
    assert_eq!(proto::TCP, 6);
    assert_eq!(proto::UDP, 17);
    assert_eq!(proto::GRE, 47);
}

/// Version 4, a 5-word header with no options, and resynth's TTL of 64
#[test]
fn test_ip_default() {
    let hdr = ip_hdr::default();
    assert_eq!(
        bytes_of(&hdr),
        [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
}

#[test]
fn test_ip_init() {
    let expected = ip_hdr::default();
    assert_eq!(ip(|h| _ = h.init()), bytes_of(&expected));
}

/// Each setter writes its own field, RFC 791 section 3.1
#[test]
fn test_ip_setters() {
    assert_eq!(ip(|h| _ = h.set_tot_len(0x0102)), zeroed_with(2, &[1, 2]));
    assert_eq!(ip(|h| _ = h.set_id(0x0304)), zeroed_with(4, &[3, 4]));
    assert_eq!(ip(|h| _ = h.set_ttl(5)), zeroed_with(8, &[5]));
    assert_eq!(ip(|h| _ = h.set_protocol(6)), zeroed_with(9, &[6]));
    assert_eq!(ip(|h| _ = h.set_csum(0x0708)), zeroed_with(10, &[7, 8]));
    assert_eq!(ip(|h| _ = h.set_saddr(SRC)), zeroed_with(12, &SRC.octets()));
    assert_eq!(ip(|h| _ = h.set_daddr(DST)), zeroed_with(16, &DST.octets()));
}

/// Growing the total length past 65535 wraps, for malformed packets, rather than panicking in
/// debug builds
#[test]
fn test_ip_add_tot_len_wraps() {
    assert_eq!(
        ip(|h| _ = h.set_tot_len(0xffff).add_tot_len(2)),
        zeroed_with(2, &[0, 1])
    );
}

#[test]
fn test_ip_add_tot_len() {
    assert_eq!(
        ip(|h| _ = h.set_tot_len(20).add_tot_len(0x0100)),
        zeroed_with(2, &[0x01, 20])
    );
}

/// The flags are the top 3 bits of the word at offset 6, and the fragment offset the rest
#[test]
fn test_ip_frag() {
    assert_eq!(ip(|h| _ = h.set_evil(true)), zeroed_with(6, &[0x80, 0]));
    assert_eq!(ip(|h| _ = h.set_df(true)), zeroed_with(6, &[0x40, 0]));
    assert_eq!(ip(|h| _ = h.set_mf(true)), zeroed_with(6, &[0x20, 0]));
    assert_eq!(
        ip(|h| _ = h.set_frag_off(0x1abc)),
        zeroed_with(6, &[0x1a, 0xbc])
    );
}

/// Setting the fragment offset keeps the flags, and setting a flag keeps the offset and the
/// other flags
#[test]
fn test_ip_frag_keeps_other_bits() {
    assert_eq!(
        ip(|h| _ = h.set_evil(true).set_mf(true).set_frag_off(0x1abc)),
        zeroed_with(6, &[0xba, 0xbc])
    );
    assert_eq!(
        ip(|h| _ = h.set_frag_off(0x1abc).set_df(true).set_df(false)),
        zeroed_with(6, &[0x1a, 0xbc])
    );
    assert_eq!(
        ip(|h| _ = h.set_evil(true).set_df(true).set_mf(true).set_mf(false)),
        zeroed_with(6, &[0xc0, 0])
    );
}

/// The header from the Wikipedia IPv4 checksum example, built with the setters
#[test]
fn test_ip_calc_csum() {
    let mut hdr = ip_hdr::default();
    hdr.set_tot_len(0x73)
        .set_df(true)
        .set_protocol(proto::UDP)
        .set_saddr(SRC)
        .set_daddr(DST)
        .calc_csum();

    assert_eq!(
        bytes_of(&hdr),
        [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ]
    );
}

/// calc_csum ignores the old checksum
#[test]
fn test_ip_calc_csum_again() {
    let mut hdr = ip_hdr::default();
    hdr.set_saddr(SRC).calc_csum();
    let once = hdr;
    hdr.calc_csum();

    assert_eq!(hdr, once);
}

#[test]
fn test_ip_getters() {
    let hdr: ip_hdr = pod_read_unaligned(&[
        0x46, 0x07, 0x01, 0x02, 0x03, 0x04, 0xba, 0xbc, 0x05, 0x06, 0x07, 0x08, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ]);

    assert_eq!(hdr.get_ihl_version(), 0x46);
    assert_eq!(hdr.get_tos(), 7);
    assert_eq!(hdr.get_tot_len(), 0x0102);
    assert_eq!(hdr.get_id(), 0x0304);
    assert_eq!(hdr.get_frag_off(), 0x1abc);
    assert!(hdr.get_evil());
    assert!(!hdr.get_df());
    assert!(hdr.get_mf());
    assert_eq!(hdr.get_ttl(), 5);
    assert_eq!(hdr.get_protocol(), 6);
    assert_eq!(hdr.get_csum(), 0x0708);
    assert_eq!(hdr.get_saddr(), SRC);
    assert_eq!(hdr.get_daddr(), DST);
}

/// Each flag getter reads its own bit
#[test]
fn test_ip_flag_getters() {
    let flags = |word: [u8; 2]| {
        let hdr: ip_hdr = pod_read_unaligned(&zeroed_with::<20>(6, &word));
        (
            hdr.get_evil(),
            hdr.get_df(),
            hdr.get_mf(),
            hdr.get_frag_off(),
        )
    };

    assert_eq!(flags([0x80, 0]), (true, false, false, 0));
    assert_eq!(flags([0x40, 0]), (false, true, false, 0));
    assert_eq!(flags([0x20, 0]), (false, false, true, 0));
    assert_eq!(flags([0x1f, 0xff]), (false, false, false, 0x1fff));
}

/// Source, destination, a zero byte, the protocol and the length, RFC 9293 section 3.1
#[test]
fn test_pseudo_hdr() {
    let expected = [
        0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7, 0, 0x11, 0x01, 0x02,
    ];

    assert_eq!(
        bytes_of(&ip_pseudo_hdr::new(SRC, DST, proto::UDP, 0x0102)),
        expected
    );
    assert_eq!(bytes_of(&ip_pseudo_hdr::udp(SRC, DST, 0x0102)), expected);

    let mut hdr = ip_hdr::default();
    hdr.set_protocol(proto::UDP).set_saddr(SRC).set_daddr(DST);
    assert_eq!(bytes_of(&hdr.get_pseudo_hdr(0x0102)), expected);

    let tcp = ip_pseudo_hdr::tcp(SRC, DST, 0x0102);
    assert_eq!(bytes_of(&tcp)[9], 6);

    assert_eq!(
        ip_pseudo_hdr::new(SRC, DST, proto::UDP, 0x0102).csum_partial(),
        ip_csum_partial(&expected)
    );
}

/// The bytes of a TCP header after `f` has set fields of a zeroed one
fn tcp(f: impl FnOnce(&mut tcp_hdr)) -> [u8; 20] {
    let mut hdr = tcp_hdr::zeroed();
    f(&mut hdr);
    bytes_of(&hdr).try_into().unwrap()
}

/// A 5-word header with no options, and resynth's window of 65535
#[test]
fn test_tcp_default() {
    assert_eq!(
        bytes_of(&tcp_hdr::default()),
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0xff, 0xff, 0, 0, 0, 0
        ]
    );
}

#[test]
fn test_tcp_init() {
    assert_eq!(tcp(|h| _ = h.init()), bytes_of(&tcp_hdr::default()));
}

#[test]
fn test_tcp_new() {
    let mut expected = bytes_of(&tcp_hdr::default()).to_vec();
    expected[..4].copy_from_slice(&[1, 2, 3, 4]);

    assert_eq!(bytes_of(&tcp_hdr::new(0x0102, 0x0304)), expected);
}

/// Each setter writes its own field, RFC 9293 section 3.1
#[test]
fn test_tcp_setters() {
    assert_eq!(tcp(|h| _ = h.set_sport(0x0102)), zeroed_with(0, &[1, 2]));
    assert_eq!(tcp(|h| _ = h.set_dport(0x0304)), zeroed_with(2, &[3, 4]));
    assert_eq!(
        tcp(|h| _ = h.set_seq(0x0506_0708)),
        zeroed_with(4, &[5, 6, 7, 8])
    );
    assert_eq!(tcp(|h| _ = h.set_win(0x0910)), zeroed_with(14, &[9, 0x10]));
    assert_eq!(
        tcp(|h| _ = h.set_csum(0x1112)),
        zeroed_with(16, &[0x11, 0x12])
    );
    assert_eq!(
        tcp(|h| _ = h.set_urp(0x1314)),
        zeroed_with(18, &[0x13, 0x14])
    );
}

/// Setting the acknowledgment number sets the ACK flag too
#[test]
fn test_tcp_set_ack() {
    let mut expected: [u8; 20] = zeroed_with(8, &[5, 6, 7, 8]);
    expected[13] = 0x10;

    assert_eq!(tcp(|h| _ = h.set_ack(0x0506_0708)), expected);
}

/// The control bits are in the byte at offset 13, and setting one keeps the others
#[test]
fn test_tcp_flags() {
    assert_eq!(tcp(|h| _ = h.set_fin()), zeroed_with(13, &[0x01]));
    assert_eq!(tcp(|h| _ = h.set_syn()), zeroed_with(13, &[0x02]));
    assert_eq!(tcp(|h| _ = h.set_rst()), zeroed_with(13, &[0x04]));
    assert_eq!(tcp(|h| _ = h.set_push()), zeroed_with(13, &[0x08]));
    assert_eq!(
        tcp(|h| _ = h.set_syn().set_fin().set_rst().set_push()),
        zeroed_with(13, &[0x0f])
    );
}

/// The bytes of a UDP header after `f` has set fields of a zeroed one
fn udp(f: impl FnOnce(&mut udp_hdr)) -> [u8; 8] {
    let mut hdr = udp_hdr::zeroed();
    f(&mut hdr);
    bytes_of(&hdr).try_into().unwrap()
}

/// The length includes the 8-byte header
#[test]
fn test_udp_default() {
    assert_eq!(bytes_of(&udp_hdr::default()), [0, 0, 0, 0, 0, 8, 0, 0]);
}

/// Each setter writes its own field, RFC 768
#[test]
fn test_udp_setters() {
    assert_eq!(udp(|h| _ = h.set_sport(0x0102)), [1, 2, 0, 0, 0, 0, 0, 0]);
    assert_eq!(udp(|h| _ = h.set_dport(0x0304)), [0, 0, 3, 4, 0, 0, 0, 0]);
    assert_eq!(udp(|h| _ = h.set_len(0x0506)), [0, 0, 0, 0, 5, 6, 0, 0]);
    assert_eq!(udp(|h| _ = h.set_csum(0x0708)), [0, 0, 0, 0, 0, 0, 7, 8]);
    assert_eq!(
        udp(|h| _ = h.set_len(8).add_len(0x0100)),
        [0, 0, 0, 0, 1, 8, 0, 0]
    );
}

#[test]
fn test_icmp_types() {
    assert_eq!(ICMP_ECHOREPLY, 0);
    assert_eq!(ICMP_ECHO, 8);
}

/// Type, code and checksum, RFC 792
#[test]
fn test_icmp_setters() {
    let mut hdr = icmp_hdr::zeroed();
    hdr.set_typ(1);
    assert_eq!(bytes_of(&hdr), [1, 0, 0, 0]);

    let mut hdr = icmp_hdr::zeroed();
    hdr.set_code(2);
    assert_eq!(bytes_of(&hdr), [0, 2, 0, 0]);

    let mut hdr = icmp_hdr::zeroed();
    hdr.set_csum(0x0304);
    assert_eq!(bytes_of(&hdr), [0, 0, 3, 4]);
}

/// Identifier, then sequence number, RFC 792
#[test]
fn test_icmp_echo_setters() {
    let mut hdr = icmp_echo_hdr::zeroed();
    hdr.set_id(0x0102);
    assert_eq!(bytes_of(&hdr), [1, 2, 0, 0]);

    let mut hdr = icmp_echo_hdr::zeroed();
    hdr.set_seq(0x0304);
    assert_eq!(bytes_of(&hdr), [0, 0, 3, 4]);
}

#[test]
fn test_tcp_getters() {
    let hdr: tcp_hdr = pod_read_unaligned(&[
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x50, 0x12, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    ]);

    assert_eq!(hdr.get_sport(), 0x0102);
    assert_eq!(hdr.get_dport(), 0x0304);
    assert_eq!(hdr.get_seq(), 0x0506_0708);
    assert_eq!(hdr.get_ack(), 0x090a_0b0c);
    assert_eq!(hdr.get_doff(), 0x50);
    assert_eq!(hdr.get_flags(), 0x12);
    assert_eq!(hdr.get_win(), 0x0d0e);
    assert_eq!(hdr.get_csum(), 0x0f10);
    assert_eq!(hdr.get_urp(), 0x1112);
}

/// Growing the length past 65535 wraps, for malformed packets, rather than panicking in debug
/// builds
#[test]
fn test_udp_add_len_wraps() {
    assert_eq!(
        udp(|h| _ = h.set_len(0xffff).add_len(2)),
        [0, 0, 0, 0, 0, 1, 0, 0]
    );
}

#[test]
fn test_udp_getters() {
    let hdr: udp_hdr = pod_read_unaligned(&[1, 2, 3, 4, 5, 6, 7, 8]);

    assert_eq!(hdr.get_sport(), 0x0102);
    assert_eq!(hdr.get_dport(), 0x0304);
    assert_eq!(hdr.get_len(), 0x0506);
    assert_eq!(hdr.get_csum(), 0x0708);
}

#[test]
fn test_icmp_getters() {
    let hdr: icmp_hdr = pod_read_unaligned(&[1, 2, 3, 4]);

    assert_eq!(hdr.get_typ(), 1);
    assert_eq!(hdr.get_code(), 2);
    assert_eq!(hdr.get_csum(), 0x0304);

    let hdr: icmp_echo_hdr = pod_read_unaligned(&[1, 2, 3, 4]);

    assert_eq!(hdr.get_id(), 0x0102);
    assert_eq!(hdr.get_seq(), 0x0304);
}
