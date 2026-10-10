use std::net::{Ipv4Addr, SocketAddrV4};

use pkt::Packet;

use super::Frame;
use crate::TcpFlow;

const CL: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
const SV: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 80);

fn flow() -> TcpFlow {
    TcpFlow::new(CL, SV, 1000, 5000, false)
}

/// Assert that every packet has correct IP and TCP checksums
fn assert_csums_ok(what: &str, pkts: impl IntoIterator<Item = Packet>) {
    for pkt in pkts {
        let frame = Frame::from(&pkt);

        assert!(frame.ip_csum_ok(), "{what}: IP checksum");
        assert!(frame.l4_csum_ok(), "{what}: TCP checksum");
    }
}

/// RST segments used to have a zero TCP checksum
#[test]
fn test_reset_csum() {
    let flow = flow();

    assert_csums_ok("client_reset", [flow.client_reset()]);
    assert_csums_ok("server_reset", [flow.server_reset()]);
}

/// Every other kind of segment gets correct checksums
#[test]
fn test_csums() {
    let mut flow = flow();

    assert_csums_ok("open", flow.open());
    assert_csums_ok("client_message", flow.client_message(b"hello", true, 0));
    assert_csums_ok("server_message", flow.server_message(b"world", true, 0));
    assert_csums_ok(
        "client_message without ack",
        flow.client_message(b"a", false, 0),
    );
    assert_csums_ok(
        "server_message without ack",
        flow.server_message(b"b", false, 0),
    );
    assert_csums_ok(
        "client_data_segment",
        [flow.client_data_segment(b"c").into()],
    );
    assert_csums_ok(
        "server_data_segment",
        [flow.server_data_segment(b"d").into()],
    );
    assert_csums_ok("client_ack", [flow.client_ack().into()]);
    assert_csums_ok("server_ack", [flow.server_ack().into()]);
    assert_csums_ok("client_close", flow.client_close());
    assert_csums_ok("server_close", flow.server_close());
}

/// Setting a fragment offset recomputes the IP checksum
#[test]
fn test_frag_off_ip_csum() {
    let mut flow = flow();

    for pkt in flow.client_message(b"hello", false, 1) {
        let frame = Frame::from(&pkt);

        assert_eq!(frame.ip().get_frag_off(), 1);
        assert!(frame.ip_csum_ok());
    }
}
