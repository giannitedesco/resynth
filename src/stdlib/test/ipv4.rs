use std::net::SocketAddrV4;

use pkt::ipv4::tcp_hdr;

use crate::val::Val;

use super::{Call, hdr, s};

/// A TCP flow whose client and server sequence numbers are easy to tell apart
fn seq_flow() -> Val {
    Call::func("ipv4::tcp::flow")
        .arg(SocketAddrV4::new([10, 0, 0, 1].into(), 40000))
        .arg(SocketAddrV4::new([10, 0, 0, 2].into(), 80))
        .named("cl_seq", 1000u64)
        .named("sv_seq", 5000u64)
        .exec()
        .expect("flow failed")
}

/// seq: and ack: on server methods used to set the ack and seq fields respectively
#[test]
fn tcp_seq_ack_overrides() {
    for (method, send_ack, payload) in [
        ("client_message", true, true),
        ("client_segment", false, true),
        ("client_ack", false, false),
        ("server_message", true, true),
        ("server_segment", false, true),
        ("server_ack", false, false),
    ] {
        let mut call = Call::method(&seq_flow(), method);
        if send_ack {
            call = call.named("send_ack", false);
        }
        call = call.named("seq", 7777u64).named("ack", 8888u64);
        if payload {
            call = call.extra(s("x"));
        }
        let frames = call.frames();
        let tcp: tcp_hdr = frames[0].l4(0);

        assert_eq!((tcp.get_seq(), tcp.get_ack()), (7777, 8888), "{method}");
    }
}

/// The raw segment methods return a TCP header and payload, with no IP header
#[test]
fn tcp_raw_segment_seq_ack_overrides() {
    for method in ["client_raw_segment", "server_raw_segment"] {
        let tcp: tcp_hdr = hdr(&Call::method(&seq_flow(), method)
            .named("seq", 7777u64)
            .named("ack", 8888u64)
            .extra(s("x"))
            .bytes());

        assert_eq!((tcp.get_seq(), tcp.get_ack()), (7777, 8888), "{method}");
    }
}

/// The TCP checksum of a bare header is whatever csum says, zero by default
#[test]
fn tcp_hdr_csum() {
    for method in ["client_hdr", "server_hdr"] {
        let tcp: tcp_hdr = hdr(&Call::method(&seq_flow(), method)
            .named("bytes", 8u64)
            .named("csum", 0x1234u64)
            .bytes());
        assert_eq!(tcp.get_csum(), 0x1234, "{method}");

        let tcp: tcp_hdr = hdr(&Call::method(&seq_flow(), method)
            .named("bytes", 8u64)
            .bytes());
        assert_eq!(tcp.get_csum(), 0, "{method}");
    }
}
