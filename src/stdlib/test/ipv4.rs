use pkt::ipv4::tcp_hdr;

use crate::program::RuntimeErrorKind::TooManyArgs;

use super::{bytes, eval, frames, hdr};

/// A TCP flow whose client and server sequence numbers are easy to tell apart
const SEQ_FLOW: &str = "import ipv4;\n\
    let flow = ipv4::tcp::flow(10.0.0.1/40000, 10.0.0.2/80, cl_seq: 1000, sv_seq: 5000);\n";

/// seq: and ack: on server methods used to set the ack and seq fields respectively
#[test]
fn tcp_seq_ack_overrides() {
    for call in [
        "flow.client_message(send_ack: false, seq: 7777, ack: 8888, \"x\");",
        "flow.client_segment(seq: 7777, ack: 8888, \"x\");",
        "flow.client_ack(seq: 7777, ack: 8888);",
        "flow.server_message(send_ack: false, seq: 7777, ack: 8888, \"x\");",
        "flow.server_segment(seq: 7777, ack: 8888, \"x\");",
        "flow.server_ack(seq: 7777, ack: 8888);",
    ] {
        let frames = frames(&format!("{SEQ_FLOW}{call}"));
        let tcp: tcp_hdr = frames[0].l4(0);

        assert_eq!((tcp.get_seq(), tcp.get_ack()), (7777, 8888), "{call}");
    }
}

/// The raw segment methods return a TCP header and payload, with no IP header
#[test]
fn tcp_raw_segment_seq_ack_overrides() {
    for call in [
        "flow.client_raw_segment(seq: 7777, ack: 8888, \"x\");",
        "flow.server_raw_segment(seq: 7777, ack: 8888, \"x\");",
    ] {
        let tcp: tcp_hdr = hdr(&bytes(&format!("{SEQ_FLOW}{call}")));

        assert_eq!((tcp.get_seq(), tcp.get_ack()), (7777, 8888), "{call}");
    }
}

/// IpFrag's methods take no payload, and passing one used to abort the process
#[test]
fn ipfrag_methods_reject_extra_args() {
    let src = "import ipv4;\n\
               let pkt = ipv4::frag(10.0.0.1, 10.0.0.2, \"01234567\");\n";

    for call in [
        "pkt.fragment(0, 1, false, \"x\");",
        "pkt.tail(0, false, \"x\");",
        "pkt.datagram(false, \"x\");",
    ] {
        let err = eval(&format!("{src}{call}")).expect_err(call);
        assert!(matches!(err.kind, TooManyArgs { .. }), "{call}: {err}");
    }
}
