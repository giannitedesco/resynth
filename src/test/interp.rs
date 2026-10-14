use std::io;
use std::mem::{offset_of, size_of};
use std::net::{Ipv4Addr, SocketAddrV4};

use bytemuck::{Pod, pod_read_unaligned};
use pkt::dhcp::dhcp_hdr;
use pkt::eth::eth_hdr;
use pkt::ipv4::{ip_hdr, tcp_hdr};

use crate::check::{Diagnostic, DiagnosticKind, check};
use crate::hir::{Call, Const, Expr, ExprKind, Program, Stmt, StmtKind};
use crate::interp::RuntimeErrorKind::{IoError, PcapWrite};
use crate::interp::{Effect, RuntimeError, TreeInterp};
use crate::lex::Lexer;
use crate::loc::Loc;
use crate::parse::parse;
use crate::stdlib::toplevel_module;
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::Val;

type Warnings = Vec<(Loc, String)>;

/// Each packet a program sent, with its timestamp
type Sent = Vec<(u64, Vec<u8>)>;

/// What happened when a program ran: what it sent, waited for and discarded before it stopped,
/// how it stopped, and the checker's warnings
struct Run {
    sent: Sent,
    waits: Vec<(Loc, u64)>,
    discards: Vec<(Loc, Val)>,
    res: Result<(), RuntimeError>,
    warnings: Warnings,
}

/// Check a program, which must check, and run it from time 0. `send` decides whether sending
/// each packet succeeds.
fn run_with(src: &str, mut send: impl FnMut() -> io::Result<()>) -> Run {
    let stmts = parse(Lexer::lex(src.lines()).expect("lex failed")).expect("parse failed");
    let mut warnings = Vec::new();
    let prog = check(stmts, |Diagnostic { loc, kind }| match kind {
        DiagnosticKind::Warning(warn) => warnings.push((loc, warn.to_string())),
        DiagnosticKind::Error(err) => panic!("check failed: {loc}: {err}"),
    })
    .unwrap_or_else(|summary| panic!("check failed: {summary}"));

    let mut sent = Vec::new();
    let mut waits = Vec::new();
    let mut discards = Vec::new();
    let res = TreeInterp::new(prog, 0).run(|loc, effect| {
        match effect {
            Effect::Packet { time, pkt } => {
                sent.push((time, pkt.to_vec()));
                send().map_err(PcapWrite)?;
            }
            Effect::TimeJump(ns) => waits.push((loc, ns)),
            Effect::Discard(val) => discards.push((loc, val)),
        }
        Ok(())
    });

    Run {
        sent,
        waits,
        discards,
        res,
        warnings,
    }
}

fn run(src: &str) -> Run {
    run_with(src, || Ok(()))
}

/// The packets a program sends, which must run to the end
fn packets(src: &str) -> Vec<Vec<u8>> {
    let Run { sent, res, .. } = run(src);
    res.expect("run failed");
    sent.into_iter().map(|(_, pkt)| pkt).collect()
}

/// The values a program discards
fn discards(src: &str) -> Vec<(Loc, Val)> {
    let Run { res, discards, .. } = run(src);
    res.expect("run failed");
    discards
}

/// A header of type `T` at `off` in `bytes`
fn hdr<T: Pod>(bytes: &[u8], off: usize) -> T {
    pod_read_unaligned(&bytes[off..off + size_of::<T>()])
}

/// Where a TCP segment's payload starts, in an Ethernet frame with no IP or TCP options
const TCP_PAYLOAD: usize = size_of::<eth_hdr>() + size_of::<ip_hdr>() + size_of::<tcp_hdr>();

const FLOW: &str = "import ipv4;\nlet c = ipv4::tcp::flow(1.2.3.4:1, 5.6.7.8:2);\n";

/// a port wider than `u16` keeps its low bits when it runs. The checker folds every constant port,
/// so the HIR is built by hand.
#[test]
fn run_slash_port_range() {
    let at = |col| Loc::new(1, col);
    let sock = |port| {
        Expr::new(
            at(1),
            ExprKind::SockAddr {
                ip: Box::new(Expr::new(
                    at(1),
                    ExprKind::Const(Const::Ip4(Ipv4Addr::new(1, 2, 3, 4))),
                )),
                port: Box::new(Expr::new(at(11), ExprKind::Const(Const::U64(port)))),
            },
        )
    };
    let prog = Program::new(
        Box::new([
            Stmt::new(at(1), StmtKind::Discard(sock(65535))),
            Stmt::new(at(1), StmtKind::Discard(sock(65536))),
        ]),
        Box::new([]),
    );

    let mut vals = Vec::new();
    TreeInterp::new(prog, 0)
        .run(|_, effect| {
            if let Effect::Discard(val) = effect {
                vals.push(val);
            }
            Ok(())
        })
        .expect("run failed");
    assert_eq!(
        vals,
        [
            Val::Sock4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 65535)),
            Val::Sock4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 0)),
        ]
    );
}

/// a port whose type is wider than `u16` runs with its value
#[test]
fn run_slash_port_from_call() {
    assert_eq!(
        discards("import text;\nlet s = 1.2.3.4 / text::len(\"ab\");\ns;"),
        [(
            Loc::new(3, 1),
            Val::Sock4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 2))
        )]
    );
}

/// an untyped integer passed as bytes is written at the narrowest width that holds it, big-endian
#[test]
fn run_untyped_int_as_bytes() {
    for (n, bytes) in [("5", &b"a\x05"[..]), ("300", b"a\x01\x2c")] {
        assert_eq!(
            discards(&format!(
                "import text;\nlet x = text::concat(\"a\", {n});\nx;"
            )),
            [(Loc::new(3, 1), Val::str(bytes))]
        );
    }
}

/// The code in each ```resynth block of a doc comment, joined into one program
fn doc_program(doc: &str) -> String {
    let mut prog = String::new();
    let mut in_block = false;

    for line in doc.lines().map(str::trim_start) {
        match line {
            "```resynth" => in_block = true,
            "```" => in_block = false,
            code if in_block => {
                prog.push_str(code);
                prog.push('\n');
            }
            _ => {}
        }
    }

    prog
}

/// The tls module's handshake example runs.
#[test]
fn run_tls_module_doc_example() {
    let src = doc_program(toplevel_module("tls").expect("no tls").doc);

    // The server flight holds the Server Key Exchange record: handshake, TLS 1.2, 556 bytes,
    // then a server_key_exchange message of 552 bytes
    let ske: &[u8] = &[0x16, 0x03, 0x03, 0x02, 0x2c, 0x0c, 0x00, 0x02, 0x28];
    assert!(
        packets(&src)
            .iter()
            .any(|pkt| pkt.windows(ske.len()).any(|w| w == ske))
    );
}

/// a call through a local function value
#[test]
fn run_call_through_local() {
    let Run {
        sent,
        res,
        warnings,
        ..
    } = run("import std;\nlet f = std::be16;\nlet x = f(1);");
    res.expect("run failed");
    assert_eq!((sent, warnings), (vec![], vec![]));
}

/// a bound method keeps its receiver, and each call advances it
#[test]
fn run_bound_method() {
    let once = packets(&format!("{FLOW}let m = c.open;\nm();"));
    assert_eq!(once.len(), 3);

    let twice = packets(&format!("{FLOW}let m = c.open;\nm();\nm();"));
    assert_eq!(twice.len(), 6);
    // The same bytes as a 444-byte pcap: a 24-byte file header, then a 16-byte header for each
    // packet
    assert_eq!(
        24 + twice.iter().map(|pkt| 16 + pkt.len()).sum::<usize>(),
        444
    );
    let seq = |pkt: &[u8]| hdr::<tcp_hdr>(pkt, TCP_PAYLOAD - size_of::<tcp_hdr>()).get_seq();
    assert!(
        seq(&twice[3]) > seq(&twice[0]),
        "the second handshake follows the first"
    );
}

#[test]
fn run_args_in_source_order_probes() {
    for (first, second) in [("file", "sname"), ("sname", "file")] {
        let Run {
            sent,
            res,
            warnings,
            ..
        } = run(&format!(
            "import ipv4;\nimport dhcp;\nlet c = ipv4::tcp::flow(1.2.3.4:1, 5.6.7.8:2);\n\
             let h = dhcp::hdr({first}: c.client_hdr(bytes: 1), {second}: c.client_hdr(bytes: 1));\n\
             h;"
        ));
        res.expect("run failed");
        assert!(sent.is_empty());
        assert_eq!(
            warnings,
            [(Loc::new(5, 1), "discarded value of type bytes".to_owned())]
        );
    }
}

/// sending `h` so its bytes can be seen: the argument written first is evaluated first, so it gets
/// the first sequence number, whatever the order of the fields
#[test]
fn run_args_in_source_order() {
    let seqs = |first: &str, second: &str| {
        let pkts = packets(&format!(
            "{FLOW}import dhcp;\n\
             let h = dhcp::hdr({first}: c.client_hdr(bytes: 1), {second}: c.client_hdr(bytes: 1));\n\
             c.client_segment(h);"
        ));
        let field = |off| hdr::<tcp_hdr>(&pkts[0], TCP_PAYLOAD + off).get_seq();
        (
            field(offset_of!(dhcp_hdr, sname)),
            field(offset_of!(dhcp_hdr, file)),
        )
    };

    assert_eq!(seqs("file", "sname"), (2, 1), "sname, file");
    assert_eq!(seqs("sname", "file"), (1, 2), "sname, file");
}

/// emit: one packet, and a sequence of them
#[test]
fn run_emit() {
    assert_eq!(packets(&format!("{FLOW}c.client_segment(\"x\");")).len(), 1);
    assert_eq!(packets(&format!("{FLOW}c.client_message(\"x\");")).len(), 2);
    assert_eq!(
        packets(&format!(
            "{FLOW}import erspan1;\nlet er = erspan1::session(10.0.0.1, 10.0.0.2);\n\
             er.encap(c.client_message(\"x\"));"
        ))
        .len(),
        2
    );
}

/// wait: a time jump moves the next packet's timestamp, and the caller is told about it at the
/// statement
#[test]
fn run_wait() {
    let Run {
        sent, waits, res, ..
    } = run(&format!(
        "{FLOW}import time;\nc.client_segment(\"x\");\ntime::jump_seconds(1);\nc.client_segment(\"x\");"
    ));
    res.expect("run failed");
    assert!(sent[1].0 - sent[0].0 > 1_000_000_000, "{sent:?}");
    assert_eq!(waits, [(Loc::new(5, 1), 1_000_000_000)]);
}

/// void: `client_hole` as a statement runs, with no warning, and isn't discarded
#[test]
fn run_void() {
    let Run {
        sent,
        discards,
        res,
        warnings,
        ..
    } = run(include_str!("../../examples/missing-start.rsyn"));
    res.expect("run failed");
    assert_eq!(warnings, []);
    assert_eq!(discards, []);
    assert!(!sent.is_empty());
}

/// discard: the caller gets the discarded value, at the statement
#[test]
fn run_discard_gives_value() {
    let Run { discards, res, .. } = run("let x = 1;\n\"abc\";");
    res.expect("run failed");
    assert_eq!(discards, [(Loc::new(2, 1), Val::Str(Buf::from(b"abc")))]);
}

/// discard: a discarded value is still evaluated, so a discarded header advances the flow
#[test]
fn run_discard_still_runs() {
    let seq = |src: &str| {
        let pkts = packets(src);
        hdr::<tcp_hdr>(&pkts[0], TCP_PAYLOAD - size_of::<tcp_hdr>()).get_seq()
    };
    assert_eq!(seq(&format!("{FLOW}c.client_segment(\"x\");")), 1);
    assert_eq!(
        seq(&format!(
            "{FLOW}c.client_hdr(bytes: 5);\nc.client_segment(\"x\");"
        )),
        6
    );
}

/// A property's object is evaluated, so its errors stop the program. No stdlib class has a
/// property, so the HIR the checker lowers it to is built by hand, and its lowering isn't tested:
/// `io::file("no-such-file.der").prop;`
#[test]
fn run_property_evaluates_object() {
    let Some(Symbol::Func(file)) = toplevel_module("io").expect("no io").get("file") else {
        panic!("no io::file");
    };
    let at = |col| Loc::new(1, col);
    let path = Expr::new(
        at(10),
        ExprKind::Const(Const::Bytes(Buf::from("no-such-file.der"))),
    );
    let call = Call::new(
        Expr::new(at(1), ExprKind::Const(Const::Func(file))),
        file,
        Box::new([(path, 0)]),
        Box::new([]),
    );
    let obj = Expr::new(at(5), ExprKind::Call(Box::new(call)));
    let value = Box::new(Expr::new(at(30), ExprKind::Const(Const::U64(1))));
    let expr = Expr::new(
        at(1),
        ExprKind::Seq {
            effects: Box::new([obj]),
            value,
        },
    );
    assert_eq!(
        expr.to_string(),
        "(seq (call func:file (: filename \"no-such-file.der\")) u64:0x1)"
    );
    let prog = Program::new(
        Box::new([Stmt::new(at(1), StmtKind::Discard(expr))]),
        Box::new([]),
    );

    let err = TreeInterp::new(prog, 0)
        .run(|_, _| Ok(()))
        .expect_err("run succeeded");
    assert!(
        matches!(err.kind, IoError(_)) && err.loc == at(5),
        "{err:?}"
    );
}

/// A static bytes constant is sent unchanged
#[test]
fn run_bytes_constant() {
    let pkts = packets(&format!(
        "{FLOW}import text;\nc.client_segment(text::CRLF);"
    ));
    assert_eq!(&pkts[0][TCP_PAYLOAD..], b"\r\n");
}

/// An Ip4 converts to 4 bytes
#[test]
fn run_ip4_to_bytes() {
    let pkts = packets(&format!("{FLOW}c.open();\nc.client_message(1.2.3.4);"));
    assert_eq!(&pkts[3][TCP_PAYLOAD..], [1, 2, 3, 4]);
}

/// The checker's warnings come before any run-time error, even on a later line
#[test]
fn run_warning_before_runtime_error() {
    for (src, warning) in [
        (
            "import io;\nlet x = io::file(\"no-such-file.der\");\n1;",
            (Loc::new(3, 1), "discarded value of type u8"),
        ),
        (
            "import io;\nlet x = io::file(\"no-such-file.der\");\nimport io;",
            (Loc::new(3, 8), "multiple imports of \"io\""),
        ),
    ] {
        let Run { res, warnings, .. } = run(src);
        let err = res.expect_err("run succeeded");
        assert!(
            matches!(err.kind, IoError(_)) && err.loc == Loc::new(2, 13),
            "{err:?}"
        );
        assert_eq!(warnings, [(warning.0, warning.1.to_owned())]);
    }
}

/// An effect that fails stops the program, at the statement
#[test]
fn run_effect_error() {
    let Run { sent, res, .. } = run_with(&format!("{FLOW}\nc.open();"), || {
        Err(io::ErrorKind::StorageFull.into())
    });
    let err = res.expect_err("run succeeded");
    assert!(
        matches!(err.kind, PcapWrite(_)) && err.loc == Loc::new(4, 1),
        "{err:?}"
    );
    assert_eq!(sent.len(), 1);
}
