use bytemuck::{Pod, pod_read_unaligned};
use pkt::eth::{eth_hdr, ethertype};
use pkt::ipv4::ip_hdr;

use crate::ast::Stmt;
use crate::lex::Lexer;
use crate::parse::parse;
use crate::program::{Program, RuntimeError};
use crate::val::Val;

mod dns;
mod ipv4;

/// Run a program and evaluate its final statement, which must be an expression
fn eval(src: &str) -> Result<Val, RuntimeError> {
    let mut stmts = parse(Lexer::lex(src.lines()).expect("lex failed")).expect("parse failed");

    let Some(Stmt::Expr(last)) = stmts.pop() else {
        panic!("the last statement must be an expression");
    };

    let mut prog = Program::dummy();
    prog.run(stmts)?;
    prog.eval(last)
}

/// Each packet produced by a program's final expression
fn frames(src: &str) -> Vec<Frame> {
    match eval(src).expect("run failed") {
        Val::Pkt(pkt) => vec![Frame(pkt.to_vec())],
        Val::PktGen(pkts) => pkts.iter().map(|pkt| Frame(pkt.to_vec())).collect(),
        val => panic!("expected packets, got {val:?}"),
    }
}

/// The bytes of a program's final expression, which must be a string
fn bytes(src: &str) -> Vec<u8> {
    match eval(src).expect("run failed") {
        Val::Str(buf) => buf.as_ref().to_vec(),
        val => panic!("expected a string, got {val:?}"),
    }
}

/// A header of type `T` at the start of `bytes`
fn hdr<T: Pod>(bytes: &[u8]) -> T {
    pod_read_unaligned(&bytes[..std::mem::size_of::<T>()])
}

/// An Ethernet frame holding an IPv4 datagram, read back through pkt's headers
struct Frame(Vec<u8>);

impl Frame {
    const IP_OFF: usize = std::mem::size_of::<eth_hdr>();

    fn eth(&self) -> eth_hdr {
        hdr(&self.0)
    }

    fn ip(&self) -> ip_hdr {
        assert_eq!(self.eth().get_proto(), ethertype::IPV4);
        hdr(&self.0[Self::IP_OFF..])
    }

    /// Everything after the IP header and any options, up to the IP total length
    fn ip_payload(&self) -> &[u8] {
        let ip = self.ip();
        let start = Self::IP_OFF + ((ip.get_ihl_version() & 0xf) as usize) * 4;

        &self.0[start..Self::IP_OFF + ip.get_tot_len() as usize]
    }

    /// The header of type `T` at `off` bytes into the IP payload
    fn l4<T: Pod>(&self, off: usize) -> T {
        hdr(&self.ip_payload()[off..])
    }
}
