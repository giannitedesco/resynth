use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

use ezpkt::TcpFlow;
use pkt::Packet;

const TCP_OPEN: FuncDef = func!(
    /// Performs a TCP 3-way handshake
    resynth fn open(
        =>
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.open().into())
        }
);

const TCP_CL_MSG: FuncDef = func!(
    /// Sends a message from client to server, advancing the sequence number.
    /// By default also emits an ACK from the server in response (`send_ack: true`).
    /// Use `send_ack: false` to suppress the ACK, for example when building
    /// out-of-order or reassembly test cases.
    resynth fn client_message(
        =>
        /// If true, emit an ACK from the server after the data segment
        send_ack: Bool = true,
        /// Override the TCP sequence number for this segment
        seq: Type = ValType::U32,
        /// Override the TCP acknowledgement number for this segment
        ack: Type = ValType::U32,
        /// IP fragment offset (in 8-byte units) for the enclosing IP datagram
        frag_off: U16 = 0,
        =>
        Str
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let send_ack: bool = args.next().into();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();
        let frag_off: u16 = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let saved = this.push_state(seq, ack);
        let pkt = this.client_message(bytes.as_ref(), send_ack, frag_off);
        this.pop_state(saved);

        Ok(pkt.into())
    }
);

const TCP_SV_MSG: FuncDef = func!(
    /// Sends a message from server to client, advancing the sequence number.
    /// By default also emits an ACK from the client in response (`send_ack: true`).
    /// Use `send_ack: false` to suppress the ACK, for example when building
    /// out-of-order or reassembly test cases.
    resynth fn server_message(
        =>
        /// If true, emit an ACK from the client after the data segment
        send_ack: Bool = true,
        /// Override the TCP sequence number for this segment
        seq: Type = ValType::U32,
        /// Override the TCP acknowledgement number for this segment
        ack: Type = ValType::U32,
        /// IP fragment offset (in 8-byte units) for the enclosing IP datagram
        frag_off: U16 = 0,
        =>
        Str
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let send_ack: bool = args.next().into();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();
        let frag_off: u16 = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let saved = this.push_state(seq, ack);
        let pkt = this.server_message(bytes.as_ref(), send_ack, frag_off);
        this.pop_state(saved);

        Ok(pkt.into())
    }
);

const TCP_CL_SEG: FuncDef = func!(
    /// Returns a single data segment from client to server, advancing the
    /// sequence number. Does not emit an ACK. Returns a `Pkt` (complete
    /// Ethernet+IP+TCP packet) rather than a `PktGen`.
    resynth fn client_segment(
        =>
        /// Override the TCP sequence number for this segment
        seq: Type = ValType::U32,
        /// Override the TCP acknowledgement number for this segment
        ack: Type = ValType::U32,
        =>
        Str
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let saved = this.push_state(seq, ack);
        let pkt: Packet = this.client_data_segment(bytes.as_ref()).into();
        this.pop_state(saved);

        Ok(pkt.into())
    }
);

const TCP_SV_SEG: FuncDef = func!(
    /// Returns a single data segment from server to client, advancing the
    /// sequence number. Does not emit an ACK. Returns a `Pkt` (complete
    /// Ethernet+IP+TCP packet) rather than a `PktGen`.
    resynth fn server_segment(
        =>
        /// Override the TCP sequence number for this segment
        seq: Type = ValType::U32,
        /// Override the TCP acknowledgement number for this segment
        ack: Type = ValType::U32,
        =>
        Str
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let saved = this.push_state(seq, ack);
        let pkt: Packet = this.server_data_segment(bytes.as_ref()).into();
        this.pop_state(saved);

        Ok(pkt.into())
    }
);

const TCP_CL_RAW_SEG: FuncDef = func!(
    /// Returns TCP header + payload bytes only (no Ethernet or IP header) for
    /// a client-to-server segment, advancing the sequence number. Returns
    /// `bytes` rather than `Pkt`. Use this with `ipv4::frag` to build
    /// IP-fragmented TCP segments.
    resynth fn client_raw_segment(
        =>
        /// Override the TCP sequence number for this segment
        seq: Type = ValType::U32,
        /// Override the TCP acknowledgement number for this segment
        ack: Type = ValType::U32,
        =>
        Str
    ) -> Str
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let saved = this.push_state(seq, ack);
        let pkt = this.client_data_segment(bytes.as_ref());
        this.pop_state(saved);

        Ok(Val::str(pkt.into_tcpseg()))
    }
);

const TCP_SV_RAW_SEG: FuncDef = func!(
    /// Returns TCP header + payload bytes only (no Ethernet or IP header) for
    /// a server-to-client segment, advancing the sequence number. Returns
    /// `bytes` rather than `Pkt`. Use this with `ipv4::frag` to build
    /// IP-fragmented TCP segments.
    resynth fn server_raw_segment(
        =>
        /// Override the TCP sequence number for this segment
        seq: Type = ValType::U32,
        /// Override the TCP acknowledgement number for this segment
        ack: Type = ValType::U32,
        =>
        Str
    ) -> Str
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let saved = this.push_state(seq, ack);
        let pkt = this.server_data_segment(bytes.as_ref());
        this.pop_state(saved);

        Ok(Val::str(pkt.into_tcpseg()))
    }
);

const TCP_CL_HDR: FuncDef = func!(
    /// Returns a TCP header only (no payload, no IP header) for a
    /// client-to-server segment, as `bytes`. The optional `bytes` argument
    /// declares how many payload bytes the header should account for in the
    /// sequence number, without actually emitting them. Use with `ipv4::frag`
    /// to craft fragmented packets where the TCP header lands in one fragment
    /// and the payload in another.
    resynth fn client_hdr(
        =>
        /// Number of payload bytes to advance the sequence number by, without emitting them
        bytes: U32 = 0,
        =>
        Void
    ) -> Str
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: u32 = args.next().into();

        Ok(Val::Str(Buf::from(this.client_hdr(bytes))))
    }
);

const TCP_SV_HDR: FuncDef = func!(
    /// Returns a TCP header only (no payload, no IP header) for a
    /// server-to-client segment, as `bytes`. The optional `bytes` argument
    /// declares how many payload bytes the header should account for in the
    /// sequence number, without actually emitting them. Use with `ipv4::frag`
    /// to craft fragmented packets where the TCP header lands in one fragment
    /// and the payload in another.
    resynth fn server_hdr(
        =>
        /// Number of payload bytes to advance the sequence number by, without emitting them
        bytes: U32 = 0,
        =>
        Void
    ) -> Str
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: u32 = args.next().into();

        Ok(Val::Str(Buf::from(this.server_hdr(bytes))))
    }
);

const TCP_CL_ACK: FuncDef = func!(
    /// Sends an ACK from the client
    resynth fn client_ack(
        =>
        /// Override the TCP sequence number for this ACK
        seq: Type = ValType::U32,
        /// Override the TCP acknowledgement number for this ACK
        ack: Type = ValType::U32,
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();

        let saved = this.push_state(seq, ack);
        let pkt: Packet = this.client_ack().into();
        this.pop_state(saved);

        Ok(pkt.into())
    }
);

const TCP_SV_ACK: FuncDef = func!(
    /// Sends an ACK from the server
    resynth fn server_ack(
        =>
        /// Override the TCP sequence number for this ACK
        seq: Type = ValType::U32,
        /// Override the TCP acknowledgement number for this ACK
        ack: Type = ValType::U32,
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();

        let saved = this.push_state(seq, ack);
        let pkt: Packet = this.server_ack().into();
        this.pop_state(saved);

        Ok(pkt.into())
    }
);

const TCP_CL_HOLE: FuncDef = func!(
    /// Creates a hole in the sever's Tx sequence space, making it look like we missed a packet
    /// from the client
    resynth fn client_hole(
        /// Number of bytes to advance the client sequence number without emitting a packet
        bytes: U32,
        =>
        =>
        Void
    ) -> Void
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: u32 = args.next().into();

        this.client_hole(bytes);
        Ok(Val::Nil)
    }
);

const TCP_SV_HOLE: FuncDef = func!(
    /// Creates a hole in the sever's Tx sequence space, making it look like we missed a packet
    /// from the server
    resynth fn server_hole(
        /// Number of bytes to advance the server sequence number without emitting a packet
        bytes: U32,
        =>
        =>
        Void
    ) -> Void
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: u32 = args.next().into();

        this.server_hole(bytes);
        Ok(Val::Nil)
    }
);

const TCP_CL_CLOSE: FuncDef = func!(
    /// Shutdown both sides of the TCP connection, with the client sending the first FIN
    resynth fn client_close(
        =>
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.client_close().into())
    }
);

const TCP_SV_CLOSE: FuncDef = func!(
    /// Shutdown both sides of the TCP connection, with the server sending the first FIN
    resynth fn server_close(
        =>
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.server_close().into())
    }
);

const TCP_CL_RESET: FuncDef = func!(
    /// Send a RST packet from the client
    resynth fn client_reset(
        =>
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.client_reset().into())
    }
);

const TCP_SV_RESET: FuncDef = func!(
    /// Send a RST packet from the server
    resynth fn server_reset(
        =>
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.server_reset().into())
    }
);

static TCP_FLOW: ClassDef = class!(
    /// # TCP Connection
    ///
    /// Represents a TCP flow between a client and server socket address. The
    /// flow tracks sequence and acknowledgement numbers automatically.
    ///
    /// Use [open](#open) to perform the 3-way handshake and [client_close](#client_close) /
    /// [server_close](#server_close) for the FIN/ACK teardown.
    ///
    /// For data transfer there are three levels of abstraction:
    ///
    /// - [client_message](#client_message) / [server_message](#server_message) — emit a data
    ///   segment and automatically follow it with an ACK from the other side. This is the
    ///   highest-level option and covers most use cases.
    /// - [client_segment](#client_segment) / [server_segment](#server_segment) — emit a single
    ///   data segment with no auto-ACK. Use when you need fine-grained control over ACK timing
    ///   or want to interleave segments from both sides manually.
    /// - [client_raw_segment](#client_raw_segment) / [server_raw_segment](#server_raw_segment) —
    ///   return TCP header + payload as raw bytes (no IP or Ethernet framing). Use with
    ///   [`ipv4::frag`](../README.md#frag) to build IP-fragmented TCP segments.
    ///
    /// [client_hdr](#client_hdr) / [server_hdr](#server_hdr) go one step further and return
    /// only the TCP header bytes, for cases where the header and payload must land in separate
    /// IP fragments. [client_hole](#client_hole) / [server_hole](#server_hole) advance the
    /// sequence number without emitting any packet, simulating a missing segment for
    /// reassembly test cases.
    resynth class TcpFlow {
        open => Symbol::Func(&TCP_OPEN),
        client_message => Symbol::Func(&TCP_CL_MSG),
        server_message => Symbol::Func(&TCP_SV_MSG),
        client_segment => Symbol::Func(&TCP_CL_SEG),
        server_segment => Symbol::Func(&TCP_SV_SEG),
        client_raw_segment => Symbol::Func(&TCP_CL_RAW_SEG),
        server_raw_segment => Symbol::Func(&TCP_SV_RAW_SEG),
        client_hdr => Symbol::Func(&TCP_CL_HDR),
        server_hdr => Symbol::Func(&TCP_SV_HDR),
        client_ack => Symbol::Func(&TCP_CL_ACK),
        server_ack => Symbol::Func(&TCP_SV_ACK),
        client_hole => Symbol::Func(&TCP_CL_HOLE),
        server_hole => Symbol::Func(&TCP_SV_HOLE),
        client_close => Symbol::Func(&TCP_CL_CLOSE),
        server_close => Symbol::Func(&TCP_SV_CLOSE),
        client_reset => Symbol::Func(&TCP_CL_RESET),
        server_reset => Symbol::Func(&TCP_SV_RESET),
    }
);

impl Class for TcpFlow {
    fn def(&self) -> &'static ClassDef {
        &TCP_FLOW
    }
}

const FLOW: FuncDef = func!(
    /// Create a [TCP flow context](TcpFlow.md), from which packets can be created
    resynth fn flow(
        /// Client socket address
        cl: Sock4,
        /// Server socket address
        sv: Sock4,
        =>
        /// Initial client TCP sequence number
        cl_seq: U32 = 1,
        /// Initial server TCP sequence number
        sv_seq: U32 = 1,
        /// Enable raw mode; omits ethernet framing
        raw: Bool = false,
        =>
        Void
    ) -> Class(&TCP_FLOW)
    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let cl_seq: u32 = args.next().into();
        let sv_seq: u32 = args.next().into();
        let raw: bool = args.next().into();
        Ok(Val::from(TcpFlow::new(cl.into(), sv.into(), cl_seq, sv_seq, raw)))
    }
);

pub const TCP4: Module = module! {
    /// # Transmission Control Protocol (TCP)
    ///
    /// TCP flow construction — open connections, send data, and close sessions over IPv4.
    resynth mod tcp {
        TcpFlow => Symbol::Class(&TCP_FLOW),
        flow => Symbol::Func(&FLOW),
    }
};
