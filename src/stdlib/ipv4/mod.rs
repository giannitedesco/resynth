use std::net::Ipv4Addr;

use pkt::Packet;
use pkt::eth::{eth_hdr, ethertype};
use pkt::ipv4::{ip_hdr, proto};

use ezpkt::IpFrag;

use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

mod icmp;
mod tcp;
mod udp;

use icmp::ICMP4;
use tcp::TCP4;
use udp::UDP4;

const PROTO: Module = module! {
    /// # IP Protocols
    resynth mod proto {
        ICMP => Symbol::u8(proto::ICMP),
        TCP => Symbol::u8(proto::TCP),
        UDP => Symbol::u8(proto::UDP),
        GRE => Symbol::u8(proto::GRE),
    }
};

const IPV4_DGRAM_OVERHEAD: usize = std::mem::size_of::<eth_hdr>() + std::mem::size_of::<ip_hdr>();

const DGRAM: FuncDef = func!(
    /// Create a raw IPv4 header or datagram
    resynth fn datagram(
        /// Source IPv4 address
        src: Ip4,
        /// Destination IPv4 address
        dst: Ip4,
        =>
        /// IP identification field
        id: U16 = 0,
        /// Set the evil bit (RFC 3514)
        evil: Bool = false,
        /// Set the Don't Fragment (DF) flag
        df: Bool = false,
        /// Set the More Fragments (MF) flag
        mf: Bool = false,
        /// IP Time-To-Live value
        ttl: U8 = 64,
        /// Fragment offset field (in 8-byte units)
        frag_off: U16 = 0,
        /// IP protocol number
        proto: U8 = proto::UDP,
        =>
        Str
    ) -> Pkt
    |mut args| {
        let src: Ipv4Addr = args.next().into();
        let dst: Ipv4Addr = args.next().into();

        let id: u16 = args.next().into();
        let evil: bool = args.next().into();
        let df: bool = args.next().into();
        let mf: bool = args.next().into();
        let ttl: u8 = args.next().into();
        let frag_off: u16 = args.next().into();
        let proto: u8 = args.next().into();

        let data: Buf = args.join_extra(b"").into();

        let payload_size: u16 = data.len() as u16;
        let tot_len: u16 = std::mem::size_of::<ip_hdr>() as u16 + payload_size;

        let eth = eth_hdr::new(
            src.into(),
            dst.into(),
            ethertype::IPV4,
        );

        let mut iph = ip_hdr::default();
        iph.set_tot_len(tot_len)
            .set_id(id)
            .set_evil(evil)
            .set_df(df)
            .set_mf(mf)
            .set_frag_off(frag_off)
            .set_ttl(ttl)
            .set_protocol(proto)
            .set_saddr(src)
            .set_daddr(dst)
            .calc_csum();

        let pkt = Packet::with_capacity(IPV4_DGRAM_OVERHEAD + payload_size as usize);
        pkt.push(eth);
        pkt.push(iph);
        pkt.push_bytes(data);

        Ok(Val::from(pkt))
    }
);

const FRAG_FRAGMENT: FuncDef = func!(
    /// Return an IPv4 packet fragment
    ///
    /// Slices the stored datagram at the given offset and length and wraps it in
    /// an IPv4 header. Both are in units of 8 bytes, as the fragment offset is in RFC 791,
    /// so `fragment(1, 2)` is bytes 8 to 23 of the payload. A fragment that would run past
    /// the end of the payload stops there, and one that starts past the end is empty. The
    /// MF (more-fragments) bit is set unless the fragment reaches the end of the payload.
    resynth fn fragment(
        /// Fragment offset in 8-byte blocks
        frag_off: U16,
        /// Length of this fragment in 8-byte blocks
        len: U16,
        =>
        /// If true, omit the ethernet header
        raw: Bool = false,
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IpFrag = r.as_mut_any().downcast_mut().unwrap();

        let frag_off: u16 = args.next().into();
        let len: u16 = args.next().into();
        let raw: bool = args.next().into();

        Ok(this.fragment(frag_off, len, raw).into())
    }
);

const FRAG_TAIL: FuncDef = func!(
    /// Return the final IPv4 fragment with MF=0
    ///
    /// Convenience wrapper around [fragment](#fragment) for the last fragment in a
    /// series — the MF bit is cleared automatically so no `len` is required.
    resynth fn tail(
        /// Fragment offset in 8-byte blocks
        frag_off: U16,
        =>
        /// If true, omit the ethernet header
        raw: Bool = false,
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IpFrag = r.as_mut_any().downcast_mut().unwrap();

        let frag_off: u16 = args.next().into();
        let raw: bool = args.next().into();

        Ok(this.tail(frag_off, raw).into())
    }
);

const FRAG_DATAGRAM: FuncDef = func!(
    /// Return the entire datagram as a single unfragmented packet
    ///
    /// Emits the full payload as one IPv4 packet with no fragmentation headers.
    resynth fn datagram(
        =>
        /// If true, omit the ethernet header
        raw: Bool = false,
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IpFrag = r.as_mut_any().downcast_mut().unwrap();
        let raw: bool = args.next().into();

        Ok(this.datagram(raw).into())
    }
);

static IPFRAG: ClassDef = class!(
    /// # IP Packet Fragment Builder
    ///
    /// Represents a single IP datagram that can be emitted either whole or split
    /// into multiple fragments. Create one with `ipv4::frag(src, dst, ..., payload)`,
    /// then emit fragments in the desired order:
    ///
    /// - `fragment(frag_off, len)` — emits a fragment with the MF (more-fragments) bit set,
    ///   unless it reaches the end of the payload
    /// - `tail(frag_off)` — emits the final fragment (MF clear), inferring the length
    /// - `datagram()` — emits the whole datagram unfragmented
    ///
    /// `frag_off` and `len` are in 8-byte units as per the IP specification. Fragments can be
    /// emitted out of order and with time gaps (using `time::jump_*`) to test
    /// reassembly timeout handling.
    resynth class IpFrag {
        fragment => Symbol::Func(&FRAG_FRAGMENT),
        tail => Symbol::Func(&FRAG_TAIL),
        datagram => Symbol::Func(&FRAG_DATAGRAM),
    }
);

impl Class for IpFrag {
    fn def(&self) -> &'static ClassDef {
        &IPFRAG
    }
}

const FRAG: FuncDef = func!(
    /// Create a context for a packet which can be arbitrarily fragmented
    resynth fn frag(
        /// Source IPv4 address
        src: Ip4,
        /// Destination IPv4 address
        dst: Ip4,
        =>
        /// IP identification field
        id: U16 = 0,
        /// Set the evil bit (RFC 3514)
        evil: Bool = false,
        /// Set the Don't Fragment (DF) flag
        df: Bool = false,
        /// IP Time-To-Live value
        ttl: U8 = 64,
        /// IP protocol number
        proto: U8 = proto::UDP,
        =>
        Str
    ) -> Class(&IPFRAG)
    |mut args| {
        let src: Ipv4Addr = args.next().into();
        let dst: Ipv4Addr = args.next().into();

        let id: u16 = args.next().into();
        let evil: bool = args.next().into();
        let df: bool = args.next().into();
        let ttl: u8 = args.next().into();
        let proto: u8 = args.next().into();

        let payload: Buf = args.join_extra(b"").into();

        let mut iph: ip_hdr = Default::default();
        iph
            .set_id(id)
            .set_evil(evil)
            .set_df(df)
            .set_ttl(ttl)
            .set_protocol(proto)
            .set_saddr(src)
            .set_daddr(dst);

        Ok(Val::from(IpFrag::new(iph, payload.cow_buffer().into())))
    }
);

pub const IPV4: Module = module! {
    /// # Internet Protocol Version 4
    ///
    /// IPv4 packet construction — TCP, UDP, ICMP flows and IP-level fragmentation.
    resynth mod ipv4 {
        IpFrag => Symbol::Class(&IPFRAG),
        tcp => Symbol::Module(&TCP4),
        udp => Symbol::Module(&UDP4),
        icmp => Symbol::Module(&ICMP4),
        datagram => Symbol::Func(&DGRAM),
        frag => Symbol::Func(&FRAG),
        proto => Symbol::Module(&PROTO),
    }
};
