use std::net::Ipv4Addr;

use pkt::Packet;
use pkt::eth::{BROADCAST, eth_addr, eth_hdr, ethertype};

use crate::err::Error;
use crate::libapi::{FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

const FRAME_OVERHEAD: usize = std::mem::size_of::<eth_hdr>();

fn ether<T: AsRef<[u8]>>(val: T) -> Result<eth_addr, Error> {
    let val = val.as_ref();

    if val.len() != 6 {
        return Err(Error::LibError(
            format!("ethernet address must be 6 bytes, got {}", val.len()).into(),
        ));
    }

    let mut octets: [u8; 6] = [0; 6];
    octets.copy_from_slice(&val[..6]);

    Ok(eth_addr::new(octets))
}

const FRAME: FuncDef = func!(
    /// Construct an Ethernet frame
    ///
    /// Wraps the payload bytes in an Ethernet II frame header.
    resynth fn frame(
        /// Source ethernet address as 6 bytes
        src: Str,
        /// Destination ethernet address as 6 bytes
        dst: Str,
        =>
        /// [EtherType](ethertype/README.md) identifying the encapsulated protocol
        ethertype: U16 = ethertype::IPV4,
        =>
        Str
    ) -> Pkt
    |mut args| {
        let src: Buf = args.next().into();
        let dst: Buf = args.next().into();
        let ethertype: u16 = args.next().into();
        let data: Buf = args.join_extra(b"").into();

        let eth = eth_hdr::new(
            ether(src)?,
            ether(dst)?,
            ethertype,
        );

        let pkt = Packet::with_capacity(FRAME_OVERHEAD + data.len());
        pkt.push(eth);
        pkt.push_bytes(data);

        Ok(Val::from(pkt))
    }
);

const FROM_IP: FuncDef = func!(
    /// Map an IPv4 address to a locally-administered Ethernet address
    ///
    /// Produces a locally-administered unicast MAC address with the IPv4 address
    /// encoded in the last four octets (e.g. `192.0.2.1` → `02:00:c0:00:02:01`).
    resynth fn from_ip(
        /// IPv4 address to map to an ethernet address
        ip: Ip4,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let ip: Ipv4Addr = args.next().into();

        let eth = eth_addr::from(ip);

        Ok(Val::Str(Buf::from_slice(&eth)))
    }
);

const TYPE: Module = module! {
    /// # Ethernet Ethertypes
    resynth mod ethertype {
        VLAN => Symbol::u16(ethertype::VLAN),
        FABRICPATH => Symbol::u16(ethertype::FABRICPATH),

        IPV4 => Symbol::u16(ethertype::IPV4),
        IPV6 => Symbol::u16(ethertype::IPV6),

        PPTP => Symbol::u16(ethertype::PPTP),
        GRETAP => Symbol::u16(ethertype::GRETAP),
        ERSPAN_1_2 => Symbol::u16(ethertype::ERSPAN_1_2),
        ERSPAN_3 => Symbol::u16(ethertype::ERSPAN_3),
    }
};

pub const MODULE: Module = module! {
    /// # Ethernet
    ///
    /// Ethernet frame construction and ethertype constants.
    resynth mod eth {
        ethertype => Symbol::Module(&TYPE),
        frame => Symbol::Func(&FRAME),
        from_ip => Symbol::Func(&FROM_IP),
        BROADCAST => Symbol::Val(ValDef::Str(&BROADCAST)),
    }
};
