#![warn(clippy::return_self_not_must_use)]

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod erspan2;
pub mod erspan3;
pub mod eth;
pub mod gre;
pub mod ipv4;
pub mod netbios;
pub mod tls;
pub mod vxlan;

mod pcap;
pub use pcap::{LinkType, PcapWriter};

mod packet;
pub use packet::{Hdr, Packet, PktSlice, Ref, RefMut, SliceRef, SliceRefMut};

#[cfg(test)]
mod test;
