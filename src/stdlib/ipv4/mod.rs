use phf::phf_map;

use crate::val::Symbol;

mod tcp;
mod udp;
mod icmp;

use tcp::TCP4;
use udp::UDP4;
use icmp::ICMP4;

pub const IPV4: phf::Map<&'static str, Symbol> = phf_map! {
    "tcp" => Symbol::Module(&TCP4),
    "udp" => Symbol::Module(&UDP4),
    "icmp" => Symbol::Module(&ICMP4),
};
