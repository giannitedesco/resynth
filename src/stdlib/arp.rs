use phf::phf_map;

use pkt::arp::hrd;

use crate::sym::Symbol;

const HRD: phf::Map<&'static str, Symbol> = phf_map! {
    "ETHER" => Symbol::int_val(hrd::ETHER as u64),
};

pub const MODULE: phf::Map<&'static str, Symbol> = phf_map! {
    "hrd" => Symbol::Module(&HRD),
};
