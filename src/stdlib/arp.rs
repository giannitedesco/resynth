use pkt::arp::hrd;

use crate::{libapi::Module, sym::Symbol};

const HRD: Module = module!(
    /// # ARP Hardware types
    resynth mod hrd {
        ETHER => Symbol::u16(hrd::ETHER as u16),
    }
);

pub const MODULE: Module = module!(
    /// # Address Resolution Protocol
    ///
    /// Note: ARP packet generation is not yet implemented. This module currently
    /// only exposes hardware type constants (eg. `arp::hrd::ETHER`).
    resynth mod arp {
        hrd => Symbol::Module(&HRD),
    }
);
