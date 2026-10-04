use std::rc::Rc;

use pkt::{Packet, vxlan};

use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use ezpkt::VxlanFlow;

const ENCAP: FuncDef = func!(
    /// Encapsulate a series of packets
    resynth fn encap(
        /// Sequence of packets to encapsulate
        it: PktGen
        =>
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut VxlanFlow = r.as_mut_any().downcast_mut().unwrap();
        let it: Rc<Box<[Packet]>> = args.next().into();

        let mut ret: Vec<Packet> = Vec::with_capacity(it.len());

        for pkt in it.iter() {
            ret.push(this.encap(pkt.as_slice().get(pkt)));
        }

        Ok(ret.into())
    }
);

const DGRAM: FuncDef = func!(
    /// Encapsulate a single packet
    resynth fn dgram(
        /// Single packet to encapsulate
        pkt: Pkt
        =>
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut VxlanFlow = r.as_mut_any().downcast_mut().unwrap();
        let pkt: Rc<Packet> = args.next().into();
        Ok(this.encap(pkt.as_slice().get(&pkt)).into())
    }
);

static VXLAN: ClassDef = class!(
    /// # VXLAN Session
    resynth class Vxlan {
        dgram => Symbol::Func(&DGRAM),
        encap => Symbol::Func(&ENCAP),
    }
);

impl Class for VxlanFlow {
    fn def(&self) -> &'static ClassDef {
        &VXLAN
    }
}

const SESSION: FuncDef = func!(
    /// Create a VXLAN session
    resynth fn session(
        /// Client (sender) socket address
        cl: Sock4,
        /// Server (receiver) socket address
        sv: Sock4,
        =>
        /// VXLAN Network Identifier (VNI)
        sessionid: U32 = 0, // TODO: Make it optional
        /// Enable raw mode; omits ethernet framing
        raw: Bool = false,
        =>
        Void
    ) -> Class(&VXLAN)
    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let vni: u32 = args.next().into();
        let raw: bool = args.next().into();
        Ok(Val::from(VxlanFlow::new(cl.into(), sv.into(), vni, raw)))
    }
);

pub const MODULE: Module = module! {
    /// # VXLAN Encapsulation
    ///
    /// Encapsulates ethernet frames in [UDP](../ipv4/udp/README.md) datagrams.
    resynth mod vxlan {
        Vxlan => Symbol::Class(&VXLAN),
        session => Symbol::Func(&SESSION),
        DEFAULT_PORT => Symbol::u16(vxlan::DEFAULT_PORT),
    }
};
