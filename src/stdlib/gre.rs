use std::rc::Rc;

use pkt::Packet;
use pkt::gre::GreFlags;

use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use ezpkt::GreFlow;

const ENCAP: FuncDef = func!(
    /// Encapsulate packets in GRETAP
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
        let this: &mut GreFlow = r.as_mut_any().downcast_mut().unwrap();
        let it: Rc<Box<[Packet]>> = args.next().into();

        let mut ret: Vec<Packet> = Vec::with_capacity(it.len());

        for pkt in it.iter() {
            ret.push(this.encap(&pkt.as_slice().get(pkt)));
        }

        Ok(ret.into())
    }
);

static GRE: ClassDef = class!(
    /// # GRE Session
    resynth class Gre {
        encap => Symbol::Func(&ENCAP),
    }
);

impl Class for GreFlow {
    fn def(&self) -> &'static ClassDef {
        &GRE
    }
}

const SESSION: FuncDef = func!(
    /// Create a GRETAP session
    resynth fn session(
        /// Source IP address
        cl: Ip4,
        /// Destination IP address
        sv: Ip4,
        /// EtherType of the encapsulated payload
        ethertype: U16,
        =>
        /// Enable raw mode; omits ethernet framing
        raw: Bool = false,
        =>
        Void
    ) -> Class(&GRE)
    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let flags = GreFlags::default();
        let ethertype: u16= args.next().into();
        let raw: bool = args.next().into();

        Ok(Val::from(GreFlow::new(cl.into(), sv.into(), flags, ethertype, raw)))
    }
);

pub const MODULE: Module = module! {
    /// # Generic Routing Encapsulation (GRE)
    ///
    /// Right now this exists only for GRETAP [sessions](#session)
    resynth mod gre {
        Gre => Symbol::Class(&GRE),
        session => Symbol::Func(&SESSION),
    }
};
