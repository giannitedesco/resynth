use std::rc::Rc;

use pkt::Packet;

use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use ezpkt::Erspan1Flow;

const ENCAP: FuncDef = func!(
    /// Encapsulate a sequence of packets
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
        let this: &mut Erspan1Flow = r.as_mut_any().downcast_mut().unwrap();
        let it: Rc<Box<[Packet]>> = args.next().into();

        let mut ret: Vec<Packet> = Vec::with_capacity(it.len());

        for pkt in it.iter() {
            ret.push(this.encap(&pkt.as_slice().get(pkt)));
        }

        Ok(ret.into())
    }
);

static ERSPAN1: ClassDef = class!(
    /// # ERSPAN1 Session
    resynth class Erspan1 {
        encap => Symbol::Func(&ENCAP),
    }
);

impl Class for Erspan1Flow {
    fn def(&self) -> &'static ClassDef {
        &ERSPAN1
    }
}

const SESSION: FuncDef = func!(
    /// Create an ERSPAN session
    resynth fn session(
        /// Source (collector) IP address
        cl: Ip4,
        /// Destination (monitor) IP address
        sv: Ip4,
        =>
        /// Enable raw mode; omits ethernet framing
        raw: Bool = false,
        =>
        Void
    ) -> Class(&ERSPAN1)
    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let raw: bool = args.next().into();
        Ok(Val::from(Erspan1Flow::new(cl.into(), sv.into(), raw)))
    }
);

pub const MODULE: Module = module! {
    /// # ERSPAN Version 1
    ///
    /// ERSPAN Type I — encapsulates mirrored traffic in a GRE tunnel (version 1, no sequence numbers).
    resynth mod erspan1 {
        Erspan1 => Symbol::Class(&ERSPAN1),
        session => Symbol::Func(&SESSION),
    }
};
