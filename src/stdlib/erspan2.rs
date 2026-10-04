use std::rc::Rc;

use pkt::Packet;

use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use ezpkt::Erspan2Flow;

const ENCAP: FuncDef = func!(
    /// Encapsulate packets in ERSPAN2
    resynth fn encap(
        /// Sequence of packets to encapsulate
        it: PktGen
        =>
        /// ERSPAN port index (identifies the source port)
        port_index: U32 = 0,
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut Erspan2Flow = r.as_mut_any().downcast_mut().unwrap();
        let it: Rc<Box<[Packet]>> = args.next().into();
        let port_index: u32 = args.next().into();

        let mut ret: Vec<Packet> = Vec::with_capacity(it.len());

        for pkt in it.iter() {
            ret.push(this.encap(&pkt.as_slice().get(pkt), port_index));
        }

        Ok(ret.into())
    }
);

static ERSPAN2: ClassDef = class!(
    /// # ERSPAN2 Session
    resynth class Erspan2 {
        encap => Symbol::Func(&ENCAP),
    }
);

impl Class for Erspan2Flow {
    fn def(&self) -> &'static ClassDef {
        &ERSPAN2
    }
}

const SESSION: FuncDef = func!(
    /// Create an erspan2 session
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
    ) -> Class(&ERSPAN2)
    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let raw: bool = args.next().into();
        Ok(Val::from(Erspan2Flow::new(cl.into(), sv.into(), raw)))
    }
);

pub const MODULE: Module = module! {
    /// # ERSPAN Version 2
    ///
    /// ERSPAN Type II — encapsulates mirrored traffic in a GRE tunnel with sequence numbers and port IDs.
    resynth mod erspan2 {
        Erspan2 => Symbol::Class(&ERSPAN2),
        session => Symbol::Func(&SESSION),
    }
};
