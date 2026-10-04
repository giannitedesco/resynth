use std::rc::Rc;

use pkt::Packet;

use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use ezpkt::Erspan3Flow;

const ENCAP: FuncDef = func!(
    /// Encapsulate packets in ERSPAN3
    resynth fn encap(
        /// Sequence of packets to encapsulate
        it: PktGen
        =>
        /// ERSPAN timestamp value to embed in the header
        timestamp: U32 = 0,
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut Erspan3Flow = r.as_mut_any().downcast_mut().unwrap();
        let it: Rc<Box<[Packet]>> = args.next().into();
        let timestamp: u32 = args.next().into();

        let ret: Vec<Packet> = it
            .iter()
            .map(|pkt| this.encap(&pkt.as_slice().get(pkt), timestamp))
            .collect();

        Ok(ret.into())
    }
);

static ERSPAN3: ClassDef = class!(
    /// # ERSPAN3 Session
    resynth class Erspan3 {
        encap => Symbol::Func(&ENCAP),
    }
);

impl Class for Erspan3Flow {
    fn def(&self) -> &'static ClassDef {
        &ERSPAN3
    }
}

const SESSION: FuncDef = func!(
    /// Create an erspan3 session
    resynth fn session(
        /// Source (collector) IP address
        cl: Ip4,
        /// Destination (monitor) IP address
        sv: Ip4,
        =>
        /// Enable raw mode; omits ethernet framing
        raw: Bool = false,
        /// Hardware ID field in the ERSPAN3 header
        hwid: U32 = 0,
        /// Security Group Tag (SGT) field
        sgt: U32 = 0,
        /// Timestamp granularity field
        granularity: U32 = 0,
        /// Direction bit (0 = ingress, non-zero = egress)
        direction: U32 = 0,
        =>
        Void
    ) -> Class(&ERSPAN3)
    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let raw: bool = args.next().into();
        let hwid: u32 = args.next().into();
        let sgt: u32 = args.next().into();
        let gra: u32 = args.next().into();
        let d: u32 = args.next().into();
        let mut flow = Erspan3Flow::new(cl.into(), sv.into(), raw);
        flow.hwid = hwid as u8;
        flow.sgt = sgt as u16;
        flow.gra = gra as u8;
        flow.d = d != 0;
        Ok(Val::from(flow))
    }
);

pub const MODULE: Module = module! {
    /// # ERSPAN Version 3
    ///
    /// ERSPAN Type III — extends version 2 with timestamps, SGT, hardware ID, and directional metadata.
    resynth mod erspan3 {
        Erspan3 => Symbol::Class(&ERSPAN3),
        session => Symbol::Func(&SESSION),
    }
};
