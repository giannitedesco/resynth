use phf::{phf_map, phf_ordered_map};

use crate::val::{ValType, Val};
use crate::str::Buf;
use crate::libapi::{FuncDef, ArgDecl, Class};
use crate::sym::Symbol;
use crate::ezpkt::UdpFlow;
use crate::func_def;

const UDP_CL_DGRAM: FuncDef = func_def!(
    "ipv4::tcp::flow.client_dgram";
    ValType::Pkt;

    =>
    =>
    ValType::Str;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut UdpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: Buf = args.join_extra(b"").into();
        Ok(this.client_dgram(bytes.as_ref()).into())
    }
);

const UDP_SV_DGRAM: FuncDef = func_def!(
    "ipv4::tcp::flow.server_dgram";
    ValType::Pkt;

    =>
    =>
    ValType::Str;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut UdpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: Buf = args.join_extra(b"").into();
        Ok(this.server_dgram(bytes.as_ref()).into())
    }
);

impl Class for UdpFlow {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "client_dgram" => Symbol::Func(&UDP_CL_DGRAM),
            "server_dgram" => Symbol::Func(&UDP_SV_DGRAM),
        }
    }

    fn class_name(&self) -> &'static str {
        "ipv4::udp4.flow"
    }
}

const UDP_FLOW: FuncDef = func_def!(
    "flow";
    ValType::Obj;

    "cl" => ValType::Sock4,
    "sv" => ValType::Sock4,
    =>
    =>
    ValType::Void;

    |mut args| {
        let cl = args.next();
        let sv = args.next();
        Ok(Val::from(UdpFlow::new(cl.into(), sv.into())))
    }
);

pub(crate) const UDP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(&UDP_FLOW),
};

