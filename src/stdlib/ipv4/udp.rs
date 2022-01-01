use phf::{phf_map, phf_ordered_map};

use crate::err::Error;
use crate::val::{ValType, Val};
use crate::object::ObjRef;
use crate::str::Buf;
use crate::args::Args;
use crate::libapi::{Symbol, FuncDef, ClassDef, ArgDecl};
use crate::ezpkt::UdpFlow;
use crate::func_def;

const UDP_CL_DGRAM: FuncDef = func_def!(
    "ipv4::tcp::flow.client_dgram";
    ValType::Pkt;

    =>
    =>
    ValType::Str;

    udp_client_dgram
);

fn udp_client_dgram(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take_this();
    let bytes: Buf = args.join_extra(b"").into();
    let this = unsafe { ObjRef::get_mut_obj::<UdpFlow>(&mut obj) };
    Ok(this.client_dgram(bytes.as_ref()).into())
}

const UDP_SV_DGRAM: FuncDef = func_def!(
    "ipv4::tcp::flow.server_dgram";
    ValType::Pkt;

    =>
    =>
    ValType::Str;

    udp_server_dgram
);

fn udp_server_dgram(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take_this();
    let bytes: Buf = args.join_extra(b"").into();
    let this = unsafe { ObjRef::get_mut_obj::<UdpFlow>(&mut obj) };
    Ok(this.server_dgram(bytes.as_ref()).into())
}

const UDP4_FLOW_CLASS: ClassDef = ClassDef {
    name: "ipv4::udp4.flow",
    methods: phf_map! {
        "client_dgram" => &UDP_CL_DGRAM,
        "server_dgram" => &UDP_SV_DGRAM,
    }
};

const UDP_FLOW: FuncDef = func_def!(
    "flow";
    ValType::Obj;

    "cl" => ValType::Sock4,
    "sv" => ValType::Sock4,
    =>
    =>
    ValType::Void;

    udp_flow
);

fn udp_flow(mut args: Args) -> Result<Val, Error> {
    let cl = args.take();
    let sv = args.take();
    let obj: ObjRef = ObjRef::new(
        &UDP4_FLOW_CLASS,
        UdpFlow::new(cl.into(), sv.into())
    );
    Ok(Val::Obj(obj))
}

pub(crate) const UDP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(&UDP_FLOW),
};

