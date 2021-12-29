use phf::{phf_map, phf_ordered_map};

use crate::err::Error;
use crate::val::{ValType, Val};
use crate::object::ObjRef;
use crate::str::BytesObj;
use crate::args::Args;
use crate::libapi::{Symbol, FuncDef, ClassDef, ArgDecl};
use crate::ezpkt::UdpFlow;
use crate::func_def;

const UDP_CL_DGRAM: FuncDef = func_def!(
    "ipv4::tcp::flow.client_message";
    ValType::Pkt;

    "dgram" => ValType::Str
    =>
    =>
    ValType::Void;

    udp_client_message
);

fn udp_client_message(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take_this();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<UdpFlow>(&mut obj) };
    Ok(this.client_message(bytes.as_ref()).into())
}

const UDP_SV_DGRAM: FuncDef = func_def!(
    "ipv4::tcp::flow.server_message";
    ValType::Pkt;

    "dgram" => ValType::Str,
    =>
    =>
    ValType::Void;

    udp_server_message
);

fn udp_server_message(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take_this();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<UdpFlow>(&mut obj) };
    Ok(this.server_message(bytes.as_ref()).into())
}

const UDP4_FLOW_CLASS: ClassDef = ClassDef {
    name: "ipv4::udp4.flow",
    methods: phf_map! {
        "client_message" => &UDP_CL_DGRAM,
        "server_message" => &UDP_SV_DGRAM,
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

pub const UDP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(&UDP_FLOW),
};

