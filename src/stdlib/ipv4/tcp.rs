use phf::{phf_map, phf_ordered_map};

use crate::err::Error;
use crate::val::{ValType, Val};
use crate::object::ObjRef;
use crate::str::Buf;
use crate::args::Args;
use crate::libapi::{Symbol, FuncDef, ClassDef, ArgDecl};
use crate::ezpkt::TcpFlow;
use crate::func_def;

const TCP_OPEN: FuncDef = func_def!(
    "ipv4::tcp::flow.open";
    ValType::PktGen;

    =>
    =>
    ValType::Void;

    tcp_open
);

fn tcp_open(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take_this();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    Ok(this.open().into())
}

const TCP_CL_CLOSE: FuncDef = func_def!(
    "ipv4::tcp::flow.client_close";
    ValType::PktGen;

    =>
    =>
    ValType::Void;

    tcp_client_close
);

fn tcp_client_close(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take_this();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    Ok(this.client_close().into())
}

const TCP_SV_CLOSE: FuncDef = func_def!(
    "ipv4::tcp::flow.server_close";
    ValType::PktGen;

    =>
    =>
    ValType::Void;

    tcp_server_close
);

fn tcp_server_close(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take_this();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    Ok(this.server_close().into())
}

const TCP_CL_MSG: FuncDef = func_def!(
    "ipv4::tcp::flow.client_message";
    ValType::Pkt;

    =>
    =>
    ValType::Str;

    tcp_client_message
);

fn tcp_client_message(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take_this();
    let bytes: Buf = args.join_extra(b"").into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    Ok(this.client_message(bytes.as_ref()).into())
}

const TCP_SV_MSG: FuncDef = func_def!(
    "ipv4::tcp::flow.server_message";
    ValType::Pkt;

    =>
    =>
    ValType::Str;

    tcp_server_message
);

fn tcp_server_message(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take_this();
    let bytes: Buf = args.join_extra(b"").into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    Ok(this.server_message(bytes.as_ref()).into())
}

const TCP4_CLASS: ClassDef = ClassDef {
    name: "ipv4::tcp4.flow",
    methods: phf_map! {
        "open" => &TCP_OPEN,
        "client_close" => &TCP_CL_CLOSE,
        "server_close" => &TCP_SV_CLOSE,
        "client_message" => &TCP_CL_MSG,
        "server_message" => &TCP_SV_MSG,
    }
};

const TCP_FLOW: FuncDef = func_def!(
    "flow";
    ValType::Obj;

    "cl" => ValType::Sock4,
    "sv" => ValType::Sock4,
    =>
    =>
    ValType::Void;

    tcp_flow
);

fn tcp_flow(mut args: Args) -> Result<Val, Error> {
    let cl = args.take();
    let sv = args.take();
    let obj: ObjRef = ObjRef::new(
        &TCP4_CLASS,
        TcpFlow::new(cl.into(), sv.into())
    );
    Ok(Val::Obj(obj))
}


pub(crate) const TCP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(&TCP_FLOW),
};
