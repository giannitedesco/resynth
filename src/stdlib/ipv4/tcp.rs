use phf::phf_map;

use crate::err::Error;
use crate::val::{Symbol, ValType, FuncDef, Args, Val, BytesObj, ObjRef, ClassDef};
use crate::ezpkt::TcpFlow;

fn tcp_open(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    Ok(this.open().into())
}

fn tcp_client_close(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    Ok(this.client_close().into())
}

fn tcp_server_close(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    Ok(this.server_close().into())
}

fn tcp_client_message(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    Ok(this.client_message(bytes.as_ref()).into())
}

fn tcp_server_message(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    Ok(this.server_message(bytes.as_ref()).into())
}

const TCP4_FLOW_CLASS: ClassDef = ClassDef {
    name: "ipv4::tcp4.flow",
    methods: phf_map! {
        "open" => FuncDef {
            name: "ipv4::tcp::flow.open",
            return_type: ValType::PktGen,
            args: &[],
            collect_type: ValType::Void,
            exec: tcp_open,
        },
        "client_close" => FuncDef {
            name: "ipv4::tcp::flow.client_close",
            return_type: ValType::PktGen,
            args: &[],
            collect_type: ValType::Void,
            exec: tcp_client_close,
        },
        "server_close" => FuncDef {
            name: "ipv4::tcp::flow.server_close",
            return_type: ValType::PktGen,
            args: &[],
            collect_type: ValType::Void,
            exec: tcp_server_close,
        },
        "client_message" => FuncDef {
            name: "ipv4::tcp::flow.client_message",
            return_type: ValType::Pkt,
            args: &[ ValType::Str ],
            collect_type: ValType::Void,
            exec: tcp_client_message,
        },
        "server_message" => FuncDef {
            name: "ipv4::tcp::flow.server_message",
            return_type: ValType::Pkt,
            args: &[ ValType::Str ],
            collect_type: ValType::Void,
            exec: tcp_server_message,
        },
    }
};

fn tcp_flow(mut args: Args) -> Result<Val, Error> {
    let cl = args.take();
    let sv = args.take();
    let obj: ObjRef = ObjRef::new(
        &TCP4_FLOW_CLASS,
        TcpFlow::new(cl.into(), sv.into())
    );
    Ok(Val::Obj(obj))
}

pub const TCP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(FuncDef {
        name: "flow",
        return_type: ValType::Obj,
        args: &[ ValType::Sock4, ValType::Sock4 ],
        collect_type: ValType::Void,
        exec: tcp_flow,
    }),
};
