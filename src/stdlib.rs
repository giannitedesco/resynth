use phf::phf_map;

use crate::err::Error;
use crate::err::Error::RuntimeError;
use crate::val::{Symbol, Val, ValType, FuncDef, ValDef, ClassDef, ObjRef, BytesObj, Args, Module};
use crate::ezpkt::TcpFlow;
use crate::ezpkt::UdpFlow;

#[allow(unused)]
fn unimplemented(mut args: Args) -> Result<Val, Error> {
    println!("Unimplemented stdlib call");
    args.void();
    Err(RuntimeError)
}

fn tcp_open(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    Ok(this.open().into())
}

fn tcp_close(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    Ok(this.close().into())
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
        "close" => FuncDef {
            name: "ipv4::tcp::flow.close",
            return_type: ValType::PktGen,
            args: &[],
            collect_type: ValType::Void,
            exec: tcp_close,
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

const TCP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(FuncDef {
        name: "flow",
        return_type: ValType::Obj,
        args: &[ ValType::Sock4, ValType::Sock4 ],
        collect_type: ValType::Str,
        exec: tcp_flow,
    }),
};

fn udp_client_message(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<UdpFlow>(&mut obj) };
    Ok(this.client_message(bytes.as_ref()).into())
}

fn udp_server_message(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<UdpFlow>(&mut obj) };
    Ok(this.server_message(bytes.as_ref()).into())
}

const UDP4_FLOW_CLASS: ClassDef = ClassDef {
    name: "ipv4::udp4.flow",
    methods: phf_map! {
        "client_message" => FuncDef {
            name: "ipv4::tcp::flow.client_message",
            return_type: ValType::Pkt,
            args: &[ ValType::Str ],
            collect_type: ValType::Void,
            exec: udp_client_message,
        },
        "server_message" => FuncDef {
            name: "ipv4::tcp::flow.server_message",
            return_type: ValType::Pkt,
            args: &[ ValType::Str ],
            collect_type: ValType::Void,
            exec: udp_server_message,
        },
    }
};

fn udp_flow(mut args: Args) -> Result<Val, Error> {
    let cl = args.take();
    let sv = args.take();
    let obj: ObjRef = ObjRef::new(
        &UDP4_FLOW_CLASS,
        UdpFlow::new(cl.into(), sv.into())
    );
    Ok(Val::Obj(obj))
}

const UDP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(FuncDef {
        name: "flow",
        return_type: ValType::Obj,
        args: &[ ValType::Sock4, ValType::Sock4 ],
        collect_type: ValType::Str,
        exec: udp_flow,
    }),
};

const ICMP4: phf::Map<&'static str, Symbol> = phf_map! {
};

const IPV4: phf::Map<&'static str, Symbol> = phf_map! {
    "tcp" => Symbol::Module(&TCP4),
    "udp" => Symbol::Module(&UDP4),
    "icmp" => Symbol::Module(&ICMP4),
};

fn text_crlflines(mut args: Args) -> Result<Val, Error> {
    let mut ret: Vec<u8> = Vec::new();
    for s in args.collect().map(|x| x.into()).intersperse(BytesObj::from(b"\r\n")) {
        ret.extend(s.as_ref());
    }
    Ok(Val::Str(BytesObj::new(ret)))
}

const TEXT: phf::Map<&'static str, Symbol> = phf_map! {
    "crlflines" => Symbol::Func(FuncDef {
        name: "crlflines",
        return_type: ValType::Str,
        args: &[],
        collect_type: ValType::Str,
        exec: text_crlflines,
    }),
    "CRLF" => Symbol::Val(ValDef {
        val: b"\r\n",
    }),
};

const STDLIB: phf::Map<&'static str, Symbol> = phf_map! {
    "ipv4" => Symbol::Module(&IPV4),
    "text" => Symbol::Module(&TEXT),
};

pub fn toplevel_module(name: &str) -> Option<&'static Module> {
    match STDLIB.get(name) {
        None => None,
        Some(Symbol::Module(module)) => Some(module),
        Some(Symbol::Func(_)) | Some(Symbol::Val(_)) => {
            /* There shouldn't be any top level function or variable */
            unreachable!();
        },
    }
}
