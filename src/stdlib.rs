use phf::phf_map;

use crate::err::Error;
use crate::err::Error::RuntimeError;
use crate::val::{Symbol, Val, ValType, FuncDef, ValDef, ClassDef, ObjRef, BytesObj, Args, Module};
use crate::ezpkt::{TcpFlow, UdpFlow, IcmpFlow};

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
        collect_type: ValType::Void,
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
        collect_type: ValType::Void,
        exec: udp_flow,
    }),
};

fn icmp_echo(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<IcmpFlow>(&mut obj) };
    Ok(this.echo(bytes.as_ref()).into())
}

fn icmp_echo_reply(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<IcmpFlow>(&mut obj) };
    Ok(this.echo_reply(bytes.as_ref()).into())
}

const ICMP4_FLOW_CLASS: ClassDef = ClassDef {
    name: "ipv4::icmp4.flow",
    methods: phf_map! {
        "echo" => FuncDef {
            name: "ipv4::tcp::flow.echo",
            return_type: ValType::Pkt,
            args: &[ ValType::Str ],
            collect_type: ValType::Void,
            exec: icmp_echo,
        },
        "echo_reply" => FuncDef {
            name: "ipv4::tcp::flow.echo_reply",
            return_type: ValType::Pkt,
            args: &[ ValType::Str ],
            collect_type: ValType::Void,
            exec: icmp_echo_reply,
        },
    }
};

fn icmp_flow(mut args: Args) -> Result<Val, Error> {
    let cl = args.take();
    let sv = args.take();
    let obj: ObjRef = ObjRef::new(
        &ICMP4_FLOW_CLASS,
        IcmpFlow::new(cl.into(), sv.into())
    );
    Ok(Val::Obj(obj))
}

const ICMP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(FuncDef {
        name: "flow",
        return_type: ValType::Obj,
        args: &[ ValType::Ip4, ValType::Ip4 ],
        collect_type: ValType::Void,
        exec: icmp_flow,
    }),
};

const IPV4: phf::Map<&'static str, Symbol> = phf_map! {
    "tcp" => Symbol::Module(&TCP4),
    "udp" => Symbol::Module(&UDP4),
    "icmp" => Symbol::Module(&ICMP4),
};

fn text_crlflines(mut args: Args) -> Result<Val, Error> {
    // We have to collect all the extra_args in to a vec so they can stay owning the bytes that
    // they reference
    let cargs: Vec<BytesObj> = args.collect_extra_args();

    // Then we construct a vec of all those references.
    //
    // XXX This is a good example of where rust imposes a performance penalty, this intermediate
    // vector is literally completely redundant. It servers no other purpose than not owning the
    // strings so that we can have a vec of unowned references for Vec::join to use.
    //
    // Itertools crate has a better "join" implementation from this use-case. And intersperse in
    // nightly also solves this reasonably well.
    let strs: Vec<&[u8]> = cargs.iter().map(|x| x.as_ref()).collect();

    // Finally we can do the join
    let ret = strs.join(b"\r\n" as &[u8]);

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
