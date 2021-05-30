use crate::err::Error;
use crate::err::Error::RuntimeError;
use crate::val::{Val, ValType, FuncDef, ValDef, ClassDef, ModuleDef, ObjRef, BytesObj, Args};
use crate::tcp4::TcpFlow;

macro_rules! arr {
    ($id: ident $name: ident: [$ty: ty; _] = $value: expr) => {
        $id $name: [$ty; $value.len()] = $value;
    };
    (pub $id: ident $name: ident: [$ty: ty; _] = $value: expr) => {
        pub $id $name: [$ty; $value.len()] = $value;
    };
}

#[allow(unused)]
fn unimplemented(mut args: Args) -> Result<Val, Error> {
    println!("Unimplemented stdlib call");
    args.void();
    Err(RuntimeError)
}

fn tcp_open(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    this.open()
}

fn tcp_close(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    this.close()
}

fn tcp_client_message(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    this.client_message(bytes.as_ref())
}

fn tcp_server_message(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<TcpFlow>(&mut obj) };
    this.server_message(bytes.as_ref())
}

fn tcp_flow(mut args: Args) -> Result<Val, Error> {
    let cl = args.take();
    let sv = args.take();
    let obj: ObjRef = ObjRef::new(
        &TCP4_FLOW_CLASS,
        TcpFlow::new(cl.into(), sv.into())
    );
    Ok(Val::Obj(obj))
}

fn text_crlflines(mut args: Args) -> Result<Val, Error> {
    let mut ret: Vec<u8> = Vec::new();
    for s in args.collect().map(|x| x.into()).intersperse(BytesObj::from(b"\r\n")) {
        ret.extend(s.as_ref());
    }
    Ok(Val::Str(BytesObj::new(ret)))
}

arr!(const TCP4_FLOW_METHODS: [FuncDef; _] = [
     FuncDef {
         name: "open",
         return_type: ValType::PktGen,
         args: &[],
         collect_type: ValType::Void,
         exec: tcp_open,
     },
     FuncDef {
         name: "close",
         return_type: ValType::PktGen,
         args: &[],
         collect_type: ValType::Void,
         exec: tcp_close,
     },
     FuncDef {
         name: "client_message",
         return_type: ValType::Pkt,
         args: &STR_ARGS,
         collect_type: ValType::Void,
         exec: tcp_client_message,
     },
     FuncDef {
         name: "server_message",
         return_type: ValType::Pkt,
         args: &STR_ARGS,
         collect_type: ValType::Void,
         exec: tcp_server_message,
     },
]);

const TCP4_FLOW_CLASS: ClassDef = ClassDef {
    name: "ipv4::tcp4.flow",
    methods: &TCP4_FLOW_METHODS,
};

arr!(const STR_ARGS: [ValType; _] = [
     ValType::Str,
]);

arr!(const L4_FLOW_ARGS: [ValType; _] = [
     ValType::Sock4,
     ValType::Sock4,
]);

arr!(const TCP4_FUNCS: [FuncDef; _] = [
     FuncDef {
         name: "flow",
         return_type: ValType::Obj,
         args: &L4_FLOW_ARGS,
         collect_type: ValType::Str,
         exec: tcp_flow,
     },
]);

arr!(const TEXT_FUNCS: [FuncDef; _] = [
     FuncDef {
         name: "crlflines",
         return_type: ValType::Str,
         args: &[],
         collect_type: ValType::Str,
         exec: text_crlflines,
     },
]);

arr!(const TEXT_VARS: [ValDef; _] = [
     ValDef {
        name: "CRLF",
        val: b"\r\n",
     },
]);

arr!(const IPV4: [ModuleDef; _] = [
    ModuleDef {
        name: "tcp",
        subs: &[],
        funcs: &TCP4_FUNCS,
        vars: &[],
    },
    ModuleDef {
        name: "udp",
        subs: &[],
        funcs: &[],
        vars: &[],
    },
    ModuleDef {
        name: "icmp",
        subs: &[],
        funcs: &[],
        vars: &[],
    },
]);

arr!(pub const BUILTINS: [ModuleDef; _] = [
    ModuleDef {
        name: "ipv4",
        subs: &IPV4,
        funcs: &[],
        vars: &[],
    },
    ModuleDef {
        name: "text",
        subs: &[],
        funcs: &TEXT_FUNCS,
        vars: &TEXT_VARS,
    },
]);
