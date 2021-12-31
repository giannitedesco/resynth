use phf::{phf_map, phf_ordered_map};

use crate::err::Error;
use crate::val::{ValType, Val};
use crate::object::ObjRef;
use crate::str::BytesObj;
use crate::libapi::{Symbol, FuncDef, ClassDef, ArgDecl};
use crate::args::Args;
use crate::ezpkt::IcmpFlow;
use crate::func_def;

const ICMP_ECHO: FuncDef = func_def!(
    "ipv4::tcp::flow.echo";
    ValType::Pkt;
    
    "payload" => ValType::Str,
    =>
    =>
    ValType::Void;

    icmp_echo
);

fn icmp_echo(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take_this();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<IcmpFlow>(&mut obj) };
    Ok(this.echo(bytes.as_ref()).into())
}

const ICMP_ECHO_REPLY: FuncDef = func_def!(
    "ipv4::tcp::flow.echo_reply";
    ValType::Pkt;

    "payload" => ValType::Str,
    =>
    =>
    ValType::Void;

    icmp_echo_reply
);

fn icmp_echo_reply(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take_this();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<IcmpFlow>(&mut obj) };
    Ok(this.echo_reply(bytes.as_ref()).into())
}

const ICMP4_FLOW_CLASS: ClassDef = ClassDef {
    name: "ipv4::icmp4.flow",
    methods: phf_map! {
        "echo" => &ICMP_ECHO,
        "echo_reply" => &ICMP_ECHO_REPLY,
    }
};

const ICMP_FLOW: FuncDef = func_def!(
    "flow";
    ValType::Obj;

    "cl" => ValType::Ip4,
    "sv" => ValType::Ip4,
    =>
    =>
    ValType::Void;

    icmp_flow
);

fn icmp_flow(mut args: Args) -> Result<Val, Error> {
    let cl = args.take();
    let sv = args.take();
    let obj: ObjRef = ObjRef::new(
        &ICMP4_FLOW_CLASS,
        IcmpFlow::new(cl.into(), sv.into())
    );
    Ok(Val::Obj(obj))
}

pub(crate) const ICMP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(&ICMP_FLOW),
};
