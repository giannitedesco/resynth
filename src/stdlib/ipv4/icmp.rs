use phf::phf_map;

use crate::err::Error;
use crate::val::{Symbol, ValType, FuncDef, Args, Val, BytesObj, ObjRef, ClassDef};
use crate::ezpkt::IcmpFlow;

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

pub const ICMP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(FuncDef {
        name: "flow",
        return_type: ValType::Obj,
        args: &[ ValType::Ip4, ValType::Ip4 ],
        collect_type: ValType::Void,
        exec: icmp_flow,
    }),
};
