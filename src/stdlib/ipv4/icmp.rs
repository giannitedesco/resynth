use phf::{phf_map, phf_ordered_map};

use crate::val::{ValType, Val};
use crate::str::Buf;
use crate::libapi::{FuncDef, ArgDecl, Class};
use crate::sym::Symbol;
use ezpkt::IcmpFlow;
use crate::func_def;

const ICMP_ECHO: FuncDef = func_def!(
    "ipv4::tcp::flow.echo";
    ValType::Pkt;
    
    "payload" => ValType::Str,
    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IcmpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: Buf = args.next().into();
        Ok(this.echo(bytes.as_ref()).into())
    }
);

const ICMP_ECHO_REPLY: FuncDef = func_def!(
    "ipv4::tcp::flow.echo_reply";
    ValType::Pkt;

    "payload" => ValType::Str,
    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IcmpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: Buf = args.next().into();
        Ok(this.echo_reply(bytes.as_ref()).into())
    }
);

impl Class for IcmpFlow {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "echo" => Symbol::Func(&ICMP_ECHO),
            "echo_reply" => Symbol::Func(&ICMP_ECHO_REPLY),
        }
    }

    fn class_name(&self) -> &'static str {
        "ipv4::icmp4.flow"
    }
}

const ICMP_FLOW: FuncDef = func_def!(
    "flow";
    ValType::Obj;

    "cl" => ValType::Ip4,
    "sv" => ValType::Ip4,
    =>
    =>
    ValType::Void;

    |mut args| {
        let cl = args.next();
        let sv = args.next();
        Ok(Val::from(IcmpFlow::new(cl.into(), sv.into())))
    }
);

pub const ICMP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(&ICMP_FLOW),
};
