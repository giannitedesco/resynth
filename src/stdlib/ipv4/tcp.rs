use phf::{phf_map, phf_ordered_map};

use crate::val::{ValType, Val, ValDef};
use crate::str::Buf;
use crate::libapi::{FuncDef, ArgDecl, Class};
use crate::sym::Symbol;
use ezpkt::TcpFlow;
use crate::func_def;

const TCP_OPEN: FuncDef = func_def!(
    "ipv4::tcp::flow.open";
    ValType::PktGen;

    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.open().into())
    }
);

const TCP_CL_CLOSE: FuncDef = func_def!(
    "ipv4::tcp::flow.client_close";
    ValType::PktGen;

    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.client_close().into())
    }
);

const TCP_SV_CLOSE: FuncDef = func_def!(
    "ipv4::tcp::flow.server_close";
    ValType::PktGen;

    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.server_close().into())
    }
);

const TCP_CL_HOLE: FuncDef = func_def!(
    "ipv4::tcp::flow.client_hole";
    ValType::Void;

    "bytes" => ValType::U64,
    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: u32 = args.next().into();

        this.server_hole(bytes);
        Ok(Val::Nil)
    }
);

const TCP_SV_HOLE: FuncDef = func_def!(
    "ipv4::tcp::flow.server_hole";
    ValType::Void;

    "bytes" => ValType::U64,
    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: u32 = args.next().into();

        this.server_hole(bytes);
        Ok(Val::Nil)
    }
);

const TCP_CL_MSG: FuncDef = func_def!(
    "ipv4::tcp::flow.client_message";
    ValType::PktGen;

    =>
    "send_ack" => ValDef::Bool(true),
    =>
    ValType::Str;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let send_ack: bool = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        Ok(this.client_message(bytes.as_ref(), send_ack).into())
    }
);

const TCP_SV_MSG: FuncDef = func_def!(
    "ipv4::tcp::flow.server_message";
    ValType::PktGen;

    =>
    "send_ack" => ValDef::Bool(true),
    =>
    ValType::Str;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let send_ack: bool = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        Ok(this.server_message(bytes.as_ref(), send_ack).into())
    }
);

impl Class for TcpFlow {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "open" => Symbol::Func(&TCP_OPEN),
            "client_close" => Symbol::Func(&TCP_CL_CLOSE),
            "server_close" => Symbol::Func(&TCP_SV_CLOSE),
            "client_message" => Symbol::Func(&TCP_CL_MSG),
            "server_message" => Symbol::Func(&TCP_SV_MSG),
            "client_hole" => Symbol::Func(&TCP_CL_HOLE),
            "server_hole" => Symbol::Func(&TCP_SV_HOLE),
        }
    }

    fn class_name(&self) -> &'static str {
        "ipv4::tcp4.flow"
    }
}

const TCP_FLOW: FuncDef = func_def!(
    "flow";
    ValType::Obj;

    "cl" => ValType::Sock4,
    "sv" => ValType::Sock4,
    =>
    =>
    ValType::Void;

    |mut args| {
        let cl = args.next();
        let sv = args.next();
        Ok(Val::from(TcpFlow::new(cl.into(), sv.into())))
    }
);


pub const TCP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(&TCP_FLOW),
};
