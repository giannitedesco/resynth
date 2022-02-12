use phf::{phf_map, phf_ordered_map};

use std::net::Ipv4Addr;

use pkt::Packet;
use ezpkt::{UdpDgram, UdpFlow};

use crate::val::{ValType, Val, ValDef};
use crate::str::Buf;
use crate::libapi::{FuncDef, ArgDecl, Class};
use crate::sym::Symbol;
use crate::func_def;

const BROADCAST: FuncDef = func_def!(
    "ipv4::udp::broadcast";
    ValType::Pkt;

    "src" => ValType::Sock4,
    "dst" => ValType::Sock4,
    =>
    "srcip" => ValDef::Type(ValType::Ip4),
    =>
    ValType::Str;

    |mut args| {
        let src = args.next();
        let dst = args.next();
        let srcip: Option<Ipv4Addr> = args.next().into();
        let buf: Buf = args.join_extra(b"").into();

        let mut dgram = UdpDgram::with_capacity(buf.len())
            .src(src.into())
            .dst(dst.into())
            .broadcast()
            .push(buf);

        if let Some(src) = srcip {
            dgram = dgram.srcip(src);
        }

        let pkt: Packet = dgram.into();
        Ok(pkt.into())
    }
);

const UNICAST: FuncDef = func_def!(
    "ipv4::udp::unicast";
    ValType::Pkt;

    "src" => ValType::Sock4,
    "dst" => ValType::Sock4,
    =>
    =>
    ValType::Str;

    |mut args| {
        let src = args.next();
        let dst = args.next();
        let buf: Buf = args.join_extra(b"").into();
        let dgram: Packet = UdpDgram::with_capacity(buf.len())
            .src(src.into())
            .dst(dst.into())
            .push(buf)
            .into();
        Ok(dgram.into())
    }
);

const CL_DGRAM: FuncDef = func_def!(
    "ipv4::udp::flow.client_dgram";
    ValType::Pkt;

    =>
    =>
    ValType::Str;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut UdpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: Buf = args.join_extra(b"").into();
        Ok(this.client_dgram(bytes.as_ref()).into())
    }
);

const SV_DGRAM: FuncDef = func_def!(
    "ipv4::udp::flow.server_dgram";
    ValType::Pkt;

    =>
    =>
    ValType::Str;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut UdpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: Buf = args.join_extra(b"").into();
        Ok(this.server_dgram(bytes.as_ref()).into())
    }
);

impl Class for UdpFlow {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "client_dgram" => Symbol::Func(&CL_DGRAM),
            "server_dgram" => Symbol::Func(&SV_DGRAM),
        }
    }

    fn class_name(&self) -> &'static str {
        "ipv4::udp4.flow"
    }
}

const FLOW: FuncDef = func_def!(
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
        Ok(Val::from(UdpFlow::new(cl.into(), sv.into())))
    }
);

pub const UDP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(&FLOW),
    "broadcast" => Symbol::Func(&BROADCAST),
    "unicast" => Symbol::Func(&UNICAST),
};

