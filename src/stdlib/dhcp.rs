use phf::{phf_map, phf_ordered_map};

use pkt::dhcp::{opcode, message, opt, CLIENT_PORT, SERVER_PORT, MAGIC, dhcp_opt};
use pkt::arp::hrd;
use ezpkt::Dhcp;

use crate::val::{ValType, Val, ValDef};
use crate::libapi::{FuncDef, ArgDecl};
use crate::sym::Symbol;
use crate::str::Buf;
use crate::func_def;

use std::net::Ipv4Addr;

const OPCODE: phf::Map<&'static str, Symbol> = phf_map! {
    "REQUEST" => Symbol::int_val(opcode::REQUEST as u64),
    "REPLY" => Symbol::int_val(opcode::REPLY as u64),
};

const TYPE: phf::Map<&'static str, Symbol> = phf_map! {
    "DISCOVER" => Symbol::int_val(message::DISCOVER as u64),
    "OFFER" => Symbol::int_val(message::OFFER as u64),
    "REQUEST" => Symbol::int_val(message::REQUEST as u64),
    "ACK" => Symbol::int_val(message::ACK as u64),
    "NACK" => Symbol::int_val(message::NACK as u64),
    "RELEASE" => Symbol::int_val(message::RELEASE as u64),
    "INFORM" => Symbol::int_val(message::INFORM as u64),
};

const OPT: phf::Map<&'static str, Symbol> = phf_map! {
    "PADDING" => Symbol::int_val(opt::PADDING as u64),
    "CLIENT_HOSTNAME" => Symbol::int_val(opt::CLIENT_HOSTNAME as u64),
    "VENDOR_SPECIFIC" => Symbol::int_val(opt::VENDOR_SPECIFIC as u64),
    "REQUESTED_ADDRESS" => Symbol::int_val(opt::REQUESTED_ADDRESS as u64),
    "MESSAGE_TYPE" => Symbol::int_val(opt::MESSAGE_TYPE as u64),
    "SERVER_ID" => Symbol::int_val(opt::SERVER_ID as u64),
    "PARAM_REQUEST_LIST" => Symbol::int_val(opt::PARAM_REQUEST_LIST as u64),
    "MAX_MESSAGE_SIZE" => Symbol::int_val(opt::MAX_MESSAGE_SIZE as u64),
    "VENDOR_CLASS_ID" => Symbol::int_val(opt::VENDOR_CLASS_ID as u64),
    "CLIENT_ID" => Symbol::int_val(opt::CLIENT_ID as u64),
    "CLIENT_FQDN" => Symbol::int_val(opt::CLIENT_FQDN as u64),

    "END" => Symbol::Val(ValDef::Str(b"\xff")),
};

const HDR: FuncDef = func_def!(
    "dhcp::hdr";
    ValType::Str;

    =>
    "opcode" => ValDef::U64(opcode::REQUEST as u64),
    "htype" => ValDef::U64(hrd::ETHER as u64),
    "hlen" => ValDef::U64(6),
    "hops" => ValDef::U64(0),

    "xid" => ValDef::U64(0),

    "ciaddr" => ValDef::Ip4(Ipv4Addr::new(0, 0, 0, 0)),
    "yiaddr" => ValDef::Ip4(Ipv4Addr::new(0, 0, 0, 0)),
    "siaddr" => ValDef::Ip4(Ipv4Addr::new(0, 0, 0, 0)),
    "giaddr" => ValDef::Ip4(Ipv4Addr::new(0, 0, 0, 0)),

    "chaddr" => ValDef::Type(ValType::Str),

    "sname" => ValDef::Type(ValType::Str),
    "file" => ValDef::Type(ValType::Str),

    "magic" => ValDef::U64(MAGIC as u64),
    =>
    ValType::Void;

    |mut args| {
        let opcode: u8 = args.next().into();
        let htype: u8 = args.next().into();
        let hlen: u8 = args.next().into();
        let hops: u8 = args.next().into();
        let xid: u32 = args.next().into();

        let ciaddr: Ipv4Addr = args.next().into();
        let yiaddr: Ipv4Addr = args.next().into();
        let siaddr: Ipv4Addr = args.next().into();
        let giaddr: Ipv4Addr = args.next().into();

        let chaddr: Option<Buf> = args.next().into();
        let sname: Option<Buf> = args.next().into();
        let file: Option<Buf> = args.next().into();

        let magic: u32 = args.next().into();

        let mut hdr = Dhcp::default()
            .op(opcode)
            .htype(htype)
            .hlen(hlen)
            .hops(hops)
            .xid(xid)
            .ciaddr(ciaddr.into())
            .yiaddr(yiaddr.into())
            .siaddr(siaddr.into())
            .giaddr(giaddr.into())
            .magic(magic);

        if let Some(ch) = chaddr {
            hdr = hdr.chaddr(ch);
        }

        if let Some(svr) = sname {
            hdr = hdr.sname(svr);
        }

        if let Some(f) = file {
            hdr = hdr.file(f);
        }

        Ok(Val::Str(Buf::from(&hdr)))
    }
);

const OPTION: FuncDef = func_def!(
    "dhcp::option";
    ValType::Str;

    "opt" => ValType::U64,
    =>
    =>
    ValType::Str;

    |mut args| {
        let opt: u8 = args.next().into();
        let data = args.join_extra(b"");
        let optbuf = dhcp_opt::create(opt, &data);
        Ok(Val::Str(Buf::from(optbuf)))
    }
);

pub const MODULE: phf::Map<&'static str, Symbol> = phf_map! {
    "CLIENT_PORT" => Symbol::int_val(CLIENT_PORT as u64),
    "SERVER_PORT" => Symbol::int_val(SERVER_PORT as u64),

    "opcode" => Symbol::Module(&OPCODE),
    "type" => Symbol::Module(&TYPE),
    "opt" => Symbol::Module(&OPT),

    "hdr" => Symbol::Func(&HDR),
    "option" => Symbol::Func(&OPTION),
};
