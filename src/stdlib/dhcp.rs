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
    "REQUEST" => Symbol::u8(opcode::REQUEST),
    "REPLY" => Symbol::u8(opcode::REPLY),
};

const TYPE: phf::Map<&'static str, Symbol> = phf_map! {
    "DISCOVER" => Symbol::u8(message::DISCOVER),
    "OFFER" => Symbol::u8(message::OFFER),
    "REQUEST" => Symbol::u8(message::REQUEST),
    "DECLINE" => Symbol::u8(message::DECLINE),
    "ACK" => Symbol::u8(message::ACK),
    "NACK" => Symbol::u8(message::NACK),
    "RELEASE" => Symbol::u8(message::RELEASE),
    "INFORM" => Symbol::u8(message::INFORM),

    "FORCERENEW" => Symbol::u8(message::FORCERENEW),
    "LEASEQUERY" => Symbol::u8(message::LEASEQUERY),
    "LEASEUNASSIGNED" => Symbol::u8(message::LEASEUNASSIGNED),
    "LEASEUNKNOWN" => Symbol::u8(message::LEASEUNKNOWN),
    "LEASEACTIVE" => Symbol::u8(message::LEASEACTIVE),
    "BULKLEASEQUERY" => Symbol::u8(message::BULKLEASEQUERY),
    "LEASEQUERYDONE" => Symbol::u8(message::LEASEQUERYDONE),
    "ACTIVELEASEQUERY" => Symbol::u8(message::ACTIVELEASEQUERY),
    "LEASEQUERYSTATUS" => Symbol::u8(message::LEASEQUERYSTATUS),
    "TLS" => Symbol::u8(message::TLS),
};

const OPT: phf::Map<&'static str, Symbol> = phf_map! {
    "PADDING" => Symbol::u8(opt::PADDING),
    "SUBNET_MASK" => Symbol::u8(opt::SUBNET_MASK),
    "CLIENT_HOSTNAME" => Symbol::u8(opt::CLIENT_HOSTNAME),
    "VENDOR_SPECIFIC" => Symbol::u8(opt::VENDOR_SPECIFIC),
    "REQUESTED_ADDRESS" => Symbol::u8(opt::REQUESTED_ADDRESS),
    "ADDRESS_LEASE_TIME" => Symbol::u8(opt::ADDRESS_LEASE_TIME),
    "MESSAGE_TYPE" => Symbol::u8(opt::MESSAGE_TYPE),
    "SERVER_ID" => Symbol::u8(opt::SERVER_ID),
    "PARAM_REQUEST_LIST" => Symbol::u8(opt::PARAM_REQUEST_LIST),
    "MAX_MESSAGE_SIZE" => Symbol::u8(opt::MAX_MESSAGE_SIZE),
    "RENEWAL_TIME" => Symbol::u8(opt::RENEWAL_TIME),
    "REBINDING_TIME" => Symbol::u8(opt::REBINDING_TIME),
    "VENDOR_CLASS_ID" => Symbol::u8(opt::VENDOR_CLASS_ID),
    "CLIENT_ID" => Symbol::u8(opt::CLIENT_ID),
    "CLIENT_FQDN" => Symbol::u8(opt::CLIENT_FQDN),

    "END" => Symbol::u8(opt::END),
};

const HDR: FuncDef = func_def!(
    "dhcp::hdr";
    ValType::Str;

    =>
    "opcode" => ValDef::U8(opcode::REQUEST),
    "htype" => ValDef::U8(hrd::ETHER),
    "hlen" => ValDef::U8(6),
    "hops" => ValDef::U8(0),

    "xid" => ValDef::U32(0),

    "ciaddr" => ValDef::Ip4(Ipv4Addr::new(0, 0, 0, 0)),
    "yiaddr" => ValDef::Ip4(Ipv4Addr::new(0, 0, 0, 0)),
    "siaddr" => ValDef::Ip4(Ipv4Addr::new(0, 0, 0, 0)),
    "giaddr" => ValDef::Ip4(Ipv4Addr::new(0, 0, 0, 0)),

    "chaddr" => ValDef::Type(ValType::Str),

    "sname" => ValDef::Type(ValType::Str),
    "file" => ValDef::Type(ValType::Str),

    "magic" => ValDef::U32(MAGIC),
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

    "opt" => ValType::U8,
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
    "CLIENT_PORT" => Symbol::u16(CLIENT_PORT),
    "SERVER_PORT" => Symbol::u16(SERVER_PORT),

    "opcode" => Symbol::Module(&OPCODE),
    "type" => Symbol::Module(&TYPE),
    "opt" => Symbol::Module(&OPT),

    "hdr" => Symbol::Func(&HDR),
    "option" => Symbol::Func(&OPTION),
};
