use phf::{phf_map, phf_ordered_map};

use crate::val::{ValType, Val, ValDef};
use crate::libapi::{Symbol, FuncDef, ArgDecl};
use crate::str::Buf;
use crate::func_def;
use crate::pkt::util::{Serialize, AsBytes};

use std::net::Ipv4Addr;

const OPCODE: phf::Map<&'static str, Symbol> = phf_map! {
    "QUERY" => Symbol::Val(ValDef::U64(0)),
    "IQUERY" => Symbol::Val(ValDef::U64(1)),
    "STATUS" => Symbol::Val(ValDef::U64(2)),
};

const TYPE: phf::Map<&'static str, Symbol> = phf_map! {
    "A" => Symbol::Val(ValDef::U64(1)),
    "NS" => Symbol::Val(ValDef::U64(2)),
    "MD" => Symbol::Val(ValDef::U64(3)),
    "MF" => Symbol::Val(ValDef::U64(4)),
    "CDNS_NAME" => Symbol::Val(ValDef::U64(5)),
    "SOA" => Symbol::Val(ValDef::U64(6)),
    "MB" => Symbol::Val(ValDef::U64(7)),
    "MG" => Symbol::Val(ValDef::U64(8)),
    "NMR" => Symbol::Val(ValDef::U64(9)),
    "NULL" => Symbol::Val(ValDef::U64(10)),
    "WKS" => Symbol::Val(ValDef::U64(11)),
    "PTR" => Symbol::Val(ValDef::U64(12)),
    "HINFO" => Symbol::Val(ValDef::U64(13)),
    "MINFO" => Symbol::Val(ValDef::U64(14)),
    "MX" => Symbol::Val(ValDef::U64(15)),
    "TXT" => Symbol::Val(ValDef::U64(16)),

    // QTYPE
    "AXFR" => Symbol::Val(ValDef::U64(252)),
    "MAILB" => Symbol::Val(ValDef::U64(253)),
    "MAILA" => Symbol::Val(ValDef::U64(254)),

    "ALL" => Symbol::Val(ValDef::U64(255)),
};

const CLASS: phf::Map<&'static str, Symbol> = phf_map! {
    "IN" => Symbol::Val(ValDef::U64(1)),
    "CS" => Symbol::Val(ValDef::U64(2)),
    "CH" => Symbol::Val(ValDef::U64(3)),
    "HS" => Symbol::Val(ValDef::U64(4)),

    // QCLASS
    "ANY" => Symbol::Val(ValDef::U64(255)),
};

const DNS_NAME: FuncDef = func_def! (
    "dns::name";
    ValType::Str;

    =>
    =>
    ValType::Str;

    |mut args| {
        let mut ret: Vec<u8> = Vec::new();

        for arg in args.extra_args() {
            let c: Buf = arg.into();
            let clen = c.len();
            ret.push(clen as u8);
            ret.extend(c.as_ref());
        }

        ret.push(0u8);

        Ok(Val::Str(Buf::from(ret)))
    }
);

#[allow(unused)]
#[repr(C, packed(1))]
struct dns_hdr {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl Serialize for dns_hdr {
}

const DNS_HDR: FuncDef = func_def!(
    "dns::hdr";
    ValType::Str;

    "id" => ValType::U64,
    "opcode" => ValType::U64,
    =>
    "response" => ValDef::U64(0),
    "qdcount" => ValDef::U64(0),
    "ancount" => ValDef::U64(0),
    "nscount" => ValDef::U64(0),
    "arcount" => ValDef::U64(0),
    =>
    ValType::Void;

    |mut args| {
        let id: u64 = args.next().into();
        let opcode: u64 = args.next().into();
        let response: u64 = args.next().into();
        let qdcount: u64 = args.next().into();
        let ancount: u64 = args.next().into();
        let nscount: u64 = args.next().into();
        let arcount: u64 = args.next().into();

        let mut flags: u16 = 0;

        if response != 0 {
            flags |= 0x8000;
        }

        flags |= ((opcode & 7) << 14) as u16;

        let hdr = dns_hdr {
            id: (id as u16).to_be(),
            flags: flags.to_be(),
            qdcount: (qdcount as u16).to_be(),
            ancount: (ancount as u16).to_be(),
            nscount: (nscount as u16).to_be(),
            arcount: (arcount as u16).to_be(),
        };

        Ok(Val::Str(Buf::from(hdr.as_bytes())))
    }
);

const DNS_QUESTION: FuncDef = func_def!(
    "dns::question";
    ValType::Str;

    "qname" => ValType::Str,
    =>
    "qtype" => ValDef::U64(1),
    "qclass" => ValDef::U64(1),
    =>
    ValType::Void;

    |mut args| {
        let name: Buf = args.next().into();
        let qtype: u64 = args.next().into();
        let qclass: u64 = args.next().into();

        let mut q: Vec<u8> = Vec::new();

        q.extend(name.as_ref());
        q.extend((qtype as u16).to_be_bytes());
        q.extend((qclass as u16).to_be_bytes());

        Ok(Val::Str(Buf::from(q)))
    }
);

const DNS_ANSWER: FuncDef = func_def!(
    "dns::answer";
    ValType::Str;

    "aname" => ValType::Str,
    "data" => ValType::Ip4,
    =>
    "atype" => ValDef::U64(1),
    "aclass" => ValDef::U64(1),
    "ttl" => ValDef::U64(229),
    =>
    ValType::Void;

    |mut args| {
        let name: Buf = args.next().into();
        let data: Ipv4Addr = args.next().into();
        let atype: u64 = args.next().into();
        let aclass: u64 = args.next().into();
        let ttl: u64 = args.next().into();

        let mut a: Vec<u8> = Vec::new();

        a.extend(name.as_ref());
        a.extend((atype as u16).to_be_bytes());
        a.extend((aclass as u16).to_be_bytes());
        a.extend((ttl as u32).to_be_bytes());
        a.extend((4u16).to_be_bytes()); // dsize
        a.extend(u32::from(data).to_be_bytes()); // ip

        Ok(Val::Str(Buf::from(a)))
    }
);

const DNS_HOST: FuncDef = func_def!(
    "dns::host";
    ValType::Str;

    "qname" => ValType::Str,
    =>
    "ns" => ValDef::Ip4(Ipv4Addr::new(1, 1, 1, 1)),
    =>
    ValType::Ip4;

    |mut args| {
        let _name: Buf = args.next().into();
        let _ns: Ipv4Addr = args.next().into();
        let _results = args.extra_args();

        // TODO: This should be a one-stop shop for generating DNS queries
        Ok(Val::Str(Buf::from(b"TODO: dns::host()")))
    }
);


pub(crate) const DNS: phf::Map<&'static str, Symbol> = phf_map! {
    "opcode" => Symbol::Module(&OPCODE),
    "type" => Symbol::Module(&TYPE),
    "class" => Symbol::Module(&CLASS),
    "hdr" => Symbol::Func(&DNS_HDR),
    "name" => Symbol::Func(&DNS_NAME),
    "question" => Symbol::Func(&DNS_QUESTION),
    "answer" => Symbol::Func(&DNS_ANSWER),
    "host" => Symbol::Func(&DNS_HOST),
};
