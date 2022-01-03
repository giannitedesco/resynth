use phf::{phf_map, phf_ordered_map};

use crate::val::{ValType, Val, ValDef};
use crate::libapi::{FuncDef, ArgDecl};
use crate::sym::Symbol;
use crate::str::Buf;
use crate::func_def;
use crate::pkt::dns::{opcode, rrtype, class, dns_hdr, flags};
use crate::pkt::AsBytes;

use std::net::Ipv4Addr;

const OPCODE: phf::Map<&'static str, Symbol> = phf_map! {
    "QUERY" => Symbol::int_val(opcode::QUERY as u64),
    "IQUERY" => Symbol::int_val(opcode::IQUERY as u64),
    "STATUS" => Symbol::int_val(opcode::STATUS as u64),
};

const TYPE: phf::Map<&'static str, Symbol> = phf_map! {
    "A" => Symbol::int_val(rrtype::A as u64),
    "NS" => Symbol::int_val(rrtype::NS as u64),
    "MD" => Symbol::int_val(rrtype::MD as u64),
    "MF" => Symbol::int_val(rrtype::MF as u64),
    "CDNS_NAME" => Symbol::int_val(rrtype::CDNS_NAME as u64),
    "SOA" => Symbol::int_val(rrtype::SOA as u64),
    "MB" => Symbol::int_val(rrtype::MB as u64),
    "MG" => Symbol::int_val(rrtype::MG as u64),
    "NMR" => Symbol::int_val(rrtype::NMR as u64),
    "NULL" => Symbol::int_val(rrtype::NULL as u64),
    "WKS" => Symbol::int_val(rrtype::WKS as u64),
    "PTR" => Symbol::int_val(rrtype::PTR as u64),
    "HINFO" => Symbol::int_val(rrtype::HINFO as u64),
    "MINFO" => Symbol::int_val(rrtype::MINFO as u64),
    "MX" => Symbol::int_val(rrtype::MX as u64),
    "TXT" => Symbol::int_val(rrtype::TXT as u64),

    // QTYPE
    "AXFR" => Symbol::int_val(rrtype::AXFR as u64),
    "MAILB" => Symbol::int_val(rrtype::MAILB as u64),
    "MAILA" => Symbol::int_val(rrtype::MAILA as u64),

    "ALL" => Symbol::int_val(rrtype::ALL as u64),
};

const CLASS: phf::Map<&'static str, Symbol> = phf_map! {
    "IN" => Symbol::int_val(class::IN as u64),
    "CS" => Symbol::int_val(class::CS as u64),
    "CH" => Symbol::int_val(class::CH as u64),
    "HS" => Symbol::int_val(class::HS as u64),

    // QCLASS
    "ANY" => Symbol::int_val(class::ANY as u64),
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
            flags |= flags::RESPONSE;
        }

        flags |= flags::from_opcode(opcode as u8);

        let hdr = *dns_hdr::default()
            .id(id as u16)
            .flags(flags)
            .qdcount(qdcount as u16)
            .ancount(ancount as u16)
            .nscount(nscount as u16)
            .arcount(arcount as u16);

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
