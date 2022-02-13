use phf::{phf_map, phf_ordered_map};

use pkt::dns::{opcode, rcode, rrtype, class, dns_hdr, DnsFlags, DnsName};
use pkt::AsBytes;
use pkt::Packet;

use ezpkt::UdpFlow;

use crate::val::{ValType, Val, ValDef};
use crate::libapi::{FuncDef, ArgDecl};
use crate::sym::Symbol;
use crate::str::Buf;
use crate::func_def;

use std::net::{Ipv4Addr, SocketAddrV4};

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
        let v = args.extra_args();

        let name = match v.len() {
            0 => DnsName::root(),
            1 => DnsName::from(v[0].as_ref()),
            _ => {
                let mut name = DnsName::new();
                for arg in v {
                    name.push(arg.as_ref());
                }
                name.finish();
                name
            }
        };

        Ok(Val::Str(Buf::from(name.as_ref())))
    }
);

const DNS_FLAGS: FuncDef = func_def!(
    "dns::flags";
    ValType::U64;

    "opcode" => ValType::U64,
    =>
    "response" => ValDef::U64(0),
    "aa" => ValDef::U64(0),
    "tc" => ValDef::U64(0),
    "rd" => ValDef::U64(0),
    "ra" => ValDef::U64(0),
    "rcode" => ValDef::U64(rcode::NOERROR as u64),
    =>
    ValType::Void;

    |mut args| {
        let opcode: u64 = args.next().into();

        let response: u64 = args.next().into();
        let aa: u64 = args.next().into();
        let tc: u64 = args.next().into();
        let rd: u64 = args.next().into();
        let ra: u64 = args.next().into();
        let rcode: u64 = args.next().into();

        Ok(Val::U64(DnsFlags::default()
            .response(response != 0)
            .opcode(opcode as u8)
            .aa(aa != 0)
            .tc(tc != 0)
            .rd(rd != 0)
            .ra(ra != 0)
            .rcode(rcode as u8)
            .build() as u64)
        )
    }
);

const DNS_HDR: FuncDef = func_def!(
    "dns::hdr";
    ValType::Str;

    "id" => ValType::U64,
    "flags" => ValType::U64,
    =>
    "qdcount" => ValDef::U64(0),
    "ancount" => ValDef::U64(0),
    "nscount" => ValDef::U64(0),
    "arcount" => ValDef::U64(0),
    =>
    ValType::Void;

    |mut args| {
        let id: u64 = args.next().into();
        let flags: u64 = args.next().into();
        let qdcount: u64 = args.next().into();
        let ancount: u64 = args.next().into();
        let nscount: u64 = args.next().into();
        let arcount: u64 = args.next().into();

        let hdr = dns_hdr::builder()
            .id(id as u16)
            .flags(flags as u16)
            .qdcount(qdcount as u16)
            .ancount(ancount as u16)
            .nscount(nscount as u16)
            .arcount(arcount as u16)
            .build();

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
    "data" => ValType::Str,
    =>
    "atype" => ValDef::U64(1),
    "aclass" => ValDef::U64(1),
    "ttl" => ValDef::U64(229),
    =>
    ValType::Void;

    |mut args| {
        let name: Buf = args.next().into();
        let data: Buf = args.next().into();
        let atype: u64 = args.next().into();
        let aclass: u64 = args.next().into();
        let ttl: u64 = args.next().into();

        let mut a: Vec<u8> = Vec::new();

        a.extend(name.as_ref());
        a.extend((atype as u16).to_be_bytes());
        a.extend((aclass as u16).to_be_bytes());
        a.extend((ttl as u32).to_be_bytes());
        a.extend((data.len() as u16).to_be_bytes()); // dsize
        a.extend(data.as_ref());

        Ok(Val::Str(Buf::from(a)))
    }
);

const DNS_HOST: FuncDef = func_def!(
    "dns::host";
    ValType::PktGen;

    "client" => ValType::Ip4,
    "qname" => ValType::Str,
    =>
    "ttl" => ValDef::U64(229),
    "ns" => ValDef::Ip4(Ipv4Addr::new(1, 1, 1, 1)),
    =>
    ValType::Ip4;

    |mut args| {
        let client: Ipv4Addr = args.next().into();
        let qname: DnsName = DnsName::from(args.next().as_ref());
        let ttl: u64 = args.next().into();
        let ns: Ipv4Addr = args.next().into();

        let mut pkts: Vec<Packet> = Vec::with_capacity(2);

        let mut flow = UdpFlow::new(
            SocketAddrV4::new(client, 32768),
            SocketAddrV4::new(ns, 53),
        );

        let mut msg: Vec<u8> = Vec::new();

        let hdr = dns_hdr::builder()
            .id(0x1234)
            .flags(DnsFlags::default()
                   .opcode(opcode::QUERY)
                   .rd(true)
                   .build())
            .qdcount(1)
            .build();
        msg.extend(hdr.as_bytes());
        msg.extend(qname.as_ref());
        msg.extend(rrtype::A.to_be_bytes());
        msg.extend(class::IN.to_be_bytes());

        pkts.push(flow.client_dgram(msg.as_ref()));
        msg.clear();

        let hdr = dns_hdr::builder()
            .id(0x1234)
            .flags(DnsFlags::default()
                   .response(true)
                   .opcode(opcode::QUERY)
                   .ra(true)
                   .build())
            .qdcount(1)
            .ancount(args.extra_len() as u16)
            .build();
        msg.extend(hdr.as_bytes());

        msg.extend(qname.as_ref());
        msg.extend(rrtype::A.to_be_bytes());
        msg.extend(class::IN.to_be_bytes());

        let results: Vec<Ipv4Addr> = args.collect_extra_args();
        for ip in results {
            msg.extend(qname.as_ref());
            msg.extend(rrtype::A.to_be_bytes());
            msg.extend(class::IN.to_be_bytes());
            msg.extend((ttl as u32).to_be_bytes());
            msg.extend((4u16).to_be_bytes()); // dsize
            msg.extend(u32::from(ip).to_be_bytes()); // ip
        }

        pkts.push(flow.server_dgram(msg.as_ref()));

        Ok(pkts.into())
    }
);


pub const DNS: phf::Map<&'static str, Symbol> = phf_map! {
    "opcode" => Symbol::Module(&OPCODE),
    "type" => Symbol::Module(&TYPE),
    "class" => Symbol::Module(&CLASS),
    "flags" => Symbol::Func(&DNS_FLAGS),
    "hdr" => Symbol::Func(&DNS_HDR),
    "name" => Symbol::Func(&DNS_NAME),
    "question" => Symbol::Func(&DNS_QUESTION),
    "answer" => Symbol::Func(&DNS_ANSWER),
    "host" => Symbol::Func(&DNS_HOST),
};
