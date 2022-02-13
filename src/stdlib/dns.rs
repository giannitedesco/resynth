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
    "QUERY" => Symbol::u8(opcode::QUERY),
    "IQUERY" => Symbol::u8(opcode::IQUERY),
    "STATUS" => Symbol::u8(opcode::STATUS),
};

const TYPE: phf::Map<&'static str, Symbol> = phf_map! {
    "A" => Symbol::u16(rrtype::A),
    "NS" => Symbol::u16(rrtype::NS),
    "MD" => Symbol::u16(rrtype::MD),
    "MF" => Symbol::u16(rrtype::MF),
    "CDNS_NAME" => Symbol::u16(rrtype::CDNS_NAME),
    "SOA" => Symbol::u16(rrtype::SOA),
    "MB" => Symbol::u16(rrtype::MB),
    "MG" => Symbol::u16(rrtype::MG),
    "NMR" => Symbol::u16(rrtype::NMR),
    "NULL" => Symbol::u16(rrtype::NULL),
    "WKS" => Symbol::u16(rrtype::WKS),
    "PTR" => Symbol::u16(rrtype::PTR),
    "HINFO" => Symbol::u16(rrtype::HINFO),
    "MINFO" => Symbol::u16(rrtype::MINFO),
    "MX" => Symbol::u16(rrtype::MX),
    "TXT" => Symbol::u16(rrtype::TXT),

    // QTYPE
    "AXFR" => Symbol::u16(rrtype::AXFR),
    "MAILB" => Symbol::u16(rrtype::MAILB),
    "MAILA" => Symbol::u16(rrtype::MAILA),

    "ALL" => Symbol::u16(rrtype::ALL),
};

const CLASS: phf::Map<&'static str, Symbol> = phf_map! {
    "IN" => Symbol::u16(class::IN),
    "CS" => Symbol::u16(class::CS),
    "CH" => Symbol::u16(class::CH),
    "HS" => Symbol::u16(class::HS),

    // QCLASS
    "ANY" => Symbol::u16(class::ANY),
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
    ValType::U16;

    "opcode" => ValType::U8,
    =>
    "response" => ValDef::Bool(false),
    "aa" => ValDef::Bool(false),
    "tc" => ValDef::Bool(false),
    "rd" => ValDef::Bool(false),
    "ra" => ValDef::Bool(false),
    "rcode" => ValDef::U8(rcode::NOERROR),
    =>
    ValType::Void;

    |mut args| {
        let opcode: u8 = args.next().into();

        let response: bool = args.next().into();
        let aa: bool = args.next().into();
        let tc: bool = args.next().into();
        let rd: bool = args.next().into();
        let ra: bool = args.next().into();
        let rcode: u8 = args.next().into();

        Ok(Val::U16(DnsFlags::default()
            .response(response)
            .opcode(opcode)
            .aa(aa)
            .tc(tc)
            .rd(rd)
            .ra(ra)
            .rcode(rcode)
            .build())
        )
    }
);

const DNS_HDR: FuncDef = func_def!(
    "dns::hdr";
    ValType::Str;

    "id" => ValType::U16,
    "flags" => ValType::U16,
    =>
    "qdcount" => ValDef::U16(0),
    "ancount" => ValDef::U16(0),
    "nscount" => ValDef::U16(0),
    "arcount" => ValDef::U16(0),
    =>
    ValType::Void;

    |mut args| {
        let id: u16 = args.next().into();
        let flags: u16 = args.next().into();
        let qdcount: u16 = args.next().into();
        let ancount: u16 = args.next().into();
        let nscount: u16 = args.next().into();
        let arcount: u16 = args.next().into();

        let hdr = dns_hdr::builder()
            .id(id)
            .flags(flags)
            .qdcount(qdcount)
            .ancount(ancount)
            .nscount(nscount)
            .arcount(arcount)
            .build();

        Ok(Val::Str(Buf::from(hdr.as_bytes())))
    }
);

const DNS_QUESTION: FuncDef = func_def!(
    "dns::question";
    ValType::Str;

    "qname" => ValType::Str,
    =>
    "qtype" => ValDef::U16(1),
    "qclass" => ValDef::U16(1),
    =>
    ValType::Void;

    |mut args| {
        let name: Buf = args.next().into();
        let qtype: u16 = args.next().into();
        let qclass: u16 = args.next().into();

        let mut q: Vec<u8> = Vec::new();

        q.extend(name.as_ref());
        q.extend(qtype.to_be_bytes());
        q.extend(qclass.to_be_bytes());

        Ok(Val::Str(Buf::from(q)))
    }
);

const DNS_ANSWER: FuncDef = func_def!(
    "dns::answer";
    ValType::Str;

    "aname" => ValType::Str,
    "data" => ValType::Str,
    =>
    "atype" => ValDef::U16(1),
    "aclass" => ValDef::U16(1),
    "ttl" => ValDef::U32(229),
    =>
    ValType::Void;

    |mut args| {
        let name: Buf = args.next().into();
        let data: Buf = args.next().into();
        let atype: u16 = args.next().into();
        let aclass: u16 = args.next().into();
        let ttl: u32 = args.next().into();

        let mut a: Vec<u8> = Vec::new();

        a.extend(name.as_ref());
        a.extend(atype.to_be_bytes());
        a.extend(aclass.to_be_bytes());
        a.extend(ttl.to_be_bytes());
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
    "ttl" => ValDef::U32(229),
    "ns" => ValDef::Ip4(Ipv4Addr::new(1, 1, 1, 1)),
    =>
    ValType::Ip4;

    |mut args| {
        let client: Ipv4Addr = args.next().into();
        let qname: DnsName = DnsName::from(args.next().as_ref());
        let ttl: u32 = args.next().into();
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
            msg.extend(ttl.to_be_bytes());
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
