use pkt::Packet;
use pkt::dns::{DnsFlags, DnsName, class, dns_hdr, opcode, rcode, rrtype};

use ezpkt::UdpFlow;

use bytemuck::bytes_of;

use crate::libapi::{FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

use std::net::{Ipv4Addr, SocketAddrV4};

const OPCODE: Module = module! {
    /// # DNS Opcode
    resynth mod opcode {
        QUERY => Symbol::u8(opcode::QUERY),
        IQUERY => Symbol::u8(opcode::IQUERY),
        STATUS => Symbol::u8(opcode::STATUS),
        NOTIFY => Symbol::u8(opcode::NOTIFY),
        UPDATE => Symbol::u8(opcode::UPDATE),
        DSO => Symbol::u8(opcode::DSO),
    }
};

const RCODE: Module = module! {
    /// # DNS Response Codes (Errors)
    resynth mod rcode {
        NOERROR => Symbol::u8(rcode::NOERROR),
        FORMERR => Symbol::u8(rcode::FORMERR),
        SERVFAIL => Symbol::u8(rcode::SERVFAIL),
        NXDOMAIN => Symbol::u8(rcode::NXDOMAIN),
        NOTIMP => Symbol::u8(rcode::NOTIMP),
        REFUSED => Symbol::u8(rcode::REFUSED),
        YXDOMAIN => Symbol::u8(rcode::YXDOMAIN),
        YXRRSET => Symbol::u8(rcode::YXRRSET),
        NXRRSET => Symbol::u8(rcode::NXRRSET),
        NOTAUTH => Symbol::u8(rcode::NOTAUTH),
        NOTZONE => Symbol::u8(rcode::NOTZONE),
    }
};

const RTYPE: Module = module! {
    /// # DNS Record Type
    resynth mod rtype {
        A => Symbol::u16(rrtype::A),
        NS => Symbol::u16(rrtype::NS),
        MD => Symbol::u16(rrtype::MD),
        MF => Symbol::u16(rrtype::MF),
        CNAME => Symbol::u16(rrtype::CNAME),
        SOA => Symbol::u16(rrtype::SOA),
        MB => Symbol::u16(rrtype::MB),
        MG => Symbol::u16(rrtype::MG),
        NMR => Symbol::u16(rrtype::NMR),
        NULL => Symbol::u16(rrtype::NULL),
        WKS => Symbol::u16(rrtype::WKS),
        PTR => Symbol::u16(rrtype::PTR),
        HINFO => Symbol::u16(rrtype::HINFO),
        MINFO => Symbol::u16(rrtype::MINFO),
        MX => Symbol::u16(rrtype::MX),
        TXT => Symbol::u16(rrtype::TXT),
        RP => Symbol::u16(rrtype::RP),
        AFSDB => Symbol::u16(rrtype::AFSDB),
        SIG => Symbol::u16(rrtype::SIG),
        KEY => Symbol::u16(rrtype::KEY),
        AAAA => Symbol::u16(rrtype::AAAA),
        LOC => Symbol::u16(rrtype::LOC),
        SRV => Symbol::u16(rrtype::SRV),
        NAPTR => Symbol::u16(rrtype::NAPTR),
        KX => Symbol::u16(rrtype::KX),
        CERT => Symbol::u16(rrtype::CERT),
        DNAME => Symbol::u16(rrtype::DNAME),
        OPT => Symbol::u16(rrtype::OPT),
        APL => Symbol::u16(rrtype::APL),
        DS => Symbol::u16(rrtype::DS),
        SSHFP => Symbol::u16(rrtype::SSHFP),
        IPSECKEY => Symbol::u16(rrtype::IPSECKEY),
        RRSIG => Symbol::u16(rrtype::RRSIG),
        NSEC => Symbol::u16(rrtype::NSEC),
        DNSKEY => Symbol::u16(rrtype::DNSKEY),
        DHCID => Symbol::u16(rrtype::DHCID),
        NSEC3 => Symbol::u16(rrtype::NSEC3),
        NSEC3PARAM => Symbol::u16(rrtype::NSEC3PARAM),
        TLSA => Symbol::u16(rrtype::TLSA),
        SMIMEA => Symbol::u16(rrtype::SMIMEA),
        HIP => Symbol::u16(rrtype::HIP),
        CDS => Symbol::u16(rrtype::CDS),
        CDNSKEY => Symbol::u16(rrtype::CDNSKEY),
        OPENPGPKEY => Symbol::u16(rrtype::OPENPGPKEY),
        CSYNC => Symbol::u16(rrtype::CSYNC),
        ZONEMD => Symbol::u16(rrtype::ZONEMD),
        SVCB => Symbol::u16(rrtype::SVCB),
        HTTPS => Symbol::u16(rrtype::HTTPS),
        EUI48 => Symbol::u16(rrtype::EUI48),
        EUI64 => Symbol::u16(rrtype::EUI64),
        TKEY => Symbol::u16(rrtype::TKEY),
        TSIG => Symbol::u16(rrtype::TSIG),
        IXFR => Symbol::u16(rrtype::IXFR),

        // QTYPE
        AXFR => Symbol::u16(rrtype::AXFR),
        MAILB => Symbol::u16(rrtype::MAILB),
        MAILA => Symbol::u16(rrtype::MAILA),

        ALL => Symbol::u16(rrtype::ALL),

        URI => Symbol::u16(rrtype::URI),
        CAA => Symbol::u16(rrtype::CAA),
        TA => Symbol::u16(rrtype::TA),
        DLV => Symbol::u16(rrtype::DLV),
    }
};

const CLASS: Module = module! {
    /// # DNS Record Class
    resynth mod class {
        IN => Symbol::u16(class::IN),
        CS => Symbol::u16(class::CS),
        CH => Symbol::u16(class::CH),
        HS => Symbol::u16(class::HS),

        // QCLASS
        ANY => Symbol::u16(class::ANY),
    }
};

pub(crate) const DNS_NAME: FuncDef = func! (
    /// A DNS name encoded with DNS label format (length-prefixed labels, null-terminated).
    ///
    /// Also used to wrap a `netbios::name::encode()` result into a complete NBNS
    /// name label for use in NBNS packets (which share the DNS wire format).
    resynth fn name(
        =>
        /// If true, append a root label to terminate the name; if false, leave it open
        complete: Bool = true,
        =>
        Str
    ) -> Str
    |mut args| {
        let complete: bool = args.next().into();
        let v: Vec<Buf> = args.collect_extra_args();

        let name = if complete {
            match v.len() {
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
            }
        } else {
            let mut name = DnsName::new();
            for arg in v {
                name.push(arg.as_ref());
            }
            name
        };

        Ok(Val::str(name.as_ref()))
    }
);

const DNS_POINTER: FuncDef = func! (
    /// A DNS compression pointer
    resynth fn pointer(
        =>
        /// Byte offset within the DNS message to point to
        offset: U16 = 0x0c,
        =>
        Void
    ) -> Str
    |mut args| {
        let offset: u16 = args.next().into();

        let name = DnsName::compression_pointer(offset);

        Ok(Val::str(name.as_ref()))
    }
);

const DNS_FLAGS: FuncDef = func!(
    /// a DNS flags field
    resynth fn flags(
        /// DNS opcode for this message
        opcode: U8,
        =>
        /// If true, this is a response; if false, a query
        response: Bool = false,
        /// Authoritative Answer flag
        aa: Bool = false,
        /// Truncation flag
        tc: Bool = false,
        /// Recursion Desired flag
        rd: Bool = false,
        /// Recursion Available flag
        ra: Bool = false,
        /// Reserved (Z) bit
        z: Bool = false,
        /// Authentic Data flag (DNSSEC)
        ad: Bool = false,
        /// Checking Disabled flag (DNSSEC)
        cd: Bool = false,
        /// Response code
        rcode: U8 = rcode::NOERROR,
        =>
        Void
    ) -> U16
    |mut args| {
        let opcode: u8 = args.next().into();

        let response: bool = args.next().into();
        let aa: bool = args.next().into();
        let tc: bool = args.next().into();
        let rd: bool = args.next().into();
        let ra: bool = args.next().into();
        let z: bool = args.next().into();
        let ad: bool = args.next().into();
        let cd: bool = args.next().into();
        let rcode: u8 = args.next().into();

        Ok(Val::U16(DnsFlags::default()
            .response(response)
            .opcode(opcode)
            .aa(aa)
            .tc(tc)
            .rd(rd)
            .ra(ra)
            .z(z)
            .ad(ad)
            .cd(cd)
            .rcode(rcode)
            .build())
        )
    }
);

const DNS_HDR: FuncDef = func!(
    /// A DNS header
    resynth fn hdr(
        /// DNS message transaction ID
        id: U16,
        /// DNS flags field (use dns::flags() to construct)
        flags: U16,
        =>
        /// Number of entries in the question section
        qdcount: U16 = 0,
        /// Number of resource records in the answer section
        ancount: U16 = 0,
        /// Number of name server resource records in the authority section
        nscount: U16 = 0,
        /// Number of resource records in the additional records section
        arcount: U16 = 0,
        =>
        Void
    ) -> Str
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

        Ok(Val::str(bytes_of(&hdr)))
    }
);

const DNS_QUESTION: FuncDef = func!(
    /// A DNS question
    resynth fn question(
        /// Encoded DNS name being queried
        qname: Str,
        =>
        /// DNS record type to query (e.g. dns::rtype::A)
        qtype: U16 = 1,
        /// DNS record class (e.g. dns::class::IN)
        qclass: U16 = 1,
        =>
        Void
    ) -> Str
    |mut args| {
        let name: Buf = args.next().into();
        let qtype: u16 = args.next().into();
        let qclass: u16 = args.next().into();

        let mut q: Vec<u8> = Vec::new();

        q.extend(name.as_ref());
        q.extend(qtype.to_be_bytes());
        q.extend(qclass.to_be_bytes());

        Ok(Val::str(q))
    }
);

const DNS_ANSWER: FuncDef = func!(
    /// A DNS answer (RR)
    resynth fn answer(
        /// Encoded DNS name this record applies to
        aname: Str,
        =>
        /// DNS record type (e.g. dns::rtype::A)
        atype: U16 = 1,
        /// DNS record class (e.g. dns::class::IN)
        aclass: U16 = 1,
        /// Time-to-live for this record in seconds
        ttl: U32 = 229,
        =>
        Str
    ) -> Str
    |mut args| {
        let name: Buf = args.next().into();
        let atype: u16 = args.next().into();
        let aclass: u16 = args.next().into();
        let ttl: u32 = args.next().into();
        let data: Buf = args.join_extra(b"").into();

        let mut a: Vec<u8> = Vec::new();

        a.extend(name.as_ref());
        a.extend(atype.to_be_bytes());
        a.extend(aclass.to_be_bytes());
        a.extend(ttl.to_be_bytes());
        a.extend((data.len() as u16).to_be_bytes()); // dsize
        a.extend(data.as_ref());

        Ok(Val::str(a))
    }
);

const DNS_HOST: FuncDef = func!(
    /// Perform a DNS lookup, with response
    resynth fn host(
        /// Client IP address sending the DNS query
        client: Ip4,
        /// DNS name to look up
        qname: Str,
        =>
        /// Time-to-live for the answer records in seconds
        ttl: U32 = 229,
        /// IP address of the DNS name server
        ns: Ip4 = Ipv4Addr::new(1, 1, 1, 1),
        /// Enable raw mode; omits ethernet framing
        raw: Bool = false,
        =>
        Ip4
    ) -> PktGen
    |mut args| {
        let client: Ipv4Addr = args.next().into();
        let qname: DnsName = DnsName::from(args.next().as_ref());
        let ttl: u32 = args.next().into();
        let ns: Ipv4Addr = args.next().into();
        let raw: bool = args.next().into();

        let mut pkts: Vec<Packet> = Vec::with_capacity(2);

        let mut flow = UdpFlow::new(
            SocketAddrV4::new(client, 32768),
            SocketAddrV4::new(ns, 53),
            raw,
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
        msg.extend(bytes_of(&hdr));
        msg.extend(qname.as_ref());
        msg.extend(rrtype::A.to_be_bytes());
        msg.extend(class::IN.to_be_bytes());

        pkts.push(flow.client_dgram(msg.as_ref()).csum().into());
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
        msg.extend(bytes_of(&hdr));

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

        pkts.push(flow.server_dgram(msg.as_ref()).csum().into());

        Ok(pkts.into())
    }
);

pub const DNS: Module = module! {
    /// # Domain Name System
    ///
    /// You can use [host](#host) to do simple DNS requests
    ///
    /// Or you can use the other functions to build custom DNS messages
    resynth mod dns {
        opcode => Symbol::Module(&OPCODE),
        rcode => Symbol::Module(&RCODE),
        rtype => Symbol::Module(&RTYPE),
        qtype => Symbol::Module(&RTYPE),
        class => Symbol::Module(&CLASS),
        flags => Symbol::Func(&DNS_FLAGS),
        hdr => Symbol::Func(&DNS_HDR),
        name => Symbol::Func(&DNS_NAME),
        pointer => Symbol::Func(&DNS_POINTER),
        question => Symbol::Func(&DNS_QUESTION),
        answer => Symbol::Func(&DNS_ANSWER),
        host => Symbol::Func(&DNS_HOST),
    }
};
