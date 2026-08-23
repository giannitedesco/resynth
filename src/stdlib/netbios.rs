use pkt::dns::{DnsFlags, rcode};
use pkt::netbios::{name, ns};

use crate::err::Error;
use crate::libapi::{FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

const OPCODE: Module = module! {
    /// # NetBIOS Name Service Opcodes
    resynth mod opcode {
        QUERY => Symbol::u8(ns::opcode::QUERY),
        REGISTRATION => Symbol::u8(ns::opcode::REGISTRATION),
        RELEASE => Symbol::u8(ns::opcode::RELEASE),
        WACK => Symbol::u8(ns::opcode::WACK),
        REFRESH => Symbol::u8(ns::opcode::REFRESH),
        REFRESH_ALT => Symbol::u8(ns::opcode::REFRESH_ALT),
        MH_REGISTRATION => Symbol::u8(ns::opcode::MH_REGISTRATION),
    }
};

const RRTYPE: Module = module! {
    /// # NetBIOS Name Service RR types
    resynth mod rrtype {
        NULL => Symbol::u16(ns::rrtype::NULL),
        NB => Symbol::u16(ns::rrtype::NB),
        NBSTAT => Symbol::u16(ns::rrtype::NBSTAT),
    }
};

const RCODE: Module = module! {
    /// # NetBIOS Name Service Response codes
    resynth mod rcode {
        ACT_ERR => Symbol::u8(ns::rcode::ACT_ERR),
        CFT_ERR => Symbol::u8(ns::rcode::CFT_ERR),
    }
};

const NBNS_FLAGS: FuncDef = func!(
    /// Returns netbios-ns flags
    resynth fn flags(
        /// NetBIOS name service opcode
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
        /// Must be zero (maps to DNS AD bit)
        ad: Bool = false, // must be zero
        /// Broadcast/multicast flag
        b: Bool = false,
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
        let b: bool = args.next().into();
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
            .cd(b) // CD is called B in NBNS
            .rcode(rcode)
            .build())
        )
    }
);

const NB_FLAGS: FuncDef = func!(
    /// Build the NB_FLAGS field for an NB resource record RDATA (RFC 1002 §4.2.1.1).
    ///
    /// Flags layout (MSB first): G(1) ONT(2) reserved(13)
    ///
    /// ONT values: 0=B-node, 1=P-node, 2=M-node, 3=H-node.
    /// The default produces 0x0000: unique name, B-node.
    ///
    /// Pass `reserved:` with a non-zero value to exercise DPI engine behaviour on
    /// unexpected reserved-bit patterns.
    resynth fn nb_flags(
        =>
        /// Group name (true) or unique name (false)
        group: Bool = false,
        /// Owner Node Type: 0=B-node, 1=P-node, 2=M-node, 3=H-node
        ont: U8 = 0,
        /// Reserved bits (bits 12-0); normally zero
        reserved: U16 = 0,
        =>
        Void
    ) -> U16
    |mut args| {
        let group: bool    = args.next().into();
        let ont: u8        = args.next().into();
        let reserved: u16  = args.next().into();

        let flags: u16 = ((group as u16) << 15)
            | ((ont as u16 & 0x3) << 13)
            | reserved;

        Ok(Val::U16(flags))
    }
);

const NAME_FLAGS: FuncDef = func!(
    /// Build a name flags field for an NBSTAT name table entry (RFC 1002 §4.2.18).
    ///
    /// Flags layout (MSB first): G(1) ONT(2) DRG(1) CNF(1) ACT(1) PRM(1) reserved(9)
    ///
    /// ONT values: 0=B-node, 1=P-node, 2=M-node, 3=H-node.
    /// The default produces 0x0400: active, unique name, B-node.
    ///
    /// Pass `reserved:` with a non-zero value to exercise DPI engine behaviour on
    /// unexpected reserved-bit patterns.
    resynth fn name_flags(
        =>
        /// Owner Node Type: 0=B-node, 1=P-node, 2=M-node, 3=H-node
        ont: U8 = 0,
        /// Name is active
        active: Bool = true,
        /// Group name (true) or unique name (false)
        group: Bool = false,
        /// Name is in the process of being deregistered
        drg: Bool = false,
        /// Name is in conflict
        cnf: Bool = false,
        /// Permanent node name (not registered via NBNS)
        prm: Bool = false,
        /// Reserved bits (bits 8-0); normally zero
        reserved: U16 = 0,
        =>
        Void
    ) -> U16
    |mut args| {
        let ont: u8       = args.next().into();
        let active: bool  = args.next().into();
        let group: bool   = args.next().into();
        let drg: bool     = args.next().into();
        let cnf: bool     = args.next().into();
        let prm: bool     = args.next().into();
        let reserved: u16 = args.next().into();

        let flags: u16 = ((group  as u16) << 15)
            | ((ont    as u16 & 0x3) << 13)
            | ((drg    as u16) << 12)
            | ((cnf    as u16) << 11)
            | ((active as u16) << 10)
            | ((prm    as u16) <<  9)
            | reserved;

        Ok(Val::U16(flags))
    }
);

const NAME_ENTRY: FuncDef = func!(
    /// Build a single name table entry for an NBSTAT RDATA block.
    ///
    /// Pads the name to 15 bytes (space-filled), appends the one-byte suffix and
    /// two-byte flags. Each entry is exactly 18 bytes and is consumed by
    /// `netbios::ns::nbstat_rdata()`.
    ///
    /// The default suffix (0x00) is the workstation service. Common suffixes:
    /// 0x00 = workstation, 0x03 = messenger (logged-in user), 0x20 = file server.
    ///
    /// The default flags (0x0400) represent an active, unique, B-node name;
    /// use `netbios::ns::name_flags()` to construct non-default values.
    resynth fn name_entry(
        =>
        /// One-byte NetBIOS name suffix (service type)
        suffix: U8 = 0x00,
        /// Two-byte name flags field
        flags: U16 = 0x0400,
        =>
        Str
    ) -> Str
    |mut args| {
        let suffix: u8 = args.next().into();
        let flags: u16 = args.next().into();
        let data: Buf  = args.join_extra(b"").into();

        let padded = name::pad(data.as_ref(), suffix).ok_or_else(|| {
            Error::LibError(format!("netbios name too long: {} bytes (max 15)", data.len()).into())
        })?;

        let mut out = Vec::with_capacity(18);
        out.extend_from_slice(&padded); // 15-byte padded name + 1-byte suffix
        out.extend(flags.to_be_bytes());

        Ok(Val::str(out))
    }
);

const STATISTICS: FuncDef = func!(
    /// Build the 64-byte statistics block appended to every NBSTAT RDATA section.
    ///
    /// The block contains a 6-byte unit ID (MAC address) followed by 58 bytes of
    /// counters. Pass the MAC address as the collect argument; omit it to use all
    /// zeros.
    resynth fn statistics(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let mac: Buf = args.join_extra(b"").into();

        let mut stats = vec![0u8; 64];
        let mac = mac.as_ref();
        stats[..mac.len().min(6)].copy_from_slice(&mac[..mac.len().min(6)]);

        Ok(Val::str(stats))
    }
);

const NBSTAT_RDATA: FuncDef = func!(
    /// Build the complete RDATA section for an NBSTAT resource record.
    ///
    /// Accepts `netbios::ns::name_entry()` values as collect arguments, prepends
    /// the one-byte name count (derived from the total length), and appends a
    /// zeroed 64-byte statistics block.
    ///
    /// To include a MAC address in the statistics block, append
    /// `netbios::ns::statistics("|aa bb cc dd ee ff|")` manually and omit this
    /// function in favour of assembling the RDATA yourself.
    resynth fn nbstat_rdata(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let entries: Buf = args.join_extra(b"").into();
        let count = entries.len() / 18;

        let mut rdata = Vec::with_capacity(1 + entries.len() + 64);
        rdata.push(count as u8);
        rdata.extend(entries.as_ref());
        rdata.extend([0u8; 64]); // zeroed statistics block

        Ok(Val::str(rdata))
    }
);

pub const NS: Module = module! {
    /// # NetBIOS Name Service
    resynth mod ns {
        opcode     => Symbol::Module(&OPCODE),
        rrtype     => Symbol::Module(&RRTYPE),
        rcode      => Symbol::Module(&RCODE),
        flags      => Symbol::Func(&NBNS_FLAGS),
        nb_flags   => Symbol::Func(&NB_FLAGS),
        name_flags => Symbol::Func(&NAME_FLAGS),
        name_entry => Symbol::Func(&NAME_ENTRY),
        statistics => Symbol::Func(&STATISTICS),
        nbstat_rdata => Symbol::Func(&NBSTAT_RDATA),
    }
};

const NAME_ENCODE: FuncDef = func! (
    /// First-level encode a NetBIOS name, including padding and the one-byte suffix field.
    ///
    /// Returns the raw 32 encoded bytes only — no DNS label length prefix or
    /// terminating null byte. To produce a complete DNS-format name label
    /// suitable for use in an NBNS packet, wrap the result with `dns::name()`:
    ///
    /// ```resynth
    /// dns::name(netbios::name::encode("BILLG"))
    /// ```
    resynth fn encode(
        =>
        /// One-byte suffix identifying the NetBIOS name type
        suffix: U8 = 0,
        =>
        Str
    ) -> Str
    |mut args| {
        let suffix: u8 = args.next().into();
        let data: Buf = args.join_extra(b"").into();
        let res = name::encode(data.as_ref(), suffix).ok_or_else(|| {
            Error::LibError(format!("netbios name too long: {} bytes (max 15)", data.len()).into())
        })?;

        Ok(Val::Str(res.as_ref().into()))
    }
);

const SUFFIX: Module = module! {
    /// # NetBIOS name suffixes
    ///
    /// The one-byte suffix field identifies the service type registered under a
    /// NetBIOS name. These are the widely-used Microsoft values (see MS-NBTE).
    ///
    /// ## Unique names (registered per host)
    ///
    /// | Constant | Value | Service |
    /// |----------|-------|---------|
    /// | `WORKSTATION` | `0x00` | Workstation service (redirector) |
    /// | `MESSENGER` | `0x03` | Messenger service — identifies the logged-in user |
    /// | `RAS_SERVER` | `0x06` | Remote Access Server |
    /// | `DOMAIN_MASTER` | `0x1B` | Domain master browser |
    /// | `DOMAIN_CONTROLLER` | `0x1C` | Domain controller |
    /// | `MASTER_BROWSER` | `0x1D` | Local master browser |
    /// | `FILE_SERVER` | `0x20` | File and print server (Server service) |
    /// | `RAS_CLIENT` | `0x21` | Remote Access client |
    ///
    /// ## Group names (registered by multiple hosts)
    ///
    /// | Constant | Value | Service |
    /// |----------|-------|---------|
    /// | `DOMAIN_NAME` | `0x00` | Domain name (group) |
    /// | `BROWSER_ELECTIONS` | `0x1E` | Browser elections |
    resynth mod suffix {
        WORKSTATION       => Symbol::u8(0x00),
        MESSENGER         => Symbol::u8(0x03),
        RAS_SERVER        => Symbol::u8(0x06),
        DOMAIN_MASTER     => Symbol::u8(0x1B),
        DOMAIN_CONTROLLER => Symbol::u8(0x1C),
        MASTER_BROWSER    => Symbol::u8(0x1D),
        BROWSER_ELECTIONS => Symbol::u8(0x1E),
        FILE_SERVER       => Symbol::u8(0x20),
        RAS_CLIENT        => Symbol::u8(0x21),
    }
};

pub const NAME: Module = module! {
    /// # NetBIOS names
    resynth mod name {
        encode => Symbol::Func(&NAME_ENCODE),
        suffix => Symbol::Module(&SUFFIX),
    }
};

pub const NETBIOS: Module = module! {
    /// # Microsoft NetBIOS
    ///
    /// NetBIOS over TCP/IP — name encoding, name-service queries, and protocol constants.
    ///
    /// ## Wire format
    ///
    /// NetBIOS Name Service (NBNS, UDP port 137) uses the DNS wire format: the same
    /// 12-byte header, question, and resource record structures. Use the `dns` module
    /// helpers (`dns::hdr`, `dns::flags`, `dns::name`, `dns::answer`) to build the
    /// packet framing, and the `netbios` helpers for name encoding and NBNS-specific
    /// constants.
    ///
    /// ### Example: positive Name Query Response for "BILLG" (workstation)
    ///
    /// ```resynth
    /// import ipv4;
    /// import dns;
    /// import netbios;
    ///
    /// ipv4::udp::unicast(
    ///     192.168.1.100/137,
    ///     192.168.1.1/137,
    ///     dns::hdr(
    ///         0x1234,
    ///         netbios::ns::flags(netbios::ns::opcode::QUERY, response: true, aa: true, ra: true),
    ///         ancount: 1,
    ///     ),
    ///     dns::answer(
    ///         dns::name(netbios::name::encode("BILLG")),
    ///         atype: netbios::ns::rrtype::NB,
    ///         ttl: 300,
    ///         netbios::ns::nb_flags(),  # NB_FLAGS: B-node, unique (defaults)
    ///         192.168.1.100,           # NB_ADDRESS
    ///     ),
    /// );
    /// ```
    resynth mod netbios {
        ns => Symbol::Module(&NS),
        name => Symbol::Module(&NAME),
    }
};
