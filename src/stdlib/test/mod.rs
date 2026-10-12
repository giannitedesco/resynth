use bytemuck::{Pod, pod_read_unaligned};
use pkt::eth::{eth_hdr, ethertype};
use pkt::ipv4::ip_hdr;

use crate::args::Args;

use crate::libapi::{ArgDecl, FuncDef};
use crate::object::ObjRef;
use crate::program::RuntimeErrorKind;
use crate::stdlib::toplevel_module;
use crate::sym::Symbol;
use crate::val::Val;

mod arp;
mod dhcp;
mod dns;
mod ipv4;
mod netbios;
mod std_fns;
mod tls;

/// The symbol at `path`, such as `"dns::rtype::A"`
fn sym(path: &str) -> Symbol {
    let mut segs = path.split("::");
    let top = segs.next().expect("empty path");
    let mut sym = Symbol::Module(toplevel_module(top).unwrap_or_else(|| panic!("no module {top}")));
    for seg in segs {
        let Symbol::Module(module) = sym else {
            panic!("{path}: {seg} is not in a module");
        };
        sym = *module
            .get(seg)
            .unwrap_or_else(|| panic!("{path}: no {seg}"));
    }
    sym
}

/// The constant at `path`, as a value
fn constant(path: &str) -> Val {
    match sym(path) {
        Symbol::Val(def) => def.into(),
        sym => panic!("{path} is not a constant: {sym:?}"),
    }
}

/// A call to a stdlib function or method, built up one argument at a time. Parameters that
/// aren't given take their defaults, as a resynth call would.
struct Call {
    func: &'static FuncDef,
    this: Option<ObjRef>,
    args: Vec<Option<Val>>,
    extra: Vec<Val>,
}

impl Call {
    /// The function at `path`, such as `"dns::name"`
    fn func(path: &str) -> Self {
        match sym(path) {
            Symbol::Func(func) => Self::new(func, None),
            sym => panic!("{path} is not a function: {sym:?}"),
        }
    }

    /// The method `name` of `obj`, which must be an object
    fn method(obj: &Val, name: &str) -> Self {
        let Val::Obj(obj) = obj else {
            panic!("{obj:?} is not an object");
        };
        let sym = obj.borrow().get(name).copied();
        match sym {
            Some(Symbol::Func(func)) => Self::new(func, Some(obj.clone())),
            sym => panic!("{name} is not a method: {sym:?}"),
        }
    }

    fn new(func: &'static FuncDef, this: Option<ObjRef>) -> Self {
        Self {
            func,
            this,
            args: vec![None; func.args.len()],
            extra: Vec::new(),
        }
    }

    /// The next parameter that hasn't been given yet
    fn arg(mut self, val: impl Into<Val>) -> Self {
        let slot = self
            .args
            .iter_mut()
            .find(|slot| slot.is_none())
            .unwrap_or_else(|| panic!("{}: too many arguments", self.func.name));
        *slot = Some(val.into());
        self
    }

    /// The parameter called `name`
    fn named(mut self, name: &str, val: impl Into<Val>) -> Self {
        let pos = (self.func.arg_pos)(name)
            .unwrap_or_else(|| panic!("{}: no parameter {name}", self.func.name));
        self.args[pos] = Some(val.into());
        self
    }

    /// A collect argument
    fn extra(mut self, val: impl Into<Val>) -> Self {
        self.extra.push(val.into());
        self
    }

    fn exec(self) -> Result<Val, RuntimeErrorKind> {
        let Self {
            func,
            this,
            args,
            extra,
        } = self;
        let args = args
            .into_iter()
            .zip(func.args)
            .map(|(val, desc)| match (val, desc.typ) {
                (Some(val), _) => val,
                (None, ArgDecl::Optional(def)) => def.into(),
                (None, ArgDecl::Positional(_)) => {
                    panic!("{}: missing argument {}", func.name, desc.name)
                }
            })
            .collect();
        (func.exec)(Args::new(this, args, extra))
    }

    /// The call's result, which must be a string
    fn bytes(self) -> Vec<u8> {
        match self.exec().expect("call failed") {
            Val::Str(buf) => buf.as_ref().to_vec(),
            val => panic!("expected a string, got {val:?}"),
        }
    }

    /// Each packet the call produces
    fn frames(self) -> Vec<Frame> {
        match self.exec().expect("call failed") {
            Val::Pkt(pkt) => vec![Frame(pkt.to_vec())],
            Val::PktGen(pkts) => pkts.iter().map(|pkt| Frame(pkt.to_vec())).collect(),
            val => panic!("expected packets, got {val:?}"),
        }
    }
}

/// A string value
fn s(bytes: impl AsRef<[u8]>) -> Val {
    Val::str(bytes.as_ref())
}

/// A header of type `T` at the start of `bytes`
fn hdr<T: Pod>(bytes: &[u8]) -> T {
    pod_read_unaligned(&bytes[..std::mem::size_of::<T>()])
}

/// An Ethernet frame holding an IPv4 datagram, read back through pkt's headers
struct Frame(Vec<u8>);

impl Frame {
    const IP_OFF: usize = std::mem::size_of::<eth_hdr>();

    fn eth(&self) -> eth_hdr {
        hdr(&self.0)
    }

    fn ip(&self) -> ip_hdr {
        assert_eq!(self.eth().get_proto(), ethertype::IPV4);
        hdr(&self.0[Self::IP_OFF..])
    }

    /// Everything after the IP header and any options, up to the IP total length
    fn ip_payload(&self) -> &[u8] {
        let ip = self.ip();
        let start = Self::IP_OFF + ((ip.get_ihl_version() & 0xf) as usize) * 4;

        &self.0[start..Self::IP_OFF + ip.get_tot_len() as usize]
    }

    /// The header of type `T` at `off` bytes into the IP payload
    fn l4<T: Pod>(&self, off: usize) -> T {
        hdr(&self.ip_payload()[off..])
    }
}
