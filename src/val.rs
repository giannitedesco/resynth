use crate::libapi::{Obj, FuncDef, Dispatchable, Symbol};
use crate::lex::{TokType, Token};
use crate::err::Error;
use crate::err::Error::{NameError, TypeError, ParseError};
use crate::pkt::Packet;
use crate::str::Buf;
use crate::object::ObjRef;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum ValType {
    Void,
    Ip4,
    Sock4,
    U64,
    Str,
    Obj,
    Func,
    Method,
    Pkt,
    PktGen,
}

pub(crate) trait Typed {
    fn val_type(&self) -> ValType;

    fn is_type(&self, typ: ValType) -> bool {
        self.val_type() == typ
    }

    fn is_nil(&self) -> bool {
        self.is_type(ValType::Void)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(unused)]
pub(crate) enum ValDef {
    Nil,
    Ip4(Ipv4Addr),
    Sock4(SocketAddrV4),
    U64(u64),
    Str(&'static [u8]),
}

impl Typed for ValDef {
    fn val_type(&self) -> ValType {
        use ValType::*;
        match self {
            ValDef::Nil => Void,
            ValDef::Ip4(..) => Ip4,
            ValDef::Sock4(..) => Sock4,
            ValDef::U64(..) => U64,
            ValDef::Str(..) => Str,
        }
    }
}

impl From<Ipv4Addr> for ValDef {
    fn from(val: Ipv4Addr) -> Self {
        Self::Ip4(val)
    }
}

impl From<SocketAddrV4> for ValDef {
    fn from(val: SocketAddrV4) -> Self {
        Self::Sock4(val)
    }
}

impl From<u64> for ValDef {
    fn from(val: u64) -> Self {
        Self::U64(val)
    }
}

impl<T> From<&'static T> for ValDef where T: AsRef<[u8]> + ? Sized {
    fn from(s: &'static T) -> Self {
        Self::Str(s.as_ref())
    }
}

#[allow(unused)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Val {
    Nil,
    Ip4(Ipv4Addr),
    Sock4(SocketAddrV4),
    U64(u64),
    Str(Buf),
    Obj(ObjRef),
    Func(&'static FuncDef),
    Method(ObjRef, &'static FuncDef),
    Pkt(Rc<Packet>),
    PktGen(Rc<Vec<Packet>>),
}

impl Default for Val {
    fn default() -> Self {
        Val::Nil
    }
}

impl From<ValDef> for Val {
    fn from(valdef: ValDef) -> Self {
        use ValDef::*;

        match valdef {
            Nil => Val::Nil,
            Ip4(ip) => Val::Ip4(ip),
            Sock4(sock) => Val::Sock4(sock),
            U64(uint) => Val::U64(uint),
            Str(s) => Val::Str(Buf::from(s)),
        }
    }
}

impl From<&'static FuncDef> for Val {
    fn from(fndef: &'static FuncDef) -> Self {
        Val::Func(fndef)
    }
}

impl From<SocketAddrV4> for Val {
    fn from(sock: SocketAddrV4) -> Self {
        Val::Sock4(sock)
    }
}

impl From<Val> for u64 {
    fn from(v: Val) -> Self {
        match v {
            Val::U64(u) => u,
            _ => unreachable!()
        }
    }
}

impl From<Val> for SocketAddrV4 {
    fn from(v: Val) -> Self {
        match v {
            Val::Sock4(s) => s,
            _ => unreachable!()
        }
    }
}

impl From<Val> for Ipv4Addr {
    fn from(v: Val) -> Self {
        match v {
            Val::Ip4(a) => a,
            _ => unreachable!()
        }
    }
}

impl From<Val> for Buf {
    fn from(v: Val) -> Self {
        match v {
            Val::Str(s) => s,
            _ => unreachable!()
        }
    }
}

impl<T: 'static + Obj> From<T> for Val {
    fn from(obj: T) -> Self {
        Val::Obj(ObjRef::from(obj))
    }
}

impl Typed for Val {
    fn val_type(&self) -> ValType {
        use ValType::*;
        match self {
            Val::Nil => Void,
            Val::Ip4(..) => Ip4,
            Val::Sock4(..) => Sock4,
            Val::U64(..) => U64,
            Val::Str(..) => Str,
            Val::Obj(..) => Obj,
            Val::Func(..) => Func,
            Val::Method(..) => Method,
            Val::Pkt(..) => Pkt,
            Val::PktGen(..) => PktGen,
        }
    }
}

impl Val {
    pub fn from_token(tok: Token) -> Result<Self, Error> {
        use Val::*;
        use TokType::*;
        let v = tok.val.unwrap();
        match tok.typ {
            StringLiteral => Ok(Str(v.parse().or(Err(ParseError))?)),
            IPv4Literal => Ok(Ip4(v.parse().or(Err(ParseError))?)),
            IntegerLiteral => Ok(U64(v.parse().or(Err(ParseError))?)),
            HexIntegerLiteral => {
                let hex = v.strip_prefix("0x").unwrap();

                // XXX: This looks horrendously inefficient
                let val: u64 = u64::from_str_radix(hex, 16).or(Err(ParseError))?;

                Ok(U64(val))
            },
            _ => unreachable!()
        }
    }

    pub fn method_lookup(&self, name: &str) -> Result<Self, Error> {
		let obj = match self {
			Val::Obj(obj) => obj,
			_ => {
                println!("no methods for non-object: {:?}", self.val_type());
                return Err(TypeError);
            }
		};

        let sym = obj.lookup_symbol(name).ok_or(NameError)?;

        match sym {
            Symbol::Func(fndef) => Ok(Val::Method(obj.clone(), fndef)),
            _ => {
                println!("calling non-func symbol: {}: {:?}", name, sym);
                Err(TypeError)
            }
        }
    }

    #[allow(dead_code)]
    pub fn lookup_symbol(&self, name: &str) -> Result<Symbol, Error> {
		match self {
			Val::Obj(obj) => obj.lookup_symbol(name).ok_or(NameError),
			_ => {
                println!("no symbols for non-object: {:?}", self.val_type());
                Err(TypeError)
            }
		}
	}
}
