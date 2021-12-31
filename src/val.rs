use crate::libapi::FuncDef;
use crate::lex::{TokType, Token};
use crate::err::Error;
use crate::err::Error::{NameError, TypeError, ParseError};
use crate::pkt::Packet;
use crate::str::BytesObj;
use crate::object::ObjRef;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ValDef {
    Ip4(Ipv4Addr),
    Sock4(SocketAddrV4),
    U64(u64),
    Str(&'static [u8]),
}

#[allow(unused)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ValType {
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

#[allow(unused)]
#[derive(Debug, Clone)]
pub enum Val {
    Void,
    Ip4(Ipv4Addr),
    Sock4(SocketAddrV4),
    U64(u64),
    Str(BytesObj),
    Obj(ObjRef),
    Func(&'static FuncDef),
    Method(ObjRef, &'static FuncDef),
    Pkt(Rc<Packet>),
    PktGen(Rc<Vec<Packet>>),
}

impl Default for Val {
    fn default() -> Self {
        Val::Void
    }
}

impl From<&ValDef> for Val {
    fn from(valdef: &ValDef) -> Self {
        use ValDef::*;

        match valdef {
            Ip4(ip) => Val::Ip4(*ip),
            Sock4(sock) => Val::Sock4(*sock),
            U64(uint) => Val::U64(*uint),
            Str(s) => Val::Str(BytesObj::from(s)),
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

impl From<Val> for BytesObj {
    fn from(v: Val) -> Self {
        match v {
            Val::Str(s) => s,
            _ => unreachable!()
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
            HexIntegerLiteral => Ok(U64(v.parse().or(Err(ParseError))?)),
            _ => unreachable!()
        }
    }

    pub fn val_type(&self) -> ValType {
        use ValType::*;
        match self {
            Val::Void => Void,
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

    pub fn is_type(&self, typ: ValType) -> bool {
        self.val_type() == typ
    }

    pub fn is_nil(&self) -> bool {
        matches!(self, Val::Void)
    }

    pub fn method_lookup(&self, name: &str) -> Result<Self, Error> {
        let obj = match self {
            Val::Obj(val) => val,
            _ => {
                println!("no methods for non-object: {:?}", self.val_type());
                return Err(TypeError);
            }
        };

        match obj.cls.methods.get(name) {
            Some(fndef) => Ok(Val::Method(obj.clone(), fndef)),
            None => Err(NameError),
        }
    }
}
