use crate::libapi::FuncDef;
use crate::sym::Symbol;
use crate::lex::{TokType, Token};
use crate::err::Error;
use crate::err::Error::{NameError, TypeError, ParseError};
use crate::str::Buf;
use crate::object::{Obj, ObjRef};
use crate::traits::Dispatchable;

use pkt::Packet;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;

/// All resynth values must be one of the following types
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ValType {
    Void,
    Bool,
    U8,
    U16,
    U32,
    U64,
    Ip4,
    Sock4,
    Str,
    Type,

    Obj,
    Func,
    Method,
    Pkt,
    PktGen,
}

/// Both [Val] and [ValDef] have types which corrsepond to each other. In fact [Val] is a subset of
/// the types allowed in [Val] since a [ValDef] must support static or constant epressions.
pub trait Typed {
    // Return the corresponding [ValType] for this value
    fn val_type(&self) -> ValType;

    // Check if the value is of the given [ValType]
    fn is_type(&self, typ: ValType) -> bool {
        self.val_type() == typ
    }

    // Check if the value is nil, by testing if it is of type [ValType::Void]
    fn is_nil(&self) -> bool {
        self.is_type(ValType::Void)
    }

    fn is_str(&self) -> bool {
        self.is_type(ValType::Str)
    }

    fn is_integral(&self) -> bool {
        matches!(self.val_type(),
            | ValType::Bool
            | ValType::U8
            | ValType::U16
            | ValType::U32
            | ValType::U64
        )
    }

    fn type_matches<T: Typed>(&self, other: &T) -> bool {
        self.is_type(other.val_type())
    }

    fn is_string_coercible(&self) -> bool {
        matches!(self.val_type(),
            ValType::Str
            | ValType::U8
            | ValType::U16
            | ValType::U32
            | ValType::U64
            | ValType::Ip4
        )
    }

    fn compatible_with<T: Typed>(&self, other: &T) -> bool {
        self.type_matches(other)
            || self.is_integral() && other.is_integral()
            || (self.is_str() && other.is_string_coercible())
    }
}

impl Typed for ValType {
    fn val_type(&self) -> ValType {
        *self
    }
}

/// Represents a static or const version of [Val]. This is used when defining constants in the
/// stdlib, or when defining default arguments for functions.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ValDef {
    Nil,
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Ip4(Ipv4Addr),
    Sock4(SocketAddrV4),
    Str(&'static [u8]),
    Type(ValType),
}

impl ValDef {
    pub fn arg_compatible<T: Typed>(&self, other: &T) -> bool {
        match self {
            ValDef::Type(t) => other.is_nil() || t.compatible_with(other),
            _ => self.compatible_with(other),
        }
    }
}

impl Typed for ValDef {
    fn val_type(&self) -> ValType {
        use ValType::*;
        match self {
            ValDef::Nil => Void,
            ValDef::Bool(..) => Bool,
            ValDef::U8(..) => U8,
            ValDef::U16(..) => U16,
            ValDef::U32(..) => U32,
            ValDef::U64(..) => U64,
            ValDef::Ip4(..) => Ip4,
            ValDef::Sock4(..) => Sock4,
            ValDef::Str(..) => Str,
            ValDef::Type(..) => Type,
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

impl From<bool> for ValDef {
    fn from(val: bool) -> Self {
        Self::Bool(val)
    }
}

impl From<u64> for ValDef {
    fn from(val: u64) -> Self {
        Self::U64(val)
    }
}

/*
impl From<u32> for ValDef {
    fn from(val: u32) -> Self {
        Self::U64(val as u64)
    }
}

impl From<u16> for ValDef {
    fn from(val: u16) -> Self {
        Self::U64(val as u64)
    }
}

impl From<u8> for ValDef {
    fn from(val: u8) -> Self {
        Self::U64(val as u64)
    }
}
*/

impl<T> From<&'static T> for ValDef where T: AsRef<[u8]> + ? Sized {
    fn from(s: &'static T) -> Self {
        Self::Str(s.as_ref())
    }
}

/// Represents a live value in the interpreter, for example the result of evaluating an expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Val {
    Nil,
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Ip4(Ipv4Addr),
    Sock4(SocketAddrV4),
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
            Bool(b) => Val::Bool(b),
            U8(uint) => Val::U8(uint),
            U16(uint) => Val::U16(uint),
            U32(uint) => Val::U32(uint),
            U64(uint) => Val::U64(uint),
            Ip4(ip) => Val::Ip4(ip),
            Sock4(sock) => Val::Sock4(sock),
            Str(s) => Val::Str(Buf::from(s)),
            Type(_) => Val::Nil,
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

impl From<bool> for Val {
    fn from(v: bool) -> Self {
        Val::Bool(v)
    }
}

impl From<u64> for Val {
    fn from(v: u64) -> Self {
        Val::U64(v)
    }
}

impl From<u32> for Val {
    fn from(v: u32) -> Self {
        Val::U64(v as u64)
    }
}

impl From<u16> for Val {
    fn from(v: u16) -> Self {
        Val::U64(v as u64)
    }
}

impl From<u8> for Val {
    fn from(v: u8) -> Self {
        Val::U64(v as u64)
    }
}

impl From<Val> for bool {
    fn from(v: Val) -> Self {
        match v {
            Val::Bool(b) => b,
            Val::U8(u) => u != 0,
            Val::U16(u) => u != 0,
            Val::U32(u) => u != 0,
            Val::U64(u) => u != 0,
            _ => unreachable!()
        }
    }
}

impl From<Val> for u64 {
    fn from(v: Val) -> Self {
        match v {
            Val::U8(u) => u as u64,
            Val::U16(u) => u as u64,
            Val::U32(u) => u as u64,
            Val::U64(u) => u,
            _ => unreachable!()
        }
    }
}

impl From<Val> for u32 {
    fn from(v: Val) -> Self {
        match v {
            Val::U8(u) => u as u32,
            Val::U16(u) => u as u32,
            Val::U32(u) => u,
            Val::U64(u) => u as u32,
            _ => unreachable!()
        }
    }
}

impl From<Val> for u16 {
    fn from(v: Val) -> Self {
        match v {
            Val::U8(u) => u as u16,
            Val::U16(u) => u,
            Val::U32(u) => u as u16,
            Val::U64(u) => u as u16,
            _ => unreachable!()
        }
    }
}

impl From<Val> for u8 {
    fn from(v: Val) -> Self {
        match v {
            Val::U8(u) => u,
            Val::U16(u) => u as u8,
            Val::U32(u) => u as u8,
            Val::U64(u) => u as u8,
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
        /* Must be implemented for all types which are Typed::is_string_coercible() */
        match v {
            Val::Str(s) => s,
            Val::U8(u) => Buf::from(&u.to_be_bytes()),
            Val::U16(u) => Buf::from(&u.to_be_bytes()),
            Val::U32(u) => Buf::from(&u.to_be_bytes()),
            Val::U64(u) => Buf::from(&u.to_be_bytes()),
            Val::Ip4(ip) => Buf::from(&u32::from(ip).to_be_bytes()),
            _ => unreachable!()
        }
    }
}

impl From<Val> for Rc<Vec<Packet>> {
    fn from(v: Val) -> Self {
        match v {
            Val::PktGen(g) => g,
            _ => unreachable!()
        }
    }
}

impl From<Val> for Rc<Packet> {
    fn from(v: Val) -> Self {
        match v {
            Val::Pkt(p) => p,
            _ => unreachable!()
        }
    }
}

impl From<Val> for Option<Ipv4Addr> {
    fn from(v: Val) -> Self {
        match v {
            Val::Nil => None,
            Val::Ip4(ip) => Some(ip),
            _ => unreachable!()
        }
    }
}

impl From<Val> for Option<u64> {
    fn from(v: Val) -> Self {
        match v {
            Val::Nil => None,
            _ => Some(u64::from(v)),
        }
    }
}

impl From<Val> for Option<u32> {
    fn from(v: Val) -> Self {
        match v {
            Val::Nil => None,
            _ => Some(u32::from(v)),
        }
    }
}

impl From<Val> for Option<u16> {
    fn from(v: Val) -> Self {
        match v {
            Val::Nil => None,
            _ => Some(u16::from(v)),
        }
    }
}

impl From<Val> for Option<u8> {
    fn from(v: Val) -> Self {
        match v {
            Val::Nil => None,
            _ => Some(u8::from(v)),
        }
    }
}

impl From<Val> for Option<Buf> {
    fn from(v: Val) -> Self {
        match v {
            Val::Nil => None,
            Val::Str(s) => Some(s),
            _ => unreachable!()
        }
    }
}

impl<T: 'static + Obj> From<T> for Val {
    fn from(obj: T) -> Self {
        Val::Obj(ObjRef::from(obj))
    }
}

impl AsRef<[u8]> for Val {
    fn as_ref(&self) -> &[u8] {
        match self {
            Val::Str(s) => s.as_ref(),
            _ => unreachable!()
        }
    }
}

impl Typed for Val {
    fn val_type(&self) -> ValType {
        use ValType::*;
        match self {
            Val::Nil => Void,
            Val::Bool(..) => Bool,
            Val::U8(..) => U8,
            Val::U16(..) => U16,
            Val::U32(..) => U32,
            Val::U64(..) => U64,
            Val::Ip4(..) => Ip4,
            Val::Sock4(..) => Sock4,
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
    pub fn from_token(tok: &Token) -> Result<Self, Error> {
        use Val::*;
        use TokType::*;
        let v = tok.val();
        match tok.tok_type() {
            StringLiteral => Ok(Str(v.parse().or(Err(ParseError))?)),
            IPv4Literal => Ok(Ip4(v.parse().or(Err(ParseError))?)),
            IntegerLiteral => Ok(U64(v.parse().or(Err(ParseError))?)),
            BooleanLiteral => Ok(Bool(v.parse().or(Err(ParseError))?)),
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

impl From<Packet> for Buf {
    fn from(pkt: Packet) -> Self {
        Self::from(pkt.as_ref())
    }
}

impl From<Packet> for Val {
    fn from(pkt: Packet) -> Self {
        Self::Pkt(pkt.into())
    }
}

impl From<Vec<Packet>> for Val {
    fn from(pkts: Vec<Packet>) -> Self {
        Self::PktGen(pkts.into())
    }
}
