use crate::lex::{TokType, Token};
use crate::err::Error;
use crate::err::Error::{NameError, TypeError, ParseError};
use crate::pkt::Packet;

use std::iter::FromIterator;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::fmt;
use std::str::FromStr;
use std::rc::Rc;
use std::cell::UnsafeCell;
use std::ops::Drop;
use std::vec;

#[cfg(debug_assertions)]
use std::alloc::Layout;

#[derive(Debug)]
pub struct ValDef {
    pub val: &'static [u8],
}

#[derive(Debug)]
pub struct FuncDef {
    pub name: &'static str,
    pub return_type: ValType,
    pub args: &'static [ValType],
    pub collect_type: ValType,
    pub exec: fn(args: Args) -> Result<Val, Error>,
}

#[derive(Debug)]
pub struct ClassDef {
    pub name: &'static str,
    pub methods: phf::Map<&'static str, FuncDef>,
}

pub type Module = phf::Map<&'static str, Symbol>;

#[derive(Debug)]
pub enum Symbol {
    Module(&'static Module),
    Func(FuncDef),
    Val(ValDef),
}

struct Opaque {
}

#[derive(Clone)]
pub struct ObjRef {
    pub cls: &'static ClassDef,
    rc: Rc<UnsafeCell<Opaque>>,

    /* This is very wasteful because it should really be part of the actual allocation but it's
     * just a sanity check
     */
    #[cfg(debug_assertions)]
    layout: Layout,
}

impl ObjRef {
    pub fn new<T>(cls: &'static ClassDef, inner: T) -> ObjRef {
        let x = Rc::new(UnsafeCell::new(inner));
        ObjRef {
            cls,
            rc: unsafe { Rc::from_raw(Rc::into_raw(x) as *const UnsafeCell<Opaque>) },
            #[cfg(debug_assertions)]
            layout: unsafe {
                Layout::from_size_align_unchecked(
                    ::std::mem::size_of::<T>(),
                    ::std::mem::align_of::<T>(),
                )
            },
        }
    }

    #[allow(unused)]
    pub unsafe fn get_obj<T>(obj: &Self) -> &T {
        #[cfg(debug_assertions)]
        debug_assert_eq!(
                Layout::from_size_align_unchecked(
                    ::std::mem::size_of::<T>(),
                    ::std::mem::align_of::<T>(),
                ),
                obj.layout
        );

        unsafe {
            let ptr = obj.rc.get();
            &*(ptr as *const T)
        }
    }

    #[allow(unused)]
    pub unsafe fn get_mut_obj<T>(obj: &mut Self) -> &mut T {
        #[cfg(debug_assertions)]
        debug_assert_eq!(
                Layout::from_size_align_unchecked(
                    ::std::mem::size_of::<T>(),
                    ::std::mem::align_of::<T>(),
                ),
                obj.layout
        );

        unsafe {
            let ptr: *mut Opaque = obj.rc.get();
            &mut *(ptr as *mut T)
        }
    }
}

impl From<Val> for ObjRef {
    fn from(val: Val) -> Self {
        match val {
            Val::Obj(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl fmt::Debug for ObjRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("Class<{}>", self.cls.name))
    }
}

#[derive(Clone)]
pub struct BytesObj {
    inner: Rc<Vec<u8>>,
}

impl AsRef<[u8]> for BytesObj {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl BytesObj {
    pub fn new(mut s: Vec<u8>) -> Self {
        s.shrink_to_fit();
        Self {
            inner: Rc::new(s),
        }
    }

    pub fn from(s: &[u8]) -> Self {
        Self {
            inner: Rc::new(s.to_owned()),
        }
    }
}

impl fmt::Debug for BytesObj {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /* TODO: allow printing of hex crap, data here does not have to be utf-8, and printing it
         * like this could panic.
         */
        let s = std::str::from_utf8(self.inner.as_ref()).unwrap();
        f.write_fmt(format_args!("Bytes<{:?}>", s))
    }
}

pub struct StringLiteralParseError {
}

fn hex_decode(chr: char) -> u8 {
    debug_assert!(chr.is_ascii_hexdigit());
    let c = chr as u8;
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => unreachable!()
    }
}

impl FromStr for BytesObj {
    type Err = StringLiteralParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = &s[1..s.len() - 1];
        let mut hex = false;
        let mut v: Vec<u8> = Vec::new();
        let mut h: [u8; 2] = [0, 0];
        let mut ix: usize = 0;

        for chr in inner.chars() {
            if !hex {
                if chr == '|' {
                    hex = true;
                    ix = 0;
                    continue;
                }
                v.push(chr as u8);
            }else{
                if chr.is_whitespace() {
                    continue;
                }

                if chr == '|' {
                    if ix != 0 {
                        /* Odd number of hex digits */
                        return Err(Self::Err {});
                    }

                    hex = false;
                    continue;
                }

                if !chr.is_ascii_hexdigit() {
                    /* Non-hex in hex sequence */
                    return Err(Self::Err {});
                }

                h[ix] = hex_decode(chr);
                ix += 1;
                if ix == 2 {
                    v.push((h[0] << 4) | h[1]);
                    ix = 0;
                }
            }
        }

        Ok(BytesObj::new(v))
    }
}

#[allow(unused)]
#[derive(Debug, PartialEq)]
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

impl From<&ValDef> for Val {
    fn from(valdef: &ValDef) -> Self {
        Val::Str(BytesObj::from(valdef.val))
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

pub struct Args {
    it: vec::IntoIter<Val>,
    extra_args: vec::IntoIter<Val>,
}

impl Args {
    pub fn from(args: Vec<Val>, extra_args: Vec<Val>) -> Self {
        Self {
            it: args.into_iter(),
            extra_args: extra_args.into_iter(),
        }
    }

    pub fn take(&mut self) -> Val {
        self.it.next().unwrap()
    }

    pub fn extra_args(&mut self) -> vec::IntoIter<Val> {
        std::mem::replace(&mut self.extra_args, Vec::new().into_iter())
    }

    // Collect all extra args into a vec of the given type
    pub fn collect_extra_args<T>(&mut self) -> Vec<T> where T: From<Val> {
        Vec::from_iter(self.extra_args().map(|x| -> T { x.into() } ))
    }

    /// Dumps all remaining, untaken args
    pub fn void(&mut self) {
        loop {
            if self.it.next().is_none() {
                break;
            }
        }
        loop {
            if self.extra_args.next().is_none() {
                break;
            }
        }
    }
}

impl Drop for Args {
    fn drop(&mut self) {
        assert!(self.it.next().is_none());
        assert!(self.extra_args.next().is_none());
    }
}
