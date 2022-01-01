use crate::err::Error::{NameError, TypeError};
use crate::val::{Val, ValDef};
use crate::object::ObjRef;
use crate::libapi::{Class, Symbol};

use phf::phf_map;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Tcp {
    pub cl_seq: u32,
    pub sv_seq: u32,
}

impl Class for Tcp {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "client_message" => Symbol::Val(ValDef::U64(1)),
            "server_message" => Symbol::Val(ValDef::U64(2)),
        }
    }

    fn class_name(&self) -> &'static str {
        "Tcp"
    }
}

impl Tcp {
    pub(crate) fn new(cl_seq: u32, sv_seq: u32) -> Self {
        Self {
            cl_seq,
            sv_seq,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Udp {
}

impl Class for Udp {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "client_dgram" => Symbol::Val(ValDef::U64(1)),
            "server_dgram" => Symbol::Val(ValDef::U64(2)),
        }
    }

    fn class_name(&self) -> &'static str {
        "Udp"
    }
}

impl Udp {
    pub(crate) fn new() -> Self {
        Self {
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

#[test]
fn obj_eq() {
    let a = Val::from(Tcp::new(123, 456));
    let b = Val::from(Tcp::new(123, 456));
    assert_eq!(a, b);
}

#[test]
fn obj_neq_nil() {
    let a = Val::from(Tcp::new(123, 456));
    let b = Val::Nil;
    assert!(a != b);
}

#[test]
fn obj_neq() {
    let a = Val::from(Tcp::new(123, 456));
    let b = Val::from(Tcp::new(123, 455));
    assert!(a != b);
}

#[test]
fn obj_neq_type() {
    let a = Val::from(Tcp::new(123, 456));
    let b = Val::from(Udp::new());
    assert!(a != b);
}

#[test]
fn method_lookup() {
    let a = Val::from(Tcp::new(123, 456));
    assert_eq!(a.lookup_symbol("client_message"), Ok(Symbol::Val(ValDef::from(1))));
}

#[test]
fn method_lookup_fail() {
    let a = Val::from(Tcp::new(123, 456));
    assert_eq!(a.lookup_symbol("client_massage"), Err(NameError));
}

#[test]
fn method_lookup_nil() {
    let a = Val::Nil;
    assert_eq!(a.lookup_symbol("client_massage"), Err(TypeError));
}

#[test]
fn downcast() {
    let a = ObjRef::from(Tcp::new(123, 456));
    let obj_ref = a.borrow();
    let b: &Tcp = obj_ref.as_any().downcast_ref().unwrap();

    assert_eq!( &Tcp::new(123, 456), b);
}

#[test]
fn mut_downcast() {
    let a = ObjRef::from(Tcp::new(123, 456));
    let mut obj_ref = a.borrow_mut();
    let b: &mut Tcp = obj_ref.as_mut_any().downcast_mut().unwrap();

    b.cl_seq = 111;
    b.sv_seq = 222;

    assert_eq!( Tcp::new(111, 222), *b);
}
