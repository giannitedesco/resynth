use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::object::ObjRef;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

#[derive(Debug, PartialEq, Eq)]
struct Tcp {
    pub cl_seq: u32,
    pub sv_seq: u32,
}

static TCP: ClassDef = class!(
    /// TCP Session
    resynth class Tcp {
        client_message => Symbol::Val(ValDef::U64(1)),
        server_message => Symbol::Val(ValDef::U64(2)),
    }
);

impl Class for Tcp {
    fn def(&self) -> &'static ClassDef {
        &TCP
    }
}

impl Tcp {
    pub(self) fn new(cl_seq: u32, sv_seq: u32) -> Self {
        Self { cl_seq, sv_seq }
    }
}

static TCP_NEW: FuncDef = func!(
    /// A TCP session
    resynth fn tcp(
        =>
        =>
        Void
    ) -> Class(&TCP)
    |_args| {
        Ok(Val::from(Tcp::new(0, 0)))
    }
);

/// A root module to check programs against, for a class with constant properties.
/// `import obj;` finds the test classes.
pub(super) static ROOT: Module = module!(
    /// Test root
    resynth mod root {
        obj => Symbol::Module(&OBJ),
    }
);

const OBJ: Module = module!(
    /// Test objects
    resynth mod obj {
        Tcp => Symbol::Class(&TCP),
        tcp => Symbol::Func(&TCP_NEW),
    }
);

#[derive(Debug, PartialEq, Eq)]
struct Udp {}

static UDP: ClassDef = class!(
    /// UDP Session
    resynth class Udp {
        client_dgram => Symbol::Val(ValDef::U64(1)),
        server_dgram => Symbol::Val(ValDef::U64(2)),
    }
);

impl Class for Udp {
    fn def(&self) -> &'static ClassDef {
        &UDP
    }
}

impl Udp {
    pub(self) fn new() -> Self {
        Self {}
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
    let a = ObjRef::from(Tcp::new(123, 456));
    assert_eq!(
        a.borrow().get("client_message"),
        Some(&Symbol::Val(ValDef::from(1)))
    );
}

#[test]
fn method_lookup_fail() {
    let a = ObjRef::from(Tcp::new(123, 456));
    assert_eq!(a.borrow().get("client_massage"), None);
}

#[test]
fn downcast() {
    let a = ObjRef::from(Tcp::new(123, 456));
    let obj_ref = a.borrow();
    let b: &Tcp = obj_ref.as_any().downcast_ref().unwrap();

    assert_eq!(&Tcp::new(123, 456), b);
}

#[test]
fn mut_downcast() {
    let a = ObjRef::from(Tcp::new(123, 456));
    let mut obj_ref = a.borrow_mut();
    let b: &mut Tcp = obj_ref.as_mut_any().downcast_mut().unwrap();

    b.cl_seq = 111;
    b.sv_seq = 222;

    assert_eq!(Tcp::new(111, 222), *b);
}
