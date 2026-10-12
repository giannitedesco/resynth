//! The high-level intermediate representation: a checked program, ready to run.
//!
//! The checker lowers the AST into a [Program]. In the HIR:
//! - Names are resolved. A local is a [slot](SlotId), and a module path is a [constant](Const).
//! - Calls are bound. Each argument is tagged with its parameter's slot, and each parameter that
//!   wasn't given holds its default.
//! - Each expression statement says what it does: [emit](StmtKind::Emit) packets,
//!   [wait](StmtKind::Wait), or evaluate and [discard](StmtKind::Discard) its value.
//!
//! Every node carries a [location](Loc). A call's location is its called name.
//!
//! Each node displays as an S-expression, for tests and debugging.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use derive_more::{Display, From};

use crate::ast::Lit;
use crate::libapi::FuncDef;
use crate::loc::Loc;
use crate::str::{Buf, Literal};

/// A checked program: its statements, and the layout of the one frame they run in. It displays
/// one statement per line.
#[derive(Debug)]
pub struct Program {
    pub(crate) stmts: Box<[Stmt]>,
    /// The name bound to each slot, indexed by [SlotId]
    pub(crate) slots: Box<[Box<str>]>,
}

/// A local's place in its frame
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq)]
#[display("${_0}")]
pub struct SlotId(pub(crate) usize);

#[derive(Debug, Display)]
#[display("{kind}")]
pub struct Stmt {
    /// The statement's first token
    pub loc: Loc,
    pub kind: StmtKind,
}

#[derive(Debug, Display)]
pub enum StmtKind {
    /// Bind a value to a new slot
    #[display("(let {slot} {value})")]
    Let { slot: SlotId, value: Expr },
    /// Write a packet, or each packet of a sequence
    #[display("(emit {_0})")]
    Emit(Expr),
    /// Advance the clock
    #[display("(wait {_0})")]
    Wait(Expr),
    /// Evaluate an expression for its side effects
    #[display("(eval {_0})")]
    Eval(Expr),
    /// Evaluate an expression for its side effects, and drop its value
    #[display("(discard {_0})")]
    Discard(Expr),
}

#[derive(Debug, Display)]
#[display("{kind}")]
pub struct Expr {
    /// Where the expression starts, or for a call, its called name
    pub loc: Loc,
    pub kind: ExprKind,
}

#[derive(Debug, Display)]
pub enum ExprKind {
    Const(Const),
    Local(SlotId),
    /// A method of the object `obj` evaluates to, bound to that object
    #[display("(. {obj} {})", func.name)]
    Method {
        obj: Box<Expr>,
        func: &'static FuncDef,
    },
    /// Evaluate each of `effects` in order for its side effects and drop its value, then
    /// evaluate `value`, which is the sequence's value. The checker makes these, so a dropped
    /// value is not a discarded statement: it gives no warning and no [discard](StmtKind::Discard)
    /// effect.
    ///
    /// A property, `f().prop`, lowers to `(seq (call f) <prop>)`. The property is its class's
    /// constant, but `f` must still be called, since nothing in the language lets a call be
    /// skipped.
    #[display("(seq {} {value})", Spaced(effects))]
    Seq {
        effects: Box<[Expr]>,
        value: Box<Expr>,
    },
    Call(Box<Call>),
    /// `ip / port`
    #[display("(/ {ip} {port})")]
    SockAddr {
        ip: Box<Expr>,
        port: Box<Expr>,
    },
}

/// A call whose arguments have been bound to its callee's parameters. Each argument displays
/// with its parameter's name, then the collect arguments follow.
#[derive(Debug)]
pub struct Call {
    /// Evaluates to [func](Self::func), or to a method bound to an object
    pub(crate) callee: Expr,
    /// The function the callee evaluates to, which the arguments were bound against
    pub(crate) func: &'static FuncDef,
    /// One argument per parameter, with its parameter's index. Arguments written in the source
    /// come first, in source order, then the defaults of the rest, in parameter order.
    pub(crate) args: Box<[(Expr, usize)]>,
    /// The collect arguments, in source order
    pub(crate) collect: Box<[Expr]>,
}

/// A value known before the program runs. Each constant displays its width: `u16:0x50`,
/// `func:be16`. A `bool`, an address or bytes displays as the AST printer shows its literal.
#[derive(Debug, Clone, PartialEq, Eq, Display, From)]
pub enum Const {
    Bool(bool),
    #[display("u8:{_0:#x}")]
    U8(u8),
    #[display("u16:{_0:#x}")]
    U16(u16),
    #[display("u32:{_0:#x}")]
    U32(u32),
    #[display("u64:{_0:#x}")]
    U64(u64),
    Ip4(Ipv4Addr),
    Sock4(SocketAddrV4),
    #[display("{}", Literal(_0.as_ref()))]
    Bytes(Buf),
    #[display("func:{}", _0.name)]
    Func(&'static FuncDef),
    /// No argument for a nullable parameter. It has no source syntax.
    #[display("nil")]
    Absent,
}

/// Expressions separated by spaces
struct Spaced<'a>(&'a [Expr]);

impl Program {
    pub fn stmts(&self) -> &[Stmt] {
        &self.stmts
    }

    /// The name bound to `slot`
    pub fn slot_name(&self, slot: SlotId) -> &str {
        &self.slots[slot.0]
    }
}

impl SlotId {
    pub fn index(self) -> usize {
        self.0
    }
}

impl Stmt {
    pub(crate) fn new(loc: Loc, kind: StmtKind) -> Self {
        Self { loc, kind }
    }
}

impl Expr {
    pub(crate) fn new(loc: Loc, kind: ExprKind) -> Self {
        Self { loc, kind }
    }

    pub fn is_const(&self) -> bool {
        matches!(self.kind, ExprKind::Const(_))
    }

    pub fn const_ip4(&self) -> Option<Ipv4Addr> {
        match &self.kind {
            ExprKind::Const(Const::Ip4(addr)) => Some(*addr),
            _ => None,
        }
    }

    pub fn const_u16(&self) -> Option<u16> {
        match &self.kind {
            ExprKind::Const(Const::U16(n)) => Some(*n),
            _ => None,
        }
    }

    /// Returns true if evaluating this expression has side effects, or calls a function that may
    /// have side effects.
    ///
    /// - A constant or local is pure.
    /// - A call is impure (until we have a flag to mark pure/impure functions).
    /// - A method binding is impure if its object is impure.
    /// - A sequence is impure if any of its effects or value are impure.
    /// - A socket address (binop in future) is impure if either of its operands are impure.
    pub fn impure(&self) -> bool {
        match &self.kind {
            ExprKind::Const(_) | ExprKind::Local(_) => false,
            ExprKind::Call(_) => true,
            ExprKind::Method { obj, .. } => obj.impure(),
            ExprKind::Seq { effects, value } => {
                effects.iter().any(|e| e.impure()) || value.impure()
            }
            ExprKind::SockAddr { ip, port } => ip.impure() || port.impure(),
        }
    }

    /// A sequence of expressions, where only the last expression's value is used.
    pub fn seq(loc: Loc, effects: Box<[Expr]>, value: Expr) -> Self {
        let effects: Box<[Expr]> = effects.into_iter().filter(|e| e.impure()).collect();
        if effects.is_empty() {
            value
        } else {
            Self::new(
                loc,
                ExprKind::Seq {
                    effects,
                    value: Box::new(value),
                },
            )
        }
    }

    /// Split out side-effects from the value of a sequence
    pub fn split(self) -> (Box<[Expr]>, Expr) {
        match self.kind {
            ExprKind::Seq { effects, value } => (effects, *value),
            _ => (Box::new([]), self),
        }
    }
}

impl Call {
    pub(crate) fn new(
        callee: Expr,
        func: &'static FuncDef,
        args: Box<[(Expr, usize)]>,
        collect: Box<[Expr]>,
    ) -> Self {
        Self {
            callee,
            func,
            args,
            collect,
        }
    }
}

impl From<Lit> for Const {
    fn from(lit: Lit) -> Self {
        match lit {
            Lit::Bool(b) => Self::Bool(b),
            Lit::Int(n) => Self::U64(n),
            Lit::Ip4(addr) => Self::Ip4(addr),
            Lit::Sock4(sa) => Self::Sock4(sa),
            Lit::Str(buf) => Self::Bytes(buf),
        }
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, stmt) in self.stmts.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{stmt}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Spaced<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, expr) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{expr}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Call {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(call {}", self.callee)?;
        for (arg, slot) in &self.args {
            write!(f, " (: {} {arg})", self.func.args[*slot].name)?;
        }
        if !self.collect.is_empty() {
            write!(f, " (*")?;
            for arg in &self.collect {
                write!(f, " {arg}")?;
            }
            write!(f, ")")?;
        }
        write!(f, ")")
    }
}
