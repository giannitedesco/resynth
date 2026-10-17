//! The high-level intermediate representation: a checked program, ready to run.
//!
//! [check](crate::check()) lowers the AST into a [Program]. In the HIR:
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
use crate::val::{Val, ValDef};

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
    pub(crate) fn new(stmts: Box<[Stmt]>, slots: Box<[Box<str>]>) -> Self {
        Self { stmts, slots }
    }

    pub fn stmts(&self) -> &[Stmt] {
        &self.stmts
    }

    /// The name bound to `slot`
    pub fn slot_name(&self, slot: SlotId) -> &str {
        &self.slots[slot.0]
    }

    fn slots_liveness(&self) -> Box<[bool]> {
        let mut live = vec![false; self.slots.len()];
        for stmt in self.stmts.iter().rev() {
            if let StmtKind::Let { slot, value } = &stmt.kind
                && !live[slot.0]
                && !value.impure()
            {
                // Dropped by eliminate_dead_lets, so our reads don't count for liveness
                continue;
            }
            stmt.kind.expr().locals(&mut |slot| {
                live[slot.0] = true;
            });
        }
        live.into_boxed_slice()
    }

    pub fn eliminate_dead_lets(self) -> Self {
        let live = self.slots_liveness();

        let mut renumber = vec![None; self.slots.len()];
        let kept = live
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, live)| *live)
            .map(|(old, _)| old);
        for (new, old) in kept.enumerate() {
            renumber[old] = Some(SlotId(new));
        }

        let Self { stmts, slots } = self;

        let stmts = stmts
            .into_iter()
            .filter_map(|Stmt { loc, kind }| {
                let kind = match kind {
                    // The same rule as slots_liveness: a dead let is dropped if its value is pure,
                    // and evaluated for its effects if it isn't
                    StmtKind::Let { slot, value } if !live[slot.0] => {
                        if !value.impure() {
                            return None;
                        }
                        StmtKind::Eval(value)
                    }
                    kind => kind,
                };
                Some(Stmt::new(loc, kind))
            })
            .map(|mut stmt| {
                if let StmtKind::Let { slot, .. } = &mut stmt.kind {
                    *slot = renumber[slot.0].expect("a kept let's slot is live");
                }
                stmt.kind.expr_mut().locals_mut(&mut |slot| {
                    *slot = renumber[slot.0].expect("a read slot is live");
                });
                stmt
            })
            .collect();

        let slots = slots
            .into_iter()
            .enumerate()
            .filter_map(|(old, name)| renumber[old].map(|_| name))
            .collect();

        Self { stmts, slots }
    }
}

impl SlotId {
    pub fn index(self) -> usize {
        self.0
    }
}

impl StmtKind {
    pub(crate) fn expr(&self) -> &Expr {
        match self {
            Self::Let { value, .. } => value,
            Self::Emit(expr) | Self::Wait(expr) | Self::Eval(expr) | Self::Discard(expr) => expr,
        }
    }

    pub(crate) fn expr_mut(&mut self) -> &mut Expr {
        match self {
            Self::Let { value, .. } => value,
            Self::Emit(expr) | Self::Wait(expr) | Self::Eval(expr) | Self::Discard(expr) => expr,
        }
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

    /// The value of an integer or `bool` constant
    pub fn const_int(&self) -> Option<i128> {
        match &self.kind {
            ExprKind::Const(c) => c.int(),
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

    /// The expression which gives this one's value: a sequence's value, or itself
    pub fn value(&self) -> &Expr {
        match &self.kind {
            ExprKind::Seq { value, .. } => value,
            _ => self,
        }
    }

    /// Split out side-effects from the value of a sequence
    pub fn split(self) -> (Box<[Expr]>, Expr) {
        match self.kind {
            ExprKind::Seq { effects, value } => (effects, *value),
            _ => (Box::new([]), self),
        }
    }

    /// Visit each local slot in this expression, mutably
    pub fn locals_mut(&mut self, f: &mut impl FnMut(&mut SlotId)) {
        match &mut self.kind {
            ExprKind::Local(slot) => f(slot),
            ExprKind::Method { obj, .. } => obj.locals_mut(f),
            ExprKind::Seq { effects, value } => {
                for e in effects.iter_mut() {
                    e.locals_mut(f);
                }
                value.locals_mut(f);
            }
            ExprKind::Call(call) => {
                call.callee.locals_mut(f);
                for (arg, _) in call.args.iter_mut() {
                    arg.locals_mut(f);
                }
                for arg in call.collect.iter_mut() {
                    arg.locals_mut(f);
                }
            }
            ExprKind::SockAddr { ip, port } => {
                ip.locals_mut(f);
                port.locals_mut(f);
            }
            ExprKind::Const(_) => {}
        }
    }

    /// Visit each local slot in this expression
    pub fn locals(&self, f: &mut impl FnMut(SlotId)) {
        match &self.kind {
            ExprKind::Local(slot) => f(*slot),
            ExprKind::Method { obj, .. } => obj.locals(f),
            ExprKind::Seq { effects, value } => {
                for e in effects.iter() {
                    e.locals(f);
                }
                value.locals(f);
            }
            ExprKind::Call(call) => {
                call.callee.locals(f);
                for (arg, _) in call.args.iter() {
                    arg.locals(f);
                }
                for arg in call.collect.iter() {
                    arg.locals(f);
                }
            }
            ExprKind::SockAddr { ip, port } => {
                ip.locals(f);
                port.locals(f);
            }
            ExprKind::Const(_) => {}
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

impl TryFrom<Lit> for Const {
    type Error = ();

    fn try_from(lit: Lit) -> Result<Self, Self::Error> {
        Ok(match lit {
            Lit::Bool(b) => Self::Bool(b),
            Lit::Ip4(addr) => Self::Ip4(addr),
            Lit::Sock4(sa) => Self::Sock4(sa),
            Lit::Str(buf) => Self::Bytes(buf),

            // Int literals are handled separately and are narrowed at the point of use
            Lit::Int(_) => return Err(()),
        })
    }
}

impl Const {
    /// The value of an integer or `bool` constant. `true` is 1.
    pub(crate) fn int(&self) -> Option<i128> {
        Some(match *self {
            Self::Bool(b) => b.into(),
            Self::U8(n) => n.into(),
            Self::U16(n) => n.into(),
            Self::U32(n) => n.into(),
            Self::U64(n) => n.into(),
            _ => return None,
        })
    }

    /// A module constant, a property, or a parameter's default. A static string is copied once,
    /// here.
    pub(crate) fn from_def(def: ValDef) -> Self {
        match def {
            ValDef::Bool(b) => Self::Bool(b),
            ValDef::U8(n) => Self::U8(n),
            ValDef::U16(n) => Self::U16(n),
            ValDef::U32(n) => Self::U32(n),
            ValDef::U64(n) => Self::U64(n),
            ValDef::Ip4(addr) => Self::Ip4(addr),
            ValDef::Sock4(sa) => Self::Sock4(sa),
            ValDef::Str(s) => Self::Bytes(Buf::from(s)),
            ValDef::Nil | ValDef::Type(_) => {
                unreachable!("{def:?} declares a nullable parameter and is never a value")
            }
        }
    }

    /// The value a parameter takes when no argument is given: its default, or [Const::Absent]
    /// if it's nullable
    pub(crate) fn default_of(def: ValDef) -> Self {
        match def {
            ValDef::Type(_) => Self::Absent,
            def => Self::from_def(def),
        }
    }

    /// The constant as a run-time value. [Const::Absent] becomes [Val::Nil] at the native
    /// boundary.
    pub(crate) fn into_val(self) -> Val {
        match self {
            Self::Bool(b) => Val::Bool(b),
            Self::U8(n) => Val::U8(n),
            Self::U16(n) => Val::U16(n),
            Self::U32(n) => Val::U32(n),
            Self::U64(n) => Val::U64(n),
            Self::Ip4(addr) => Val::Ip4(addr),
            Self::Sock4(sa) => Val::Sock4(sa),
            Self::Bytes(buf) => Val::Str(buf),
            Self::Func(func) => Val::Func(func),
            Self::Absent => Val::Nil,
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
