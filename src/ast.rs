//! The abstract syntax tree produced by the parser.
//!
//! Every [Expr] carries the location of its first token. Names carry their own location, as an
//! [Ident], so that errors about a name can point at it.
//!
//! Every node displays as an S-expression, for tests and debugging. Locations aren't printed.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use derive_more::Display;

use crate::loc::Loc;
use crate::str::{Buf, Literal};

/// A name, and where it appears in the source.
#[derive(Debug, Display)]
#[display("{name}")]
pub struct Ident {
    pub loc: Loc,
    pub name: Box<str>,
}

/// `module::inner*::item`, resolved through the imports table.
#[derive(Debug)]
pub struct ModulePath {
    pub module: Ident,
    pub inner: Box<[Ident]>,
    pub item: Ident,
}

/// A literal value, as written in the source.
#[derive(Debug, Display)]
pub enum Lit {
    Bool(bool),
    #[display("{_0:#x}")]
    Int(i128),
    Ip4(Ipv4Addr),
    Sock4(SocketAddrV4),
    #[display("{}", Literal(_0.as_ref()))]
    Str(Buf),
}

#[derive(Debug, Display)]
#[display("{kind}")]
pub struct Expr {
    pub loc: Loc,
    pub kind: ExprKind,
}

#[derive(Debug, Display)]
pub enum ExprKind {
    Literal(Lit),
    LocalRef(Ident),
    ModulePath(Box<ModulePath>),
    #[display("(. {obj} {name})")]
    Member {
        obj: Box<Expr>,
        name: Ident,
    },
    #[display("(call {callee}{})", Prefixed(" ", args))]
    Call {
        callee: Box<Expr>,
        args: Box<[Arg]>,
    },
    #[display("({op} {lhs} {rhs})")]
    Binary {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
}

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    #[display("/")]
    Slash,
}

/// An argument in a call, named if it was written `name: value`.
#[derive(Debug)]
pub struct Arg {
    pub name: Option<Ident>,
    pub value: Expr,
}

/// A complete statement of the resynth language
#[derive(Debug, Display)]
pub enum Stmt {
    #[display("(import {_0})")]
    Import(Ident),
    #[display("(let {target} {value})")]
    Let {
        target: Ident,
        value: Expr,
    },
    Expr(Expr),
}

impl BinOp {
    pub fn symbol(&self) -> &'static str {
        match self {
            Self::Slash => "/",
        }
    }
}

impl Expr {
    /// Where errors from calling this expression are reported: the name being called, if it has
    /// one, as in `flow.client_message(..)` or `tls::message(..)`. Otherwise the expression's
    /// first token.
    pub fn name_loc(&self) -> Loc {
        match &self.kind {
            ExprKind::Member { name, .. } => name.loc,
            ExprKind::ModulePath(path) => path.item.loc,
            ExprKind::LocalRef(ident) => ident.loc,
            ExprKind::Literal(_) | ExprKind::Call { .. } | ExprKind::Binary { .. } => self.loc,
        }
    }
}

impl fmt::Display for ModulePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            module,
            inner,
            item,
        } = self;
        write!(f, "{module}{}::{item}", Prefixed("::", inner))
    }
}

impl fmt::Display for Arg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => write!(f, "(: {name} {})", self.value),
            None => write!(f, "{}", self.value),
        }
    }
}

/// Displays each item with a prefix, as in `::b::c` or ` a b`, for lists inside an S-expression.
struct Prefixed<'a, T>(&'static str, &'a [T]);

impl<T: fmt::Display> fmt::Display for Prefixed<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(prefix, items) = self;
        items
            .iter()
            .try_for_each(|item| write!(f, "{prefix}{item}"))
    }
}
