//! The abstract syntax tree produced by the parser.
//!
//! Every [Expr] carries the location of its first token. Names carry their own location, as an
//! [Ident], so that errors about a name can point at it.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::loc::Loc;
use crate::str::{Buf, Literal};

/// A name, and where it appears in the source.
#[derive(Debug)]
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
#[derive(Debug)]
pub enum Lit {
    Bool(bool),
    Int(u64),
    Ip4(Ipv4Addr),
    Sock4(SocketAddrV4),
    Str(Buf),
}

#[derive(Debug)]
pub struct Expr {
    pub loc: Loc,
    pub kind: ExprKind,
}

#[derive(Debug)]
pub enum ExprKind {
    Literal(Lit),
    LocalRef(Ident),
    ModulePath(Box<ModulePath>),
    Member {
        obj: Box<Expr>,
        name: Ident,
    },
    Call {
        callee: Box<Expr>,
        args: Box<[Arg]>,
    },
    Binary {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Slash,
}

/// An argument in a call, named if it was written `name: value`.
#[derive(Debug)]
pub struct Arg {
    pub name: Option<Ident>,
    pub value: Expr,
}

/// A complete statement of the resynth language
#[derive(Debug)]
pub enum Stmt {
    Import(Ident),
    Let { target: Ident, value: Expr },
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

    /// Displays the expression as an S-expression, for tests and debugging.
    pub fn sexpr(&self) -> ExprSexpr<'_> {
        ExprSexpr(self)
    }
}

impl Stmt {
    /// Displays the statement as an S-expression, for tests and debugging.
    pub fn sexpr(&self) -> StmtSexpr<'_> {
        StmtSexpr(self)
    }
}

/// Helper struct for displaying an [Expr] as an S-expression, returned by [Expr::sexpr].
pub struct ExprSexpr<'a>(&'a Expr);

/// Helper struct for displaying a [Stmt] as an S-expression, returned by [Stmt::sexpr].
pub struct StmtSexpr<'a>(&'a Stmt);

impl ExprSexpr<'_> {
    fn fmt_lit(f: &mut fmt::Formatter<'_>, lit: &Lit) -> fmt::Result {
        match lit {
            Lit::Bool(b) => write!(f, "{b}"),
            Lit::Int(i) => write!(f, "{i:#x}"),
            Lit::Ip4(addr) => write!(f, "{addr}"),
            Lit::Sock4(sa) => write!(f, "{sa}"),
            Lit::Str(buf) => write!(f, "{}", Literal(buf.as_ref())),
        }
    }

    fn fmt_path(f: &mut fmt::Formatter<'_>, path: &ModulePath) -> fmt::Result {
        write!(f, "{}", path.module.name)?;
        for seg in &path.inner {
            write!(f, "::{}", seg.name)?;
        }
        write!(f, "::{}", path.item.name)
    }
}

impl fmt::Display for ExprSexpr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0.kind {
            ExprKind::Literal(lit) => Self::fmt_lit(f, lit),
            ExprKind::LocalRef(ident) => write!(f, "{}", ident.name),
            ExprKind::ModulePath(path) => Self::fmt_path(f, path),
            ExprKind::Member { obj, name } => write!(f, "(. {} {})", obj.sexpr(), name.name),
            ExprKind::Call { callee, args } => {
                write!(f, "(call {}", callee.sexpr())?;
                for arg in args {
                    match &arg.name {
                        Some(name) => write!(f, " (: {} {})", name.name, arg.value.sexpr())?,
                        None => write!(f, " {}", arg.value.sexpr())?,
                    }
                }
                write!(f, ")")
            }
            ExprKind::Binary { op, lhs, rhs } => {
                write!(f, "({} {} {})", op.symbol(), lhs.sexpr(), rhs.sexpr())
            }
        }
    }
}

impl fmt::Display for StmtSexpr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Stmt::Import(module) => write!(f, "(import {})", module.name),
            Stmt::Let { target, value } => write!(f, "(let {} {})", target.name, value.sexpr()),
            Stmt::Expr(expr) => write!(f, "{}", expr.sexpr()),
        }
    }
}
