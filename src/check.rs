//! The check phase. It resolves names, binds call arguments and checks types, lowering the AST
//! to a [HIR](crate::hir) [Program] before anything runs.
//!
//! The checker reports at most one error per statement, then carries on with the next one. A
//! `let` whose value fails to check leaves its name poisoned: later statements that use it stop
//! checking without reporting anything more.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddrV4;
use std::num::NonZeroUsize;

use derive_more::{Display, Error, From};

use crate::ast::{self, BinOp, Ident, ModulePath};
use crate::hir::{Call, Const, Expr, ExprKind, Program, SlotId, Stmt, StmtKind};
use crate::libapi::{ClassDef, FuncDef, Module};
use crate::loc::Loc;
use crate::stdlib::STDLIB;
use crate::sym::Symbol;
use crate::val::ValType;

pub(crate) mod bind;

use SemanticErrorKind::{
    AlreadyBound, NoMembers, NotAModule, NotAValue, NotCallable, NotImported, OperandType,
    UnknownItem, UnknownMember, UnknownModule, UnknownName, VoidValue,
};
use bind::{ArgIn, Bound};

/// Check a program and lower it to HIR, giving each error and warning to `diag` as it is found.
/// There is at most one error per statement. If there were any errors, it fails with how many
/// errors and warnings were given.
pub fn check(
    stmts: impl IntoIterator<Item = ast::Stmt>,
    diag: impl FnMut(Diagnostic),
) -> Result<Program, ErrorSummary> {
    check_in(&STDLIB, stmts, diag)
}

/// [check], importing modules from `root` instead of the stdlib
pub(crate) fn check_in(
    root: &'static Module,
    stmts: impl IntoIterator<Item = ast::Stmt>,
    diag: impl FnMut(Diagnostic),
) -> Result<Program, ErrorSummary> {
    Checker::new(root, diag).run(stmts)
}

/// An error or a warning, and where
#[derive(Debug, Display)]
#[display("{loc}: {kind}")]
pub struct Diagnostic {
    pub loc: Loc,
    pub kind: DiagnosticKind,
}

impl From<SemanticError> for Diagnostic {
    fn from(SemanticError { loc, kind }: SemanticError) -> Self {
        Self {
            loc,
            kind: kind.into(),
        }
    }
}

#[derive(Debug, Display, From)]
pub enum DiagnosticKind {
    /// The program can't run
    #[display("{_0}")]
    Error(SemanticErrorKind),

    /// The program can run, but probably doesn't do what was meant
    #[display("{_0}")]
    Warning(WarningKind),
}

/// What is suspicious about the program
#[derive(Debug, Display)]
pub enum WarningKind {
    /// A second `import` of the same name, which does nothing
    #[display("multiple imports of {:?}", _0)]
    MultipleImports(Box<str>),

    /// An expression statement whose value isn't packets, a time jump or `void`
    #[display("discarded value of type {}", _0)]
    DiscardedValue(Ty),
}

impl WarningKind {
    /// This warning, at `loc`
    fn at(self, loc: Loc) -> Diagnostic {
        Diagnostic {
            loc,
            kind: DiagnosticKind::Warning(self),
        }
    }
}

/// How many errors and warnings were given for a program that failed to check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorSummary {
    pub errors: NonZeroUsize,
    pub warnings: usize,
}

/// For example `2 errors, 1 warning`, or `1 error` when there were no warnings
impl fmt::Display for ErrorSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let plural = |n: usize| if n == 1 { "" } else { "s" };

        let errors = self.errors.get();
        write!(f, "{errors} error{}", plural(errors))?;
        if self.warnings > 0 {
            write!(f, ", {} warning{}", self.warnings, plural(self.warnings))?;
        }
        Ok(())
    }
}

/// Why the program can't run, and where
#[derive(Debug, Display, Error)]
#[display("{loc}: {kind}")]
pub struct SemanticError {
    pub loc: Loc,
    pub kind: SemanticErrorKind,
}

/// What is wrong with the program
#[derive(Debug, Display, Error)]
pub enum SemanticErrorKind {
    /// A local that isn't bound
    #[display("unknown name {:?}", _0)]
    #[error(ignore)]
    UnknownName(Box<str>),

    /// A name in a module path that its module doesn't have
    #[display("unknown name {name:?} in module {module}")]
    UnknownItem {
        name: Box<str>,
        module: &'static str,
    },

    #[display("{class} has no member {name:?}")]
    UnknownMember { class: &'static str, name: Box<str> },

    #[display("unknown module {:?}", _0)]
    #[error(ignore)]
    UnknownModule(Box<str>),

    #[display("module {:?} not imported", _0)]
    #[error(ignore)]
    NotImported(Box<str>),

    #[display("{:?} is not a module", _0)]
    #[error(ignore)]
    NotAModule(Box<str>),

    #[display("{:?} is not a value", _0)]
    #[error(ignore)]
    NotAValue(Box<str>),

    /// A second `let` of the same name
    #[display("{name:?} is already bound, at {first}")]
    AlreadyBound { name: Box<str>, first: Loc },

    /// Member access on a value that isn't an object
    #[display("value of type {} has no members", _0)]
    #[error(ignore)]
    NoMembers(Ty),

    #[display("{side} operand of {} must be {expected}, found {found}", op.symbol())]
    OperandType {
        op: BinOp,
        side: Side,
        expected: Ty,
        found: Ty,
    },

    #[display("value of type {} is not callable", _0)]
    #[error(ignore)]
    NotCallable(Ty),

    #[display("{func}: too many arguments: {got} > {want}")]
    TooManyArgs {
        func: &'static str,
        got: usize,
        want: usize,
    },

    #[display("{func}: not enough arguments: {got} < {want}")]
    TooFewArgs {
        func: &'static str,
        got: usize,
        want: usize,
    },

    #[display("{func}: argument {arg:?} not specified")]
    MissingArg {
        func: &'static str,
        arg: &'static str,
    },

    /// A named argument that isn't a parameter
    #[display("{func}: unknown argument {arg:?}")]
    UnknownArg { func: &'static str, arg: Box<str> },

    #[display("{func}: argument {arg:?} given more than once")]
    DuplicateArg { func: &'static str, arg: Box<str> },

    #[display("{func}: unexpected collect-arguments")]
    UnexpectedCollectArgs { func: &'static str },

    #[display("{func}: unexpected named argument: {arg:?}")]
    UnexpectedNamedArg { func: &'static str, arg: Box<str> },

    #[display("{func}: argument {arg:?} must be {expected}, found {found}")]
    ArgType {
        func: &'static str,
        arg: &'static str,
        expected: ValType,
        found: Ty,
    },

    #[display("{func}: collect argument must be {expected}, found {found}")]
    CollectArgType {
        func: &'static str,
        expected: ValType,
        found: Ty,
    },

    /// A `void` expression where a value is needed
    #[display("void value used as a value")]
    VoidValue,
}

/// Which operand of a binary operator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum Side {
    #[display("left")]
    Left,
    #[display("right")]
    Right,
}

impl SemanticErrorKind {
    /// This error, at `loc`
    pub(crate) fn at(self, loc: Loc) -> SemanticError {
        SemanticError { loc, kind: self }
    }
}

/// The checker's type of an expression. Every variant is the type of some expression.
#[derive(Clone, Copy, PartialEq, Eq, Display)]
pub enum Ty {
    /// A call to a function that returns nothing
    #[display("void")]
    Void,
    #[display("bool")]
    Bool,
    #[display("u8")]
    U8,
    #[display("u16")]
    U16,
    #[display("u32")]
    U32,
    #[display("u64")]
    U64,
    #[display("Ip4")]
    Ip4,
    #[display("Sock4")]
    Sock4,
    #[display("bytes")]
    Bytes,
    #[display("Pkt")]
    Pkt,
    #[display("PktGen")]
    PktGen,
    #[display("TimeJump")]
    TimeJump,
    /// An object
    #[display("{}", _0.name)]
    Class(&'static ClassDef),
    /// A function, such as `std::be16`
    #[display("function {}", _0.name)]
    Func(&'static FuncDef),
    /// A method bound to an object, such as `c.open`
    #[display("method {}.{}", _0.name, _1.name)]
    Method(&'static ClassDef, &'static FuncDef),
}

impl Ty {
    /// The type of a call to `func`, from its declared return type
    pub(crate) fn of_return(func: &FuncDef) -> Self {
        Self::try_from(func.return_type)
            .unwrap_or_else(|t| panic!("{}: return type {t} has no Ty", func.name))
    }

    /// The type of a literal, a module constant or a property
    pub(crate) fn of_const(c: &Const) -> Self {
        match c {
            Const::Bool(_) => Self::Bool,
            Const::U8(_) => Self::U8,
            Const::U16(_) => Self::U16,
            Const::U64(_) => Self::U64,
            Const::Ip4(_) => Self::Ip4,
            Const::Sock4(_) => Self::Sock4,
            Const::Bytes(_) => Self::Bytes,
            Const::Func(func) => Self::Func(func),
            Const::U32(_) | Const::Absent => {
                unreachable!("no literal, module constant or property is {c:?}")
            }
        }
    }

    fn is_integral(self) -> bool {
        matches!(self, Self::Bool | Self::U8 | Self::U16 | Self::U64)
    }

    /// Whether a value of this type can be passed for a parameter declared `param`: any integer
    /// or `bool` fits any integer parameter, bytes accept anything that converts to bytes, and a
    /// packet sequence accepts one packet. The stdlib function converts the value itself,
    /// through `From<Val>`.
    pub(crate) fn fits(self, param: ValType) -> bool {
        use ValType as V;
        match param {
            V::Bool | V::U8 | V::U16 | V::U32 | V::U64 => self.is_integral(),
            V::Str => self.is_integral() || matches!(self, Self::Bytes | Self::Pkt | Self::Ip4),
            V::PktGen => matches!(self, Self::PktGen | Self::Pkt),
            V::Ip4 => self == Self::Ip4,
            V::Sock4 => self == Self::Sock4,
            V::Pkt => self == Self::Pkt,
            V::TimeJump => self == Self::TimeJump,
            V::Class(cls) => self == Self::Class(cls),
            V::Func => matches!(self, Self::Func(_)),
            V::Method => matches!(self, Self::Method(..)),
            V::Void | V::Type | V::Obj => false,
        }
    }
}

/// A run-time type the checker has a type for. `U32`, `Type` and `Obj` are never the type of an
/// expression, and a bare `Func` or `Method` doesn't say which function.
impl TryFrom<ValType> for Ty {
    type Error = ValType;

    fn try_from(t: ValType) -> Result<Self, ValType> {
        Ok(match t {
            ValType::Void => Self::Void,
            ValType::Bool => Self::Bool,
            ValType::U8 => Self::U8,
            ValType::U16 => Self::U16,
            ValType::U64 => Self::U64,
            ValType::Ip4 => Self::Ip4,
            ValType::Sock4 => Self::Sock4,
            ValType::Str => Self::Bytes,
            ValType::Pkt => Self::Pkt,
            ValType::PktGen => Self::PktGen,
            ValType::TimeJump => Self::TimeJump,
            ValType::Class(cls) => Self::Class(cls),
            ValType::U32 | ValType::Type | ValType::Obj | ValType::Func | ValType::Method => {
                return Err(t);
            }
        })
    }
}

/// Names classes and functions without dumping their symbol tables
impl fmt::Debug for Ty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Class(cls) => write!(f, "Class({})", cls.name),
            Self::Func(func) => write!(f, "Func({})", func.name),
            Self::Method(cls, func) => write!(f, "Method({}, {})", cls.name, func.name),
            ty => write!(f, "{ty}"),
        }
    }
}

/// Why a statement stopped checking
enum Stop {
    /// An error, for the statement loop to record
    Reported(SemanticError),
    /// The statement used a poisoned name, whose error was reported where it was bound
    Poisoned,
}

impl From<SemanticError> for Stop {
    fn from(err: SemanticError) -> Self {
        Self::Reported(err)
    }
}

type Checked<T> = Result<T, Stop>;

/// What the checker knows about one slot of the frame
struct Binding {
    /// Where it was bound, for [AlreadyBound]
    loc: Loc,
    state: BindState,
}

/// What a let binding can be bound to. A `let` whose value failed to check leaves its name
/// poisoned, so later statements that use it stop checking without reporting anything more.
enum BindState {
    /// A value known only at runtime, in a frame slot
    Slot(SlotId, Ty),
    /// A value known at compile time
    Const(Const),
    /// Its `let` didn't check
    Failed,
}

/// What the checker knows about one imported name
#[derive(Clone, Copy)]
enum ImportState {
    Found(&'static Module),
    /// No module has its name
    Failed,
}

struct Checker<D> {
    /// Where `import` finds modules
    root: &'static Module,
    imports: HashMap<Box<str>, ImportState>,
    bindings: HashMap<Box<str>, Binding>,
    slots: Vec<Box<str>>,
    /// How many errors and warnings have been given to `diag`
    errors: usize,
    warnings: usize,
    diag: D,
}

impl<D: FnMut(Diagnostic)> Checker<D> {
    fn new(root: &'static Module, diag: D) -> Self {
        Self {
            root,
            imports: HashMap::new(),
            bindings: HashMap::new(),
            slots: Vec::new(),
            errors: 0,
            warnings: 0,
            diag,
        }
    }

    fn run(mut self, stmts: impl IntoIterator<Item = ast::Stmt>) -> Result<Program, ErrorSummary> {
        let mut out = Vec::new();
        for stmt in stmts {
            match self.stmt(stmt, &mut out) {
                Err(Stop::Reported(err)) => self.error(err),
                Err(Stop::Poisoned) => {}
                Ok(_) => {}
            }
        }

        if let Some(errors) = NonZeroUsize::new(self.errors) {
            return Err(ErrorSummary {
                errors,
                warnings: self.warnings,
            });
        }

        Ok(Program::new(out.into(), self.slots.into()))
    }

    fn error(&mut self, err: SemanticError) {
        self.errors += 1;
        (self.diag)(err.into());
    }

    fn warn(&mut self, loc: Loc, warn: WarningKind) {
        self.warnings += 1;
        (self.diag)(warn.at(loc));
    }

    /// Check a statement, adding its lowered HIR to `out`. A `let` may add multiple statements:
    /// one for each side-effect of its value, then one for the `let` itself. An `import` adds
    /// nothing to `out`.
    fn stmt(&mut self, stmt: ast::Stmt, out: &mut Vec<Stmt>) -> Checked<()> {
        match stmt {
            ast::Stmt::Import(module) => {
                self.import(module)?;
            }
            ast::Stmt::Let { target, value } => {
                let loc = target.loc;
                let (effs, kind) = self.let_stmt(target, value)?;

                out.extend(
                    effs.into_iter()
                        .map(|e| Stmt::new(e.loc, StmtKind::Eval(e))),
                );
                out.extend(kind.map(|k| Stmt::new(loc, k)));
            }
            ast::Stmt::Expr(expr) => {
                let loc = expr.loc;
                out.push(Stmt::new(loc, self.expr_stmt(loc, expr)?));
            }
        }
        Ok(())
    }

    fn import(&mut self, module: Ident) -> Checked<()> {
        let Ident { loc, name } = module;

        if self.imports.contains_key(&name) {
            self.warn(loc, WarningKind::MultipleImports(name));
            return Ok(());
        }

        // A failed import poisons its name, as a failed `let` does
        match self.root.get(&name) {
            Some(Symbol::Module(module)) => {
                self.imports.insert(name, ImportState::Found(module));
                Ok(())
            }
            None => {
                self.imports.insert(name.clone(), ImportState::Failed);
                Err(UnknownModule(name).at(loc).into())
            }
            Some(Symbol::Func(_) | Symbol::Class(_) | Symbol::Val(_)) => {
                unreachable!("{name}: a root module holds only modules")
            }
        }
    }

    /// A `let` gets a new slot. Its name is in scope from the end of the `let`, so `let x = x;` is
    /// an error.
    fn let_stmt(
        &mut self,
        target: Ident,
        value: ast::Expr,
    ) -> Checked<(Box<[Expr]>, Option<StmtKind>)> {
        let Ident { loc, name } = target;

        if let Some(prev) = self.bindings.get(&name) {
            return Err(AlreadyBound {
                name,
                first: prev.loc,
            }
            .at(loc)
            .into());
        }

        let (value, ty) = match self.value(value) {
            Err(stop) => {
                self.bindings.insert(
                    name,
                    Binding {
                        loc,
                        state: BindState::Failed,
                    },
                );
                return Err(stop);
            }
            Ok(ret) => ret,
        };

        let (effs, value) = value.split();

        let (state, kind) = match (value, ty) {
            (
                Expr {
                    kind: ExprKind::Const(c),
                    ..
                },
                _ty,
            ) => (BindState::Const(c), None),
            (value, ty) => {
                let slot = SlotId(self.slots.len());
                self.slots.push(name.clone());
                (
                    BindState::Slot(slot, ty),
                    Some(StmtKind::Let { slot, value }),
                )
            }
        };

        self.bindings.insert(name, Binding { loc, state });

        Ok((effs, kind))
    }

    /// An expression statement's kind comes from its type. Any value other than packets, a time
    /// jump or `void` is discarded, with a warning at the statement.
    fn expr_stmt(&mut self, loc: Loc, expr: ast::Expr) -> Checked<StmtKind> {
        let (expr, ty) = self.expr(expr)?;
        Ok(match ty {
            Ty::Pkt | Ty::PktGen => StmtKind::Emit(expr),
            Ty::TimeJump => StmtKind::Wait(expr),
            Ty::Void => StmtKind::Eval(expr),
            ty => {
                self.warn(loc, WarningKind::DiscardedValue(ty));
                StmtKind::Discard(expr)
            }
        })
    }

    /// An expression whose value is used. Only an expression statement may be `void`. Only a
    /// call can be `void`, so the error points at its called name.
    fn value(&mut self, expr: ast::Expr) -> Checked<(Expr, Ty)> {
        let (expr, ty) = self.expr(expr)?;
        if ty == Ty::Void {
            return Err(VoidValue.at(expr.loc).into());
        }
        Ok((expr, ty))
    }

    fn expr(&mut self, expr: ast::Expr) -> Checked<(Expr, Ty)> {
        let ast::Expr { loc, kind } = expr;
        match kind {
            ast::ExprKind::Literal(lit) => Ok(Self::constant(loc, Const::from(lit))),
            ast::ExprKind::LocalRef(ident) => self.local(ident),
            ast::ExprKind::ModulePath(path) => self.path(loc, *path),
            ast::ExprKind::Member { obj, name } => self.member(loc, *obj, name),
            ast::ExprKind::Call { callee, args } => self.call(*callee, args),
            ast::ExprKind::Binary {
                op: BinOp::Slash,
                lhs,
                rhs,
            } => self.slash(loc, *lhs, *rhs),
        }
    }

    fn constant(loc: Loc, c: Const) -> (Expr, Ty) {
        let ty = Ty::of_const(&c);
        (Expr::new(loc, ExprKind::Const(c)), ty)
    }

    fn local(&mut self, ident: Ident) -> Checked<(Expr, Ty)> {
        let Ident { loc, name } = ident;
        let Some(binding) = self.bindings.get(&name) else {
            return Err(UnknownName(name).at(loc).into());
        };
        match binding.state {
            BindState::Slot(slot, ty) => Ok((Expr::new(loc, ExprKind::Local(slot)), ty)),
            BindState::Const(ref c) => Ok(Self::constant(loc, c.clone())),
            BindState::Failed => Err(Stop::Poisoned),
        }
    }

    /// `module::inner*::item`, through the imports table. Errors point at the segment which
    /// failed.
    fn path(&mut self, loc: Loc, path: ModulePath) -> Checked<(Expr, Ty)> {
        let ModulePath {
            module,
            inner,
            item,
        } = path;

        let mut top = match self.imports.get(&module.name) {
            Some(ImportState::Found(top)) => *top,
            Some(ImportState::Failed) => return Err(Stop::Poisoned),
            None => return Err(NotImported(module.name).at(module.loc).into()),
        };

        for seg in inner {
            top = match top.get(&seg.name) {
                Some(Symbol::Module(module)) => module,
                Some(_) => return Err(NotAModule(seg.name).at(seg.loc).into()),
                None => return Err(Self::unknown_item(top, seg).into()),
            };
        }

        match top.get(&item.name) {
            Some(Symbol::Val(def)) => Ok(Self::constant(loc, Const::from_def(*def))),
            Some(Symbol::Func(func)) => Ok(Self::constant(loc, Const::Func(func))),
            Some(Symbol::Module(_) | Symbol::Class(_)) => {
                Err(NotAValue(item.name).at(item.loc).into())
            }
            None => Err(Self::unknown_item(top, item).into()),
        }
    }

    fn unknown_item(module: &Module, name: Ident) -> SemanticError {
        UnknownItem {
            name: name.name,
            module: module.name,
        }
        .at(name.loc)
    }

    /// `obj.name`, through the object's class. A method is bound to the object. A property is
    /// its class's value, read once the object has been evaluated.
    fn member(&mut self, loc: Loc, obj: ast::Expr, name: Ident) -> Checked<(Expr, Ty)> {
        let (obj, ty) = self.value(obj)?;
        let Ty::Class(cls) = ty else {
            return Err(NoMembers(ty).at(name.loc).into());
        };

        match cls.get(&name.name) {
            Some(Symbol::Func(func)) => {
                let obj = Box::new(obj);
                let expr = Expr::new(loc, ExprKind::Method { obj, func });
                Ok((expr, Ty::Method(cls, func)))
            }
            Some(Symbol::Val(def)) => {
                // A Symbol::Val is a const property of the object. We can just const propagate it
                // in most cases. Unless we're doing f(...).prop, in which case if f() has
                // side-effects then we need to evaluate f().
                //
                // TODO: once functions are marked as having side effects or not, lower a property
                // of an object with no side effects to the constant alone. Reading a local has
                // none already.
                let (value, ty) = Self::constant(name.loc, Const::from_def(*def));
                Ok((
                    if obj.impure() {
                        let effects = Box::new([obj]);
                        let value = Box::new(value);
                        Expr::new(loc, ExprKind::Seq { effects, value })
                    } else {
                        value
                    },
                    ty,
                ))
            }
            Some(Symbol::Module(_) | Symbol::Class(_)) => {
                Err(NotAValue(name.name).at(name.loc).into())
            }
            None => Err(UnknownMember {
                class: cls.name,
                name: name.name,
            }
            .at(name.loc)
            .into()),
        }
    }

    /// A call is located at its called name. Its arguments are checked in source order, then
    /// bound to the callee's parameters.
    fn call(&mut self, callee: ast::Expr, args: Box<[ast::Arg]>) -> Checked<(Expr, Ty)> {
        let loc = callee.name_loc();
        let (callee, ty) = self.value(callee)?;
        let func = match ty {
            Ty::Func(func) | Ty::Method(_, func) => func,
            ty => return Err(NotCallable(ty).at(loc).into()),
        };

        let args = args
            .into_iter()
            .map(|ast::Arg { name, value }| {
                let value_loc = value.loc;
                let (hir, ty) = self.value(value)?;
                Ok(ArgIn {
                    name,
                    loc: value_loc,
                    hir,
                    ty,
                })
            })
            .collect::<Checked<Vec<_>>>()?;

        let Bound { args, collect } = Bound::bind(func, loc, args)?;
        let call = Call::new(callee, func, args, collect);
        Ok((
            Expr::new(loc, ExprKind::Call(Box::new(call))),
            Ty::of_return(func),
        ))
    }

    /// `ip / port`. The port's range is checked when it runs.
    fn slash(&mut self, loc: Loc, lhs: ast::Expr, rhs: ast::Expr) -> Checked<(Expr, Ty)> {
        let operand = |side, expected, found| OperandType {
            op: BinOp::Slash,
            side,
            expected,
            found,
        };

        let lhs_loc = lhs.loc;
        let (ip, ty) = self.value(lhs)?;
        if ty != Ty::Ip4 {
            return Err(operand(Side::Left, Ty::Ip4, ty).at(lhs_loc).into());
        }

        let rhs_loc = rhs.loc;
        let (port, ty) = self.value(rhs)?;
        if !ty.is_integral() {
            return Err(operand(Side::Right, Ty::U16, ty).at(rhs_loc).into());
        }

        if let Some(ip) = ip.const_ip4()
            && let Some(port) = port.const_u16()
        {
            let val = SocketAddrV4::new(ip, port);
            return Ok((Expr::new(loc, ExprKind::Const(val.into())), Ty::Sock4));
        }

        let kind = ExprKind::SockAddr {
            ip: Box::new(ip),
            port: Box::new(port),
        };
        Ok((Expr::new(loc, kind), Ty::Sock4))
    }
}
