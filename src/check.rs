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
    AlreadyBound, IntegralTooLarge, NoMembers, NotAModule, NotAValue, NotCallable, NotImported,
    OperandType, UnknownItem, UnknownMember, UnknownModule, UnknownName, VoidValue,
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

    /// An integer constant that doesn't fit the integer type it is used as. It keeps its low
    /// bits.
    #[display("integer {value} truncated to {ty}")]
    Truncated { value: i128, ty: Ty },

    /// A value whose integer type is wider than the type it is used as. It keeps its low bits
    /// when it runs.
    #[display("value of type {found} may be truncated to {ty}")]
    Overflow { found: Ty, ty: Ty },
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
    NoMembers(Found),

    #[display("{side} operand of {} must be {expected}, found {found}", op.symbol())]
    OperandType {
        op: BinOp,
        side: Side,
        expected: Ty,
        found: Found,
    },

    #[display("value of type {} is not callable", _0)]
    #[error(ignore)]
    NotCallable(Found),

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
        found: Found,
    },

    #[display("{func}: collect argument must be {expected}, found {found}")]
    CollectArgType {
        func: &'static str,
        expected: ValType,
        found: Found,
    },

    /// A `void` expression where a value is needed
    #[display("void value used as a value")]
    VoidValue,

    /// An integer literal that doesn't fit in any integral type
    #[display("integer literal is too large for any integral type")]
    IntegralTooLarge(),
}

/// The type an error found. An untyped integer has none until it is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum Found {
    #[display("{_0}")]
    Ty(Ty),
    /// An untyped integer
    #[display("integer")]
    Int,
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
            Const::U32(_) => Self::U32,
            Const::U64(_) => Self::U64,
            Const::Ip4(_) => Self::Ip4,
            Const::Sock4(_) => Self::Sock4,
            Const::Bytes(_) => Self::Bytes,
            Const::Func(func) => Self::Func(func),
            Const::Absent => {
                unreachable!("no literal, module constant or property is {c:?}")
            }
        }
    }

    /// How many bits an integer or `bool` of this type holds
    fn bits(self) -> Option<u32> {
        match self {
            Self::Bool => Some(1),
            Self::U8 => Some(8),
            Self::U16 => Some(16),
            Self::U32 => Some(32),
            Self::U64 => Some(64),
            _ => None,
        }
    }

    fn is_integral(self) -> bool {
        self.bits().is_some()
    }

    /// A constant of this integer type, holding the low bits of `n`
    fn truncate(self, n: i128) -> Const {
        match self {
            Self::U8 => Const::U8(n as u8),
            Self::U16 => Const::U16(n as u16),
            Self::U32 => Const::U32(n as u32),
            Self::U64 => Const::U64(n as u64),
            ty => unreachable!("{ty} isn't an integer type"),
        }
    }

    /// Whether this integer type holds `n` without truncating it
    fn holds(self, n: i128) -> bool {
        self.truncate(n).int() == Some(n)
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

/// A run-time type the checker has a type for. `Type` and `Obj` are never the type of an
/// expression, and a bare `Func` or `Method` doesn't say which function.
impl TryFrom<ValType> for Ty {
    type Error = ValType;

    fn try_from(t: ValType) -> Result<Self, ValType> {
        Ok(match t {
            ValType::Void => Self::Void,
            ValType::Bool => Self::Bool,
            ValType::U8 => Self::U8,
            ValType::U16 => Self::U16,
            ValType::U32 => Self::U32,
            ValType::U64 => Self::U64,
            ValType::Ip4 => Self::Ip4,
            ValType::Sock4 => Self::Sock4,
            ValType::Str => Self::Bytes,
            ValType::Pkt => Self::Pkt,
            ValType::PktGen => Self::PktGen,
            ValType::TimeJump => Self::TimeJump,
            ValType::Class(cls) => Self::Class(cls),
            ValType::Type | ValType::Obj | ValType::Func | ValType::Method => {
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

pub(crate) struct TypedValue {
    pub(crate) expr: Expr,
    pub(crate) ty: Ty,
}

/// What an expression lowers to. An untyped integer never reaches HIR: each context it is used
/// in narrows it.
pub(crate) enum Value {
    Typed(TypedValue),
    /// An untyped integer, and where it is
    Int(Loc, i128),
}

impl Value {
    /// For an integer literal, narrow to the narrowest type that can hold it. For a typed value,
    /// return it unchanged.
    fn narrow(self) -> Result<TypedValue, SemanticErrorKind> {
        Ok(match self {
            Self::Typed(tv) => tv,
            Self::Int(loc, n) => {
                let ty = [Ty::U8, Ty::U16, Ty::U32, Ty::U64]
                    .into_iter()
                    .find(|ty| ty.holds(n))
                    .ok_or(IntegralTooLarge())?;
                let expr = Expr::new(loc, ExprKind::Const(ty.truncate(n)));
                TypedValue { expr, ty }
            }
        })
    }

    /// Where an error about this value points
    fn loc(&self) -> Loc {
        match self {
            Self::Typed(TypedValue { expr, .. }) => expr.loc,
            Self::Int(loc, _) => *loc,
        }
    }

    /// What an error says it found
    fn found(&self) -> Found {
        match self {
            Self::Typed(TypedValue { ty, .. }) => Found::Ty(*ty),
            Self::Int(..) => Found::Int,
        }
    }

    /// Narrow to the integer type `ty`, where only an integer will do. An untyped integer, or an
    /// integer constant, becomes a constant of type `ty`, and so does a sequence's constant value,
    /// keeping its effects. Any other integer is converted when it runs. Either way it keeps its
    /// low bits, with a warning at `loc` if it truncates, or might. If it isn't an integer, fails
    /// with what was found.
    fn narrow_to(
        self,
        loc: Loc,
        ty: Ty,
        warn: &mut impl FnMut(Loc, WarningKind),
    ) -> Result<Expr, Found> {
        let (seq_loc, effects, const_loc, n) = match self {
            Self::Int(int_loc, n) => (int_loc, Box::default(), int_loc, n),
            Self::Typed(TypedValue { expr, ty: found }) => {
                if !found.is_integral() {
                    return Err(Found::Ty(found));
                }
                let Some(n) = expr.value().const_int() else {
                    if found.bits() > ty.bits() {
                        warn(loc, WarningKind::Overflow { found, ty });
                    }
                    return Ok(expr);
                };
                let seq_loc = expr.loc;
                let (effects, value) = expr.split();
                (seq_loc, effects, value.loc, n)
            }
        };

        if !ty.holds(n) {
            warn(loc, WarningKind::Truncated { value: n, ty });
        }
        let value = Expr::new(const_loc, ExprKind::Const(ty.truncate(n)));
        Ok(Expr::seq(seq_loc, effects, value))
    }

    /// Convert for a parameter of type `param`, written at `loc`. An integer parameter narrows
    /// as [narrow_to](Self::narrow_to) does. An untyped integer is `true` for a `bool` if
    /// it's non-zero, and narrows to the narrowest type that holds it for bytes. If it doesn't
    /// fit, fails with the error `err` makes from what was found.
    fn fit(
        self,
        loc: Loc,
        param: ValType,
        warn: &mut impl FnMut(Loc, WarningKind),
        err: impl FnOnce(Found) -> SemanticError,
    ) -> Result<Expr, SemanticError> {
        use ValType as V;
        match (param, self) {
            (V::U8 | V::U16 | V::U32 | V::U64, value) => {
                let ty = Ty::try_from(param).expect("an integer parameter has a Ty");
                value.narrow_to(loc, ty, warn).map_err(err)
            }
            (V::Bool, Self::Int(loc, n)) => {
                Ok(Expr::new(loc, ExprKind::Const(Const::Bool(n != 0))))
            }
            (V::Str, value @ Self::Int(..)) => match value.narrow() {
                Ok(TypedValue { expr, .. }) => Ok(expr),
                Err(kind) => Err(kind.at(loc)),
            },
            (_, Self::Int(..)) => Err(err(Found::Int)),
            (param, Self::Typed(TypedValue { expr, ty })) => {
                if !ty.fits(param) {
                    return Err(err(Found::Ty(ty)));
                }
                Ok(expr)
            }
        }
    }
}

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
    /// An untyped integer, narrowed at each use
    Int(i128),
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

        Ok(Program::new(out.into(), self.slots.into()).eliminate_dead_lets())
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

    /// A `let` of a constant binds the constant to the name and emits nothing. A `let` of a local
    /// binds that local's slot. Any other `let` gets a new slot. Its name is in scope from the end
    /// of the `let` so `let x = x;` is an error.
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

        let value = match self.value(value) {
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

        let TypedValue { ty, expr: value } = match value {
            Value::Typed(tv) => tv,
            Value::Int(_, n) => {
                let state = BindState::Int(n);
                self.bindings.insert(name, Binding { loc, state });
                return Ok((Box::default(), None));
            }
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
            // A local is an alias: bind the name to its slot and emit nothing
            (
                Expr {
                    kind: ExprKind::Local(slot),
                    ..
                },
                ty,
            ) => (BindState::Slot(slot, ty), None),
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
        let TypedValue { expr, ty } = self.expr(expr)?.narrow().map_err(|kind| kind.at(loc))?;
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
    fn value(&mut self, expr: ast::Expr) -> Checked<Value> {
        let value = self.expr(expr)?;

        if let Value::Typed(TypedValue { expr, ty: Ty::Void }) = &value {
            return Err(VoidValue.at(expr.loc).into());
        }

        Ok(value)
    }

    /// A value which must have type `expected`
    fn typed_value(
        &mut self,
        expr: ast::Expr,
        expected: Ty,
        err: impl FnOnce(Found) -> SemanticErrorKind,
    ) -> Checked<Expr> {
        let value = self.value(expr)?;

        match value {
            Value::Typed(TypedValue { expr, ty }) if ty == expected => Ok(expr),
            value => Err(err(value.found()).at(value.loc()).into()),
        }
    }

    /// A value which must be an integer, narrowed to `expected`. A constant that truncates, or a
    /// value whose type is wider than `expected`, gives a warning.
    fn integral(
        &mut self,
        expr: ast::Expr,
        expected: Ty,
        err: impl FnOnce(Found) -> SemanticErrorKind,
    ) -> Checked<Expr> {
        let loc = expr.loc;
        let value = self.value(expr)?;
        let err_loc = value.loc();

        value
            .narrow_to(loc, expected, &mut |loc, warn| self.warn(loc, warn))
            .map_err(|found| err(found).at(err_loc).into())
    }

    fn expr(&mut self, expr: ast::Expr) -> Checked<Value> {
        let ast::Expr { loc, kind } = expr;
        let typed = match kind {
            ast::ExprKind::Literal(ast::Lit::Int(n)) => return Ok(Value::Int(loc, n)),
            ast::ExprKind::Literal(lit) => Self::constant(loc, Const::try_from(lit).unwrap()),
            ast::ExprKind::LocalRef(ident) => return self.local(ident),
            ast::ExprKind::ModulePath(path) => self.path(loc, *path)?,
            ast::ExprKind::Member { obj, name } => self.member(loc, *obj, name)?,
            ast::ExprKind::Call { callee, args } => self.call(*callee, args)?,
            ast::ExprKind::Binary {
                op: BinOp::Slash,
                lhs,
                rhs,
            } => self.slash(loc, *lhs, *rhs)?,
        };
        Ok(Value::Typed(typed))
    }

    fn constant(loc: Loc, c: Const) -> TypedValue {
        let ty = Ty::of_const(&c);
        TypedValue {
            expr: Expr::new(loc, ExprKind::Const(c)),
            ty,
        }
    }

    fn local(&mut self, ident: Ident) -> Checked<Value> {
        let Ident { loc, name } = ident;
        let Some(binding) = self.bindings.get(&name) else {
            return Err(UnknownName(name).at(loc).into());
        };
        match binding.state {
            BindState::Slot(slot, ty) => Ok(Value::Typed(TypedValue {
                expr: Expr::new(loc, ExprKind::Local(slot)),
                ty,
            })),
            BindState::Const(ref c) => Ok(Value::Typed(Self::constant(loc, c.clone()))),
            BindState::Int(n) => Ok(Value::Int(loc, n)),
            BindState::Failed => Err(Stop::Poisoned),
        }
    }

    /// `module::inner*::item`, through the imports table. Errors point at the segment which
    /// failed.
    fn path(&mut self, loc: Loc, path: ModulePath) -> Checked<TypedValue> {
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
    fn member(&mut self, loc: Loc, obj: ast::Expr, name: Ident) -> Checked<TypedValue> {
        let (obj, cls) = match self.value(obj)? {
            Value::Typed(TypedValue {
                expr,
                ty: Ty::Class(cls),
            }) => (expr, cls),
            value => return Err(NoMembers(value.found()).at(name.loc).into()),
        };

        match cls.get(&name.name) {
            Some(Symbol::Func(func)) => {
                let obj = Box::new(obj);
                let expr = Expr::new(loc, ExprKind::Method { obj, func });
                Ok(TypedValue {
                    expr,
                    ty: Ty::Method(cls, func),
                })
            }
            Some(Symbol::Val(def)) => {
                // A Symbol::Val is a const property of the object. We can just const propagate it
                // in most cases. Unless we're doing f(...).prop, in which case if f() has
                // side-effects then we need to evaluate f().
                //
                // TODO: once functions are marked as having side effects or not, lower a property
                // of an object with no side effects to the constant alone. Reading a local has
                // none already.
                let TypedValue { expr: value, ty } =
                    Self::constant(name.loc, Const::from_def(*def));
                Ok(TypedValue {
                    expr: if obj.impure() {
                        let effects = Box::new([obj]);
                        let value = Box::new(value);
                        Expr::new(loc, ExprKind::Seq { effects, value })
                    } else {
                        value
                    },
                    ty,
                })
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
    fn call(&mut self, callee: ast::Expr, args: Box<[ast::Arg]>) -> Checked<TypedValue> {
        let loc = callee.name_loc();
        let (callee, func) = match self.value(callee)? {
            Value::Typed(TypedValue {
                expr,
                ty: Ty::Func(func) | Ty::Method(_, func),
            }) => (expr, func),
            value => return Err(NotCallable(value.found()).at(loc).into()),
        };

        let args = args
            .into_iter()
            .map(|ast::Arg { name, value }| {
                let value_loc = value.loc;
                let value = self.value(value)?;
                Ok(ArgIn {
                    name,
                    loc: value_loc,
                    value,
                })
            })
            .collect::<Checked<Vec<_>>>()?;

        let Bound { args, collect } =
            Bound::bind(func, loc, args, &mut |loc, warn| self.warn(loc, warn))?;
        let call = Call::new(callee, func, args, collect);
        Ok(TypedValue {
            expr: Expr::new(loc, ExprKind::Call(Box::new(call))),
            ty: Ty::of_return(func),
        })
    }

    /// `ip / port`. A port wider than `u16` keeps its low bits, with a warning. If both operands'
    /// values are constants, it folds, keeping the operands' effects in source order.
    fn slash(&mut self, loc: Loc, lhs: ast::Expr, rhs: ast::Expr) -> Checked<TypedValue> {
        let ip = self.typed_value(lhs, Ty::Ip4, |found| OperandType {
            op: BinOp::Slash,
            side: Side::Left,
            expected: Ty::Ip4,
            found,
        })?;

        let port = self.integral(rhs, Ty::U16, |found| OperandType {
            op: BinOp::Slash,
            side: Side::Right,
            expected: Ty::U16,
            found,
        })?;

        // Only when every operand's value is a constant: an effect hoisted out of an operand would
        // otherwise run before the operands to its left
        if let Some(addr) = ip.value().const_ip4()
            && let Some(num) = port.value().const_u16()
        {
            let val = Const::Sock4(SocketAddrV4::new(addr, num));
            let effects = [ip, port].into_iter().flat_map(|e| e.split().0).collect();
            return Ok(TypedValue {
                expr: Expr::seq(loc, effects, Expr::new(loc, ExprKind::Const(val))),
                ty: Ty::Sock4,
            });
        }

        let kind = ExprKind::SockAddr {
            ip: Box::new(ip),
            port: Box::new(port),
        };
        Ok(TypedValue {
            expr: Expr::new(loc, kind),
            ty: Ty::Sock4,
        })
    }
}
