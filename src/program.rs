use crate::args::ArgSpec;
use crate::ast::{Arg, BinOp, Expr, ExprKind, Ident, ModulePath, Stmt};
use crate::libapi::{FuncDef, Module};
use crate::loc::Loc;
use crate::object::ObjRef;
use crate::stdlib::toplevel_module;
use crate::sym::Symbol;
use crate::val::{Typed, Val, ValType};

use pkt::PcapWriter;

use derive_more::{Display, Error, From};

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddrV4;

use RuntimeErrorKind::{
    ImportError, MultipleAssignError, NameError, NotAModule, NotAValue, NotCallable, NotImported,
    PcapWrite, PortOutOfRange, TypeError,
};

/// Why the program could not be run, and where
#[derive(Debug, Display, Error)]
#[display("{loc}: {kind}")]
pub struct RuntimeError {
    /// The name or expression which failed, or the statement which wrote a packet
    pub loc: Loc,
    pub kind: RuntimeErrorKind,
}

/// What went wrong while running the program
#[derive(Debug, Display, Error, From)]
pub enum RuntimeErrorKind {
    /// An I/O error in the stdlib, such as `io::file` failing to read its file
    #[display("{}", _0)]
    #[from]
    IoError(io::Error),

    /// Writing a packet to the pcap failed
    #[display("{}", _0)]
    #[from(ignore)]
    PcapWrite(io::Error),

    #[display("import error: unknown module {:?}", _0)]
    #[error(ignore)]
    ImportError(Box<str>),

    #[display("unknown name {:?}", _0)]
    #[error(ignore)]
    NameError(Box<str>),

    #[display("type error")]
    TypeError,

    /// The right of `ip / port` is more than `u16::MAX`
    #[display("port {} out of range", _0)]
    #[error(ignore)]
    PortOutOfRange(u64),

    #[display("unimplemented stdlib call")]
    LibTodo,

    #[display("{}", _0)]
    #[error(ignore)]
    LibError(Cow<'static, str>),

    #[display("variable {:?} reassigned", _0)]
    #[error(ignore)]
    MultipleAssignError(Box<str>),

    #[display("module {:?} not imported", _0)]
    #[error(ignore)]
    NotImported(Box<str>),

    #[display("{:?} is not a module", _0)]
    #[error(ignore)]
    NotAModule(Box<str>),

    #[display("{:?} is not a value", _0)]
    #[error(ignore)]
    NotAValue(Box<str>),

    #[display("value of type {} is not callable", _0)]
    #[error(ignore)]
    NotCallable(ValType),

    #[display("{func}: too many arguments: {got} > {want}")]
    #[error(ignore)]
    TooManyArgs {
        func: Box<str>,
        got: usize,
        want: usize,
    },

    #[display("{func}: no such argument: {arg:?}")]
    #[error(ignore)]
    NoSuchArg { func: Box<str>, arg: Box<str> },

    #[display("{func}: argument {arg:?} multiply specified")]
    #[error(ignore)]
    ArgMultiplySpecified { func: Box<str>, arg: Box<str> },

    #[display("{func}: unexpected collect-arguments")]
    #[error(ignore)]
    UnexpectedCollectArgs { func: Box<str> },

    #[display("{func}: unexpected named argument: {arg:?}")]
    #[error(ignore)]
    UnexpectedNamedArg { func: Box<str>, arg: Box<str> },

    #[display("{func}: not enough arguments: {got} < {want}")]
    #[error(ignore)]
    TooFewArgs {
        func: Box<str>,
        got: usize,
        want: usize,
    },

    #[display("{func}: argument {arg:?} not specified")]
    #[error(ignore)]
    MissingArg { func: Box<str>, arg: Box<str> },

    #[display("{func}: argument {arg:?} has the wrong type")]
    #[error(ignore)]
    ArgTypeMismatch { func: Box<str>, arg: Box<str> },

    #[display("{func}: collect argument has the wrong type")]
    #[error(ignore)]
    CollectArgTypeMismatch { func: Box<str> },
}

impl RuntimeErrorKind {
    /// This error, at `loc`
    pub(crate) fn at(self, loc: Loc) -> RuntimeError {
        RuntimeError { loc, kind: self }
    }
}

type WarningCallback<'a> = &'a mut dyn FnMut(Loc, &str);

type Result<T> = std::result::Result<T, RuntimeError>;

/// The interpreter and program-state
pub struct Program<'a> {
    now: Cell<u64>,
    regs: HashMap<String, Val>,
    imports: HashMap<String, &'static Module>,
    wr: Option<PcapWriter>,
    warning: Option<WarningCallback<'a>>,
}

impl<'a> Program<'a> {
    pub fn dummy() -> Self {
        Program {
            now: Cell::new(0),
            regs: HashMap::new(),
            imports: HashMap::new(),
            wr: None,
            warning: None,
        }
    }

    pub fn with_pcap_writer(wr: PcapWriter) -> Self {
        Program {
            now: Cell::new(0),
            regs: HashMap::new(),
            imports: HashMap::new(),
            wr: Some(wr),
            warning: None,
        }
    }

    pub fn set_warning(&mut self, warning: WarningCallback<'a>) {
        self.warning = Some(warning);
    }

    fn warn(&mut self, loc: Loc, msg: &str) {
        if let Some(ref mut func) = self.warning {
            (func)(loc, msg);
        }
    }

    /// Run each statement in turn, stopping at the first error
    pub fn run(&mut self, stmts: impl IntoIterator<Item = Stmt>) -> Result<()> {
        for stmt in stmts {
            match stmt {
                Stmt::Import(module) => self.add_import(module)?,
                Stmt::Let { target, value } => self.add_let(target, value)?,
                Stmt::Expr(expr) => self.add_expr(expr)?,
            }
        }

        Ok(())
    }

    /// Flush the pcap writer, if there is one, and report any error. Dropping the program
    /// flushes too, but ignores any error.
    pub fn flush(self) -> io::Result<()> {
        match self.wr {
            Some(wr) => wr.flush(),
            None => Ok(()),
        }
    }

    /// Look up a `module::inner*::item` path, reporting errors at the segment which failed
    fn eval_module_path(&self, path: ModulePath) -> Result<Val> {
        let ModulePath {
            module,
            inner,
            item,
        } = path;

        /* Lookup the first item in the imports table */
        let mut top = self
            .imports
            .get(&*module.name)
            .ok_or(NotImported(module.name).at(module.loc))?;

        /* All the double-colon components must be submodules */
        for seg in inner {
            top = match top.get(&seg.name) {
                Some(Symbol::Module(module)) => module,
                None => return Err(NameError(seg.name).at(seg.loc)),
                _ => return Err(NotAModule(seg.name).at(seg.loc)),
            }
        }

        match top.get(&item.name) {
            Some(Symbol::Val(valdef)) => Ok((*valdef).into()),
            Some(Symbol::Func(fndef)) => Ok((*fndef).into()),
            Some(Symbol::Module(_)) | Some(Symbol::Class(_)) => {
                Err(NotAValue(item.name).at(item.loc))
            }
            None => Err(NameError(item.name).at(item.loc)),
        }
    }

    fn eval_local_ref(&self, ident: Ident) -> Result<Val> {
        self.regs
            .get(&*ident.name)
            .cloned()
            .ok_or(NameError(ident.name).at(ident.loc))
    }

    fn eval_args(&mut self, args: Box<[Arg]>) -> Result<Vec<ArgSpec>> {
        args.into_iter()
            .map(|Arg { name, value }| {
                let val = self.eval(value)?;
                Ok(ArgSpec::new(name.map(|n| n.name.into_string()), val))
            })
            .collect()
    }

    /// Call a function, reporting errors from argument binding and from the function itself at
    /// `loc`, the name being called
    fn eval_callable(
        &mut self,
        loc: Loc,
        func: &'static FuncDef,
        this: Option<ObjRef>,
        args: Box<[Arg]>,
    ) -> Result<Val> {
        let argvals = self.eval_args(args)?;
        let args = func.args(this, argvals).map_err(|kind| kind.at(loc))?;

        /* Finally, we're ready to make the call */
        let ret = (func.exec)(args).map_err(|kind| kind.at(loc))?;

        /* This is a debug_assert because the stdlib is not user-defined */
        debug_assert!(ret.val_type() == func.return_type);

        Ok(ret)
    }

    fn eval_call(&mut self, callee: Expr, args: Box<[Arg]>) -> Result<Val> {
        let loc = callee.name_loc();
        match self.eval(callee)? {
            Val::Func(f) => self.eval_callable(loc, f, None, args),
            Val::Method(obj, f) => self.eval_callable(loc, f, Some(obj), args),
            other => Err(NotCallable(other.val_type()).at(loc)),
        }
    }

    pub fn eval(&mut self, expr: Expr) -> Result<Val> {
        Ok(match expr.kind {
            ExprKind::Literal(lit) => lit.into(),
            ExprKind::LocalRef(ident) => self.eval_local_ref(ident)?,
            ExprKind::ModulePath(path) => self.eval_module_path(*path)?,
            ExprKind::Member { obj, name } => self
                .eval(*obj)?
                .method_lookup(&name.name)
                .map_err(|kind| kind.at(name.loc))?,
            ExprKind::Call { callee, args } => self.eval_call(*callee, args)?,
            ExprKind::Binary {
                op: BinOp::Slash,
                lhs,
                rhs,
            } => {
                let (a_loc, b_loc) = (lhs.loc, rhs.loc);

                let a = self.eval(*lhs)?;
                if !a.is_type(ValType::Ip4) {
                    return Err(TypeError.at(a_loc));
                }

                let b = self.eval(*rhs)?;
                if !b.is_integral() {
                    return Err(TypeError.at(b_loc));
                }
                let port = u64::from(b);
                let port = u16::try_from(port).map_err(|_| PortOutOfRange(port).at(b_loc))?;

                Val::Sock4(SocketAddrV4::new(a.into(), port))
            }
        })
    }

    fn add_import(&mut self, module: Ident) -> Result<()> {
        let Ident { loc, name } = module;

        if self.imports.contains_key(&*name) {
            self.warn(loc, &format!("multiple imports of {:?}", name));
            return Ok(());
        }

        match toplevel_module(&name) {
            None => Err(ImportError(name).at(loc)),
            Some(module) => {
                self.imports.insert(name.into_string(), module);
                Ok(())
            }
        }
    }

    fn add_let(&mut self, target: Ident, value: Expr) -> Result<()> {
        let Ident { loc, name } = target;

        if self.regs.contains_key(&*name) {
            return Err(MultipleAssignError(name).at(loc));
        }

        let val = self.eval(value)?;

        self.regs.insert(name.into_string(), val);

        Ok(())
    }

    pub fn update_time(&mut self, ns: u64) {
        self.now.set(self.now().saturating_add(ns));
    }

    pub fn now(&self) -> u64 {
        self.now.get()
    }

    fn add_expr(&mut self, expr: Expr) -> Result<()> {
        let loc = expr.loc;
        let val = self.eval(expr)?;
        match val {
            Val::Nil => {}
            Val::Pkt(pkt) => {
                self.update_time(pkt.bit_time());

                if let Some(ref mut wr) = self.wr {
                    wr.write_packet(self.now.get(), &pkt)
                        .map_err(|err| PcapWrite(err).at(loc))?;
                };
            }
            Val::PktGen(it) => {
                for pkt in it.iter() {
                    self.update_time(pkt.bit_time());
                    if let Some(ref mut wr) = self.wr {
                        wr.write_packet(self.now.get(), pkt)
                            .map_err(|err| PcapWrite(err).at(loc))?;
                    }
                }
            }
            Val::TimeJump(ns) => self.update_time(ns),
            _ => self.warn(loc, &format!("discarded value {:?}", val)),
        };
        Ok(())
    }
}
