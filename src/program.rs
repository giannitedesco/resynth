use crate::args::ArgSpec;
use crate::ast::{Arg, BinOp, Expr, ExprKind, Ident, ModulePath, Stmt};
use crate::err::Error;
use crate::err::Error::{
    ImportError, MultipleAssignError, NameError, NotAModule, NotAValue, NotCallable, NotImported,
    TypeError,
};
use crate::libapi::{FuncDef, Module};
use crate::loc::Loc;
use crate::object::ObjRef;
use crate::stdlib::toplevel_module;
use crate::sym::Symbol;
use crate::val::{Typed, Val, ValType};

use pkt::PcapWriter;

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::rc::Rc;

type WarningCallback<'a> = &'a mut dyn FnMut(Loc, &str);

type Result<T> = std::result::Result<T, (Loc, Error)>;

/// The interpreter and program-state
pub struct Program<'a> {
    now: u64,
    regs: HashMap<String, Val>,
    imports: HashMap<String, &'static Module>,
    wr: Option<PcapWriter>,
    warning: Option<WarningCallback<'a>>,
}

impl<'a> Program<'a> {
    pub fn dummy() -> Self {
        Program {
            now: 0,
            regs: HashMap::new(),
            imports: HashMap::new(),
            wr: None,
            warning: None,
        }
    }

    pub fn with_pcap_writer(wr: PcapWriter) -> Self {
        Program {
            now: 0,
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
    pub fn flush(self) -> std::io::Result<()> {
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
            .ok_or((module.loc, NotImported(module.name)))?;

        /* All the double-colon components must be submodules */
        for seg in inner {
            top = match top.get(&seg.name) {
                Some(Symbol::Module(module)) => module,
                None => return Err((seg.loc, NameError(seg.name))),
                _ => return Err((seg.loc, NotAModule(seg.name))),
            }
        }

        match top.get(&item.name) {
            Some(Symbol::Val(valdef)) => Ok((*valdef).into()),
            Some(Symbol::Func(fndef)) => Ok((*fndef).into()),
            Some(Symbol::Module(_)) | Some(Symbol::Class(_)) => {
                Err((item.loc, NotAValue(item.name)))
            }
            None => Err((item.loc, NameError(item.name))),
        }
    }

    fn eval_local_ref(&self, ident: Ident) -> Result<Val> {
        self.regs
            .get(&*ident.name)
            .cloned()
            .ok_or((ident.loc, NameError(ident.name)))
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
        let args = func.args(this, argvals).map_err(|err| (loc, err))?;

        /* Finally, we're ready to make the call */
        let ret = (func.exec)(args).map_err(|err| (loc, err))?;

        /* This is a debug_assert because the stdlib is not user-defined */
        debug_assert!(ret.val_type() == func.return_type);

        Ok(ret)
    }

    fn eval_call(&mut self, callee: Expr, args: Box<[Arg]>) -> Result<Val> {
        let loc = callee.name_loc();
        match self.eval(callee)? {
            Val::Func(f) => self.eval_callable(loc, f, None, args),
            Val::Method(obj, f) => self.eval_callable(loc, f, Some(obj), args),
            other => Err((loc, NotCallable(other.val_type()))),
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
                .map_err(|err| (name.loc, err))?,
            ExprKind::Call { callee, args } => self.eval_call(*callee, args)?,
            ExprKind::Binary {
                op: BinOp::Slash,
                lhs,
                rhs,
            } => {
                let (a_loc, b_loc) = (lhs.loc, rhs.loc);

                let a = self.eval(*lhs)?;
                if !a.is_type(ValType::Ip4) {
                    return Err((a_loc, TypeError));
                }

                let b = self.eval(*rhs)?;
                if !b.is_integral() {
                    return Err((b_loc, TypeError));
                }

                Val::Sock4(SocketAddrV4::new(a.into(), b.into()))
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
            None => Err((loc, ImportError(name))),
            Some(module) => {
                self.imports.insert(name.into_string(), module);
                Ok(())
            }
        }
    }

    fn add_let(&mut self, target: Ident, value: Expr) -> Result<()> {
        let Ident { loc, name } = target;

        if self.regs.contains_key(&*name) {
            return Err((loc, MultipleAssignError(name)));
        }

        let val = self.eval(value)?;

        self.regs.insert(name.into_string(), val);

        Ok(())
    }

    pub fn update_time(&mut self, ns: u64) {
        self.now += ns;
    }

    fn add_expr(&mut self, expr: Expr) -> Result<()> {
        let loc = expr.loc;
        let val = self.eval(expr)?;
        match val {
            Val::Nil => {}
            Val::Pkt(mut ptr) => {
                self.update_time(ptr.bit_time());

                /* XXX: cloning the packet here is wasteful */
                if let Some(ref mut wr) = self.wr {
                    let pkt = Rc::make_mut(&mut ptr);

                    wr.write_packet(self.now, pkt)
                        .map_err(|err| (loc, Error::IoError(err)))?;
                };
            }
            Val::PktGen(mut it) => {
                for pkt in it.iter() {
                    self.update_time(pkt.bit_time());
                }

                /* XXX: cloning the packets here is wasteful */
                if let Some(ref mut wr) = self.wr {
                    let inner = Rc::make_mut(&mut it);

                    for pkt in inner {
                        wr.write_packet(self.now, pkt)
                            .map_err(|err| (loc, Error::IoError(err)))?;
                    }
                };
            }
            Val::TimeJump(ns) => self.update_time(ns),
            _ => self.warn(loc, &format!("discarded value {:?}", val)),
        };
        Ok(())
    }
}
