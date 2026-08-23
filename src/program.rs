use crate::args::{ArgExpr, ArgSpec};
use crate::err::Error;
use crate::err::Error::{
    ImportError, MultipleAssignError, NameError, NotAModule, NotAValue, NotCallable, NotImported,
    TooManyComponents, TypeError,
};
use crate::libapi::{FuncDef, Module};
use crate::loc::Loc;
use crate::object::ObjRef;
use crate::parse::{Assign, Call, Expr, Import, ObjectRef, Stmt};
use crate::stdlib::toplevel_module;
use crate::sym::Symbol;
use crate::val::{Typed, Val, ValType};

use pkt::PcapWriter;

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::rc::Rc;

type WarningCallback<'a> = &'a mut dyn FnMut(Loc, &str);

/// The interpreter and program-state
pub struct Program<'a> {
    now: u64,
    regs: HashMap<String, Val>,
    imports: HashMap<String, &'static Module>,
    wr: Option<PcapWriter>,
    loc: Loc,
    warning: Option<WarningCallback<'a>>,
}

impl<'a> Program<'a> {
    pub fn dummy() -> Result<Self, Error> {
        Ok(Program {
            now: 0,
            regs: HashMap::new(),
            imports: HashMap::new(),
            wr: None,
            loc: Loc::nil(),
            warning: None,
        })
    }

    pub fn with_pcap_writer(wr: PcapWriter) -> Result<Self, Error> {
        Ok(Program {
            now: 0,
            regs: HashMap::new(),
            imports: HashMap::new(),
            wr: Some(wr),
            loc: Loc::nil(),
            warning: None,
        })
    }

    pub fn loc(&self) -> Loc {
        self.loc
    }

    pub fn set_warning(&mut self, warning: WarningCallback<'a>) {
        self.warning = Some(warning);
    }

    pub fn execute(stmts: Vec<Stmt>, wr: PcapWriter) -> Result<Self, Error> {
        let mut prog = Self::with_pcap_writer(wr)?;
        prog.add_stmts(stmts)?;
        Ok(prog)
    }

    fn import(&mut self, name: &str, module: &'static Module) -> Result<(), Error> {
        self.imports.insert(name.to_owned(), module);
        Ok(())
    }

    fn store(&mut self, name: &str, val: Val) -> Result<(), Error> {
        self.regs.insert(name.to_owned(), val);
        Ok(())
    }

    pub fn eval_extern_ref(&self, obj: ObjectRef) -> Result<Val, Error> {
        let toplevel = &obj.modules[0];

        /* Lookup the first item in the imports table */
        let mut top = self
            .imports
            .get(toplevel)
            .ok_or_else(|| NotImported(toplevel.as_str().into()))?;

        /* All the double-colon components must be submodules */
        for c in obj.modules.iter().skip(1) {
            top = match top.get(c) {
                Some(Symbol::Module(module)) => module,
                None => return Err(NameError(c.as_str().into())),
                _ => return Err(NotAModule(c.as_str().into())),
            }
        }

        let topvar = &obj.components[0];
        let ret: Val = match top.get(topvar) {
            Some(Symbol::Val(valdef)) => (*valdef).into(),
            Some(Symbol::Func(fndef)) => (*fndef).into(),
            Some(Symbol::Module(_)) | Some(Symbol::Class(_)) => {
                return Err(NotAValue(topvar.as_str().into()));
            }
            None => return Err(NameError(topvar.as_str().into())),
        };

        /* We only support functions and string variables in stdlib right now */
        if obj.components.len() > 1 {
            unreachable!("multi-component external references are not supported");
        }

        Ok(ret)
    }

    pub fn eval_local_ref(&self, obj: ObjectRef) -> Result<Val, Error> {
        if obj.components.len() > 2 {
            return Err(TooManyComponents(obj.components.join(".").into()));
        }

        let var_name = &obj.components[0];
        let val = self
            .regs
            .get(var_name)
            .ok_or_else(|| NameError(var_name.as_str().into()))?;

        if obj.components.len() == 1 {
            return Ok(val.clone());
        }

        let method_name = &obj.components[1];
        val.method_lookup(method_name)
    }

    pub fn eval_obj_ref(&self, obj: ObjectRef) -> Result<Val, Error> {
        if !obj.modules.is_empty() {
            self.eval_extern_ref(obj)
        } else if !obj.components.is_empty() {
            self.eval_local_ref(obj)
        } else {
            unreachable!();
        }
    }

    fn eval_args(&mut self, argexprs: Vec<ArgExpr>) -> Result<Vec<ArgSpec>, Error> {
        let mut ret = Vec::new();

        for x in argexprs {
            let ArgExpr { name, expr } = x;
            let val = self.eval(expr)?;
            ret.push(ArgSpec::new(name, val));
        }

        ret.shrink_to_fit();
        Ok(ret)
    }

    fn eval_callable(
        &mut self,
        func: &'static FuncDef,
        this: Option<ObjRef>,
        argexprs: Vec<ArgExpr>,
    ) -> Result<Val, Error> {
        let argvals = self.eval_args(argexprs)?;
        let args = func.args(this, argvals)?;

        /* Finally, we're ready to make the call */
        let ret = (func.exec)(args)?;

        /* This is a debug_assert because the stdlib is not user-defined */
        debug_assert!(ret.val_type() == func.return_type);

        Ok(ret)
    }

    pub fn eval_call(&mut self, call: Call) -> Result<Val, Error> {
        match self.eval_obj_ref(call.obj)? {
            Val::Func(f) => self.eval_callable(f, None, call.args),
            Val::Method(obj, f) => self.eval_callable(f, Some(obj), call.args),
            other => Err(NotCallable(other.val_type())),
        }
    }

    pub fn eval(&mut self, expr: Expr) -> Result<Val, Error> {
        Ok(match expr {
            Expr::Nil => Val::Nil,
            Expr::Literal(loc, lit) => {
                self.loc = loc;
                lit
            }
            Expr::ObjectRef(obj) => {
                self.loc = obj.loc;
                self.eval_obj_ref(obj)?
            }
            Expr::Call(call) => {
                self.loc = call.obj.loc;
                self.eval_call(call)?
            }
            Expr::Slash(a, b) => {
                let a = self.eval(*a)?;
                if !a.is_type(ValType::Ip4) {
                    return Err(TypeError);
                }

                let a_loc = self.loc;

                let b = self.eval(*b)?;
                if !b.is_integral() {
                    return Err(TypeError);
                }

                /* TODO: Perhaps use location of the operator? */
                self.loc = a_loc;

                Val::Sock4(SocketAddrV4::new(a.into(), b.into()))
            }
        })
    }

    pub fn add_stmts(&mut self, stmts: Vec<Stmt>) -> Result<(), Error> {
        for stmt in stmts {
            self.add_stmt(stmt)?;
        }

        Ok(())
    }

    pub fn add_stmt(&mut self, stmt: Stmt) -> Result<(), Error> {
        match stmt {
            Stmt::Import(import) => self.add_import(import)?,
            Stmt::Assign(assign) => self.add_assign(assign)?,
            Stmt::Expr(expr) => self.add_expr(expr)?,
        };
        Ok(())
    }

    pub fn add_import(&mut self, import: Import) -> Result<(), Error> {
        let name = import.module.as_str();

        self.loc = import.loc;

        if self.imports.contains_key(name) {
            if let Some(ref mut func) = self.warning {
                (func)(self.loc, &format!("multiple imports of {:?}", name));
            }
            return Ok(());
        }

        match toplevel_module(name) {
            None => {
                return Err(ImportError(name.into()));
            }
            Some(module) => {
                self.import(name, module)?;
            }
        }

        Ok(())
    }

    pub fn add_assign(&mut self, assign: Assign) -> Result<(), Error> {
        let name = assign.target.as_str();

        self.loc = assign.loc;

        if self.regs.contains_key(name) {
            return Err(MultipleAssignError(name.into()));
        }

        let val = self.eval(assign.rvalue)?;

        self.store(name, val)?;

        Ok(())
    }

    pub fn update_time(&mut self, ns: u64) {
        self.now += ns;
    }

    pub fn add_expr(&mut self, expr: Expr) -> Result<(), Error> {
        let val = self.eval(expr)?;
        match val {
            Val::Nil => {}
            Val::Pkt(mut ptr) => {
                self.update_time(ptr.bit_time());

                /* XXX: cloning the packet here is wasteful */
                if let Some(ref mut wr) = self.wr {
                    let pkt = Rc::make_mut(&mut ptr);

                    wr.write_packet(self.now, pkt)
                        .expect("failed to write packet");
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
                            .expect("failed to write packet");
                    }
                };
            }
            Val::TimeJump(ns) => self.update_time(ns),
            _ => {
                if let Some(ref mut func) = self.warning {
                    (func)(self.loc, &format!("discarded value {:?}", val));
                }
            }
        };
        Ok(())
    }
}
