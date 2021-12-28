use crate::parse::{ObjectRef, Call, Expr, Import, Assign, Stmt};
use crate::err::Error;
use crate::err::Error::{ImportError, NameError, TypeError, MultipleAssignError};
use crate::val::{Val, FuncDef, ObjRef, Args, Symbol, Module};
use crate::pkt::PcapWriter;
use crate::stdlib::toplevel_module;

use std::rc::Rc;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Program {
    regs: HashMap<String, Val>,
    imports: HashMap<String, &'static Module>,
    wr: Option<PcapWriter>,
}

impl Program {
    #[allow(unused)]
    pub fn dummy() -> Result<Self, Error> {
        Ok(Program {
            regs: HashMap::new(),
            imports: HashMap::new(),
            wr: None,
        })
    }

    pub fn with_pcap_writer(wr: PcapWriter) -> Result<Self, Error> {
        Ok(Program {
            regs: HashMap::new(),
            imports: HashMap::new(),
            wr: Some(wr),
        })
    }

    #[allow(unused)]
    pub fn execute(stmts: Vec<Stmt>, wr: PcapWriter) -> Result<Self, Error> {
        let mut prog = Self::with_pcap_writer(wr)?;
        prog.add_stmts(stmts)?;
        Ok(prog)
    }

    fn import(&mut self, name: &str, module: &'static Module) -> Result<(), Error> {
        self.imports.insert(
            name.to_owned(),
            module,
        );
        Ok(())
    }

    fn store(&mut self, name: &str, val: Val) -> Result<(), Error> {
        //println!("let {} := {:?}", name, val);
        //println!();
        self.regs.insert(
            name.to_owned(),
            val
        );
        Ok(())
    }

    pub fn eval_extern_ref(&self, obj: ObjectRef) -> Result<Val, Error> {
        let toplevel = &obj.modules[0];

        //println!("eval extern {:?}", obj);

        /* Lookup the first item in the imports table */
        let mut top = match self.imports.get(toplevel) {
            None => {
                println!("You have not imported {}", toplevel);
                return Err(NameError);
            },
            Some(module) => module,
        };

        /* All the double-colon components must be submodules */
        for c in obj.modules.iter().skip(1) {
            top = match top.get(c) {
                Some(Symbol::Module(module)) => module,
                None => {
                    println!("Can't find module component: {}", c);
                    return Err(NameError);
                },
                _ => {
                    println!("Component is not module: {}", c);
                    return Err(TypeError);
                },
            }
        }

        let topvar = &obj.components[0];
        let ret: Val = match top.get(topvar) {
            Some(Symbol::Val(valdef)) => valdef.into(),
            Some(Symbol::Func(fndef)) => fndef.into(),
            Some(Symbol::Module(_)) => {
                println!("Component is a module, cannot be a variable: {}", topvar);
                return Err(TypeError);
            },
            None => {
                println!("Can't find ref component: {}", topvar);
                return Err(NameError);
            },
        };

        for c in obj.components.iter().skip(1) {
            /* We only support functions and string variables in stdlib right now */
            println!(" > comp: lookup {}", c);
            unreachable!();
        }

        Ok(ret)
    }

    pub fn eval_local_ref(&self, obj: ObjectRef) -> Result<Val, Error> {
        if obj.components.len() > 2 {
            println!("too many components in object: {:?}", obj);
            return Err(NameError)
        }

        let var_name = &obj.components[0];
        let val = self.regs.get(var_name).ok_or(NameError)?;

        if obj.components.len() == 1 {
            return Ok(val.clone());
        }

        let method_name = &obj.components[1];
        val.method_lookup(method_name)
    }

    pub fn eval_obj_ref(&self, obj: ObjectRef) -> Result<Val, Error> {
        if obj.modules.len() > 0 {
            self.eval_extern_ref(obj)
        }else if obj.components.len() > 0 {
            self.eval_local_ref(obj)
        } else {
            unreachable!();
        }
    }

    fn eval_callable(&self,
                     func: &'static FuncDef,
                     obj: Option<&ObjRef>,
                     arg_exprs: Vec<Expr>,
                     ) -> Result<Val, Error> {
        //dbg!(func);
        //dbg!(&arg_exprs);

        /* First check we have at least enough positiuonal args */
        if arg_exprs.len() < func.args.len() {
            println!("{}: Not enough arguments: expected {}, got {}",
                     func.name, func.args.len(), arg_exprs.len());
            return Err(TypeError);
        }

        /* Now evaluate all args */
        let mut args_vec = Vec::new();
        for expr in arg_exprs {
            let arg = self.eval(expr)?;
            args_vec.push(arg);
        }

        /* Check the types of the positional args */
        for (arg, expected_type) in args_vec.iter().zip(func.args.iter()) {
            if arg.val_type() != *expected_type {
                println!("Got {:?} but expected {:?}", &arg.val_type(), expected_type);
                return Err(TypeError);
            }
        }

        /* Check the types of the remaining args */
        for arg in args_vec[func.args.len()..].iter() {
            if arg.val_type() != func.collect_type {
                println!("Got {:?} but expected {:?}", &arg.val_type(), func.collect_type);
                return Err(TypeError);
            }
        }

        /* We're going to consume the args in to two new vecs now: positional and collect */
        let mut arg_vals = args_vec.into_iter();

        /* For positional, prepend the 'self' pointer if this is a method call */
        let pos_args = if let Some(this) = obj {
            let mut v: Vec<Val> = vec!(Val::Obj(this.clone()));
            v.extend((&mut arg_vals).take(func.args.len()));
            v
        } else {
            (&mut arg_vals).take(func.args.len()).collect()
        };

        let extra: Vec<Val> = arg_vals.collect();

        //dbg!(&pos_args);
        //dbg!(&extra);

        /* Finally, we're ready to make the call */
        let ret = (func.exec)(Args::from(pos_args, extra))?;

        /* This is an assert because the stdlib is not user-defined */
        //println!("{:?} {:?}", ret.val_type(), func.return_type);
        debug_assert!(ret.val_type() == func.return_type);
        //println!();

        Ok(ret)
    }

    pub fn eval_call(&self, call: Call) -> Result<Val, Error> {
        match self.eval_obj_ref(call.obj)? {
            Val::Func(f) => self.eval_callable(f, None, call.args),
            Val::Method(obj, f) => self.eval_callable(f, Some(&obj), call.args),
            other => {
                println!("Not callable: {:?}", other);
                Err(TypeError)
            }
        }
    }

    pub fn eval(&self, expr: Expr) -> Result<Val, Error> {
        Ok(match expr {
            Expr::Literal(lit) => lit,
            Expr::ObjectRef(obj) => self.eval_obj_ref(obj)?,
            Expr::Call(call) => self.eval_call(call)?,
        })
    }

    pub fn add_stmts(&mut self, stmts: Vec<Stmt>) -> Result<(), Error> {
        for stmt in stmts {
            self.add_stmt(stmt)?;
        }

        Ok(())
    }

    pub fn add_stmt(&mut self, stmt: Stmt) -> Result<(), Error> {
        //println!("{:?}", stmt);
        match stmt {
            //Stmt::Nop => self,
            Stmt::Import(import) => self.add_import(import)?,
            Stmt::Assign(assign) => self.add_assign(assign)?,
            Stmt::Expr(expr) => self.add_expr(expr)?,
        };
        Ok(())
    }

    pub fn add_import(&mut self, import: Import) -> Result<(), Error> {
        let name = &import.module;

        if self.imports.get(name).is_some() {
            println!("Multiple imports of {:?}", name);
            return Ok(());
        }

        match toplevel_module(name) {
            None => {
                println!("import: unknown module: {:?}", name);
                return Err(ImportError);
            }
            Some(module) => {
                self.import(name, module)?;
            }
        }

        Ok(())
    }

    pub fn add_assign(&mut self, assign: Assign) -> Result<(), Error> {
        let name = &assign.target;

        if self.regs.get(name).is_some() {
            return Err(MultipleAssignError(name.to_owned()));
        }

        let val = self.eval(assign.rvalue)?;

        self.store(name, val)?;

        Ok(())
    }

    pub fn add_expr(&mut self, expr: Expr) -> Result<(), Error> {
        let val = self.eval(expr)?;
        match val {
            Val::Void => {},
            Val::Pkt(mut ptr) => {
                if let Some(ref mut wr) = self.wr {
                    /* FIXME: error handling */
                    let pkt = Rc::get_mut(&mut ptr).unwrap();
                    wr.write_packet(pkt).expect("failed to write packet");
                };
            }
            Val::PktGen(mut gen) => {
                if let Some(ref mut wr) = self.wr {
                    let inner = Rc::get_mut(&mut gen).unwrap();
                    for pkt in inner {
                        wr.write_packet(pkt).expect("failed to write packet");
                    }
                };
            }
            _ => {
                println!("warning: discarded {:?}", val);
            }
        };
        Ok(())
    }
}
