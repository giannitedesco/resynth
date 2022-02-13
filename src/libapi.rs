use crate::err::Error;
use crate::err::Error::TypeError;
use crate::val::{Val, ValType, ValDef, Typed};
use crate::object::ObjRef;
use crate::args::{Args, ArgVec, ArgSpec};
use crate::sym::Symbol;

use std::fmt::Debug;

/// Argument declarator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgDecl {
    Positional(ValType),
    Named(ValDef),
}

/// Defines a function or method for the resynth stdlib
#[derive(Debug)]
pub struct FuncDef {
    pub name: &'static str,
    pub return_type: ValType,
    pub args: phf::OrderedMap<&'static str, ArgDecl>,
    pub min_args: usize,
    pub collect_type: ValType,
    pub exec: fn(args: Args) -> Result<Val, Error>,
}

impl Eq for FuncDef {}
impl PartialEq for FuncDef {
    fn eq(&self, other: &FuncDef) -> bool {
        std::ptr::eq(self as *const FuncDef, other as *const FuncDef)
    }
}

/// A module is a mapping between names and [Symbol]
pub type Module = phf::Map<&'static str, Symbol>;

pub trait Class {
    fn symbols(&self) -> phf::Map<&'static str, Symbol>;
    fn class_name(&self) -> &'static str;
}

struct NamedArg {
    name: String,
    val: Val,
}

struct ArgPrep {
    anon: Vec<Val>,
    named: Vec<NamedArg>,
    extra: Vec<Val>,
}

impl FuncDef {
    pub fn is_collect(&self) -> bool {
        self.collect_type != ValType::Void
    }

    fn split_args(&self,
                      args: Vec<ArgSpec>,
                      ) -> Result<ArgPrep, Error> {
        enum State {
            Anon,
            Named,
            Extra,
            Unexpected,
        }

        let mut anon: Vec<Val> = Vec::new();
        let mut named: Vec<NamedArg> = Vec::new();
        let mut extra: Vec<Val> = Vec::new();
        let mut state = State::Anon;

        for arg in args {
            loop {
                match state {
                    State::Anon => {
                        if !arg.is_anon() {
                            state = State::Named;
                            continue;
                        } else if anon.len() >= self.min_args {
                            state = State::Extra;
                            continue;
                        } else {
                            let ArgSpec { name: _, val } = arg;
                            anon.push(val);
                            break;
                        }
                    },
                    State::Named => {
                        if let ArgSpec { name: Some(name), val } = arg {
                            named.push(NamedArg { name, val });
                            break;
                        } else {
                            state = State::Extra;
                            continue;
                        }
                    },
                    State::Extra => {
                        if !self.is_collect() {
                            println!("ERR: Unexpected extra arguments");
                            return Err(TypeError);
                        }else if !arg.is_anon() {
                            state = State::Unexpected;
                            continue;
                        } else {
                            let ArgSpec { name: _, val } = arg;
                            extra.push(val);
                            break;
                        }
                    },
                    State::Unexpected => {
                        println!("ERR: Unexpected named arguments");
                        return Err(TypeError);
                    }
                }
            }
        }

        anon.shrink_to_fit();
        named.shrink_to_fit();
        extra.shrink_to_fit();

        Ok(ArgPrep {anon, named, extra})
    }

    pub fn argvec(&self, this: Option<ObjRef>, args: Vec<ArgSpec>) -> Result<ArgVec, Error> {
        let ArgPrep {anon, named, extra} = self.split_args(args)?;
        let nr_anon = anon.len();
        let nr_named = named.len();
        let nr_specified = nr_anon + nr_named;

        // Now do some basic sanity checks to stup us shooting ourselves in the foot later
        if nr_specified < self.min_args {
            println!("ERR: Not enough specified args: {} ({} + {}) < {}",
                     nr_specified,
                     nr_anon,
                     nr_named,
                     self.min_args);
            return Err(TypeError);
        }

        if nr_anon > self.args.len() {
            println!("ERR: Too many positional args: {} > {}",
                     nr_anon,
                     self.args.len());
            return Err(TypeError);
        }

        if self.is_collect() && extra.iter().any(|x| !self.collect_type.compatible_with(x)) {
            println!("ERR: Collect argument of wrong type");
            return Err(TypeError);
        }

        // Now we actually start building the args struct
        let mut args: Vec<Val> = Vec::with_capacity(self.args.len());

        // 1. push anon vals to start with
        for a in anon {
            args.push(a);
        }

        // 2. Fill in up to min_args with voids
        for _ in nr_anon..self.min_args {
            args.push(Val::Nil);
        }

        // 3. Fill in defaults for named args
        for dfl in self.args.values().skip(self.min_args) {
            if let ArgDecl::Named(val) = dfl {
                args.push((*val).into());
            } else {
                unreachable!();
            }
        }

        // 4. Go over named arguments using map.get_index() to overwrite vals
        for spec in named {
            let NamedArg {name, val} = spec;

            if let Some(i) = self.args.get_index(&name) {
                args[i] = val;
            } else {
                println!("ERR: Unknown arg: {}", &name);
                return Err(TypeError);
            }
        }

        // 5. Check all mandatory args have been filled in
        for val in &args[..self.min_args] {
            if val.is_nil() {
                println!("ERR: Mandatory argument not passed");
                return Err(TypeError);
            }
        }

        // 6. Final type-check of all positional args
        for ((name, spec), arg) in self.args.entries().zip(args.iter()) {
            if !match spec {
                ArgDecl::Positional(typ) => { typ.compatible_with(arg) }
                ArgDecl::Named(dfl) => { dfl.arg_compatible(arg) },
            } {
                println!("ERR: Argument type-check failed for {:?}", name);
                return Err(TypeError);
            }
        }

        Ok(ArgVec::new(this, args, extra))
    }

    pub fn args(&self, this: Option<ObjRef>, args: Vec<ArgSpec>) -> Result<Args, Error> {
        Ok(self.argvec(this, args)?.into())
    }
}
