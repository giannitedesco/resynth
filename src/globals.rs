use std::collections::HashMap;

use crate::err::Error;
use crate::val::{Val, ModuleDef, FuncDef, ValDef, BytesObj};
use crate::stdlib::BUILTINS;

#[derive(Debug)]
pub enum Symbol {
    Module(&'static ModuleDef),
    Func(&'static FuncDef),
    StrObj(&'static ValDef),
}

#[derive(Debug)]
pub struct Globals {
    syms: HashMap<String, Symbol>,
}

impl Globals {
    pub fn new() -> Self {
        Self {
            syms: HashMap::new(),
        }
    }

    /*
    pub fn from(defs: &'static [ModuleDef]) -> Result<Self, Error> {
        Self::new().add_module_defs(defs)
    }*/

    pub fn from_builtins() -> Result<Self, Error> {
        Self::new().load_builtins()
    }

    pub fn add_module_defs(mut self, defs: &'static [ModuleDef]) -> Result<Self, Error> {
        for def in defs.iter() {
            self = self.add_module_def(def)?;
        }

        Ok(self)
    }

    pub fn add_module_def(self, def: &'static ModuleDef) -> Result<Self, Error> {
        self.add_submodule_def("", def)
    }

    pub fn add_submodule_def(mut self,
                             prefix: &str,
                             def: &'static ModuleDef,
                             ) -> Result<Self, Error> {
        let s = format!("{}::{}", prefix, def.name);

        for sub in def.subs.iter() {
            self = self.add_submodule_def(&s, sub)?;
        }

        for meth in def.funcs.iter() {
            self = self.add_func_def(&s, meth)?;
        }

        for var in def.vars.iter() {
            self = self.add_var_def(&s, var)?;
        }

        //println!("register module: {}", s);
        self.syms.insert(
            s,
            Symbol::Module(def),
        );

        Ok(self)
    }

    pub fn add_func_def(mut self,
                             prefix: &str,
                             def: &'static FuncDef,
                             ) -> Result<Self, Error> {
        let s = format!("{}.{}", prefix, def.name);

        //println!("register method: {}", s);
        self.syms.insert(
            s,
            Symbol::Func(def),
        );

        Ok(self)
    }

    pub fn add_var_def(mut self,
                             prefix: &str,
                             def: &'static ValDef,
                             ) -> Result<Self, Error> {
        let s = format!("{}.{}", prefix, def.name);

        //println!("register method: {}", s);
        self.syms.insert(
            s,
            Symbol::StrObj(def),
        );

        Ok(self)
    }

    pub fn load_builtins(self) -> Result<Self, Error> {
        self.add_module_defs(&BUILTINS)
    }

    pub fn lookup_toplevel(&self, name: &str) -> Option<&'static ModuleDef> {
        let q = format!("::{}", name);
        match self.syms.get(&q) {
            Some(Symbol::Module(r)) => Some(*r),
            _ => None
        }
    }

    pub fn lookup_module(&self, qname: &str) -> Option<&'static ModuleDef> {
        match self.syms.get(qname) {
            Some(Symbol::Module(r)) => Some(*r),
            _ => None
        }
    }

    pub fn lookup(&self, qname: &str) -> Option<Val> {
        match self.syms.get(qname) {
            Some(Symbol::Func(f)) => Some(Val::Func(f)),
            Some(Symbol::StrObj(s)) => Some(Val::Str(BytesObj::from(s.val))),
            Some(Symbol::Module(..)) => None,
            None => None
        }
    }
}
