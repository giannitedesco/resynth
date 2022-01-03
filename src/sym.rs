use crate::libapi::{Module, FuncDef};
use crate::val::ValDef;

#[derive(Debug, Copy, Clone)]
pub(crate) enum Symbol {
    Module(&'static Module),
    Func(&'static FuncDef),
    Val(ValDef),
}

impl Eq for Symbol {}
impl PartialEq for Symbol {
    fn eq(&self, other: &Symbol) -> bool {
        match self {
            Symbol::Module(a) => {
                if let Symbol::Module(b) = other {
                    std::ptr::eq((*a) as *const Module, (*b) as *const Module)
                } else {
                    false
                }
            },
            Symbol::Func(a) => {
                if let Symbol::Func(b) = other {
                    std::ptr::eq((*a) as *const FuncDef, (*b) as *const FuncDef)
                } else {
                    false
                }
            },
            Symbol::Val(a) => {
                if let Symbol::Val(b) = other {
                    a == b
                } else {
                    false
                }
            },
        }
    }
}
