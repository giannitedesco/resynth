use crate::libapi::{Module, FuncDef};
use crate::val::ValDef;

/// A symbol can either point to a [const value](ValDef), [another module](Module), or a [function
/// or method](FuncDef)
#[derive(Debug, Copy, Clone)]
pub enum Symbol {
    Module(&'static Module),
    Func(&'static FuncDef),
    Val(ValDef),
}

impl Symbol {
    /// This const initializer is a convenience helpers for describing modules in static/const
    /// structures where the From trait isn't allowed. Without this, the descriptions become very
    /// ponderous. ie. `Symbol::Val(ValDef::U64(123))` vs. `Symbol::int_val(123)`
    pub const fn int_val(val: u64) -> Self {
        Self::Val(ValDef::U64(val))
    }
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
