use crate::sym::Symbol;

pub trait Dispatchable {
    fn lookup_symbol(&self, name: &str) -> Option<Symbol>;
}
