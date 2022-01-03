use crate::sym::Symbol;

pub(crate) trait Dispatchable {
    fn lookup_symbol(&self, name: &str) -> Option<Symbol>;
}
