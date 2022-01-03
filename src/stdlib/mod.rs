use phf::phf_map;

use crate::err::Error;
use crate::err::Error::RuntimeError;
use crate::libapi::Module;
use crate::sym::Symbol;
use crate::val::Val;
use crate::args::Args;

#[allow(unused)]
fn unimplemented(mut args: Args) -> Result<Val, Error> {
    println!("Unimplemented stdlib call");
    args.void();
    Err(RuntimeError)
}

mod text;
mod ipv4;
mod dns;

use text::TEXT;
use ipv4::IPV4;
use dns::DNS;

const STDLIB: phf::Map<&'static str, Symbol> = phf_map! {
    "text" => Symbol::Module(&TEXT),
    "ipv4" => Symbol::Module(&IPV4),
    "dns" => Symbol::Module(&DNS),
};

pub(crate) fn toplevel_module(name: &str) -> Option<&'static Module> {
    match STDLIB.get(name) {
        None => None,
        Some(Symbol::Module(module)) => Some(module),
        Some(Symbol::Func(_)) | Some(Symbol::Val(_)) => {
            /* There shouldn't be any top level function or variable */
            unreachable!();
        },
    }
}
