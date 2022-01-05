use phf::{phf_map, phf_ordered_map};

use crate::err::Error;
use crate::val::{ValType, Val, ValDef};
use crate::libapi::FuncDef;
use crate::sym::Symbol;
use crate::args::Args;
use crate::func_def;

fn text_crlflines(mut args: Args) -> Result<Val, Error> {
    Ok(args.join_extra(b"\r\n"))
}

const TEXT_CRLFLINES: FuncDef = func_def!(
    "crlflines";
    ValType::Str;

    =>
    =>
    ValType::Str;

    text_crlflines
);

pub const TEXT: phf::Map<&'static str, Symbol> = phf_map! {
    "crlflines" => Symbol::Func(&TEXT_CRLFLINES),
    "CRLF" => Symbol::Val(ValDef::Str(b"\r\n")),
};
