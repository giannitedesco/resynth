use phf::{phf_map, phf_ordered_map};

use crate::val::{ValType, ValDef};
use crate::libapi::FuncDef;
use crate::sym::Symbol;
use crate::func_def;

const TEXT_CRLFLINES: FuncDef = func_def!(
    "crlflines";
    ValType::Str;

    =>
    =>
    ValType::Str;

    |mut args| {
        Ok(args.join_extra(b"\r\n"))
    }
);

pub const MODULE: phf::Map<&'static str, Symbol> = phf_map! {
    "crlflines" => Symbol::Func(&TEXT_CRLFLINES),
    "CRLF" => Symbol::Val(ValDef::Str(b"\r\n")),
};
