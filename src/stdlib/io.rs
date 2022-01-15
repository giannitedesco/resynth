use std::os::unix::ffi::OsStrExt;
use std::ffi::OsStr;
use std::path::Path;
use std::fs::File;
use std::io::Read;

use phf::{phf_map, phf_ordered_map};

use crate::val::{ValType, Val};
use crate::libapi::{FuncDef, ArgDecl};
use crate::sym::Symbol;
use crate::str::Buf;
use crate::func_def;

const IO_FILE: FuncDef = func_def!(
    "file";
    ValType::Str;

    "filename" => ValType::Str,
    =>
    =>
    ValType::Str;

    |mut args| {
        let arg: Buf = args.next().into();
        let path = Path::new(OsStr::from_bytes(arg.as_ref()));
        let mut f = File::open(path)?;

        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;

        Ok(Val::Str(Buf::from(buf)))
    }
);

pub const MODULE: phf::Map<&'static str, Symbol> = phf_map! {
    "file" => Symbol::Func(&IO_FILE),
};
