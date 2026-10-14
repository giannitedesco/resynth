use crate::libapi::{FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

static CONCAT: FuncDef = func!(
    /// Concatenate strings
    resynth fn concat(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        Ok(args.join_extra(b""))
    }
);

static CRLFLINES: FuncDef = func!(
    /// join strings with CRLF line-endings
    resynth fn crlflines(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        Ok(args.join_extra(b"\r\n"))
    }
);

static LEN: FuncDef = func!(
    /// Return the length of a string (or strings)
    resynth fn len(
        =>
        =>
        Str
    ) -> U64
    |mut args| {
        let buf: Buf = args.join_extra(b"").into();
        Ok(Val::U64(buf.len() as u64))
    }
);

pub const MODULE: Module = module! {
    /// # Text / Byte-String Functions
    ///
    /// String and byte-buffer manipulation — concatenation, length, encoding, and hex conversion.
    resynth mod text {
        concat => Symbol::Func(&CONCAT),
        crlflines => Symbol::Func(&CRLFLINES),
        len => Symbol::Func(&LEN),
        CRLF => Symbol::Val(ValDef::Str(b"\r\n")),
    }
};
