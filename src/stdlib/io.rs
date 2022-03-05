use std::os::unix::ffi::OsStrExt;
use std::ffi::OsStr;
use std::path::Path;
use std::fs::File;
use std::io::Read;

use phf::{phf_map, phf_ordered_map};

use crate::val::{ValType, Val};
use crate::libapi::{FuncDef, ArgDecl, Class};
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

#[derive(Debug, PartialEq, Eq, Default)]
struct BufIo {
    buf: Vec<u8>,
    taken: usize,
}

impl BufIo {
    pub fn read(&mut self, bytes: usize) -> &[u8] {
        let remaining = self.buf.len() - self.taken;
        let take = std::cmp::min(remaining, bytes);

        let ret = &self.buf[self.taken..self.taken + take];
        self.taken += take;

        ret
    }

    pub fn read_all(&mut self) -> &[u8] {
        let remaining = self.buf.len() - self.taken;

        let ret = &self.buf[self.taken..self.taken + remaining];
        self.taken += remaining;

        ret
    }
}

impl<T> From<&T> for BufIo where T: AsRef<[u8]> + ?Sized {
    fn from(s: &T) -> Self {
        Self {
            buf: Vec::from(s.as_ref()),
            taken: 0,
        }
    }
}

const BUFIO_READ: FuncDef = func_def!(
    "io::bufio.read";
    ValType::Str;

    "bytes" => ValType::U64,
    =>
    =>
    ValType::Void;

    |mut args| {
        let bytes: u64 = args.next().into();
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut BufIo = r.as_mut_any().downcast_mut().unwrap();
        Ok(Val::Str(this.read(bytes as usize).into()))
    }
);

const BUFIO_READ_ALL: FuncDef = func_def!(
    "io::bufio.read_all";
    ValType::Str;

    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut BufIo = r.as_mut_any().downcast_mut().unwrap();
        Ok(Val::Str(this.read_all().into()))
    }
);

impl Class for BufIo {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "read" => Symbol::Func(&BUFIO_READ),
            "read_all" => Symbol::Func(&BUFIO_READ_ALL),
        }
    }

    fn class_name(&self) -> &'static str {
        "io::bufio"
    }
}

const BUFIO: FuncDef = func_def!(
    "bufio";
    ValType::Obj;

    =>
    =>
    ValType::Str;

    |mut args| {
        let bytes: Buf = args.join_extra(b"").into();
        Ok(Val::from(BufIo::from(bytes.as_ref())))
    }
);


pub const MODULE: phf::Map<&'static str, Symbol> = phf_map! {
    "file" => Symbol::Func(&IO_FILE),
    "bufio" => Symbol::Func(&BUFIO),
};
