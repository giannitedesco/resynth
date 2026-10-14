use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::Val;

static IO_FILE: FuncDef = func!(
    /// Load the contents of a file into a string
    resynth fn file(
        /// Path to the file to load
        filename: Str,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let arg: Buf = args.next().into();
        let path = Path::new(OsStr::from_bytes(arg.as_ref()));
        let mut f = File::open(path)?;

        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;

        Ok(Val::str(buf))
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

impl<T> From<T> for BufIo
where
    T: AsRef<[u8]>,
{
    fn from(s: T) -> Self {
        Self {
            buf: Vec::from(s.as_ref()),
            taken: 0,
        }
    }
}

static BUFIO_READ: FuncDef = func!(
    /// Read the next `bytes` bytes from the buffer, advancing the read position.
    /// If fewer than `bytes` bytes remain, returns what is left.
    resynth fn read(
        /// Number of bytes to read from the buffer
        bytes: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let bytes: u64 = args.next().into();
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut BufIo = r.as_mut_any().downcast_mut().unwrap();
        Ok(Val::Str(this.read(bytes as usize).into()))
    }
);

static BUFIO_READ_ALL: FuncDef = func!(
    /// Read all remaining bytes from the buffer, advancing the read position to the end.
    resynth fn read_all(
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut BufIo = r.as_mut_any().downcast_mut().unwrap();
        Ok(Val::Str(this.read_all().into()))
    }
);

static BUFIO_CLASS: ClassDef = class!(
    /// # Buffered I/O
    ///
    /// A stateful byte buffer that can be read in sequential chunks. Useful for
    /// splitting a pre-built payload (such as a TLS record or protocol message)
    /// across multiple packets without duplicating the content.
    ///
    /// Create with `io::bufio(...)`, then call `read(n)` to consume `n` bytes at
    /// a time, or `read_all()` to consume the remainder.
    resynth class BufIO {
        read => Symbol::Func(&BUFIO_READ),
        read_all => Symbol::Func(&BUFIO_READ_ALL),
    }
);

impl Class for BufIo {
    fn def(&self) -> &'static ClassDef {
        &BUFIO_CLASS
    }
}

static BUFIO: FuncDef = func!(
    /// Create a `BufIO` buffer from one or more byte strings, from which bytes
    /// can be consumed in sequential chunks using `read(n)` and `read_all()`.
    /// This is useful for splitting a pre-assembled payload across multiple
    /// packets — for example, sending the first 15 bytes of a TLS record in one
    /// TCP segment and the rest in another.
    resynth fn bufio(
        =>
        =>
        Str
    ) -> Class(&BUFIO_CLASS)
    |mut args| {
        let bytes: Buf = args.join_extra(b"").into();
        Ok(Val::from(BufIo::from(bytes.as_ref())))
    }
);

pub const MODULE: Module = module!(
    /// # Buffers and File I/O
    ///
    /// Buffered I/O — read from and write to byte buffers and files.
    resynth mod io {
        BufIO => Symbol::Class(&BUFIO_CLASS),
        file => Symbol::Func(&IO_FILE),
        bufio => Symbol::Func(&BUFIO),
    }
);
