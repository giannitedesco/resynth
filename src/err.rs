use std::io;
use std::fmt;

#[allow(unused, clippy::enum_variant_names)]
#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    LexError,
    ParseError,
    MemoryError,
    ImportError,
    NameError,
    TypeError,
    RuntimeError,
    MultipleAssignError(String),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IoError(e)
    }
}


impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;

        match self {
            IoError(ref io) => io.fmt(fmt),
            LexError => write!(fmt, "Lex Error"),
            ParseError => write!(fmt, "Parse Error"),
            MemoryError => write!(fmt, "Memory Error"),
            ImportError => write!(fmt, "Import Error"),
            NameError => write!(fmt, "Name Error"),
            TypeError => write!(fmt, "Type Error"),
            RuntimeError => write!(fmt, "Runtime Error"),
            MultipleAssignError(s) => write!(fmt, "Variable '{}' reassigned", s),
        }
    }
}
