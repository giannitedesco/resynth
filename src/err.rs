use std::io;
use std::fmt;

#[allow(unused, clippy::enum_variant_names)]
#[derive(Debug)]
pub(crate) enum Error {
    IoError(io::Error),
    LexError,
    ParseError,
    MemoryError,
    ImportError(String),
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

impl Eq for Error {}
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        use Error::*;

        match self {
            IoError(a) => {
                if let IoError(b) = other {
                    a.kind() == b.kind()
                } else {
                    false
                }
            }
            LexError => matches!(other, LexError),
            ParseError => matches!(other, ParseError),
            MemoryError => matches!(other, MemoryError),
            ImportError(a) => {
                if let ImportError(b) = other {
                    a == b
                } else {
                    false
                }
            },
            NameError => matches!(other, NameError),
            TypeError => matches!(other, TypeError),
            RuntimeError => matches!(other, RuntimeError),
            MultipleAssignError(a) => {
                if let MultipleAssignError(b) = other {
                    a == b
                } else {
                    false
                }
            },
        }
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
            ImportError(s) => write!(fmt, "Import Error: Unknown module '{}'", s),
            NameError => write!(fmt, "Name Error"),
            TypeError => write!(fmt, "Type Error"),
            RuntimeError => write!(fmt, "Runtime Error"),
            MultipleAssignError(s) => write!(fmt, "Variable '{}' reassigned", s),
        }
    }
}
