use std::io;

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
    MultipleAssignError,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IoError(e)
    }
}
