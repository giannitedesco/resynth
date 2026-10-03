use std::borrow::Cow;
use std::io;

use derive_more::{Display, Error, From};

use crate::val::ValType;

/// Error code for resynth program. Think of it as base exception type for the resynth language.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Display, Error, From)]
pub enum Error {
    #[display("{}", _0)]
    #[from]
    IoError(io::Error),

    #[display("Lex Error")]
    LexError,

    #[display("Parse Error")]
    ParseError,

    #[display("Import Error: Unknown Module {:?}", _0)]
    #[error(ignore)]
    ImportError(Box<str>),

    #[display("Unknown name {:?}", _0)]
    #[error(ignore)]
    NameError(Box<str>),

    #[display("Type Error")]
    TypeError,

    #[display("Unimplemented stdlib call")]
    LibTodo,

    #[display("{}", _0)]
    #[error(ignore)]
    LibError(Cow<'static, str>),

    #[display("Variable {:?} reassigned", _0)]
    #[error(ignore)]
    MultipleAssignError(Box<str>),

    #[display("Module {:?} not imported", _0)]
    #[error(ignore)]
    NotImported(Box<str>),

    #[display("{:?} is not a module", _0)]
    #[error(ignore)]
    NotAModule(Box<str>),

    #[display("{:?} is not a value", _0)]
    #[error(ignore)]
    NotAValue(Box<str>),

    #[display("Too many components in reference {:?}", _0)]
    #[error(ignore)]
    TooManyComponents(Box<str>),

    #[display("Value of type {} is not callable", _0)]
    #[error(ignore)]
    NotCallable(ValType),

    #[display("{func}: too many arguments: {got} > {want}")]
    #[error(ignore)]
    TooManyArgs {
        func: Box<str>,
        got: usize,
        want: usize,
    },

    #[display("{func}: no such argument: {arg:?}")]
    #[error(ignore)]
    NoSuchArg { func: Box<str>, arg: Box<str> },

    #[display("{func}: argument {arg:?} multiply specified")]
    #[error(ignore)]
    ArgMultiplySpecified { func: Box<str>, arg: Box<str> },

    #[display("{func}: unexpected collect-arguments")]
    #[error(ignore)]
    UnexpectedCollectArgs { func: Box<str> },

    #[display("{func}: unexpected named argument: {arg:?}")]
    #[error(ignore)]
    UnexpectedNamedArg { func: Box<str>, arg: Box<str> },

    #[display("{func}: not enough arguments: {got} < {want}")]
    #[error(ignore)]
    TooFewArgs {
        func: Box<str>,
        got: usize,
        want: usize,
    },

    #[display("{func}: argument {arg:?} not specified")]
    #[error(ignore)]
    MissingArg { func: Box<str>, arg: Box<str> },

    #[display("{func}: argument {arg:?} has the wrong type")]
    #[error(ignore)]
    ArgTypeMismatch { func: Box<str>, arg: Box<str> },

    #[display("{func}: collect argument has the wrong type")]
    #[error(ignore)]
    CollectArgTypeMismatch { func: Box<str> },
}

impl Eq for Error {}
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        use Error::*;
        match (self, other) {
            (IoError(a), IoError(b)) => a.kind() == b.kind(),
            (LexError, LexError) => true,
            (ParseError, ParseError) => true,
            (ImportError(a), ImportError(b)) => a == b,
            (NameError(a), NameError(b)) => a == b,
            (TypeError, TypeError) => true,
            (LibTodo, LibTodo) => true,
            (LibError(a), LibError(b)) => a == b,
            (MultipleAssignError(a), MultipleAssignError(b)) => a == b,
            (NotImported(a), NotImported(b)) => a == b,
            (NotAModule(a), NotAModule(b)) => a == b,
            (NotAValue(a), NotAValue(b)) => a == b,
            (TooManyComponents(a), TooManyComponents(b)) => a == b,
            (
                TooManyArgs {
                    func: f1,
                    got: g1,
                    want: w1,
                },
                TooManyArgs {
                    func: f2,
                    got: g2,
                    want: w2,
                },
            ) => f1 == f2 && g1 == g2 && w1 == w2,
            (NoSuchArg { func: f1, arg: a1 }, NoSuchArg { func: f2, arg: a2 }) => {
                f1 == f2 && a1 == a2
            }
            (
                ArgMultiplySpecified { func: f1, arg: a1 },
                ArgMultiplySpecified { func: f2, arg: a2 },
            ) => f1 == f2 && a1 == a2,
            (UnexpectedCollectArgs { func: f1 }, UnexpectedCollectArgs { func: f2 }) => f1 == f2,
            (
                UnexpectedNamedArg { func: f1, arg: a1 },
                UnexpectedNamedArg { func: f2, arg: a2 },
            ) => f1 == f2 && a1 == a2,
            (
                TooFewArgs {
                    func: f1,
                    got: g1,
                    want: w1,
                },
                TooFewArgs {
                    func: f2,
                    got: g2,
                    want: w2,
                },
            ) => f1 == f2 && g1 == g2 && w1 == w2,
            (MissingArg { func: f1, arg: a1 }, MissingArg { func: f2, arg: a2 }) => {
                f1 == f2 && a1 == a2
            }
            (ArgTypeMismatch { func: f1, arg: a1 }, ArgTypeMismatch { func: f2, arg: a2 }) => {
                f1 == f2 && a1 == a2
            }
            (CollectArgTypeMismatch { func: f1 }, CollectArgTypeMismatch { func: f2 }) => f1 == f2,
            (NotCallable(a), NotCallable(b)) => a == b,
            _ => false,
        }
    }
}
