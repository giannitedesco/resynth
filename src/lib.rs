//! # Resynth: A Packet Synthesis Language
//!
//! Resynth is a packet synthesis language. It produces network traffic (in the form of pcap files)
//! from textual descriptions of traffic. It enables version-controlled packets-as-code workflows
//! which can be useful for various packet processing, or security research applications such as
//! DPI engines, or network intrusion detection systems.
//!
//! ## Structure of the Codebase
//! The codebase is split in to several major components
//! - [pkt] A low-level packet generation library which mostly contains structs and consts
//!   to do with various network protocols.
//! - [ezpkt] A more high-level packet generation library which provides abstractions around
//!   concepts such as flows
//! - [crate] The language compiler and interpreter itself is the root of the crate. In future we
//!   will probably move in to its own module at some point in future.
//! - [stdlib] Contains the resynth standard library which is mostly glue to allow
//!   resynth programs to use the functionality in [pkt] and [ezpkt]
//!
//! ## Compiler Phases
//! 1. [Lexer] is a hand-written lexer which splits a source file, a line at a time, in to a
//!    queue of [tokens](Token), decoding identifiers, integers and IP addresses as it goes. It
//!    fails with a [LexError]
//! 2. [parse::parse] is a recursive descent parser, using Pratt parsing for expressions. It turns
//!    the whole queue of tokens in to a list of [statements](ast::Stmt) before anything runs. It
//!    fails with a [ParseError]
//! 3. [check()] resolves names, binds call arguments and checks types, lowering the statements to
//!    a [HIR](hir) [Program] before anything runs. It gives each error, at most one per statement,
//!    and each warning to its caller as a [Diagnostic] as it goes. It fails with an
//!    [ErrorSummary]
//! 4. [TreeInterp] runs a [Program] one statement at a time. Each packet it sends, each wait
//!    and each discarded value is an [Effect], which the caller handles, for example by writing
//!    packets to a pcap file. It fails with a [RuntimeError]
//!
//! Each lex, parse and runtime error, and each diagnostic, carries the [location](Loc) in the
//! source where it happened.

#[macro_use]
mod macros;
mod args;
pub mod ast;
pub mod check;
pub mod hir;
pub mod interp;
mod lex;
mod libapi;
mod loc;
mod object;
pub mod parse;
mod str;
mod sym;
mod val;

pub mod stdlib;

#[cfg(test)]
mod test;

pub use check::{
    Diagnostic, DiagnosticKind, ErrorSummary, SemanticError, SemanticErrorKind, WarningKind, check,
};
pub use hir::Program;
pub use interp::{Effect, RuntimeError, RuntimeErrorKind, TreeInterp};
pub use lex::{
    LexError, LexErrorKind, LexLineError, Lexeme, LexemeKind, Lexer, Scanner, Tok, Token,
};
pub use loc::Loc;
pub use parse::{ParseError, ParseErrorKind};
