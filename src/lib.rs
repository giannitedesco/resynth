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
//! 3. [Program] maintains the execution state of any given program. It [runs](Program::run) one
//!    statement at a time, and updates the program state based on that. If the program has a
//!    [pkt::PcapWriter] attached to it, then any generated packets will be written in to the
//!    corresponding pcap file as they are generated. It fails with a [RuntimeError]
//!
//! Each phase's error carries the [location](Loc) in the source where it happened.

#[macro_use]
mod macros;
mod args;
pub mod ast;
mod lex;
mod libapi;
mod loc;
mod object;
pub mod parse;
mod program;
mod str;
mod sym;
mod traits;
mod val;

pub mod stdlib;

#[cfg(test)]
mod test;

pub use lex::{
    LexError, LexErrorKind, LexLineError, Lexeme, LexemeKind, Lexer, Scanner, Tok, Token,
};
pub use loc::Loc;
pub use parse::{ParseError, ParseErrorKind};
pub use program::{Program, RuntimeError, RuntimeErrorKind};
