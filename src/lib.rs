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
//! to do with various network protocols.
//! - [ezpkt] A more high-level packet generation library which provides abstractions around
//! concepts such as flows
//! - [crate] The language compiler and interpreter itself is the root of the crate. In future we
//! will probably move in to its own module at some point in future.
//! - [stdlib](crate::stdlib) Contains the resynth standard library which is mostly glue to allow
//! resynth programs to use the functionality in [pkt] and [ezpkt]
//!
//! ## Compiler Phases
//! 1. [Lexer] uses a static regex to parse each line in to a stream of tokens
//! 2. [Parser] is a hand-written LR-parser which takes a token at a time and whenever a complete
//!    [statement](Stmt) is encountered, the [statement](Stmt) is pushed in to a
//!    [results vector](Parser::get_results) which can later be [retreived](Parser::get_results)
//! 3. [Program] maintains the execution state of any given program. It takes one statement at a
//!    time, and updates the program state based on that. If the program has a [pkt::PcapWriter]
//!    attached to it, then any generated packets will be written in to the corresponding pcap file
//!    as they are generated.

#[macro_use]
mod macros;
mod err;
mod lex;
mod parse;
mod program;
mod val;
mod libapi;
mod str;
mod object;
mod args;
mod sym;
mod traits;
mod loc;

pub mod stdlib;

#[cfg(test)]
mod test;

pub use err::Error;
pub use loc::Loc;
pub use lex::{Lexer, EOF, Token};
pub use parse::{Parser, Stmt};
pub use program::Program;
