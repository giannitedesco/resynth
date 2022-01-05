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
//! - [crate::stdlib] Contains the resynth standard library which is mostly glue to allow resynth
//! programs to use the functionality in [pkt] and [ezpkt]
//!
//! ## Compiler Phases
//! 1. [crate::process_file()] is the basic wrapper function which handles all phases of the
//!    compiler
//! 2. [Lexer] uses a static regex to parse each line in to a stream of tokens
//! 3. [Parser] is a hand-written LR-parser which takes a token at a time and whenever a complete
//!    [statement](Stmt) is encountered, the [statement](Stmt) is pushed in to a
//!    [results vector](Parser::get_results) which can later be [retreived](Parser::get_results)
//! 4. [Program] maintains the execution state of any given program. It takes one statement at a
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

use pkt::PcapWriter;

pub use err::Error;
pub use loc::Loc;
pub use lex::{Lexer, EOF, Token};
pub use parse::{Parser, Stmt};
pub use program::Program;

use std::path::{Path, PathBuf};
use std::fs;
use std::io;
use std::io::BufRead;

use clap::{Arg, App};
use termcolor::{ColorChoice, StandardStream, Color, ColorSpec, WriteColor};

/// A [source code location](Loc) and an [error code](Error)
#[derive(Debug)]
pub struct ErrorLoc {
    pub loc: Loc,
    pub err: Error,
}

impl ErrorLoc {
    pub fn new(loc: Loc, err: Error) -> Self {
        Self {
            loc,
            err,
        }
    }
}

impl From<Error> for ErrorLoc {
    fn from(e: Error) -> Self {
        Self::new(Loc::nil(), e)
    }
}

impl From<io::Error> for ErrorLoc {
    fn from(e: io::Error) -> Self {
        Self::new(Loc::nil(), e.into())
    }
}

pub fn process_file(stdout: &mut StandardStream,
                    inp: &Path,
                    out: &Path,
                    verbose: bool,
                    ) -> Result<(), ErrorLoc> {
    let file = fs::File::open(inp)?;
    let rd = io::BufReader::new(file);
    let wr = {
        let wr = PcapWriter::create(out)?;
        if verbose {
            wr.debug()
        } else {
            wr
        }
    };
    let mut prog = Program::with_pcap_writer(wr)?;
    let mut parse = Parser::default();
    let mut lex = Lexer::default();

    let mut warning = |loc: Loc, warn: &str| {

        if loc.is_nil() {
            print!("{}: ", inp.display());
        } else {
            print!("{}:{}:{}: ", inp.display(), loc.line(), loc.col());
        }
        warn!(stdout, "warning");
        println!(": {}", warn);
    };
    prog.set_warning(&mut warning);

    for (lno, res) in rd.lines().enumerate() {
        let line = res?;

        let toks = match lex.line(lno + 1, &line) {
            Ok(toks) => toks,
            Err(err) => return Err(ErrorLoc::new(lex.loc(), err)),
        };

        for tok in toks {
            if let Err(err) = parse.feed(tok) {
                return Err(ErrorLoc::new(tok.loc(), err));
            }
        }

        if let Err(err) = prog.add_stmts(parse.get_results()) {
            return Err(ErrorLoc::new(prog.loc(), err));
        }
    }

    if let Err(err) = parse.feed(EOF) {
        return Err(ErrorLoc::new(lex.loc(), err));
    }

    if let Err(err) = prog.add_stmts(parse.get_results()) {
        return Err(ErrorLoc::new(prog.loc(), err));
    }

    Ok(())
}

fn resynth() -> Result<(), ()> {
    let mut ret = Ok(());

    let argv = App::new("resynth")
        .version("0.1")
        .author("Gianni Teesco <gianni@scaramanga.co.uk>")
        .about("Packet synthesis language")
        .arg(Arg::new("color")
            .long("color")
            .help("always|ansi|auto"))
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .help("Print packets"))
        .arg(Arg::new("keep")
            .short('k')
            .long("keep")
            .help("Keep pcap files on error"))
        .arg(Arg::new("out")
            .short('o')
            .long("out-dir")
            .value_name("DIR")
            .required(true)
            .help("Directory to write pcap files to")
            .takes_value(true))
        .arg(Arg::new("in")
            .help("Sets the input file to use")
            .value_name("FILE")
            .required(true)
            .multiple_occurrences(true)
            .index(1))
        .get_matches();

    let verbose = argv.is_present("verbose");
    let keep = argv.is_present("keep");

    let preference = argv.value_of("color").unwrap_or("auto");
    let color = match preference {
        "always" => ColorChoice::Always,
        "ansi" => ColorChoice::AlwaysAnsi,
        "auto" => {
            if atty::is(atty::Stream::Stdout) {
                ColorChoice::Auto
            } else {
                ColorChoice::Never
            }
        }
        _ => ColorChoice::Never,
    };
    let mut stdout = StandardStream::stdout(color);

    let mut out = argv.value_of("out").map_or(
        PathBuf::new(),
        PathBuf::from,
    );

    for arg in argv.values_of("in").unwrap() {
        let p = Path::new(arg);

        out.push(p.file_stem().unwrap());
        out.set_extension("pcap");

        let result = process_file(&mut stdout, p, &out, verbose);

        if let Err(error) = result {
            let ErrorLoc { loc, err } = error;

            if loc.is_nil() {
                print!("{}: ", p.display());
            } else {
                print!("{}:{}:{}: ", p.display(), loc.line(), loc.col());
            }
            error!(stdout, "error");
            println!(": {}", err);

            if !keep {
                if let Err(rm_err) = fs::remove_file(&out) {
                    print!("{}: ", p.display());
                    error!(stdout, "error");
                    println!(": {}", rm_err);
                }
            }

            ret = Err(());
        } else {
            print!("{} -> {} ", p.display(), out.display());
            ok!(stdout, "ok");
            println!();
        }

        out.pop();
    }

    ret
}

fn main() {
    if matches!(resynth(), Err(_)) {
        std::process::exit(1);
    }
}
