mod err;
mod lex;
mod parse;
mod program;
mod stdlib;
mod val;
mod pkt;
mod ezpkt;

use err::Error;
use lex::{lex, EOF};
use parse::Parser;
use program::Program;
use pkt::PcapWriter;

use std::env;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io;
use std::io::BufRead;

use clap::{Arg, App};

#[macro_use]
extern crate lazy_static;

fn process_file(inp: &Path, out: &Path, verbose: bool) -> Result<(), Error> {
    let file = File::open(inp)?;
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
    let mut parse = Parser::new();

    for res in rd.lines() {
        let line = res?;
        let toks = match lex(&line) {
            Ok(toks) => toks,
            _ => return Err(Error::LexError),
        };

        for tok in toks {
            parse.feed(tok)?;
        }

        prog.add_stmts(parse.get_results())?;
    }

    parse.feed(EOF)?;
    prog.add_stmts(parse.get_results())?;

    Ok(())
}

const PROGRAM_NAME: &str = "resynth";

// An inefficiency of rust is that we cannot seem to obtain a static reference to argv[0],
// presumably because calls to C libraries could modify the contents? This means that when argv[0]
// isn't present or valid then we have to malloc the const string "resynth" in case of an error.
fn prog_invocation_name(dfl: &str) -> String {
    env::args().next().unwrap_or_else(|| dfl.to_owned())
}

fn main() {
    let matches = App::new("resynth")
        .version("0.1")
        .author("Gianni Teesco <gianni@scaramanga.co.uk>")
        .about("Packet synthesis language")
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .about("Print packets"))
        .arg(Arg::new("out")
            .short('o')
            .long("out-dir")
            .value_name("DIR")
            .required(true)
            .about("Directory to write pcap files to")
            .takes_value(true))
        .arg(Arg::new("in")
            .about("Sets the input file to use")
            .value_name("FILE")
            .required(true)
            .multiple(true)
            .index(1))
        .get_matches();

    let mut prog: Option<String> = None;
    let verbose = matches.is_present("verbose");

    let mut out = matches.value_of("out").map_or(
        PathBuf::new(),
        PathBuf::from,
    );

    for arg in matches.values_of("in").unwrap() {
        let p = Path::new(arg);

        out.push(p.file_stem().unwrap());
        out.set_extension("pcap");

        println!("Processing: {:?} -> {:?}", p, out);
        if let Err(error) = process_file(p, &out, verbose) {
            if prog.is_none() {
                prog = Some(prog_invocation_name(PROGRAM_NAME));
            }

            println!("{}: error: {:?}: {:?}", prog.as_ref().unwrap(), p, error);
        }
    }
}
