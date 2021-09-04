#![feature(iter_intersperse)]

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

const PROGRAM_NAME: &str = "resynth";

fn process_file(inp: &Path, out: &Path) -> Result<(), Error> {
    let file = File::open(inp)?;
    let rd = io::BufReader::new(file);
    let wr = PcapWriter::create(out)?;
    let mut prog = Program::with_pcap_writer(wr)?;
    let mut parse = Parser::new();

    for res in rd.lines() {
        let line = res?;
        let toks = match lex(&line) {
            Ok(toks) => toks,
            _ => return Err(Error::LexError),
        };

        for tok in toks.into_iter() {
            parse.feed(tok)?;
        }

        prog.add_stmts(parse.get_results())?;
    }

    parse.feed(EOF)?;
    prog.add_stmts(parse.get_results())?;

    Ok(())
}

fn prog_invocation_name() -> Option<String> {
    env::current_exe()
            .ok()?
            .file_name()?
            .to_str()?
            .to_owned()
            .into()
}

fn main() {
    let matches = App::new("resynth")
        .version("0.1")
        .author("Gianni Teesco <gianni@scaramanga.co.uk>")
        .about("Packet synthesis language")
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

    let prog = match prog_invocation_name() {
        Some(ret) => ret,
        None => String::from(PROGRAM_NAME),
    };

    let mut out = matches.value_of("out").map_or(
        PathBuf::new(),
        PathBuf::from,
    );

    for arg in matches.values_of("in").unwrap() {
        let p = Path::new(arg);

        out.push(p.file_stem().unwrap());
        out.set_extension("pcap");

        println!("Processing: {:?} -> {:?}", p, out);
        if let Err(error) = process_file(p, &out) {
            println!("{}: error: {:?}: {:?}", prog, p, error);
        }
    }
}
