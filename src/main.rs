#[macro_use]
mod macros;
mod err;
mod lex;
mod parse;
mod program;
mod stdlib;
mod val;
mod libapi;
mod str;
mod object;
mod args;
mod pkt;
mod ezpkt;

#[cfg(test)]
mod test;

use err::Error;
use lex::{lex, EOF};
use parse::Parser;
use program::Program;
use pkt::PcapWriter;

use std::path::{Path, PathBuf};
use std::fs;
use std::io;
use std::io::BufRead;

use clap::{Arg, App};
use termcolor::{ColorChoice, StandardStream, Color, ColorSpec, WriteColor};
use atty;

fn process_file(color: ColorChoice,
                inp: &Path,
                out: &Path,
                verbose: bool,
                ) -> Result<(), Error> {
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
    let mut parse = Parser::new();

    prog.set_color(color);

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

fn resynth() -> Result<(), Error> {
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

        notice!(stdout, "Processing");
        println!(": {} -> {}", p.display(), out.display());

        let result = process_file(color, p, &out, verbose);

        notice!(stdout, "    Result");
        print!(": ");

        if let Err(error) = result {
            error!(stdout, "Error");
            println!(" -> {}", error);

            ret = Err(error);

            if !keep {
                notice!(stdout, "    Action");
                print!(": ");
                if let Err(rm_err) = fs::remove_file(&out) {
                    error!(stdout, "Delete");
                    println!(" {} -> {}", out.display(), rm_err);
                } else {
                    notice!(stdout, "Delete");
                    println!(" {}", out.display());
                }
            }
        } else {
            ok!(stdout, "Ok");
            println!("");
        }

        out.pop();

        println!("");
    }

    ret
}

fn main() {
    if matches!(resynth(), Err(_)) {
        std::process::exit(1);
    }
}
