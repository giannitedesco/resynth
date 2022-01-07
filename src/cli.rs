use pkt::PcapWriter;

use resynth::{Error, Loc, Lexer, EOF, Parser, Program};
use resynth::{warn, error, ok};

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
