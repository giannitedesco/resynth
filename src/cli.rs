use pkt::PcapWriter;

use resynth::stdlib::{write_docs, write_stdlib_json};
use resynth::{EOF, Error, Lexer, Loc, Parser, Program};
use resynth::{error, ok, warn};

use std::borrow::Cow;
use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::{fs, io};

use clap::{ArgGroup, Parser as ClapParser};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

#[derive(ClapParser, Debug)]
#[command(
    version,
    author,
    about,
    group(
        ArgGroup::new("run_mode")
            .args(["docs", "stdlib_json", "input"])
            .required(true)
    ),
)]
struct Cli {
    /// Output color: always, ansi, auto, never
    #[arg(long, default_value = "auto", value_parser = ["always", "ansi", "auto", "never"])]
    color: String,

    /// Print packets
    #[arg(short, long)]
    verbose: bool,

    /// Keep pcap files on error
    #[arg(short, long)]
    keep: bool,

    /// Output documentation to DIR
    #[arg(long = "output-docs", value_name = "DIR")]
    docs: Option<PathBuf>,

    /// Output stdlib as JSON to FILE (omit FILE to write to stdout)
    #[arg(long = "output-stdlib-json", value_name = "FILE", num_args = 0..=1, default_missing_value = "")]
    stdlib_json: Option<String>,

    /// Output pcap filenames (must match number of input files)
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    out: Vec<PathBuf>,

    /// Directory to write pcap files to
    #[arg(
        long = "out-dir",
        value_name = "DIR",
        default_value = ".",
        conflicts_with = "out"
    )]
    outdir: PathBuf,

    /// Input .rsyn files
    #[arg(value_name = "FILE")]
    input: Vec<String>,
}

/// A [source code location](Loc) and an [error code](Error)
#[derive(Debug)]
pub struct ErrorLoc {
    pub loc: Loc,
    pub err: Error,
}

impl ErrorLoc {
    pub fn new(loc: Loc, err: Error) -> Self {
        Self { loc, err }
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

pub fn process_file(
    stdout: &mut StandardStream,
    inp: &Path,
    out: &Path,
    verbose: bool,
) -> Result<(), ErrorLoc> {
    let file = fs::File::open(inp)?;
    let rd = io::BufReader::new(file);
    let wr = {
        let wr = PcapWriter::create(out)?;
        if verbose { wr.debug() } else { wr }
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
            if let Err(err) = parse.feed(&tok) {
                return Err(ErrorLoc::new(tok.loc(), err));
            }
        }

        if let Err(err) = prog.add_stmts(parse.get_results()) {
            return Err(ErrorLoc::new(prog.loc(), err));
        }
    }

    if let Err(err) = parse.feed(&EOF) {
        return Err(ErrorLoc::new(lex.loc(), err));
    }

    if let Err(err) = prog.add_stmts(parse.get_results()) {
        return Err(ErrorLoc::new(prog.loc(), err));
    }

    Ok(())
}

fn resynth() -> Result<(), ()> {
    let argv = Cli::parse();

    let color = match argv.color.as_str() {
        "always" => ColorChoice::Always,
        "ansi" => ColorChoice::AlwaysAnsi,
        "auto" => {
            if std::io::stdout().is_terminal() {
                ColorChoice::Auto
            } else {
                ColorChoice::Never
            }
        }
        _ => ColorChoice::Never,
    };
    let mut stdout = StandardStream::stdout(color);

    if let Some(docs_dir) = &argv.docs {
        write_docs(docs_dir);
        return Ok(());
    }

    if let Some(json_path) = &argv.stdlib_json {
        let path = if json_path.is_empty() {
            None
        } else {
            Some(PathBuf::from(json_path))
        };
        write_stdlib_json(path.as_deref());
        return Ok(());
    }

    let use_filenames = !argv.out.is_empty();

    if use_filenames && argv.out.len() != argv.input.len() {
        eprintln!(
            "error: Received {} output(s), expected: {}",
            argv.out.len(),
            argv.input.len(),
        );
        return Err(());
    }

    let mut ret = Ok(());

    for (i, input) in argv.input.iter().enumerate() {
        let p = Path::new(input);
        let out: Cow<Path> = if use_filenames {
            Cow::Borrowed(&argv.out[i])
        } else {
            let mut out = argv.outdir.clone();
            out.push(p.file_stem().unwrap());
            out.set_extension("pcap");
            Cow::Owned(out)
        };

        let result = process_file(&mut stdout, p, &out, argv.verbose);

        if let Err(error) = result {
            let ErrorLoc { loc, err } = error;

            if loc.is_nil() {
                print!("{}: ", p.display());
            } else {
                print!("{}:{}:{}: ", p.display(), loc.line(), loc.col());
            }
            error!(stdout, "error");
            println!(": {}", err);

            if !argv.keep
                && let Err(rm_err) = fs::remove_file(out.as_ref())
            {
                print!("{}: ", p.display());
                error!(stdout, "error");
                println!(": delete: {}", rm_err);
            }

            ret = Err(());
        } else {
            print!("{} -> {} ", p.display(), out.display());
            ok!(stdout, "ok");
            println!();
        }
    }

    ret
}

fn main() {
    if resynth().is_err() {
        std::process::exit(1);
    }
}
