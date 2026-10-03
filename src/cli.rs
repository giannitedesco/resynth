use pkt::PcapWriter;

use resynth::stdlib::{write_docs, write_stdlib_json};
use resynth::{Error, Lexer, Loc, Parser, Program};
use resynth::{error, ok, warn};

use std::borrow::Cow;
use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::{fs, io};

use chrono::DateTime;
use clap::{Args, CommandFactory, Parser as ClapParser, Subcommand, error::ErrorKind};
use derive_more::{Display, Error};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

#[derive(Debug, Display, Error)]
enum StartTimeError {
    #[display("{}: expected unix seconds, RFC 3339: YYYY-MM-DDTHH:MM:SSZ", _0)]
    #[error(ignore)]
    Format(Box<str>),

    #[display("{}: Outside of pcap timestamp range (1970 - 2106)", _0)]
    #[error(ignore)]
    OutOfRange(Box<str>),
}

/// Nanoseconds since the Unix epoch (1970-01-01 00:00:00 UTC), within pcap's u32 seconds range
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
struct StartTime(u64);

impl StartTime {
    const MAX_NANOS: i64 = (u32::MAX as i64 + 1) * 1_000_000_000 - 1;

    const fn as_nanos(&self) -> u64 {
        self.0
    }
}

impl FromStr for StartTime {
    type Err = StartTimeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ns = match s.parse::<i64>() {
            Ok(secs) => secs.checked_mul(1_000_000_000),
            Err(_) => DateTime::parse_from_rfc3339(s)
                .map_err(|_| StartTimeError::Format(s.into()))?
                .timestamp_nanos_opt(),
        };
        ns.filter(|ns| (0..=Self::MAX_NANOS).contains(ns))
            .and_then(|ns| u64::try_from(ns).ok())
            .map(Self)
            .ok_or_else(|| StartTimeError::OutOfRange(s.into()))
    }
}

/// Where each input's pcap file is written
#[derive(Debug, Clone, PartialEq, Eq)]
enum OutputMode {
    /// `-o FILE`: the one and only input is written to `FILE`
    File(PathBuf),

    /// Default: next to each input, as `<input dir>/<input name>.pcap`
    BesideInput,

    /// `--out-dir DIR`: every input is written to `DIR/<input name>.pcap`
    Dir(PathBuf),
}

#[derive(Debug, Display, Error)]
enum OutputError {
    #[display("-o/--output needs exactly one input file, got {}", _0)]
    #[error(ignore)]
    FileWithInputs(usize),

    #[display("input has no file name")]
    NoFileName,
}

impl OutputMode {
    const EXTENSION: &str = "pcap";

    /// The pcap path for `input`. Only the last extension of the input's name
    /// is replaced, so `a.b.rsyn` becomes `a.b.pcap`.
    fn path_for<'a>(&'a self, input: &Path) -> Result<Cow<'a, Path>, OutputError> {
        let name = input.file_name().ok_or(OutputError::NoFileName)?;
        Ok(match self {
            Self::File(file) => Cow::Borrowed(file.as_path()),
            Self::BesideInput => Cow::Owned(input.with_extension(Self::EXTENSION)),
            Self::Dir(dir) => Cow::Owned(dir.join(name).with_extension(Self::EXTENSION)),
        })
    }
}

#[derive(Args, Debug, Default)]
struct OutputArgs {
    /// Output pcap file (only valid with a single input file)
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    file: Option<PathBuf>,

    /// Write every pcap file to DIR (default: alongside each input file)
    #[arg(long = "out-dir", value_name = "DIR", conflicts_with = "file")]
    dir: Option<PathBuf>,
}

impl OutputArgs {
    fn into_mode(self, inputs: usize) -> Result<OutputMode, OutputError> {
        let Self { file, dir } = self;
        match (file, dir) {
            (Some(_), Some(_)) => {
                unreachable!("clap should prevent file and dir being set at the same time")
            }
            (Some(file), None) if inputs == 1 => Ok(OutputMode::File(file)),
            (Some(_), None) => Err(OutputError::FileWithInputs(inputs)),
            (None, Some(dir)) => Ok(OutputMode::Dir(dir)),
            (None, None) => Ok(OutputMode::BesideInput),
        }
    }
}

#[derive(ClapParser, Debug)]
#[command(
    version,
    author,
    about,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Cli {
    #[command(flatten)]
    output: OutputArgs,

    /// Output color: always, ansi, auto, never
    #[arg(long, default_value = "auto", value_parser = ["always", "ansi", "auto", "never"])]
    color: String,

    /// Print packets
    #[arg(short, long)]
    verbose: bool,

    /// Keep pcap files on error
    #[arg(short, long)]
    keep: bool,

    /// Start time for pcap files (unix seconds, RFC 3339: YYYY-MM-DDTHH:MM:SSZ)
    #[arg(long, default_value = "1981-08-15T00:00:00Z")]
    start_time: StartTime,

    /// Input .rsyn files
    #[arg(value_name = "FILE")]
    input: Vec<PathBuf>,

    #[command(subcommand)]
    introspection: Option<Introspection>,
}

#[derive(Subcommand, Debug)]
enum Introspection {
    /// Output documentation to DIR
    #[command(hide = true, long_flag = "output-docs")]
    Docs { dir: PathBuf },

    /// Output stdlib as JSON to FILE (omit FILE to write to stdout)
    #[command(hide = true, long_flag = "output-stdlib-json")]
    StdlibJson { file: Option<PathBuf> },
}

/// A [source code location](Loc) and an [error code](Error)
#[derive(Debug)]
struct ErrorLoc {
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

fn process_file(
    stdout: &mut StandardStream,
    inp: &Path,
    out: &Path,
    start_time: StartTime,
    verbose: bool,
) -> Result<(), ErrorLoc> {
    let file = fs::File::open(inp)?;
    let rd = io::BufReader::new(file);
    let mut lex = Lexer::default();

    for line in rd.lines() {
        if let Err(err) = lex.line(&line?) {
            return Err(ErrorLoc::new(lex.loc(), err));
        }
    }

    let wr = {
        let wr = PcapWriter::create(out)?;
        if verbose { wr.debug() } else { wr }
    };
    let mut prog = Program::with_pcap_writer(wr);
    let mut parse = Parser::default();
    prog.update_time(start_time.as_nanos());

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

    for tok in lex.finish() {
        if let Err(err) = parse.feed(&tok) {
            return Err(ErrorLoc::new(tok.loc(), err));
        }

        if let Err(err) = prog.add_stmts(parse.get_results()) {
            return Err(ErrorLoc::new(prog.loc(), err));
        }
    }

    Ok(())
}

fn resynth() -> Result<(), ()> {
    let argv = Cli::parse();

    match argv.introspection {
        Some(Introspection::Docs { dir }) => {
            write_docs(&dir);
            return Ok(());
        }
        Some(Introspection::StdlibJson { file }) => {
            write_stdlib_json(file.as_deref());
            return Ok(());
        }
        None => {}
    }

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

    let mode = match argv.output.into_mode(argv.input.len()) {
        Ok(mode) => mode,
        Err(err) => {
            Cli::command()
                .error(ErrorKind::ArgumentConflict, err)
                .exit();
        }
    };

    let mut ret = Ok(());

    for p in &argv.input {
        let out = match mode.path_for(p) {
            Ok(out) => out,
            Err(err) => {
                print!("{}: ", p.display());
                error!(stdout, "error");
                println!(": output: {err}");
                ret = Err(());
                continue;
            }
        };

        let result = process_file(&mut stdout, p, &out, argv.start_time, argv.verbose);

        if let Err(error) = result {
            let ErrorLoc { loc, err } = error;

            if loc.is_nil() {
                print!("{}: ", p.display());
            } else {
                print!("{}:{}:{}: ", p.display(), loc.line(), loc.col());
            }
            error!(stdout, "error");
            println!(": {}", err);

            // By default, if the file failed for any reason, regardless of whether we created it
            // or not, we delete it. This behaviour can be overridden with the `--keep` flag.
            //
            // This is basically because we anticipate that we're translating source files to e.g.
            // test cases, and we want the test cases to fail with "no file", rather than producing
            // weird or spurious output.
            //
            // Maybe we readdress this and only delete things we actually created in future.
            if !argv.keep
                && let Err(rm_err) = fs::remove_file(out.as_ref())
                && rm_err.kind() != io::ErrorKind::NotFound
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

fn main() -> ExitCode {
    if resynth().is_err() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `mode`'s output path for `input`, owned for easy comparison
    fn out(mode: &OutputMode, input: &str) -> PathBuf {
        mode.path_for(Path::new(input))
            .expect("output path")
            .into_owned()
    }

    /// The [`OutputMode`] for `-o file` and `--out-dir dir` with `inputs` input files
    fn mode(
        file: Option<&str>,
        dir: Option<&str>,
        inputs: usize,
    ) -> Result<OutputMode, OutputError> {
        OutputArgs {
            file: file.map(PathBuf::from),
            dir: dir.map(PathBuf::from),
        }
        .into_mode(inputs)
    }

    #[test]
    fn into_mode_defaults_to_beside_input() {
        assert_eq!(mode(None, None, 3).unwrap(), OutputMode::BesideInput);
    }

    #[test]
    fn into_mode_selects_dir() {
        assert_eq!(
            mode(None, Some("out"), 3).unwrap(),
            OutputMode::Dir("out".into()),
        );
    }

    #[test]
    fn into_mode_selects_file_for_one_input() {
        assert_eq!(
            mode(Some("x.pcap"), None, 1).unwrap(),
            OutputMode::File("x.pcap".into()),
        );
    }

    #[test]
    fn into_mode_rejects_file_with_many_inputs() {
        assert!(matches!(
            mode(Some("x.pcap"), None, 2),
            Err(OutputError::FileWithInputs(2)),
        ));
    }

    #[test]
    fn cli_rejects_file_and_dir() {
        let err = Cli::try_parse_from(["resynth", "-o", "x.pcap", "--out-dir", "out", "a.rsyn"])
            .expect_err("-o and --out-dir should conflict");
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn beside_input_replaces_only_last_extension() {
        assert_eq!(
            out(&OutputMode::BesideInput, "dir/a.b.rsyn"),
            PathBuf::from("dir/a.b.pcap"),
        );
    }

    #[test]
    fn beside_input_adds_missing_extension() {
        assert_eq!(
            out(&OutputMode::BesideInput, "dir/a"),
            PathBuf::from("dir/a.pcap")
        );
    }

    #[test]
    fn dir_drops_input_directory() {
        assert_eq!(
            out(&OutputMode::Dir("out".into()), "x/y/a.b.rsyn"),
            PathBuf::from("out/a.b.pcap"),
        );
    }

    #[test]
    fn file_ignores_input_name() {
        assert_eq!(
            out(&OutputMode::File("custom.cap".into()), "x/a.rsyn"),
            PathBuf::from("custom.cap"),
        );
    }

    #[test]
    fn input_without_file_name_is_error() {
        for input in ["..", "/", ""] {
            assert!(
                matches!(
                    OutputMode::BesideInput.path_for(Path::new(input)),
                    Err(OutputError::NoFileName),
                ),
                "{input:?}",
            );
        }
    }
}
