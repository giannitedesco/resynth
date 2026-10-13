use pkt::PcapWriter;

use resynth::ast::Stmt;
use resynth::parse::parse;
use resynth::stdlib::{write_docs, write_stdlib_json};
use resynth::{
    Diagnostic, DiagnosticKind, Effect, ErrorSummary, LexError, Lexer, Loc, ParseError, Program,
    RuntimeError, RuntimeErrorKind, TreeInterp, check,
};
use resynth::{error, ok, warn};

use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::{fs, io};

use chrono::DateTime;
use clap::{Args, CommandFactory, Parser as ClapParser, Subcommand, error::ErrorKind};
use derive_more::{Display, Error, From};
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

/// A program to compile
#[derive(Debug, Display, PartialEq, Eq)]
enum Input {
    #[display("{}", _0.display())]
    File(PathBuf),

    #[display("<stdin>")]
    Stdin,
}

impl Input {
    fn open(&self) -> io::Result<Box<dyn BufRead>> {
        Ok(match self {
            Self::File(p) => Box::new(io::BufReader::new(fs::File::open(p)?)),
            Self::Stdin => Box::new(io::stdin().lock()),
        })
    }
}

/// Where each input file's pcap file is written, when `-o` doesn't name it
#[derive(Debug, Clone, PartialEq, Eq)]
enum OutputMode {
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

    #[display("-o/--output FILE is required when reading from stdin")]
    StdinRequiresOutput,

    #[display("REPL cannot be output to a file")]
    ReplCannotOutput,

    #[display("{}: input has no file name", _0.display())]
    #[error(ignore)]
    NoFileName(PathBuf),
}

impl OutputMode {
    const EXTENSION: &str = "pcap";

    /// The pcap path for `input`. Only the last extension of the input's name
    /// is replaced, so `a.b.rsyn` becomes `a.b.pcap`.
    fn path_for(&self, input: &Path) -> Result<PathBuf, OutputError> {
        let name = input
            .file_name()
            .ok_or_else(|| OutputError::NoFileName(input.into()))?;
        Ok(match self {
            Self::BesideInput => input.with_extension(Self::EXTENSION),
            Self::Dir(dir) => dir.join(name).with_extension(Self::EXTENSION),
        })
    }
}

#[derive(Args, Debug, Default)]
struct OutputArgs {
    /// Output pcap file (only valid with a single input file, or stdin)
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    file: Option<PathBuf>,

    /// Write every pcap file to DIR (default: alongside each input file)
    #[arg(long = "out-dir", value_name = "DIR", conflicts_with = "file")]
    dir: Option<PathBuf>,
}

impl OutputArgs {
    /// What to do with the input `files`. With none, the program is read from stdin, or the REPL
    /// is started if stdin is a terminal. Every argument error is found here, before anything is
    /// compiled or written.
    fn plan(self, files: Vec<PathBuf>, stdin_is_tty: bool) -> Result<Plan, OutputError> {
        let Self { file, dir } = self;

        if files.is_empty() {
            return match (stdin_is_tty, file, dir) {
                (true, None, None) => Ok(Plan::Repl),
                (true, ..) => Err(OutputError::ReplCannotOutput),
                (false, Some(output), None) => Ok(Plan::Compile(vec![Job {
                    input: Input::Stdin,
                    output,
                }])),
                (false, ..) => Err(OutputError::StdinRequiresOutput),
            };
        }

        let mode = match (file, dir) {
            (Some(_), Some(_)) => {
                unreachable!("clap should prevent file and dir being set at the same time")
            }
            (Some(output), None) => {
                let [file] = <[PathBuf; 1]>::try_from(files)
                    .map_err(|files| OutputError::FileWithInputs(files.len()))?;
                return Ok(Plan::Compile(vec![Job {
                    input: Input::File(file),
                    output,
                }]));
            }
            (None, Some(dir)) => OutputMode::Dir(dir),
            (None, None) => OutputMode::BesideInput,
        };

        files
            .into_iter()
            .map(|file| {
                Ok(Job {
                    output: mode.path_for(&file)?,
                    input: Input::File(file),
                })
            })
            .collect::<Result<_, _>>()
            .map(Plan::Compile)
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

    /// Input .rsyn files (none: read the program from stdin)
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

/// Why an input file could not be turned in to a pcap: an I/O error, or an error from one of the
/// compiler's phases
#[derive(Debug, Display, Error, From)]
enum CompileError {
    #[from]
    #[error(ignore)]
    Io(io::Error),

    #[from]
    #[error(ignore)]
    Lex(LexError),

    #[from]
    #[error(ignore)]
    Parse(ParseError),

    /// Every semantic error has already been printed, as a diagnostic
    #[from]
    #[error(ignore)]
    Semantic(ErrorSummary),

    #[from]
    #[error(ignore)]
    Runtime(RuntimeError),
}

impl CompileError {
    /// Where in the input the error is. An I/O error and a semantic error summary have no
    /// location.
    const fn loc(&self) -> Option<Loc> {
        match self {
            Self::Io(_) | Self::Semantic(_) => None,
            Self::Lex(err) => Some(err.loc),
            Self::Parse(err) => Some(err.loc),
            Self::Runtime(err) => Some(err.loc),
        }
    }

    const fn phase(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::Lex(_) => "lex",
            Self::Parse(_) => "parse",
            Self::Semantic(_) => "semantic",
            Self::Runtime(_) => "runtime",
        }
    }

    fn print(&self, stdout: &mut StandardStream, input: &Input) {
        let loc = self.loc();
        let phase = self.phase();

        print!("{}", input);
        if let Some(loc) = loc {
            print!(":{}:{}", loc.line(), loc.col());
        }
        print!(": ");
        error!(stdout, "{} error", phase);
        print!(": ");
        match self {
            Self::Io(err) => println!("{}", err),
            Self::Lex(err) => println!("{}", err.kind),
            Self::Parse(err) => println!("{}", err.kind),
            Self::Semantic(summary) => println!("{}", summary),
            Self::Runtime(err) => println!("{}", err.kind),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Plan {
    Repl,
    Compile(Vec<Job>),
}

/// One compile: an input and the pcap file it's written to
#[derive(Debug, PartialEq, Eq)]
struct Job {
    input: Input,
    output: PathBuf,
}

impl Job {
    fn diagnostic(&self, stdout: &mut StandardStream, diag: Diagnostic) {
        let Diagnostic { loc, kind } = diag;

        if loc.is_nil() {
            print!("{}: ", self.input);
        } else {
            print!("{}:{}:{}: ", self.input, loc.line(), loc.col());
        }
        match kind {
            DiagnosticKind::Error(err) => {
                error!(stdout, "semantic error");
                println!(": {}", err);
            }
            DiagnosticKind::Warning(warn) => {
                warn!(stdout, "warning");
                println!(": {}", warn);
            }
        }
    }

    /// Lex and parse the input
    fn parse(&self) -> Result<Vec<Stmt>, CompileError> {
        let mut lex = Lexer::default();

        for line in self.input.open()?.lines() {
            lex.line(&line?)?;
        }

        Ok(parse(lex.finish())?)
    }

    /// Run a checked program, writing each packet it sends to the output pcap file
    fn write_pcap(
        &self,
        prog: Program,
        start_time: StartTime,
        verbose: bool,
    ) -> Result<(), CompileError> {
        let mut wr = PcapWriter::create(&self.output)?;
        if verbose {
            wr = wr.debug();
        }

        TreeInterp::new(prog, start_time.as_nanos()).run(|_loc, effect| match effect {
            Effect::Packet { time, pkt } => wr
                .write_packet(time, pkt)
                .map_err(RuntimeErrorKind::PcapWrite),
            // The checker already warned about the discarded value, and the interpreter stamps
            // each packet with the time
            Effect::Discard(_) | Effect::TimeJump(_) => Ok(()),
        })?;
        wr.flush()?;

        Ok(())
    }

    /// Compile the input to a pcap. The program is checked before the pcap file is created, so a
    /// program that doesn't check never touches it. Each error and warning from the checker is
    /// printed as it is found.
    fn compile(
        &self,
        stdout: &mut StandardStream,
        start_time: StartTime,
        verbose: bool,
    ) -> Result<(), CompileError> {
        let stmts = self.parse()?;
        let prog = check(stmts, |diag| self.diagnostic(stdout, diag))?;
        self.write_pcap(prog, start_time, verbose)
    }

    /// Compiles the job and reports how it went. On failure, the output is deleted unless `keep`.
    fn run(
        &self,
        stdout: &mut StandardStream,
        start_time: StartTime,
        verbose: bool,
        keep: bool,
    ) -> Result<(), ()> {
        let Err(error) = self.compile(stdout, start_time, verbose) else {
            print!("{} -> {} ", self.input, self.output.display());
            ok!(stdout, "ok");
            println!();
            return Ok(());
        };

        error.print(stdout, &self.input);

        // By default, if the file failed for any reason, regardless of whether we created it or
        // not, we delete it. This behaviour can be overridden with the `--keep` flag.
        //
        // This is basically because we anticipate that we're translating source files to e.g.
        // test cases, and we want the test cases to fail with "no file", rather than producing
        // weird or spurious output.
        //
        // Maybe we readdress this and only delete things we actually created in future.
        if !keep
            && let Err(rm_err) = fs::remove_file(&self.output)
            && rm_err.kind() != io::ErrorKind::NotFound
        {
            print!("{}: ", self.input);
            error!(stdout, "error");
            println!(": delete: {}", rm_err);
        }

        Err(())
    }
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

    let plan = match argv.output.plan(argv.input, io::stdin().is_terminal()) {
        Ok(plan) => plan,
        Err(err) => {
            Cli::command()
                .error(ErrorKind::ArgumentConflict, err)
                .exit();
        }
    };

    match plan {
        Plan::Repl => {
            Cli::command()
                .error(ErrorKind::ArgumentConflict, "REPL not implemented yet")
                .exit();
        }

        // Not short-circuiting: every job runs, even after one fails
        Plan::Compile(jobs) => jobs
            .iter()
            .map(|job| job.run(&mut stdout, argv.start_time, argv.verbose, argv.keep))
            .fold(Ok(()), Result::and),
    }
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

    use std::num::NonZeroUsize;

    use resynth::{LexErrorKind, ParseErrorKind, RuntimeErrorKind};

    fn compile_errors() -> [CompileError; 5] {
        [
            CompileError::Io(io::ErrorKind::NotFound.into()),
            CompileError::Lex(LexError {
                loc: Loc::new(1, 2),
                kind: LexErrorKind::UnterminatedString,
            }),
            CompileError::Parse(ParseError {
                loc: Loc::new(3, 4),
                kind: ParseErrorKind::IntOutOfRange,
            }),
            CompileError::Semantic(ErrorSummary {
                errors: NonZeroUsize::MIN,
                warnings: 0,
            }),
            CompileError::Runtime(RuntimeError {
                loc: Loc::new(7, 8),
                kind: RuntimeErrorKind::LibTodo,
            }),
        ]
    }

    #[test]
    fn compile_error_loc() {
        assert_eq!(
            compile_errors().map(|err| err.loc()),
            [
                None,
                Some(Loc::new(1, 2)),
                Some(Loc::new(3, 4)),
                None,
                Some(Loc::new(7, 8)),
            ]
        );
    }

    #[test]
    fn compile_error_phase() {
        assert_eq!(
            compile_errors().map(|err| err.phase()),
            ["io", "lex", "parse", "semantic", "runtime"]
        );
    }

    /// `mode`'s output path for `input`
    fn out(mode: &OutputMode, input: &str) -> PathBuf {
        mode.path_for(Path::new(input)).expect("output path")
    }

    /// The plan for `-o file` and `--out-dir dir` with input `files`
    fn plan(
        file: Option<&str>,
        dir: Option<&str>,
        files: &[&str],
        stdin_is_tty: bool,
    ) -> Result<Plan, OutputError> {
        OutputArgs {
            file: file.map(PathBuf::from),
            dir: dir.map(PathBuf::from),
        }
        .plan(files.iter().map(PathBuf::from).collect(), stdin_is_tty)
    }

    fn job(input: &str, output: &str) -> Job {
        Job {
            input: Input::File(input.into()),
            output: output.into(),
        }
    }

    #[test]
    fn plan_starts_repl_on_tty() {
        assert_eq!(plan(None, None, &[], true).unwrap(), Plan::Repl);
    }

    #[test]
    fn plan_rejects_output_for_repl() {
        for (file, dir) in [(Some("x.pcap"), None), (None, Some("out"))] {
            assert!(matches!(
                plan(file, dir, &[], true),
                Err(OutputError::ReplCannotOutput),
            ));
        }
    }

    /// `resynth -o out.pcap < prog.rsyn`
    #[test]
    fn plan_reads_stdin_to_file() {
        assert_eq!(
            plan(Some("out.pcap"), None, &[], false).unwrap(),
            Plan::Compile(vec![Job {
                input: Input::Stdin,
                output: "out.pcap".into(),
            }]),
        );
    }

    #[test]
    fn plan_requires_file_for_stdin() {
        for dir in [None, Some("out")] {
            assert!(matches!(
                plan(None, dir, &[], false),
                Err(OutputError::StdinRequiresOutput),
            ));
        }
    }

    #[test]
    fn plan_ignores_tty_with_files() {
        assert_eq!(
            plan(None, None, &["a.rsyn"], true).unwrap(),
            plan(None, None, &["a.rsyn"], false).unwrap(),
        );
    }

    #[test]
    fn plan_defaults_to_beside_input() {
        assert_eq!(
            plan(None, None, &["a.rsyn", "d/b.rsyn"], false).unwrap(),
            Plan::Compile(vec![job("a.rsyn", "a.pcap"), job("d/b.rsyn", "d/b.pcap")]),
        );
    }

    #[test]
    fn plan_writes_to_dir() {
        assert_eq!(
            plan(None, Some("out"), &["x/a.rsyn", "b.rsyn"], false).unwrap(),
            Plan::Compile(vec![
                job("x/a.rsyn", "out/a.pcap"),
                job("b.rsyn", "out/b.pcap")
            ]),
        );
    }

    #[test]
    fn plan_writes_one_input_to_file() {
        assert_eq!(
            plan(Some("x.pcap"), None, &["a.rsyn"], false).unwrap(),
            Plan::Compile(vec![job("a.rsyn", "x.pcap")]),
        );
    }

    #[test]
    fn plan_file_ignores_input_name() {
        assert_eq!(
            plan(Some("x.pcap"), None, &["/"], false).unwrap(),
            Plan::Compile(vec![job("/", "x.pcap")]),
        );
    }

    #[test]
    fn plan_rejects_file_with_many_inputs() {
        assert!(matches!(
            plan(Some("x.pcap"), None, &["a.rsyn", "b.rsyn"], false),
            Err(OutputError::FileWithInputs(2)),
        ));
    }

    #[test]
    fn plan_rejects_any_input_without_file_name() {
        assert!(matches!(
            plan(None, None, &["a.rsyn", ".."], false),
            Err(OutputError::NoFileName(p)) if p == Path::new(".."),
        ));
    }

    #[test]
    fn input_display() {
        assert_eq!(Input::File("d/a.rsyn".into()).to_string(), "d/a.rsyn");
        assert_eq!(Input::Stdin.to_string(), "<stdin>");
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
    fn input_without_file_name_is_error() {
        for input in ["..", "/", ""] {
            assert!(
                matches!(
                    OutputMode::BesideInput.path_for(Path::new(input)),
                    Err(OutputError::NoFileName(_)),
                ),
                "{input:?}",
            );
        }
    }
}
