//! An interactive REPL, for language development. Input is highlighted as it's typed. Each input
//! ends at a blank line, and is checked on its own and printed as HIR.

use std::borrow::Cow;
use std::fmt;
use std::io;

use nu_ansi_term::{Color as Ansi, Style};
use reedline::{
    DefaultPrompt, DefaultPromptSegment, Highlighter, Prompt, PromptEditMode, PromptHistorySearch,
    Reedline, Signal, StyledText, ValidationResult, Validator,
};
use termcolor::{Color, ColorSpec, StandardStream, WriteColor};

use resynth::parse::parse;
use resynth::{Diagnostic, DiagnosticKind, Lexeme, LexemeKind, Lexer, Loc, Scanner, Tok, check};
use resynth::{error, warn};

struct ReplPrompt(DefaultPrompt);

impl Prompt for ReplPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        self.0.render_prompt_left()
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        self.0.render_prompt_right()
    }

    fn render_prompt_indicator(&self, edit_mode: PromptEditMode) -> Cow<'_, str> {
        self.0.render_prompt_indicator(edit_mode)
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed("... ")
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<'_, str> {
        self.0
            .render_prompt_history_search_indicator(history_search)
    }
}

impl ReplPrompt {
    fn new(left: DefaultPromptSegment, right: DefaultPromptSegment) -> Self {
        Self(DefaultPrompt::new(left, right))
    }
}

pub struct Repl {
    editor: Reedline,
    prompt: ReplPrompt,
}

impl Repl {
    /// With `ansi` false, input is not highlighted
    pub fn new(ansi: bool) -> Self {
        Self {
            editor: Reedline::create()
                .with_highlighter(Box::new(Highlight))
                .with_validator(Box::new(BlankLine))
                .with_ansi_colors(ansi),
            prompt: ReplPrompt::new(
                DefaultPromptSegment::Basic("rsyn".into()),
                DefaultPromptSegment::Empty,
            ),
        }
    }

    /// Read and check inputs until Ctrl-D
    pub fn run(mut self, stdout: &mut StandardStream) -> io::Result<()> {
        loop {
            match self.editor.read_line(&self.prompt)? {
                Signal::Success(src) if src.trim().is_empty() => {}
                Signal::Success(src) => Report { src: &src, stdout }.compile(),
                Signal::CtrlD => return Ok(()),
                // Ctrl-C abandons the input. No host commands or external breaks are set up.
                _ => {}
            }
        }
    }
}

/// Colours each lexeme of the input as it's typed
struct Highlight;

impl Highlight {
    fn error() -> Style {
        Ansi::Red.underline()
    }

    fn style(kind: &LexemeKind, text: &str) -> Style {
        match kind {
            LexemeKind::Trivia if text.starts_with('#') || text.starts_with("//") => {
                Style::new().fg(Ansi::DarkGray)
            }
            LexemeKind::Trivia => Style::new(),
            LexemeKind::Str(_) => Style::new().fg(Ansi::Green),
            LexemeKind::Tok(tok) => match tok {
                Tok::ImportKeyword | Tok::LetKeyword => Style::new().fg(Ansi::Purple).bold(),
                Tok::BooleanLiteral(_)
                | Tok::IPv4Literal(_)
                | Tok::HexLiteral(_)
                | Tok::DecLiteral(_) => Style::new().fg(Ansi::Cyan),
                Tok::StringLiteral(_) => Style::new().fg(Ansi::Green),
                Tok::Identifier(_)
                | Tok::Eof
                | Tok::LParen
                | Tok::RParen
                | Tok::Dot
                | Tok::DoubleColon
                | Tok::Colon
                | Tok::SemiColon
                | Tok::Equals
                | Tok::Comma
                | Tok::Slash => Style::new(),
            },
        }
    }

    /// Append one line, without its `\n`, to `out`. Every byte of the line is appended, whether
    /// or not it lexes.
    fn line(line: &str, out: &mut StyledText) {
        let mut end = 0;
        for lexeme in Scanner::new(line) {
            let (span, style) = match lexeme {
                Ok(Lexeme { span, kind }) => {
                    let style = Self::style(&kind, &line[span.clone()]);
                    (span, style)
                }
                Err(err) => (err.span, Self::error()),
            };
            if span.start > end {
                out.push((Style::new(), line[end..span.start].into()));
            }
            out.push((style, line[span.clone()].into()));
            end = span.end;
        }
        if end < line.len() {
            out.push((Style::new(), line[end..].into()));
        }
    }
}

impl Highlighter for Highlight {
    /// The [Scanner] lexes a line at a time, so each line of the buffer is highlighted on its own
    fn highlight(&self, buf: &str, _cursor: usize) -> StyledText {
        let mut out = StyledText::new();
        for line in buf.split_inclusive('\n') {
            match line.strip_suffix('\n') {
                Some(line) => {
                    Self::line(line, &mut out);
                    out.push((Style::new(), "\n".into()));
                }
                None => Self::line(line, &mut out),
            }
        }
        out
    }
}

/// An input is complete once its last line is blank. Until then, Enter starts a new line.
struct BlankLine;

impl Validator for BlankLine {
    fn validate(&self, buf: &str) -> ValidationResult {
        let last = buf.rsplit('\n').next().unwrap_or_default();
        if last.trim().is_empty() {
            ValidationResult::Complete
        } else {
            ValidationResult::Incomplete
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Error,
    Warning,
}

impl Severity {
    fn paint(self, stdout: &mut StandardStream, text: &str) {
        match self {
            Self::Error => error!(stdout, "{}", text),
            Self::Warning => warn!(stdout, "{}", text),
        }
    }
}

/// The source line a location points into, and carets under the lexeme there
#[derive(Debug, PartialEq, Eq)]
struct Snippet<'a> {
    lno: usize,
    line: &'a str,
    /// Lines up the carets under the source line: a tab for each tab before the location, and a
    /// space for each other char
    pad: String,
    carets: usize,
}

impl<'a> Snippet<'a> {
    /// `None` when `loc` is nil, or points outside `src`. The end of input is on the line after
    /// the last.
    fn new(src: &'a str, loc: Loc) -> Option<Self> {
        let line = src.lines().nth(loc.line().checked_sub(1)?)?;
        let start = loc.col().checked_sub(1)?;
        let pad = line
            .get(..start)?
            .chars()
            .map(|c| if c == '\t' { '\t' } else { ' ' })
            .collect();
        let carets = Scanner::new(line)
            .map(|lexeme| match lexeme {
                Ok(lexeme) => lexeme.span,
                Err(err) => err.span,
            })
            .find(|span| span.start == start)
            .map_or(1, |span| line[span].chars().count());

        Some(Self {
            lno: loc.line(),
            line,
            pad,
            carets,
        })
    }

    fn print(&self, stdout: &mut StandardStream, severity: Severity) {
        let width = self.lno.to_string().len();
        println!("{:>width$} | {}", self.lno, self.line);
        print!("{:>width$} | {}", "", self.pad);
        severity.paint(stdout, &"^".repeat(self.carets));
        println!();
    }
}

/// Compiles one input, printing each diagnostic with the source it points at
struct Report<'a> {
    src: &'a str,
    stdout: &'a mut StandardStream,
}

impl Report<'_> {
    const NAME: &str = "<repl>";

    fn print(&mut self, loc: Option<Loc>, severity: Severity, label: &str, msg: &dyn fmt::Display) {
        let loc = loc.filter(|loc| !loc.is_nil());
        match loc {
            Some(loc) => print!("{}:{}:{}: ", Self::NAME, loc.line(), loc.col()),
            None => print!("{}: ", Self::NAME),
        }
        severity.paint(self.stdout, label);
        println!(": {}", msg);

        if let Some(snippet) = loc.and_then(|loc| Snippet::new(self.src, loc)) {
            snippet.print(self.stdout, severity);
        }
    }

    fn diagnostic(&mut self, Diagnostic { loc, kind }: Diagnostic) {
        match kind {
            DiagnosticKind::Error(err) => {
                self.print(Some(loc), Severity::Error, "semantic error", &err)
            }
            DiagnosticKind::Warning(warn) => {
                self.print(Some(loc), Severity::Warning, "warning", &warn)
            }
        }
    }

    /// Print the input's HIR, or why it doesn't check. A lex or parse error is printed as its
    /// kind alone, since [`print`](Self::print) gives the location.
    fn compile(mut self) {
        let mut lex = Lexer::default();
        for line in self.src.lines() {
            if let Err(err) = lex.line(line) {
                return self.print(Some(err.loc), Severity::Error, "lex error", &err.kind);
            }
        }

        let stmts = match parse(lex.finish()) {
            Ok(stmts) => stmts,
            Err(err) => {
                return self.print(Some(err.loc), Severity::Error, "parse error", &err.kind);
            }
        };

        match check(stmts, |diag| self.diagnostic(diag)) {
            Ok(prog) => println!("{}", prog),
            Err(summary) => self.print(None, Severity::Error, "semantic error", &summary),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The highlighted text of `buf`
    fn highlighted(buf: &str) -> String {
        Highlight.highlight(buf, 0).raw_string()
    }

    #[test]
    fn highlight_keeps_every_byte() {
        for buf in [
            "",
            "\n",
            "let x = 1;",
            "let x = 1;\n",
            "let x = 1;\nx;\n\n",
            "let x = 1;\r\nx;\r\n",
            "let s = \"abc",
            "let s = \"abc\n\"def\";",
            "# héllo wörld\nlet x = 0x1g;",
            "let x = 1.2.3;",
            "let \t x = $ @ 1;",
            "1.2.3.4 \"|00|\" true // c",
        ] {
            assert_eq!(highlighted(buf), buf, "{buf:?}");
        }
    }

    #[test]
    fn highlight_styles() {
        let text = Highlight.highlight("let x = \"a\"; # c\n$", 0);
        let styles: Vec<_> = text
            .buffer
            .iter()
            .map(|(style, s)| (s.as_str(), *style))
            .collect();
        assert_eq!(
            styles,
            [
                ("let", Style::new().fg(Ansi::Purple).bold()),
                (" ", Style::new()),
                ("x", Style::new()),
                (" ", Style::new()),
                ("=", Style::new()),
                (" ", Style::new()),
                ("\"a\"", Style::new().fg(Ansi::Green)),
                (";", Style::new()),
                (" ", Style::new()),
                ("# c", Style::new().fg(Ansi::DarkGray)),
                ("\n", Style::new()),
                ("$", Highlight::error()),
            ]
        );
    }

    fn complete(buf: &str) -> bool {
        matches!(BlankLine.validate(buf), ValidationResult::Complete)
    }

    #[test]
    fn blank_line_ends_input() {
        assert!(complete(""));
        assert!(complete("  "));
        assert!(complete("x;\n"));
        assert!(complete("x;\n  "));
        assert!(complete("x;\n\ny;\n"));
        assert!(!complete("x;"));
        assert!(!complete("x;\ny;"));
        assert!(!complete("x;\n\ny;"));
    }

    #[test]
    fn snippet_underlines_lexeme() {
        assert_eq!(
            Snippet::new("let x = 1;\nlet y = foo;", Loc::new(2, 9)),
            Some(Snippet {
                lno: 2,
                line: "let y = foo;",
                pad: " ".repeat(8),
                carets: 3,
            })
        );
    }

    #[test]
    fn snippet_inside_lexeme_has_one_caret() {
        assert_eq!(
            Snippet::new("let s = \"ab\tc\";", Loc::new(1, 12)).map(|s| s.carets),
            Some(1)
        );
    }

    #[test]
    fn snippet_pads_by_char_and_keeps_tabs() {
        assert_eq!(
            Snippet::new("\t\"é\" x", Loc::new(1, 7)),
            Some(Snippet {
                lno: 1,
                line: "\t\"é\" x",
                pad: "\t    ".into(),
                carets: 1,
            })
        );
    }

    #[test]
    fn snippet_outside_source_is_none() {
        let src = "let x =\n";
        // Nil, the end of input on the line after the last, past the end of a line, and inside
        // a char
        for loc in [Loc::nil(), Loc::new(2, 1), Loc::new(1, 20)] {
            assert_eq!(Snippet::new(src, loc), None, "{loc:?}");
        }
        assert_eq!(Snippet::new("\"é\"", Loc::new(1, 3)), None);
    }
}
