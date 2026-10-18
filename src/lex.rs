use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::num::{IntErrorKind, ParseIntError};
use std::ops::Range;

use derive_more::{Display, Error};

use crate::loc::Loc;
use crate::str::{Buf, StringLiteralErrorKind};

/// A token of the resynth language. Literals carry their decoded values.
///
/// Its [Display](std::fmt::Display) is for diagnostics. A string literal's decoded bytes are not
/// re-encoded, and integers print their value, not their source text.
#[derive(Debug, Display, Clone, PartialEq, Eq)]
pub enum Tok {
    /// At the start of the line after the last, so its line is one more than the number of lines
    #[display("eof")]
    Eof,

    #[display("`(`")]
    LParen,
    #[display("`)`")]
    RParen,
    #[display("`.`")]
    Dot,
    #[display("`::`")]
    DoubleColon,
    #[display("`:`")]
    Colon,
    #[display("`;`")]
    SemiColon,
    #[display("`=`")]
    Equals,
    #[display("`,`")]
    Comma,
    #[display("`/`")]
    Slash,

    #[display("`import`")]
    ImportKeyword,
    #[display("`let`")]
    LetKeyword,

    #[display("`{_0}`")]
    Identifier(Box<str>),
    #[display("`{_0}`")]
    BooleanLiteral(bool),
    #[display("`{_0}`")]
    IPv4Literal(Ipv4Addr),
    /// The decoded bytes of one or more adjacent string literals, joined
    #[display("string literal")]
    StringLiteral(Buf),
    /// In `0..=i128::MAX`
    #[display("`{_0:#x}`")]
    HexLiteral(i128),
    /// In `0..=i128::MAX`
    #[display("`{_0}`")]
    DecLiteral(i128),
}

impl Tok {
    /// Classify a word: a keyword, a boolean literal, or else an identifier
    fn word(word: &str) -> Self {
        match word {
            "import" => Self::ImportKeyword,
            "let" => Self::LetKeyword,
            "true" => Self::BooleanLiteral(true),
            "false" => Self::BooleanLiteral(false),
            _ => Self::Identifier(word.into()),
        }
    }

    /// Decode a dotted quad, along with any word characters which follow it
    fn ipv4_literal(lexeme: &str) -> Result<Self, LexErrorKind> {
        lexeme
            .parse()
            .map(Self::IPv4Literal)
            .map_err(|_| LexErrorKind::IPv4Literal)
    }

    /// Decode the hex digits following `0x`, along with any word characters which follow them
    fn hex_literal(digits: &str) -> Result<Self, LexErrorKind> {
        Ok(Self::HexLiteral(i128::from_str_radix(digits, 16)?))
    }

    /// Decode a decimal literal, along with any word characters which follow it
    fn dec_literal(lexeme: &str) -> Result<Self, LexErrorKind> {
        if lexeme.starts_with('0')
            && lexeme.len() > 1
            && lexeme.chars().nth(1).unwrap().is_ascii_digit()
        {
            return Err(LexErrorKind::IntLeadingZero);
        }
        Ok(Self::DecLiteral(lexeme.parse::<i128>()?))
    }
}

/// A [Tok] and where it starts in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub(crate) loc: Loc,
    pub(crate) tok: Tok,
}

impl Token {
    pub fn loc(&self) -> Loc {
        self.loc
    }

    pub fn tok(&self) -> &Tok {
        &self.tok
    }

    pub fn into_parts(self) -> (Loc, Tok) {
        (self.loc, self.tok)
    }
}

/// Why the source could not be lexed, and where
#[derive(Debug, Display, Error, Clone, PartialEq, Eq)]
#[display("{}-{}: {kind}", span.start + 1, span.end)]
pub struct LexLineError {
    pub span: Range<usize>,
    pub kind: LexErrorKind,
}

impl LexLineError {
    pub fn loc(&self, lno: usize) -> Loc {
        Loc::new(lno, self.span.start + 1)
    }

    pub fn locate(self, lno: usize) -> LexError {
        LexError {
            loc: self.loc(lno),
            kind: self.kind,
        }
    }
}

/// Why the source could not be lexed, and where
#[derive(Debug, Display, Error, Clone, PartialEq, Eq)]
#[display("{loc}: {kind}")]
pub struct LexError {
    pub loc: Loc,
    pub kind: LexErrorKind,
}

/// What is wrong with the source
#[derive(Debug, Display, Error, Clone, PartialEq, Eq)]
pub enum LexErrorKind {
    /// No token starts with this character
    #[display("unexpected character {_0:?}")]
    #[error(ignore)]
    UnexpectedChar(char),

    /// A `"` with no closing `"` on the same line
    #[display("unterminated string literal")]
    UnterminatedString,

    #[display("{_0}")]
    #[error(ignore)]
    StringLiteral(StringLiteralErrorKind),

    /// An integer literal greater than `i128::MAX`
    #[display("integer literal out of range")]
    IntOutOfRange,

    /// A decimal integer literal with a leading zero, e.g. `0123`
    #[display("decimal integer literal with leading zero")]
    IntLeadingZero,

    /// An integer literal with an unrecognized suffix, e.g. `123abc`
    #[display("integer literal with invalid suffix")]
    IntInvalidSuffix,

    /// Bad IPv4 literal, e.g. `256.0.0.1`, `01.2.3.4`
    #[display("invalid IPv4 literal")]
    IPv4Literal,
}

impl LexErrorKind {
    /// This error, at `loc`
    pub(crate) fn at(self, loc: Loc) -> LexError {
        LexError { loc, kind: self }
    }

    fn within_line(self, span: Range<usize>) -> LexLineError {
        LexLineError { span, kind: self }
    }
}

impl From<ParseIntError> for LexErrorKind {
    fn from(err: ParseIntError) -> Self {
        match err.kind() {
            IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => Self::IntOutOfRange,
            IntErrorKind::InvalidDigit => Self::IntInvalidSuffix,
            _ => unreachable!("unexpected error parsing integer literal: {err:?}"),
        }
    }
}

/// Adjacent string literals which are being joined in to a single token
#[derive(Debug)]
struct PendingStr {
    loc: Loc,
    bytes: Vec<u8>,
}

impl PendingStr {
    fn into_token(self) -> Token {
        Token {
            loc: self.loc,
            tok: Tok::StringLiteral(Buf::from(self.bytes)),
        }
    }
}

/// What the [Scanner] found at one position in a line
#[derive(Debug)]
pub enum LexemeKind<'a> {
    /// Whitespace or a comment
    Trivia,
    /// The body of a string literal, between its quotes. It may be joined with those which
    /// follow it.
    Str(&'a str),
    Tok(Tok),
}

impl<'a> LexemeKind<'a> {
    fn at(self, span: Range<usize>) -> Lexeme<'a> {
        Lexeme { span, kind: self }
    }
}

#[derive(Debug)]
pub struct Lexeme<'a> {
    pub span: Range<usize>,
    pub kind: LexemeKind<'a>,
}

/// A position within one line
#[derive(Debug)]
pub struct Scanner<'a> {
    line: &'a str,
    /// Always on a char boundary
    pos: usize,
}

impl<'a> Scanner<'a> {
    pub const fn new(line: &'a str) -> Self {
        Self { line, pos: 0 }
    }

    /// `\n` is not whitespace, because it's not allowed in a line
    const fn is_space(c: char) -> bool {
        c.is_whitespace() && c != '\n'
    }

    const fn is_word(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '_'
    }

    fn peek(&self) -> Option<char> {
        self.line[self.pos..].chars().next()
    }

    /// Advance past `c`, if it's next
    fn eat(&mut self, c: char) -> bool {
        let found = self.peek() == Some(c);
        if found {
            self.pos += c.len_utf8();
        }
        found
    }

    /// Advance past the longest run of chars matching `pred`, and return them
    fn eat_while(&mut self, pred: impl Fn(char) -> bool) -> &'a str {
        let start = self.pos;
        for c in self.line[start..].chars().take_while(|&c| pred(c)) {
            self.pos += c.len_utf8();
        }
        &self.line[start..self.pos]
    }

    /// Lex whatever starts with `c`, which must be the [next](Scanner::peek) char. On error, the
    /// location of the error is where the cursor was.
    fn lexeme(&mut self, c: char) -> Result<LexemeKind<'a>, LexErrorKind> {
        let start = self.pos;
        self.pos += c.len_utf8();

        Ok(match c {
            c if Self::is_space(c) => {
                self.eat_while(Self::is_space);
                LexemeKind::Trivia
            }
            '#' => {
                self.eat_while(|c| c != '\n');
                LexemeKind::Trivia
            }
            '/' if self.eat('/') => {
                self.eat_while(|c| c != '\n');
                LexemeKind::Trivia
            }

            '(' => LexemeKind::Tok(Tok::LParen),
            ')' => LexemeKind::Tok(Tok::RParen),
            '.' => LexemeKind::Tok(Tok::Dot),
            ':' if self.eat(':') => LexemeKind::Tok(Tok::DoubleColon),
            ':' => LexemeKind::Tok(Tok::Colon),
            ';' => LexemeKind::Tok(Tok::SemiColon),
            '=' => LexemeKind::Tok(Tok::Equals),
            ',' => LexemeKind::Tok(Tok::Comma),
            '/' => LexemeKind::Tok(Tok::Slash),

            '"' => {
                let body = self.eat_while(|c| c != '"' && c != '\n');
                if !self.eat('"') {
                    return Err(LexErrorKind::UnterminatedString);
                }
                LexemeKind::Str(body)
            }

            'a'..='z' | 'A'..='Z' | '_' => {
                self.eat_while(Self::is_word);
                LexemeKind::Tok(Tok::word(&self.line[start..self.pos]))
            }

            '0'..='9' => LexemeKind::Tok(self.number(start)?),

            c => return Err(LexErrorKind::UnexpectedChar(c)),
        })
    }

    /// Lex a numeric literal starting at `start`, the cursor being just past its first digit.
    ///
    /// Four runs of digits separated by `.` are an IPv4 literal. Otherwise, a run of word
    /// characters starting with `0x` and a hex digit is a hex literal, and any other is a decimal
    /// literal. Any word characters which follow the literal are part of it, so that `123abc` is
    /// one malformed literal, and not a literal followed by an identifier.
    fn number(&mut self, start: usize) -> Result<Tok, LexErrorKind> {
        self.eat_while(|c| c.is_ascii_digit());
        let mut dotted_quad = true;
        for _ in 0..3 {
            if !self.eat('.') || self.eat_while(|c| c.is_ascii_digit()).is_empty() {
                dotted_quad = false;
                self.pos = start;
                break;
            }
        }

        self.eat_while(Self::is_word);
        let lexeme = &self.line[start..self.pos];

        if dotted_quad {
            return Tok::ipv4_literal(lexeme);
        }
        match lexeme.strip_prefix("0x") {
            Some(digits) if digits.starts_with(|c: char| c.is_ascii_hexdigit()) => {
                Tok::hex_literal(digits)
            }
            _ => Tok::dec_literal(lexeme),
        }
    }
}

impl<'a> Iterator for Scanner<'a> {
    type Item = Result<Lexeme<'a>, LexLineError>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.pos;
        let c = self.peek()?;
        Some(match self.lexeme(c) {
            Ok(kind) => Ok(kind.at(start..self.pos)),
            Err(err) => Err(err.within_line(start..self.pos)),
        })
    }
}

/// The lexer is fed a [line at a time](Lexer::line), and appends the [tokens](Token) to a
/// [queue](VecDeque) which is returned by [Lexer::finish]. Each [LexError] carries the location
/// of the offending character.
///
/// The lexer never needs the whole source in memory, only the line being lexed. Memory use is
/// bounded by the longest line and the number of tokens, not by the size of the file.
#[derive(Debug, Default)]
pub struct Lexer {
    /// Number of lines fed so far
    lno: usize,
    /// String literals which may yet be joined with ones on following lines
    pending: Option<PendingStr>,
    toks: VecDeque<Token>,
}

impl Lexer {
    /// Lex one line. The line must not include its terminator: a `\n` anywhere in it is a lex
    /// error. A `\r` is whitespace, so lines with CRLF endings are accepted as they are.
    ///
    /// Whitespace and comments are dropped. Adjacent string literals, even across lines and
    /// comments, are joined in to one token located at the first of them. Columns are counted
    /// in bytes.
    ///
    /// After an error the lexer must not be fed any more lines.
    pub fn line(&mut self, line: &str) -> Result<(), LexError> {
        self.lno += 1;

        for lexeme in Scanner::new(line) {
            let lexeme = lexeme.map_err(|err| err.locate(self.lno))?;
            let loc = Loc::new(self.lno, lexeme.span.start + 1);
            match lexeme.kind {
                LexemeKind::Trivia => {}
                LexemeKind::Str(body) => {
                    let pend = self.pending.get_or_insert_with(|| PendingStr {
                        loc,
                        bytes: Vec::new(),
                    });
                    // Each literal is decoded on its own, so a hex sequence can't span two
                    if let Err(err) = Buf::decode_literal_into(body, &mut pend.bytes) {
                        // Located at the offending character, just past the opening `"`
                        let loc = Loc::new(self.lno, loc.col() + 1 + err.offset);
                        return Err(LexErrorKind::StringLiteral(err.kind).at(loc));
                    }
                }
                LexemeKind::Tok(tok) => {
                    self.toks
                        .extend(self.pending.take().map(PendingStr::into_token));
                    self.toks.push_back(Token { loc, tok });
                }
            }
        }

        Ok(())
    }

    /// Append [Tok::Eof]. Every line is taken to end with a `\n`, even the last, so the file
    /// ends at the start of the line after it, and the line of `Eof` is one more than the number
    /// of lines.
    fn push_eof(&mut self) {
        self.toks.push_back(Token {
            loc: Loc::new(self.lno + 1, 1),
            tok: Tok::Eof,
        });
    }

    /// All of the tokens, ending with a single [Tok::Eof] at the start of the line after the
    /// last.
    pub fn finish(mut self) -> VecDeque<Token> {
        self.toks
            .extend(self.pending.take().map(PendingStr::into_token));
        self.push_eof();

        self.toks
    }

    /// The tokens queued so far, without [finishing](Lexer::finish), so that tests can see what
    /// was lexed before an error. String literals not yet joined are not included.
    #[cfg(test)]
    pub(crate) fn toks(&self) -> &VecDeque<Token> {
        &self.toks
    }

    /// Lex every line, as if by [Lexer::line], and then [finish](Lexer::finish), stopping at the
    /// first error.
    pub fn lex<I>(lines: I) -> Result<VecDeque<Token>, LexError>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut lexer = Self::default();

        for line in lines {
            lexer.line(line.as_ref())?;
        }

        Ok(lexer.finish())
    }
}
