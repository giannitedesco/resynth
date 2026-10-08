use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::num::{IntErrorKind, ParseIntError};

use derive_more::{Display, Error};
use lazy_regex::*;
use regex::CaptureLocations;

use crate::loc::Loc;
use crate::str::{Buf, StringLiteralErrorKind};

static LEX_RE: Lazy<Regex> = lazy_regex!(
    "^\
    (?:\
    (?P<whitespace>[^\\S\n][^\\S\n]*)\
    |\
    (?P<hashcomment>#[^\\n]*)\
    |\
    (?P<cppcomment>//[^\\n]*)\
    |\
    (?P<lparen>\\()\
    |\
    (?P<rparen>\\))\
    |\
    (?P<dot>\\.)\
    |\
    (?P<doublecolon>::)\
    |\
    (?P<colon>:)\
    |\
    (?P<semicolon>;)\
    |\
    (?P<equals>=)\
    |\
    (?P<comma>,)\
    |\
    (?P<slash>/)\
    |\
    (?P<import_keyword>\\bimport\\b)\
    |\
    (?P<let_keyword>\\blet\\b)\
    |\
    (?P<boolean_literal>\\b(?:true|false)\\b)\
    |\
    (?P<identifier>[a-zA-Z_][a-zA-Z0-9_]*)\
    |\
    (?P<ipv4_literal>[0-9]+(?:\\.[0-9]+){3}[a-zA-Z0-9_]*)\
    |\
    (?P<string_literal>\"[^\"\\n]*\")\
    |\
    (?P<hex_integer_literal>0x[0-9a-fA-F][a-zA-Z0-9_]*)\
    |\
    (?P<integer_literal>[0-9][a-zA-Z0-9_]*)\
    )\
"
);

/// A named capture group of `LEX_RE`: the lexical rule which matched.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Rule {
    Whitespace,
    HashComment,
    CppComment,

    LParen,
    RParen,
    Dot,
    DoubleColon,
    Colon,
    SemiColon,
    Equals,
    Comma,
    Slash,

    ImportKeyword,
    LetKeyword,
    BooleanLiteral,
    Identifier,
    IPv4Literal,
    StringLiteral,
    HexIntegerLiteral,
    IntegerLiteral,
}

impl Rule {
    /// Invariant: in the same order as the named capture groups in `LEX_RE`, so that capture
    /// group `i + 1` is `ALL[i]`. [Rule::from_caps] relies on this.
    const ALL: [Rule; 20] = [
        Rule::Whitespace,
        Rule::HashComment,
        Rule::CppComment,
        Rule::LParen,
        Rule::RParen,
        Rule::Dot,
        Rule::DoubleColon,
        Rule::Colon,
        Rule::SemiColon,
        Rule::Equals,
        Rule::Comma,
        Rule::Slash,
        Rule::ImportKeyword,
        Rule::LetKeyword,
        Rule::BooleanLiteral,
        Rule::Identifier,
        Rule::IPv4Literal,
        Rule::StringLiteral,
        Rule::HexIntegerLiteral,
        Rule::IntegerLiteral,
    ];

    /// The rule which matched, and the length of the match
    fn from_caps(caps: &CaptureLocations) -> Option<(Self, usize)> {
        Self::ALL
            .iter()
            .enumerate()
            .find_map(|(i, rule)| caps.get(i + 1).map(|(_, end)| (*rule, end)))
    }
}

/// A token of the resynth language. Literals carry their decoded values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    Eof,

    LParen,
    RParen,
    Dot,
    DoubleColon,
    Colon,
    SemiColon,
    Equals,
    Comma,
    Slash,

    ImportKeyword,
    LetKeyword,

    Identifier(Box<str>),
    BooleanLiteral(bool),
    IPv4Literal(Ipv4Addr),
    /// The decoded bytes of one or more adjacent string literals, joined
    StringLiteral(Buf),
    /// In `0..=i128::MAX`
    HexLiteral(i128),
    /// In `0..=i128::MAX`
    DecLiteral(i128),
}

impl Tok {
    /// Decode the text matched by a rule. Rules which don't produce a token on their own
    /// (whitespace, comments and string literals) are handled by [Lexer::line].
    fn decode(rule: Rule, lexeme: &str) -> Result<Self, LexErrorKind> {
        Ok(match rule {
            Rule::LParen => Self::LParen,
            Rule::RParen => Self::RParen,
            Rule::Dot => Self::Dot,
            Rule::DoubleColon => Self::DoubleColon,
            Rule::Colon => Self::Colon,
            Rule::SemiColon => Self::SemiColon,
            Rule::Equals => Self::Equals,
            Rule::Comma => Self::Comma,
            Rule::Slash => Self::Slash,
            Rule::ImportKeyword => Self::ImportKeyword,
            Rule::LetKeyword => Self::LetKeyword,
            Rule::Identifier => Self::Identifier(lexeme.into()),
            Rule::BooleanLiteral => Self::BooleanLiteral(lexeme == "true"),
            Rule::IPv4Literal => {
                Self::IPv4Literal(lexeme.parse().map_err(|_| LexErrorKind::IPv4Literal)?)
            }
            Rule::HexIntegerLiteral => Self::HexLiteral(i128::from_str_radix(&lexeme[2..], 16)?),
            Rule::IntegerLiteral => {
                if lexeme.starts_with('0')
                    && lexeme.len() > 1
                    && lexeme.chars().nth(1).unwrap().is_ascii_digit()
                {
                    return Err(LexErrorKind::IntLeadingZero);
                }
                Self::DecLiteral(lexeme.parse::<i128>()?)
            }
            Rule::Whitespace | Rule::HashComment | Rule::CppComment | Rule::StringLiteral => {
                unreachable!("{rule:?} is handled by Lexer::line")
            }
        })
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
    /// The end of the last line, where [Tok::Eof] is located
    loc: Loc,
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
        let mut caps = LEX_RE.capture_locations();
        let mut pos = 0;

        self.lno += 1;

        while pos < line.len() {
            let loc = Loc::new(self.lno, pos + 1);

            if LEX_RE.captures_read(&mut caps, &line[pos..]).is_none() {
                let c = line[pos..]
                    .chars()
                    .next()
                    .expect("pos < line.len() and is on a char boundary");
                // The string rule only excludes `"` and `\n` from the body, so a `"` it doesn't
                // match can only be one with no closing `"` before the end of the line
                let kind = match c {
                    '"' => LexErrorKind::UnterminatedString,
                    c => LexErrorKind::UnexpectedChar(c),
                };
                return Err(kind.at(loc));
            }
            let (rule, len) =
                Rule::from_caps(&caps).expect("a match always captures exactly one rule");
            let lexeme = &line[pos..pos + len];
            pos += len;

            match rule {
                Rule::Whitespace | Rule::HashComment | Rule::CppComment => {}
                Rule::StringLiteral => {
                    let pend = self.pending.get_or_insert_with(|| PendingStr {
                        loc,
                        bytes: Vec::new(),
                    });
                    // Each literal is decoded on its own, so a hex sequence can't span two
                    let body = &lexeme[1..len - 1];
                    if let Err(err) = Buf::decode_literal_into(body, &mut pend.bytes) {
                        // Located at the offending character, just past the opening `"`
                        let loc = Loc::new(self.lno, loc.col() + 1 + err.offset);
                        return Err(LexErrorKind::StringLiteral(err.kind).at(loc));
                    }
                }
                rule => {
                    self.toks
                        .extend(self.pending.take().map(PendingStr::into_token));
                    self.toks.push_back(Token {
                        loc,
                        tok: Tok::decode(rule, lexeme).map_err(|kind| kind.at(loc))?,
                    });
                }
            }
        }

        self.loc = Loc::new(self.lno, pos + 1);

        Ok(())
    }

    /// All of the tokens, ending with a single [Tok::Eof] located at the end of the last line.
    pub fn finish(mut self) -> VecDeque<Token> {
        self.toks
            .extend(self.pending.take().map(PendingStr::into_token));
        self.toks.push_back(Token {
            loc: if self.lno == 0 {
                Loc::new(1, 1)
            } else {
                self.loc
            },
            tok: Tok::Eof,
        });

        self.toks
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
