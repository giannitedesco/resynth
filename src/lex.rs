use std::collections::VecDeque;
use std::net::Ipv4Addr;

use lazy_regex::*;
use regex::CaptureLocations;

use crate::err::Error;
use crate::err::Error::{IntLiteralError, LexError};
use crate::loc::Loc;

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
    (?P<ipv4_literal>\
        (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}\
        (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\
    )\
    |\
    (?P<string_literal>\"[^\"\\n]*\")\
    |\
    (?P<hex_integer_literal>0x[0-9a-fA-F][0-9a-fA-F]*)\
    |\
    (?P<integer_literal>[0-9][0-9]*)\
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
    /// The text between the quotes of one or more adjacent string literals, joined. It is not
    /// decoded yet.
    StringLiteral(Box<str>),
    /// In `0..=i128::MAX`
    HexLiteral(i128),
    /// In `0..=i128::MAX`
    DecLiteral(i128),
}

impl Tok {
    /// Decode the text matched by a rule. Rules which don't produce a token on their own
    /// (whitespace, comments and string literals) are handled by [Lexer::line].
    fn decode(rule: Rule, lexeme: &str) -> Result<Self, Error> {
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
            Rule::IPv4Literal => Self::IPv4Literal(
                lexeme
                    .parse()
                    .expect("the regex limits each octet to 0-255"),
            ),
            Rule::HexIntegerLiteral => Self::HexLiteral(
                i128::from_str_radix(&lexeme[2..], 16).map_err(|_| IntLiteralError)?,
            ),
            Rule::IntegerLiteral => Self::DecLiteral(lexeme.parse().map_err(|_| IntLiteralError)?),
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

/// Adjacent string literals which are being joined in to a single token
#[derive(Debug)]
struct PendingStr {
    loc: Loc,
    body: String,
}

impl PendingStr {
    fn into_token(self) -> Token {
        Token {
            loc: self.loc,
            tok: Tok::StringLiteral(self.body.into()),
        }
    }
}

/// The lexer is fed a [line at a time](Lexer::line), and appends the [tokens](Token) to a
/// [queue](VecDeque) which is returned by [Lexer::finish]. If an error occurs then the location
/// of that error may be retreived from [Lexer::loc].
///
/// The lexer never needs the whole source in memory, only the line being lexed. Memory use is
/// bounded by the longest line and the number of tokens, not by the size of the file.
#[derive(Debug, Default)]
pub struct Lexer {
    /// Number of lines fed so far
    lno: usize,
    /// Location of the last token, or the error, or the end of the last line
    loc: Loc,
    /// String literals which may yet be joined with ones on following lines
    pending: Option<PendingStr>,
    toks: VecDeque<Token>,
}

impl Lexer {
    pub fn loc(&self) -> Loc {
        self.loc
    }

    /// Lex one line. The line must not include its terminator: a `\n` anywhere in it is a lex
    /// error. A `\r` is whitespace, so lines with CRLF endings are accepted as they are.
    ///
    /// Whitespace and comments are dropped. Adjacent string literals, even across lines and
    /// comments, are joined in to one token located at the first of them. Columns are counted
    /// in bytes.
    ///
    /// After an error the lexer must not be fed any more lines.
    pub fn line(&mut self, line: &str) -> Result<(), Error> {
        let mut caps = LEX_RE.capture_locations();
        let mut pos = 0;

        self.lno += 1;

        while pos < line.len() {
            let loc = Loc::new(self.lno, pos + 1);
            self.loc = loc;

            if LEX_RE.captures_read(&mut caps, &line[pos..]).is_none() {
                return Err(LexError);
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
                        body: String::new(),
                    });
                    pend.body.push_str(&lexeme[1..len - 1]);
                }
                rule => {
                    self.toks
                        .extend(self.pending.take().map(PendingStr::into_token));
                    self.toks.push_back(Token {
                        loc,
                        tok: Tok::decode(rule, lexeme)?,
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

    /// Lex every line, as if by [Lexer::line], and then [finish](Lexer::finish). On error,
    /// returns the location of the offending character along with the error.
    pub fn lex<I>(lines: I) -> Result<VecDeque<Token>, (Loc, Error)>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut lexer = Self::default();

        for line in lines {
            lexer.line(line.as_ref()).map_err(|err| (lexer.loc, err))?;
        }

        Ok(lexer.finish())
    }
}
