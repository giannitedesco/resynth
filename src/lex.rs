use std::slice::Iter;

use lazy_regex::*;
use regex::CaptureLocations;

use crate::loc::Loc;
use crate::err::Error;
use crate::err::Error::LexError;

static LEX_RE: Lazy<Regex> = lazy_regex!("^\
    (?:\
    (?P<whitespace>[^\\S\n][^\\S\n]*)\
    |\
    (?P<hashcomment>#[^\\n]*)\
    |\
    (?P<cppcomment>//[^\\n]*)\
    |\
    (?P<newline>\\n)\
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
    (?P<import_keyword>\\bimport\\b)\
    |\
    (?P<let_keyword>\\blet\\b)\
    |\
    (?P<identifier>[a-zA-Z_][a-zA-Z0-9_]*)\
    |\
    (?P<ipv4_literal>\
        (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}\
        (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\
    )\
    |\
    (?P<string_literal>\"(?:\\\\.|[^\"\\\\])*\")\
    |\
    (?P<hex_integer_literal>0x[0-9a-fA-F][0-9a-fA-F]*)\
    |\
    (?P<integer_literal>[-]?[0-9][0-9]*)\
    )\
");

#[derive(Debug, Copy, Clone)]
pub enum TokType {
    Eof,

    Whitespace,
    HashComment,
    CppComment,
    NewLine,

    LParen,
    RParen,
    Dot,
    DoubleColon,
    Colon,
    SemiColon,
    Equals,
    Comma,

    ImportKeyword,
    LetKeyword,
    Identifier,
    IPv4Literal,
    StringLiteral,
    HexIntegerLiteral,
    IntegerLiteral,

    Max,
}

impl TokType {
    pub fn iterator() -> Iter<'static, TokType> {
        const TYPES: [TokType; TokType::Max as usize] = [
            TokType::Eof,

            TokType::Whitespace,
            TokType::HashComment,
            TokType::CppComment,
            TokType::NewLine,

            TokType::LParen,
            TokType::RParen,
            TokType::Dot,
            TokType::DoubleColon,
            TokType::Colon,
            TokType::SemiColon,
            TokType::Equals,
            TokType::Comma,

            TokType::ImportKeyword,
            TokType::LetKeyword,
            TokType::Identifier,
            TokType::IPv4Literal,
            TokType::StringLiteral,
            TokType::HexIntegerLiteral,
            TokType::IntegerLiteral,
        ];
        TYPES.iter()
    }

    pub fn from_caps(caps: &CaptureLocations,
                     ) -> Option<(TokType, usize)> {
        for x in TokType::iterator().skip(1) {
            let match_end = match caps.get(*x as usize) {
                Some((_, to)) => to,
                None => continue,
            };

            if match_end > 0 {
                return Some((*x, match_end));
            }
        }

        println!("no capture");
        None
    }

    pub fn ignore(self) -> bool {
        matches!(self,
            TokType::Whitespace
            | TokType::HashComment
            | TokType::CppComment
            | TokType::NewLine
        )
    }

    pub fn get_val(self, val: &str) -> Option<&str> {
        match self {
        TokType::Identifier => Some(val),
        TokType::HexIntegerLiteral => Some(val),
        TokType::IntegerLiteral => Some(val),
        TokType::StringLiteral => Some(val),
        TokType::IPv4Literal => Some(val),
        _ => None,
        }
    }
}

/// Represents a lexeme within the resynth language.
///
/// ## Lifetime
/// For things like identifiers and string literals, a reference is included to the original
/// string. So the [Token] must outlive that buffer.
#[derive(Debug, Copy, Clone)]
pub struct Token<'a> {
    loc: Loc,
    typ: TokType,
    val: Option<&'a str>,
}

impl<'a> Token<'a> {
    pub fn loc(&self) -> Loc {
        self.loc
    }

    pub fn tok_type(&self) -> TokType {
        self.typ
    }

    pub fn val(&self) -> &'a str {
        self.val.unwrap()
    }
}

impl From<Token<'_>> for String {
    fn from(tok: Token) -> String {
        tok.val.unwrap().to_owned()
    }
}

/// EOF token
pub const EOF: Token = Token {
    loc: Loc::nil(),
    typ: TokType::Eof,
    val: None,
};

/// The lexer takes a [line at a time](Lexer::line) and returns a [vector](Vec) of
/// [tokens](Token). If an error occurs then the location of that error may be retreived from
/// [Lexer::loc].
#[derive(Debug, Default)]
pub struct Lexer {
    loc: Loc,
}

impl Lexer {
    pub fn loc(&self) -> Loc {
        self.loc
    }

    fn throw(&mut self, pos: usize) -> Error {
        self.loc.set_col(pos + 1);
        LexError
    }

    pub fn line<'a>(&mut self, lno: usize, line: &'a str) -> Result<Vec<Token<'a>>, Error> {
        let mut ret = Vec::new();
        let mut pos = 0_usize;
        let mut caps = LEX_RE.capture_locations();

        self.loc = Loc::new(lno, pos + 1);

        while pos < line.len() {
            let s = &line[pos..];
            let res = LEX_RE.captures_read(&mut caps, s);
            let m = match res {
                Some(m) => m,
                None => {
                    return Err(self.throw(pos + 1));
                }
            };

            let (tok_type, match_end) = match TokType::from_caps(&caps) {
                Some(result) => result,
                _ => return Err(self.throw(pos + 1)),
            };
            let tok_val = &s[..m.end()];

            assert!(match_end == m.end());

            /*
            println!("  {:?} {:?} => {}..{}/{} {:?}",
                tok_type,
                LEX_RE.capture_names().nth(tok_type as usize).unwrap().unwrap(),
                pos,
                m.end(),
                match_end,
                tok_val,
            );
            */

            if !tok_type.ignore() {
                ret.push(Token {
                    loc: Loc::new(lno, pos + 1),
                    typ: tok_type,
                    val: tok_type.get_val(tok_val),
                });
            }

            pos += m.end();
        }

        self.loc = Loc::new(lno, pos + 1);

        ret.shrink_to_fit();
        Ok(ret)
    }
}
