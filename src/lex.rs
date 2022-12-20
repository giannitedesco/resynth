use std::borrow::Cow;
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
    Slash,

    ImportKeyword,
    LetKeyword,
    BooleanLiteral,
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
            TokType::Slash,

            TokType::ImportKeyword,
            TokType::LetKeyword,
            TokType::BooleanLiteral,
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
            TokType::BooleanLiteral => Some(val),
            TokType::StringLiteral => Some(&val[1..val.len()-1]),
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
#[derive(Debug, Clone)]
pub struct Token<'a> {
    loc: Loc,
    typ: TokType,
    val: Option<Cow<'a, str>>,
}

impl<'a> Token<'a> {
    pub fn loc(&self) -> Loc {
        self.loc
    }

    pub fn tok_type(&self) -> TokType {
        self.typ
    }

    pub fn optval(&self) -> Option<Cow<'a, str>> {
        self.val.to_owned()
    }

    pub fn val(&self) -> Cow<'a, str> {
        self.val.as_ref().unwrap().clone()
    }
}

impl From<&Token<'_>> for String {
    fn from(tok: &Token) -> String {
        tok.val.as_ref().unwrap().to_string()
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
    concatenated_strings: String,
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
        let mut string_literals: Vec<&str> = Vec::new();
        let mut caps = LEX_RE.capture_locations();

        if !self.concatenated_strings.is_empty() {
            string_literals.push(&self.concatenated_strings);
        }

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

            if !tok_type.ignore() || !string_literals.is_empty() && !matches!(tok_type, TokType::Whitespace) {
                if matches!(tok_type, TokType::StringLiteral) {
                    string_literals.push(&tok_val[1..m.end()-1]);
                } else {
                    if !string_literals.is_empty() {
                        ret.push(Token {
                            loc: Loc::new(lno, pos + 1),
                            typ: TokType::StringLiteral,
                            val: Some(Cow::from(string_literals.concat())),
                        });
                        string_literals.clear();
                    }
                    ret.push(Token {
                        loc: Loc::new(lno, pos + 1),
                        typ: tok_type,
                        val: tok_type.get_val(tok_val).map(Cow::from),
                    });
                }
            }

            pos += m.end();
        }

        self.concatenated_strings = if string_literals.is_empty() {
            String::new()
        } else {
            string_literals.concat()
        };

        self.loc = Loc::new(lno, pos + 1);

        ret.shrink_to_fit();
        Ok(ret)
    }
}
