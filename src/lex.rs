use std::slice::Iter;

use lazy_regex::*;
use regex::CaptureLocations;

static LEX_RE: Lazy<Regex> = lazy_regex!("^\
    (?:\
    (?P<whitespace>[^\\S\n][^\\S\n]*)\
    |\
    (?P<comment>#[^\\n]*)\
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
pub(crate) enum TokType {
    Eof,

    Whitespace,
    Comment,
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
            TokType::Comment,
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
            | TokType::Comment
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

#[derive(Debug, Copy, Clone)]
pub(crate) struct Token<'a> {
    pub typ: TokType,
    pub val: Option<&'a str>,
}

impl From<Token<'_>> for String {
    fn from(tok: Token) -> String {
        tok.val.unwrap().to_owned()
    }
}

pub(crate) const EOF: Token = Token {
    typ: TokType::Eof,
    val: None,
};

pub(crate) fn lex(line: &str) -> Result<Vec<Token>, ()> {
    let mut ret = Vec::new();
    let mut pos = 0_usize;
    let mut caps = LEX_RE.capture_locations();

    while pos < line.len() {
        let s = &line[pos..];
        let res = LEX_RE.captures_read(&mut caps, s);
        let m = match res {
            Some(m) => m,
            None => {
                println!("fucked on {:?} @ {:?}", line, pos);
                return Err(());
            }
        };

        let (tok_type, match_end) = match TokType::from_caps(&caps) {
            Some(result) => result,
            _ => return Err(()),
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
                typ: tok_type,
                val: tok_type.get_val(tok_val),
            });
        }

        pos += m.end();
    }
    ret.shrink_to_fit();
    Ok(ret)
}
