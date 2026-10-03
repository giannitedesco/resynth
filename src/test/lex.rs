use crate::err::Error;
use crate::lex::{Lexer, Tok, Token};
use crate::loc::Loc;

use std::net::Ipv4Addr;

fn lex(src: &str) -> Vec<Token> {
    Lexer::lex(src.lines()).expect("failed to lex").into()
}

fn lex_err(src: &str) -> (Loc, Error) {
    Lexer::lex(src.lines()).expect_err("lexed successfully")
}

fn tok(line: usize, col: usize, tok: Tok) -> Token {
    Token {
        loc: Loc::new(line, col),
        tok,
    }
}

fn str_tok(line: usize, col: usize, body: &str) -> Token {
    tok(line, col, Tok::StringLiteral(body.into()))
}

fn ident(line: usize, col: usize, name: &str) -> Token {
    tok(line, col, Tok::Identifier(name.into()))
}

#[test]
fn lex_empty() {
    assert_eq!(lex(""), vec![tok(1, 1, Tok::Eof)]);
    assert_eq!(lex("\n"), vec![tok(1, 1, Tok::Eof)]);
}

#[test]
fn lex_comments_only() {
    assert_eq!(lex("# hash\n// cpp"), vec![tok(2, 7, Tok::Eof)]);
}

#[test]
fn lex_punctuation() {
    assert_eq!(
        lex("().:::;=,/"),
        vec![
            tok(1, 1, Tok::LParen),
            tok(1, 2, Tok::RParen),
            tok(1, 3, Tok::Dot),
            tok(1, 4, Tok::DoubleColon),
            tok(1, 6, Tok::Colon),
            tok(1, 7, Tok::SemiColon),
            tok(1, 8, Tok::Equals),
            tok(1, 9, Tok::Comma),
            tok(1, 10, Tok::Slash),
            tok(1, 11, Tok::Eof),
        ]
    );
}

#[test]
fn lex_backslash() {
    assert_eq!(
        lex("\"\\\";"),
        vec![
            str_tok(1, 1, "\\"),
            tok(1, 4, Tok::SemiColon),
            tok(1, 5, Tok::Eof),
        ]
    );
}

#[test]
fn lex_string_chars() {
    let body = concat!(
        "!#$%&'()*+,-./", // " is not allowed
        "0123456789",
        ":;<=>?",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "[\\]^_`",
        "abcdefghijklmnopqrstuvwxyz",
        "{|}~",
    );

    assert_eq!(
        lex(&format!("\"{body}\";\n")),
        vec![
            str_tok(1, 1, body),
            tok(1, 95, Tok::SemiColon),
            tok(1, 96, Tok::Eof),
        ]
    );
}

#[test]
fn lex_string_is_not_decoded() {
    assert_eq!(
        lex("\"|78:24:af:23:f0:a9|\";"),
        vec![
            str_tok(1, 1, "|78:24:af:23:f0:a9|"),
            tok(1, 22, Tok::SemiColon),
            tok(1, 23, Tok::Eof),
        ]
    );
}

#[test]
fn lex_adjacent_strings_join_across_lines() {
    assert_eq!(
        lex("\"abc\" # comment\n  \"def\";"),
        vec![
            str_tok(1, 1, "abcdef"),
            tok(2, 8, Tok::SemiColon),
            tok(2, 9, Tok::Eof),
        ]
    );
}

#[test]
fn lex_adjacent_strings_located_at_first() {
    assert_eq!(
        lex("x \"a\" \"b\";"),
        vec![
            ident(1, 1, "x"),
            str_tok(1, 3, "ab"),
            tok(1, 10, Tok::SemiColon),
            tok(1, 11, Tok::Eof),
        ]
    );
}

#[test]
fn lex_string_at_eof() {
    assert_eq!(
        lex("\"abc\""),
        vec![str_tok(1, 1, "abc"), tok(1, 6, Tok::Eof)]
    );
}

#[test]
fn lex_unterminated_string() {
    assert_eq!(lex_err("\"abc\n\";"), (Loc::new(1, 1), Error::LexError));
    assert_eq!(lex_err("x \"abc"), (Loc::new(1, 3), Error::LexError));
}

#[test]
fn lex_integers() {
    assert_eq!(
        lex("123 0x1f 0123"),
        vec![
            tok(1, 1, Tok::DecLiteral(123)),
            tok(1, 5, Tok::HexLiteral(0x1f)),
            tok(1, 10, Tok::DecLiteral(123)),
            tok(1, 14, Tok::Eof),
        ]
    );
}

#[test]
fn lex_negative_is_error() {
    assert_eq!(lex_err("-1"), (Loc::new(1, 1), Error::LexError));
}

#[test]
fn lex_integer_limits() {
    let max = format!("{:#x}", i128::MAX);
    assert_eq!(
        lex(&max),
        vec![
            tok(1, 1, Tok::HexLiteral(i128::MAX)),
            tok(1, max.len() + 1, Tok::Eof),
        ]
    );

    let too_big = format!("x = {:#x}", i128::MAX as u128 + 1);
    assert_eq!(lex_err(&too_big), (Loc::new(1, 5), Error::IntLiteralError));

    let too_big = format!("{}", i128::MAX as u128 + 1);
    assert_eq!(lex_err(&too_big), (Loc::new(1, 1), Error::IntLiteralError));
}

#[test]
fn lex_identifiers_keywords_and_literals() {
    assert_eq!(
        lex("foo true 1.2.3.4 import let"),
        vec![
            ident(1, 1, "foo"),
            tok(1, 5, Tok::BooleanLiteral(true)),
            tok(1, 10, Tok::IPv4Literal(Ipv4Addr::new(1, 2, 3, 4))),
            tok(1, 18, Tok::ImportKeyword),
            tok(1, 25, Tok::LetKeyword),
            tok(1, 28, Tok::Eof),
        ]
    );
}

#[test]
fn lex_trailing_cr_is_whitespace() {
    assert_eq!(
        Lexer::lex(["let\r", "x\r"]).expect("failed to lex"),
        vec![
            tok(1, 1, Tok::LetKeyword),
            ident(2, 1, "x"),
            tok(2, 3, Tok::Eof),
        ]
    );
}

#[test]
fn lex_newline_in_line_is_error() {
    assert_eq!(
        Lexer::lex(["x\ny"]).expect_err("lexed successfully"),
        (Loc::new(1, 2), Error::LexError)
    );
    assert_eq!(
        Lexer::lex(["\"a\nb\""]).expect_err("lexed successfully"),
        (Loc::new(1, 1), Error::LexError)
    );
}

#[test]
fn lex_columns_count_bytes() {
    assert_eq!(
        lex("\"é\" x"),
        vec![str_tok(1, 1, "é"), ident(1, 6, "x"), tok(1, 7, Tok::Eof)]
    );
}
