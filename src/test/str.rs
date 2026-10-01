use crate::str::StringLiteralErrorKind::*;
use crate::str::{Buf, Literal};
use std::str::FromStr;

#[test]
fn str_nohex() {
    let s = Buf::from_str(concat!(
        "!#$%&'()*+,-./", // " is not allowed
        "0123456789",
        ":;<=>?",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "[\\]^_`",
        "abcdefghijklmnopqrstuvwxyz",
        "{}~", // | is not allowed
    ))
    .expect("parse failed");

    assert_eq!(
        s.cow_buffer(),
        concat!(
            "!#$%&'()*+,-./",
            "0123456789",
            ":;<=>?",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "[\\]^_`",
            "abcdefghijklmnopqrstuvwxyz",
            "{}~",
        )
        .as_bytes()
        .into()
    )
}

#[test]
fn str_backslash() {
    let s = Buf::from_str("\\").expect("parse failed");

    assert_eq!(s.cow_buffer().as_ref(), "\\".as_bytes())
}

#[test]
fn str_bin() {
    let s = Buf::from_str("|00 01 02|").expect("parse failed");

    assert_eq!(s.cow_buffer().as_ref(), &b"\x00\x01\x02"[..])
}

#[test]
fn str_space() {
    let s = Buf::from_str("a b|20|").expect("parse failed");

    assert_eq!(s.as_ref(), b"a b ")
}

#[test]
fn str_hex_separators() {
    let s = Buf::from_str("|0a:0b.0c_0d-0e'0f`10 11|").expect("parse failed");

    assert_eq!(s.as_ref(), &b"\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"[..])
}

#[test]
fn str_non_ascii_is_error() {
    assert_eq!(Buf::from_str("aé"), Err(BadChar('é').at(1)));

    assert_eq!(Buf::from_str("|00 é|"), Err(BadChar('é').at(4)))
}

#[test]
fn str_control_is_error() {
    for (body, offset, chr) in [
        ("a\tb", 1, '\t'),
        ("a\r", 1, '\r'),
        ("\0", 0, '\0'),
        ("\x7f", 0, '\x7f'),
        ("|00\t01|", 3, '\t'),
    ] {
        assert_eq!(
            Buf::from_str(body),
            Err(BadChar(chr).at(offset)),
            "{body:?}"
        );
    }
}

#[test]
fn str_bad_char_message() {
    let err = Buf::from_str("é").expect_err("parsed successfully");
    assert_eq!(
        err.to_string(),
        "'é' is not allowed in a string literal, write it as |c3 a9|"
    );

    let err = Buf::from_str("\t").expect_err("parsed successfully");
    assert_eq!(
        err.to_string(),
        "'\\t' is not allowed in a string literal, write it as |09|"
    );
}

#[test]
fn str_odd_hex_digits() {
    assert_eq!(Buf::from_str("|00 0|"), Err(OddHexDigits.at(5)))
}

#[test]
fn str_unterminated_hex() {
    assert_eq!(Buf::from_str("ab|00"), Err(UnterminatedHex.at(2)));

    // A dangling digit is reported as the unterminated sequence it belongs to
    assert_eq!(Buf::from_str("|0"), Err(UnterminatedHex.at(0)))
}

#[test]
fn str_bad_hex_digit() {
    assert_eq!(Buf::from_str("|0g|"), Err(BadHexDigit('g').at(2)))
}

#[test]
fn literal_text_and_hex() {
    assert_eq!(Literal(b"\x03com\x00").to_string(), r#""|03|com|00|""#);
    assert_eq!(Literal(b"\xff\xff\xff").to_string(), r#""|ff ff ff|""#);
    assert_eq!(Literal(b"a b").to_string(), r#""a b""#);
    assert_eq!(Literal(b"").to_string(), r#""""#);
}

#[test]
fn literal_hex_encodes_specials() {
    assert_eq!(
        Literal("a|\"\\\té".as_bytes()).to_string(),
        r#""a|7c 22|\|09 c3 a9|""#
    );
}

#[test]
fn literal_round_trips_every_byte() {
    let all: Vec<u8> = (0..=u8::MAX).collect();
    let lit = Literal(&all).to_string();
    let body = &lit[1..lit.len() - 1];

    assert_eq!(
        Buf::from_str(body).expect("parse failed").as_ref(),
        &all[..]
    )
}

#[test]
fn buf_debug_is_literal() {
    assert_eq!(
        format!("{:?}", Buf::from(&b"a\x00\xff"[..])),
        r#""a|00 ff|""#
    )
}
