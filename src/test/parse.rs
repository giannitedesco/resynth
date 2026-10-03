use crate::err::Error;
use crate::lex::Lexer;
use crate::parse::{Expr, Parser, Stmt};
use crate::val::Val;

use std::net::{Ipv4Addr, SocketAddrV4};

fn parse(src: &str) -> Result<Vec<Stmt>, Error> {
    let mut parser = Parser::default();
    for tok in Lexer::lex(src.lines()).map_err(|(_, err)| err)? {
        parser.feed(&tok)?;
    }
    Ok(parser.get_results())
}

fn parse_let_literal(src: &str) -> Val {
    let stmts = parse(src).expect("parse failed");
    let [Stmt::Assign(assign)] = stmts.as_slice() else {
        panic!("expected a single assignment, got {stmts:?}");
    };
    let Expr::Literal(_, val) = &assign.rvalue else {
        panic!("expected a literal, got {:?}", assign.rvalue);
    };
    val.clone()
}

#[test]
fn parse_joined_string_literal() {
    let Val::Str(buf) = parse_let_literal("let x = \"ab\" \"|63|\";") else {
        panic!("expected a string");
    };
    assert_eq!(buf.as_ref(), b"abc");
}

#[test]
fn parse_int_literal_u64_max() {
    assert_eq!(
        parse_let_literal("let x = 0xffffffffffffffff;"),
        Val::U64(u64::MAX)
    );
}

#[test]
fn parse_int_literal_wider_than_u64() {
    assert_eq!(
        parse("let x = 0x10000000000000000;").map(|_| ()),
        Err(Error::IntLiteralError)
    );
}

#[test]
fn parse_sockaddr_port_is_decimal() {
    assert_eq!(
        parse_let_literal("let x = 1.2.3.4:80;"),
        Val::Sock4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80))
    );
    assert_eq!(
        parse("let x = 1.2.3.4:0x50;").map(|_| ()),
        Err(Error::ParseError)
    );
}
