use crate::ast::{Expr, ExprKind, Stmt};
use crate::lex::{Lexer, Tok};
use crate::loc::Loc;
use crate::parse::ParseErrorKind::{IntOutOfRange, UnexpectedToken};
use crate::parse::{ParseError, parse};

fn parse_src(src: &str) -> Result<Vec<Stmt>, ParseError> {
    parse(Lexer::lex(src.lines()).expect("lex failed"))
}

/// The program as S-expressions, one statement per line
fn sexpr(src: &str) -> String {
    parse_src(src)
        .expect("parse failed")
        .iter()
        .map(|stmt| stmt.sexpr().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_err(src: &str) -> ParseError {
    parse_src(src).unwrap_err()
}

fn unexpected(
    line: usize,
    col: usize,
    expected: &'static [&'static str],
    found: Tok,
) -> ParseError {
    UnexpectedToken {
        expected: expected.into(),
        found,
    }
    .at(Loc::new(line, col))
}

/// The expression of a single expression statement
fn expr_stmt(src: &str) -> Expr {
    let stmts = parse_src(src).expect("parse failed");
    let Ok([Stmt::Expr(expr)]) = <[Stmt; 1]>::try_from(stmts) else {
        panic!("expected a single expression statement");
    };
    expr
}

const AFTER_EXPR: &[&str] = &["`(`", "`.`", "`/`", "`;`"];
const AFTER_NAME: &[&str] = &["`::`", "`(`", "`.`", "`/`", "`;`"];
const AFTER_IP4: &[&str] = &["`:`", "`(`", "`.`", "`/`", "`;`"];
const ARG_START: &[&str] = &["expression", "`)`"];
const ARG_AFTER_NAME: &[&str] = &["`::`", "`(`", "`.`", "`/`", "`:`", "`,`", "`)`"];

#[test]
fn parse_empty() {
    assert_eq!(sexpr(""), "");
    assert_eq!(sexpr("# nothing\n// here\n"), "");
}

#[test]
fn parse_import() {
    assert_eq!(sexpr("import a;"), "(import a)");
    assert_eq!(
        parse_err("import a::b;"),
        unexpected(1, 9, &["`;`"], Tok::DoubleColon)
    );
    assert_eq!(
        parse_err("import;"),
        unexpected(1, 7, &["identifier"], Tok::SemiColon)
    );
}

#[test]
fn parse_joined_string_literal() {
    assert_eq!(sexpr("let x = \"ab\" \"|63|\";"), r#"(let x "abc")"#);
}

#[test]
fn parse_int_literal_u64_max() {
    assert_eq!(
        sexpr("let x = 0xffffffffffffffff;"),
        "(let x 0xffffffffffffffff)"
    );
}

/// An integer literal is an `i128`, as lexed. The checker narrows it.
#[test]
fn parse_int_literal_wider_than_u64() {
    assert_eq!(
        sexpr("let x = 0x10000000000000000;"),
        "(let x 0x10000000000000000)"
    );
}

#[test]
fn parse_sockaddr() {
    assert_eq!(sexpr("let x = 1.2.3.4:80;"), "(let x 1.2.3.4:80)");
    assert_eq!(sexpr("let x = 1.2.3.4 : 80;"), "(let x 1.2.3.4:80)");
}

#[test]
fn parse_sockaddr_port_is_decimal() {
    assert_eq!(
        parse_err("let x = 1.2.3.4:0x50;"),
        unexpected(1, 17, &["decimal port"], Tok::HexLiteral(0x50))
    );
}

#[test]
fn parse_sockaddr_port_fits_u16() {
    assert_eq!(sexpr("let x = 1.2.3.4:65535;"), "(let x 1.2.3.4:65535)");
    assert_eq!(
        parse_err("let x = 1.2.3.4:65536;"),
        IntOutOfRange.at(Loc::new(1, 17))
    );
    assert_eq!(
        parse_err("let x = 1.2.3.4:18446744073709551616;"),
        IntOutOfRange.at(Loc::new(1, 17))
    );
}

#[test]
fn parse_arg_lists() {
    assert_eq!(sexpr("f();"), "(call f)");
    assert_eq!(sexpr("f(1);"), "(call f 0x1)");
    assert_eq!(sexpr("f(1,);"), "(call f 0x1)");
    assert_eq!(parse_err("f(,);"), unexpected(1, 3, ARG_START, Tok::Comma));
    assert_eq!(
        parse_err("f(1,,2);"),
        unexpected(1, 5, ARG_START, Tok::Comma)
    );
}

#[test]
fn parse_named_args() {
    assert_eq!(sexpr("f(a: 1.2.3.4:80);"), "(call f (: a 1.2.3.4:80))");
    assert_eq!(sexpr("f(a: b);"), "(call f (: a b))");
    assert_eq!(sexpr("f(a::b);"), "(call f a::b)");
    assert_eq!(
        parse_err("f(a:);"),
        unexpected(1, 5, &["expression"], Tok::RParen)
    );
}

#[test]
fn parse_paths() {
    assert_eq!(sexpr("a::b.c;"), "(. a::b c)");
    assert_eq!(
        parse_err("a.b::c;"),
        unexpected(1, 4, AFTER_EXPR, Tok::DoubleColon)
    );
    assert_eq!(
        parse_err("a::;"),
        unexpected(1, 4, &["identifier"], Tok::SemiColon)
    );
}

#[test]
fn parse_postfix_chains() {
    assert_eq!(
        sexpr("a.b().c(1, x: 2);"),
        "(call (. (call (. a b)) c) 0x1 (: x 0x2))"
    );
    assert_eq!(
        sexpr("ipv4::tcp::flow(a, b).open();"),
        "(call (. (call ipv4::tcp::flow a b) open))"
    );
    assert_eq!(sexpr("f()();"), "(call (call f))");
    assert_eq!(sexpr("x.a.b;"), "(. (. x a) b)");
}

#[test]
fn parse_postfix_in_args() {
    assert_eq!(
        sexpr("f(a.b(c).d, e: g());"),
        "(call f (. (call (. a b) c) d) (: e (call g)))"
    );
}

#[test]
fn parse_slash_is_left_associative() {
    assert_eq!(sexpr("1.2.3.4 / 80 / 5;"), "(/ (/ 1.2.3.4 0x50) 0x5)");
    assert_eq!(sexpr("a.b / c.d();"), "(/ (. a b) (call (. c d)))");
}

#[test]
fn parse_any_expr_is_a_stmt() {
    assert_eq!(sexpr("\"abc\";"), r#""abc""#);
    assert_eq!(sexpr("1.2.3.4:80;"), "1.2.3.4:80");
}

#[test]
fn parse_errors_at_eof() {
    assert_eq!(parse_err("x."), unexpected(2, 1, &["identifier"], Tok::Eof));
    assert_eq!(
        parse_err("let x = f("),
        unexpected(2, 1, ARG_START, Tok::Eof)
    );
    assert_eq!(
        parse_err("let x = 1"),
        unexpected(2, 1, AFTER_EXPR, Tok::Eof)
    );
    assert_eq!(parse_err("f(a"), unexpected(2, 1, ARG_AFTER_NAME, Tok::Eof));
}

#[test]
fn parse_let_errors() {
    assert_eq!(
        parse_err("let let = 1;"),
        unexpected(1, 5, &["identifier"], Tok::LetKeyword)
    );
    assert_eq!(
        parse_err("let 1 = 2;"),
        unexpected(1, 5, &["identifier"], Tok::DecLiteral(1))
    );
}

#[test]
fn parse_stmt_start_errors() {
    let stmt_start = &["eof", "`import`", "`let`", "expression"];
    assert_eq!(parse_err("(1);"), unexpected(1, 1, stmt_start, Tok::LParen));
    assert_eq!(parse_err(");"), unexpected(1, 1, stmt_start, Tok::RParen));
    assert_eq!(
        parse_err(");").to_string(),
        "1:1: expected one of eof, `import`, `let` or expression, found `)`"
    );
}

#[test]
fn parse_expected_depends_on_how_the_expr_ends() {
    assert_eq!(
        parse_err("let x = f(1) 2;"),
        unexpected(1, 14, AFTER_EXPR, Tok::DecLiteral(2))
    );
    assert_eq!(
        parse_err("let x = f(1) 2;").kind.to_string(),
        "expected one of `(`, `.`, `/` or `;`, found `2`"
    );
    assert_eq!(
        parse_err("let x = 1.2.3.4 2;"),
        unexpected(1, 17, AFTER_IP4, Tok::DecLiteral(2))
    );
    assert_eq!(
        parse_err("let x = y / a 2;"),
        unexpected(1, 15, AFTER_NAME, Tok::DecLiteral(2))
    );
    assert_eq!(
        parse_err("f(a 2);"),
        unexpected(1, 5, ARG_AFTER_NAME, Tok::DecLiteral(2))
    );
    assert_eq!(
        parse_err("f(x: a 2);"),
        unexpected(
            1,
            8,
            &["`::`", "`(`", "`.`", "`/`", "`,`", "`)`"],
            Tok::DecLiteral(2)
        )
    );
    assert_eq!(
        parse_err("f(a.b 2);"),
        unexpected(
            1,
            7,
            &["`(`", "`.`", "`/`", "`,`", "`)`"],
            Tok::DecLiteral(2)
        )
    );
    assert_eq!(
        parse_err("f(1.2.3.4 2);"),
        unexpected(
            1,
            11,
            &["`:`", "`(`", "`.`", "`/`", "`,`", "`)`"],
            Tok::DecLiteral(2)
        )
    );
    // Only a lone identifier can become a named argument
    assert_eq!(
        parse_err("f(x / a 2);"),
        unexpected(
            1,
            9,
            &["`::`", "`(`", "`.`", "`/`", "`,`", "`)`"],
            Tok::DecLiteral(2)
        )
    );
}

#[test]
fn parse_loc_arg_ref() {
    let ExprKind::Call { args, .. } = expr_stmt("f(x);").kind else {
        panic!("expected a call");
    };
    assert_eq!(args[0].value.loc, Loc::new(1, 3));
}

#[test]
fn parse_loc_member_chain() {
    let outer = expr_stmt("a.b.c;");
    let ExprKind::Member {
        obj: inner,
        name: c,
    } = outer.kind
    else {
        panic!("expected a member");
    };
    let ExprKind::Member { name: b, .. } = inner.kind else {
        panic!("expected a member");
    };
    assert_eq!(outer.loc, Loc::new(1, 1));
    assert_eq!(inner.loc, Loc::new(1, 1));
    assert_eq!(b.loc, Loc::new(1, 3));
    assert_eq!(c.loc, Loc::new(1, 5));
}

#[test]
fn parse_loc_method_call() {
    assert_eq!(expr_stmt("flow.client_message(1);").loc, Loc::new(1, 1));
}

#[test]
fn parse_loc_module_path_call() {
    let call = expr_stmt("ipv4::tcp::flow(1);");
    assert_eq!(call.loc, Loc::new(1, 1));
    let ExprKind::Call { callee, .. } = call.kind else {
        panic!("expected a call");
    };
    assert_eq!(callee.loc, Loc::new(1, 1));
    let ExprKind::ModulePath(path) = callee.kind else {
        panic!("expected a module path");
    };
    assert_eq!(path.module.loc, Loc::new(1, 1));
    assert_eq!(path.inner[0].loc, Loc::new(1, 7));
    assert_eq!(path.item.loc, Loc::new(1, 12));
}

#[test]
fn parse_loc_binary() {
    assert_eq!(expr_stmt("x / 80;").loc, Loc::new(1, 1));
}

#[test]
fn parse_loc_sockaddr() {
    let stmts = parse_src("let x = 1.2.3.4 : 80;").expect("parse failed");
    let [Stmt::Let { value, .. }] = stmts.as_slice() else {
        panic!("expected a let");
    };
    assert_eq!(value.loc, Loc::new(1, 9));
}
