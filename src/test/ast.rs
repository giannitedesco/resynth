use crate::ast::{Arg, BinOp, Expr, ExprKind, Ident, Lit, ModulePath, Stmt};
use crate::loc::Loc;
use crate::str::Buf;

use std::net::{Ipv4Addr, SocketAddrV4};

fn ident(name: &str) -> Ident {
    Ident {
        loc: Loc::nil(),
        name: name.into(),
    }
}

fn expr(kind: ExprKind) -> Expr {
    Expr {
        loc: Loc::nil(),
        kind,
    }
}

fn local(name: &str) -> Expr {
    expr(ExprKind::LocalRef(ident(name)))
}

fn int(i: u64) -> Expr {
    expr(ExprKind::Literal(Lit::Int(i)))
}

fn path(module: &str, inner: &[&str], item: &str) -> Expr {
    expr(ExprKind::ModulePath(Box::new(ModulePath {
        module: ident(module),
        inner: inner.iter().map(|s| ident(s)).collect(),
        item: ident(item),
    })))
}

fn call(callee: Expr, args: impl IntoIterator<Item = Arg>) -> Expr {
    expr(ExprKind::Call {
        callee: Box::new(callee),
        args: args.into_iter().collect(),
    })
}

fn member(obj: Expr, name: &str) -> Expr {
    expr(ExprKind::Member {
        obj: Box::new(obj),
        name: ident(name),
    })
}

fn pos(value: Expr) -> Arg {
    Arg { name: None, value }
}

#[test]
fn sexpr_call_with_named_arg() {
    let e = call(
        path("a", &["b"], "c"),
        [
            pos(int(1)),
            Arg {
                name: Some(ident("x")),
                value: expr(ExprKind::Literal(Lit::Str(Buf::from(b"\x00")))),
            },
        ],
    );
    assert_eq!(e.sexpr().to_string(), r#"(call a::b::c 0x1 (: x "|00|"))"#);
}

#[test]
fn sexpr_method_on_call_result() {
    let e = call(
        member(
            call(
                path("ipv4", &["tcp"], "flow"),
                [pos(local("a")), pos(local("b"))],
            ),
            "open",
        ),
        [],
    );
    assert_eq!(
        e.sexpr().to_string(),
        "(call (. (call ipv4::tcp::flow a b) open))"
    );
}

#[test]
fn sexpr_binary() {
    let e = expr(ExprKind::Binary {
        op: BinOp::Slash,
        lhs: Box::new(local("x")),
        rhs: Box::new(int(80)),
    });
    assert_eq!(e.sexpr().to_string(), "(/ x 0x50)");
}

#[test]
fn sexpr_stmts() {
    let sock = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80);
    let stmts = [
        Stmt::Import(ident("ipv4")),
        Stmt::Let {
            target: ident("x"),
            value: expr(ExprKind::Literal(Lit::Sock4(sock))),
        },
        Stmt::Expr(call(local("f"), [])),
        Stmt::Expr(expr(ExprKind::Literal(Lit::Str(Buf::from(b"abc"))))),
    ];
    let out: Vec<String> = stmts.iter().map(|s| s.sexpr().to_string()).collect();
    assert_eq!(
        out,
        [
            "(import ipv4)",
            "(let x 1.2.3.4:80)",
            "(call f)",
            r#""abc""#
        ]
    );
}
