use crate::check::SemanticErrorKind::{
    AlreadyBound, ArgType, CollectArgType, DuplicateArg, IntegralTooLarge, MissingArg, NoMembers,
    NotAModule, NotAValue, NotCallable, NotImported, OperandType, TooFewArgs, TooManyArgs,
    UnexpectedCollectArgs, UnexpectedNamedArg, UnknownArg, UnknownItem, UnknownMember,
    UnknownModule, UnknownName, VoidValue,
};
use std::num::NonZeroUsize;

use crate::check::{
    Diagnostic, DiagnosticKind, ErrorSummary, Found, SemanticError, Side, Ty, WarningKind, check_in,
};
use crate::hir::{Const, Expr, ExprKind, Program, StmtKind};
use crate::lex::Lexer;
use crate::libapi::{ArgDecl, FuncDef, Module};
use crate::loc::Loc;
use crate::parse::parse;
use crate::stdlib::{STDLIB, toplevel_module};
use crate::sym::Symbol;
use crate::val::{ValDef, ValType};

use super::object;

type Warnings = Vec<(Loc, String)>;

/// Every diagnostic a program gives, in order, and the result of checking it
fn diagnostics(src: &str) -> (Result<Program, ErrorSummary>, Vec<Diagnostic>) {
    diagnostics_in(&STDLIB, src)
}

/// [diagnostics], importing modules from `root`
fn diagnostics_in(
    root: &'static Module,
    src: &str,
) -> (Result<Program, ErrorSummary>, Vec<Diagnostic>) {
    let stmts = parse(Lexer::lex(src.lines()).expect("lex failed")).expect("parse failed");
    let mut diags = Vec::new();
    let res = check_in(root, stmts, |diag| diags.push(diag));
    (res, diags)
}

/// Check a program, returning the program or every error it gave, and every warning it gave.
/// A failure's summary must count the errors and warnings that were given.
fn check_src(src: &str) -> (Result<Program, Vec<SemanticError>>, Warnings) {
    let (res, diags) = diagnostics(src);

    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    for Diagnostic { loc, kind } in diags {
        match kind {
            DiagnosticKind::Error(kind) => errors.push(SemanticError { loc, kind }),
            DiagnosticKind::Warning(warn) => warnings.push((loc, warn.to_string())),
        }
    }

    let res = match res {
        Ok(prog) => {
            assert!(errors.is_empty(), "check succeeded with errors: {errors:?}");
            Ok(prog)
        }
        Err(summary) => {
            assert_eq!(
                (summary.errors.get(), summary.warnings),
                (errors.len(), warnings.len()),
                "{summary:?}"
            );
            Err(errors)
        }
    };
    (res, warnings)
}

/// A program that checks, and its warnings
fn checked(src: &str) -> (Program, Warnings) {
    let (res, warnings) = check_src(src);
    match res {
        Ok(prog) => (prog, warnings),
        Err(errs) => panic!("check failed: {errs:?}"),
    }
}

/// A program's HIR, as S-expressions
fn lower(src: &str) -> String {
    checked(src).0.to_string()
}

/// [lower], importing modules from `root`
fn lower_in(root: &'static Module, src: &str) -> String {
    match diagnostics_in(root, src) {
        (Ok(prog), _) => prog.to_string(),
        (Err(_), diags) => panic!("check failed: {diags:?}"),
    }
}

/// Every error a program gives
fn errors(src: &str) -> Vec<SemanticError> {
    match check_src(src).0 {
        Ok(prog) => panic!("check succeeded: {prog}"),
        Err(errs) => errs,
    }
}

/// The one error a program gives
fn error(src: &str) -> SemanticError {
    let mut errs = errors(src);
    assert_eq!(errs.len(), 1, "{errs:?}");
    errs.remove(0)
}

/// Where each warning was given
fn warning_locs(src: &str) -> Vec<Loc> {
    checked(src).1.into_iter().map(|(loc, _)| loc).collect()
}

/// The function at `path`
fn func(path: &str) -> &'static FuncDef {
    let (modules, item) = path.rsplit_once("::").expect("not a path");
    let mut segs = modules.split("::");
    let mut module = toplevel_module(segs.next().unwrap()).unwrap();
    for seg in segs {
        let Some(Symbol::Module(inner)) = module.get(seg) else {
            panic!("{path}: no module {seg}");
        };
        module = inner;
    }
    match module.get(item) {
        Some(Symbol::Func(func)) => func,
        sym => panic!("{path}: not a function: {sym:?}"),
    }
}

const FLOW: &str = "import ipv4;\nlet c = ipv4::tcp::flow(1.2.3.4:1, 5.6.7.8:2);\n";

// Names and slots

/// a name isn't in scope in its own `let`
#[test]
fn check_let_name_not_in_scope_in_its_value() {
    let err = error("import ipv4;\nlet x = x;");
    assert!(
        matches!(&err.kind, UnknownName(n) if &**n == "x") && err.loc == Loc::new(2, 9),
        "{err:?}"
    );
}

#[test]
fn check_unknown_name() {
    let err = error("import ipv4;\nnope;");
    assert!(
        matches!(&err.kind, UnknownName(n) if &**n == "nope") && err.loc == Loc::new(2, 1),
        "{err:?}"
    );
    let err = error("import dns;\ndns::name(nosuch);");
    assert!(
        matches!(&err.kind, UnknownName(n) if &**n == "nosuch") && err.loc == Loc::new(2, 11),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "2:11: unknown name \"nosuch\"");
}

/// the semantic error is reported, and the call on line 2 never runs
#[test]
fn check_error_after_io() {
    let err = error("import io;\nlet cert = io::file(\"no-such-file.der\");\nundefined_name;");
    assert!(
        matches!(&err.kind, UnknownName(n) if &**n == "undefined_name")
            && err.loc == Loc::new(3, 1),
        "{err:?}"
    );
}

/// examples/error-multiple-assign.rsyn
#[test]
fn check_already_bound() {
    let err = error(include_str!("../../examples/error-multiple-assign.rsyn"));
    assert!(
        matches!(&err.kind, AlreadyBound { name, first } if &**name == "conn" && *first == Loc::new(3, 5))
            && err.loc == Loc::new(8, 5),
        "{err:?}"
    );
    let err = error("let x = 1;\nlet x = 2;");
    assert!(
        matches!(&err.kind, AlreadyBound { name, .. } if &**name == "x")
            && err.loc == Loc::new(2, 5),
        "{err:?}"
    );
}

#[test]
fn check_import_errors() {
    let err = error("import nosuch;");
    assert!(
        matches!(&err.kind, UnknownModule(n) if &**n == "nosuch") && err.loc == Loc::new(1, 8),
        "{err:?}"
    );
    let err = error("dns::name(\"x\");");
    assert!(
        matches!(&err.kind, NotImported(n) if &**n == "dns") && err.loc == Loc::new(1, 1),
        "{err:?}"
    );
}

/// A failed import poisons its name, so paths through it report nothing
#[test]
fn check_failed_import_is_silent() {
    let err = error("import nosuch;\nnosuch::x;\nnosuch::y;\nnosuch::z();");
    assert!(
        matches!(&err.kind, UnknownModule(n) if &**n == "nosuch") && err.loc == Loc::new(1, 8),
        "{err:?}"
    );

    // Importing it again warns, and doesn't report it again
    let (res, warnings) = check_src("import nosuch;\nimport nosuch;\nnosuch::x;");
    let errs = res.expect_err("check succeeded");
    assert!(
        matches!(&errs[..], [SemanticError { loc, kind: UnknownModule(_) }] if *loc == Loc::new(1, 8)),
        "{errs:?}"
    );
    let locs: Vec<_> = warnings.into_iter().map(|(loc, _)| loc).collect();
    assert_eq!(locs, [Loc::new(2, 8)]);
}

/// Errors in a module path point at the segment which failed
#[test]
fn check_module_path_errors_at_failing_segment() {
    let err = error("import dns;\ndns::nmae(\"x\");");
    assert!(
        matches!(&err.kind, UnknownItem { name, module: "dns" } if &**name == "nmae")
            && err.loc == Loc::new(2, 6),
        "{err:?}"
    );
    let err = error("import ipv4;\nipv4::nosuch::flow;");
    assert!(
        matches!(&err.kind, UnknownItem { name, module: "ipv4" } if &**name == "nosuch")
            && err.loc == Loc::new(2, 7),
        "{err:?}"
    );
    let err = error("import ipv4;\nipv4::tcp.flow;");
    assert!(
        matches!(&err.kind, NotAValue(n) if &**n == "tcp") && err.loc == Loc::new(2, 7),
        "{err:?}"
    );
    let err = error("import ipv4;\nipv4::tcp::flow::x;");
    assert!(
        matches!(&err.kind, NotAModule(n) if &**n == "flow") && err.loc == Loc::new(2, 12),
        "{err:?}"
    );
}

/// A local and a module of the same name don't clash
#[test]
fn check_locals_and_modules_are_separate() {
    // As in examples/tls.rsyn
    assert_eq!(
        warning_locs("import dns;\nlet dns = 1.2.3.4;\ndns::name(\"x\");\ndns;"),
        [Loc::new(3, 1), Loc::new(4, 1)]
    );
}

// Members

/// A typo in a method name is found before anything runs
#[test]
fn check_unknown_member() {
    let err = error(&format!("{FLOW}c.open();\nc.client_mesage(\"x\");"));
    assert!(
        matches!(&err.kind, UnknownMember { class: "TcpFlow", name } if &**name == "client_mesage")
            && err.loc == Loc::new(4, 3),
        "{err:?}"
    );
}

/// Member access on a value that isn't an object
#[test]
fn check_no_members() {
    let err = error("import std;\n\"abc\".len;");
    assert!(
        matches!(&err.kind, NoMembers(Found::Ty(Ty::Bytes))) && err.loc == Loc::new(2, 7),
        "{err:?}"
    );
    let err = error("import ipv4;\nipv4::tcp::flow.new;");
    assert!(
        matches!(&err.kind, NoMembers(Found::Ty(Ty::Func(f))) if f.name == "flow")
            && err.loc == Loc::new(2, 17),
        "{err:?}"
    );
    let err = error(&format!("{FLOW}c.client_message.b;"));
    assert!(
        matches!(&err.kind, NoMembers(Found::Ty(Ty::Method(_, f))) if f.name == "client_message")
            && err.loc == Loc::new(3, 18),
        "{err:?}"
    );
}

// Calls

/// Calls whose callee isn't a function
#[test]
fn check_not_callable() {
    let err = error("import std;\n1();");
    assert!(
        matches!(&err.kind, NotCallable(Found::Int)) && err.loc == Loc::new(2, 1),
        "{err:?}"
    );
    let err = error("let x = 1.2.3.4;\nx();");
    assert!(
        matches!(&err.kind, NotCallable(Found::Ty(Ty::Ip4))) && err.loc == Loc::new(2, 1),
        "{err:?}"
    );
    // The outer call of `f()()` points at the start of the callee
    let err = error("import dns;\ndns::name(\"x\")();");
    assert!(
        matches!(&err.kind, NotCallable(Found::Ty(Ty::Bytes))) && err.loc == Loc::new(2, 1),
        "{err:?}"
    );
}

/// an argument that isn't a parameter is unknown, though it's also misplaced
#[test]
fn check_unknown_arg() {
    let err = error(&format!(
        "{FLOW}c.open();\nc.client_message(c.client_segment(\"A\"), nope: 1);"
    ));
    assert!(
        matches!(&err.kind, UnknownArg { func: "client_message", arg } if &**arg == "nope")
            && err.loc == Loc::new(4, 41),
        "{err:?}"
    );
    let err = error("import dns;\ndns::name(nosuch: \"x\");");
    assert!(
        matches!(&err.kind, UnknownArg { func: "name", arg } if &**arg == "nosuch")
            && err.loc == Loc::new(2, 11),
        "{err:?}"
    );
}

/// A named argument followed by a positional one, for a function with no collect parameter
#[test]
fn check_unexpected_collect_args() {
    let err = error("import std;\nstd::be16(val: 1, 2);");
    assert!(
        matches!(&err.kind, UnexpectedCollectArgs { func: "be16" }) && err.loc == Loc::new(2, 19),
        "{err:?}"
    );
}

/// An argument of the wrong type points at the argument, with expected and found types
#[test]
fn check_arg_type() {
    let err = error("import dns;\ndns::hdr(id: \"x\", flags: 0);");
    assert!(
        matches!(
            &err.kind,
            ArgType {
                func: "hdr",
                arg: "id",
                expected: ValType::U16,
                found: Found::Ty(Ty::Bytes)
            }
        ) && err.loc == Loc::new(2, 10),
        "{err:?}"
    );
}

/// Each argument is converted as soon as it's bound, so a bad argument is the error even when
/// a later one would be too many
#[test]
fn check_arg_type_before_too_many() {
    let err = error("import std;\nstd::u8(\"x\", 1);");
    assert!(
        matches!(
            &err.kind,
            ArgType {
                func: "u8",
                arg: "val",
                expected: ValType::U8,
                found: Found::Ty(Ty::Bytes)
            }
        ) && err.loc == Loc::new(2, 9),
        "{err:?}"
    );
}

/// Functions with no use for extra arguments reject them.
#[test]
fn check_extra_args_rejected() {
    let err = error("import io;\nio::file(\"a\", \"b\");");
    assert!(
        matches!(
            &err.kind,
            TooManyArgs {
                func: "file",
                got: 2,
                want: 1
            }
        ) && err.loc == Loc::new(2, 15),
        "{err:?}"
    );

    let src = "import ipv4;\n\
               let pkt = ipv4::frag(10.0.0.1, 10.0.0.2, \"01234567\");\n";
    for call in [
        "pkt.fragment(0, 1, false, \"x\");",
        "pkt.tail(0, false, \"x\");",
        "pkt.datagram(false, \"x\");",
    ] {
        let err = error(&format!("{src}{call}"));
        assert!(matches!(err.kind, TooManyArgs { .. }), "{call}: {err}");
    }
}

/// The binder's other errors, end to end. Errors about a missing argument point at the called
/// name, and errors about one argument point at it.
#[test]
fn check_binding_errors() {
    let err = error("import ipv4;\nipv4::tcp::flow(1.2.3.4:1);");
    assert!(
        matches!(
            err.kind,
            TooFewArgs {
                func: "flow",
                got: 1,
                want: 2
            }
        ) && err.loc == Loc::new(2, 12),
        "{err:?}"
    );
    let err = error("import ipv4;\nipv4::tcp::flow(1.2.3.4:1, cl_seq: 5);");
    assert!(
        matches!(
            err.kind,
            MissingArg {
                func: "flow",
                arg: "sv"
            }
        ) && err.loc == Loc::new(2, 12),
        "{err:?}"
    );
    let err = error("import ipv4;\nipv4::tcp::flow(1.2.3.4:1, 5.6.7.8:2, cl: 1.2.3.4:1);");
    assert!(
        matches!(&err.kind, DuplicateArg { func: "flow", arg } if &**arg == "cl")
            && err.loc == Loc::new(2, 39),
        "{err:?}"
    );
    let err = error("import dns;\ndns::name(\"a\", complete: true);");
    assert!(
        matches!(&err.kind, UnexpectedNamedArg { func: "name", arg } if &**arg == "complete")
            && err.loc == Loc::new(2, 16),
        "{err:?}"
    );
    let err = error("import tls;\ntls::ciphers(\"x\");");
    assert!(
        matches!(
            err.kind,
            CollectArgType {
                func: "ciphers",
                expected: ValType::U16,
                found: Found::Ty(Ty::Bytes)
            }
        ) && err.loc == Loc::new(2, 14),
        "{err:?}"
    );
}

// `void`

/// A `void` call can't be bound by `let`. The poisoned `n` then reports nothing.
#[test]
fn check_void_let() {
    let err = error(&format!(
        "{FLOW}let n = c.client_hole(1);\nc.client_message(seq: n, \"x\");"
    ));
    assert!(
        matches!(err.kind, VoidValue) && err.loc == Loc::new(3, 11),
        "{err:?}"
    );
}

/// Using a name poisoned by a `void` `let` reports nothing more
#[test]
fn check_void_let_then_use() {
    let err = error(
        "import ipv4;\nimport std;\nlet c = ipv4::tcp::flow(1.2.3.4:1, 5.6.7.8:2);\n\
         let n = c.client_hole(1);\nstd::be16(n);",
    );
    assert!(
        matches!(err.kind, VoidValue) && err.loc == Loc::new(4, 11),
        "{err:?}"
    );
}

/// A `void` call can't be an argument either
#[test]
fn check_void_arg() {
    let err = error(&format!(
        "{FLOW}c.client_message(seq: c.client_hole(1), \"x\");"
    ));
    assert!(
        matches!(err.kind, VoidValue) && err.loc == Loc::new(3, 25),
        "{err:?}"
    );
}

/// `void` as a statement gives no warning
#[test]
fn check_void_stmt() {
    let (prog, warnings) = checked(include_str!("../../examples/missing-start.rsyn"));
    assert_eq!(warnings, []);
    assert!(
        prog.stmts()
            .iter()
            .any(|stmt| matches!(stmt.kind, StmtKind::Eval(_))),
        "{prog}"
    );
}

// `/`

/// Both operands of `/` are type checked
#[test]
fn check_slash_operand_types() {
    let err = error("import ipv4;\n\"a\" / 80;");
    assert!(
        matches!(
            err.kind,
            OperandType {
                side: Side::Left,
                expected: Ty::Ip4,
                found: Found::Ty(Ty::Bytes),
                ..
            }
        ) && err.loc == Loc::new(2, 1),
        "{err:?}"
    );
    let err = error("let x = 80 / 80;");
    assert!(
        matches!(
            err.kind,
            OperandType {
                side: Side::Left,
                expected: Ty::Ip4,
                found: Found::Int,
                ..
            }
        ) && err.loc == Loc::new(1, 9),
        "{err:?}"
    );
    let err = error("let x = 1.2.3.4 / 1.2.3.4;");
    assert!(
        matches!(
            err.kind,
            OperandType {
                side: Side::Right,
                expected: Ty::U16,
                found: Found::Ty(Ty::Ip4),
                ..
            }
        ) && err.loc == Loc::new(1, 19),
        "{err:?}"
    );
}

/// the right of `/` narrows to `u16`, so a constant port folds. So does an untyped integer bound
/// by a `let`, and a `bool`.
#[test]
fn check_slash_folds_constant_port() {
    assert_eq!(lower("1.2.3.4 / 80;"), "(discard 1.2.3.4:80)");
    assert_eq!(
        lower("let p = 80;\nlet s = 1.2.3.4 / p;\ns;"),
        "(discard 1.2.3.4:80)"
    );
    assert_eq!(lower("1.2.3.4 / true;"), "(discard 1.2.3.4:1)");
    assert_eq!(lower("let x = 1.2.3.4;\nx / 80;"), "(discard 1.2.3.4:80)");
    assert_eq!(
        lower("import dns;\nlet s = 1.2.3.4 / dns::rtype::A;\ns;"),
        "(discard 1.2.3.4:1)"
    );
}

/// a constant port that doesn't fit `u16` keeps its low bits, with a warning
#[test]
fn check_slash_port_truncated() {
    let (prog, warnings) = checked("let p = 65536;\nlet s = 1.2.3.4 / p;\ns;");
    assert_eq!(prog.to_string(), "(discard 1.2.3.4:0)");
    assert_eq!(
        warnings,
        [
            (Loc::new(2, 19), "integer 65536 truncated to u16".to_owned()),
            (Loc::new(3, 1), "discarded value of type Sock4".to_owned()),
        ]
    );
    assert_eq!(warning_locs("let s = 1.2.3.4 / 65535;"), []);
    assert_eq!(warning_locs("let s = 1.2.3.4 / true;"), []);
}

/// A port whose type is wider than `u16` may be truncated when it runs
#[test]
fn check_slash_port_overflow() {
    let (prog, warnings) = checked("import text;\nlet s = 1.2.3.4 / text::len(\"ab\");");
    assert_eq!(
        prog.to_string(),
        "(eval (/ 1.2.3.4 (call func:len (* \"ab\"))))"
    );
    assert_eq!(
        warnings,
        [(
            Loc::new(2, 19),
            "value of type u64 may be truncated to u16".to_owned()
        )]
    );
}

// Untyped integers

/// An untyped integer with no context narrows to the narrowest type that holds it
#[test]
fn check_untyped_int_no_context() {
    for (src, ty) in [("5;", "u8"), ("300;", "u16"), ("70000;", "u32")] {
        assert_eq!(
            checked(src).1,
            [(Loc::new(1, 1), format!("discarded value of type {ty}"))]
        );
    }
    assert_eq!(lower("300;"), "(discard u16:0x12c)");
}

/// An untyped integer that no type holds, with no context
#[test]
fn check_untyped_int_too_large() {
    let err = error("18446744073709551616;");
    assert!(
        matches!(err.kind, IntegralTooLarge()) && err.loc == Loc::new(1, 1),
        "{err:?}"
    );
}

/// An untyped integer has no members
#[test]
fn check_untyped_int_no_members() {
    let err = error("5.foo;");
    assert!(
        matches!(err.kind, NoMembers(Found::Int)) && err.loc == Loc::new(1, 3),
        "{err:?}"
    );
}

/// An untyped integer argument narrows to its parameter's type, keeping its low bits, with a
/// warning at the argument if that truncates it
#[test]
fn check_untyped_arg_truncated() {
    let (prog, warnings) = checked("import std;\nstd::u8(300);");
    assert_eq!(prog.to_string(), "(discard (call func:u8 (: val u8:0x2c)))");
    assert_eq!(
        warnings,
        [
            (Loc::new(2, 9), "integer 300 truncated to u8".to_owned()),
            (Loc::new(2, 1), "discarded value of type bytes".to_owned()),
        ]
    );

    // one wider than `u64`, too
    let (prog, warnings) = checked("import std;\nstd::be64(18446744073709551616);");
    assert_eq!(
        prog.to_string(),
        "(discard (call func:be64 (: val u64:0x0)))"
    );
    assert_eq!(
        warnings[0],
        (
            Loc::new(2, 11),
            "integer 18446744073709551616 truncated to u64".to_owned()
        )
    );
}

/// a `let` bound to an untyped integer is narrowed at each use, so it may be used at two types
#[test]
fn check_untyped_let_used_at_two_types() {
    let (prog, warnings) = checked("import std;\nlet p = 80;\nstd::u8(p);\n1.2.3.4 / p;");
    assert_eq!(
        prog.to_string(),
        "(discard (call func:u8 (: val u8:0x50)))\n(discard 1.2.3.4:80)"
    );
    assert_eq!(
        warnings,
        [
            (Loc::new(3, 1), "discarded value of type bytes".to_owned()),
            (Loc::new(4, 1), "discarded value of type Sock4".to_owned()),
        ]
    );
}

/// an untyped integer passed as a `bool` is `true` if it's non-zero
#[test]
fn check_untyped_arg_as_bool() {
    for (n, b) in [(0, "false"), (2, "true")] {
        let prog = lower(&format!("{FLOW}c.client_message(send_ack: {n}, \"x\");"));
        assert!(prog.contains(&format!("(: send_ack {b})")), "{prog}");
    }
}

/// an untyped integer passed as bytes narrows to the narrowest type that holds it
#[test]
fn check_untyped_arg_as_bytes() {
    assert_eq!(
        lower("import text;\nlet x = text::concat(\"a\", 5, 300);"),
        "(eval (call func:concat (* \"a\" u8:0x5 u16:0x12c)))"
    );
}

/// The narrowing example in docs/grammar.md §8.2 gives exactly one warning per line
#[test]
fn check_narrowing_doc_example() {
    let (_, warnings) = checked(
        "import std;\n\
         import text;\n\
         let a = std::u8(300);\n\
         let b = 1.2.3.4 / 65536;\n\
         let c = 1.2.3.4 / text::len(\"ab\");",
    );
    assert_eq!(
        warnings,
        [
            (Loc::new(3, 17), "integer 300 truncated to u8".to_owned()),
            (Loc::new(4, 19), "integer 65536 truncated to u16".to_owned()),
            (
                Loc::new(5, 19),
                "value of type u64 may be truncated to u16".to_owned()
            ),
        ]
    );
}

/// std::be16() takes a u16, it must warn when a const parameter gets truncated
#[test]
fn check_wide_encoder_arg_not_truncated() {
    assert_eq!(
        warning_locs("import std;\nlet x = std::be16(70000);"),
        [Loc::new(2, 19)]
    );
}

/// An argument whose type is wider than its parameter's may be truncated when it runs
#[test]
fn check_arg_overflow() {
    let (_, warnings) =
        checked("import dns;\nimport text;\ndns::hdr(id: text::len(\"x\"), flags: 0);");
    assert_eq!(
        warnings[0],
        (
            Loc::new(3, 14),
            "value of type u64 may be truncated to u16".to_owned()
        )
    );
}

// Error recovery

/// a poisoned name stops the statements that use it, without more errors
#[test]
fn check_poisoned_name_is_silent() {
    let err = error(
        "import ipv4;\nlet c = ipv4::tcp::flw(1.2.3.4:1, 5.6.7.8:2);\nc.open();\nc.client_message(\"x\");",
    );
    assert!(
        matches!(&err.kind, UnknownItem { name, module: "tcp" } if &**name == "flw")
            && err.loc == Loc::new(2, 20),
        "{err:?}"
    );

    // ...even when the statement has an error of its own
    let err = error(
        "import ipv4;\nlet c = ipv4::tcp::flw(1.2.3.4:1, 5.6.7.8:2);\nc.client_message(nosuch);",
    );
    assert!(
        matches!(&err.kind, UnknownItem { name, .. } if &**name == "flw"),
        "{err:?}"
    );
}

/// Only the first error in a statement is reported
#[test]
fn check_one_error_per_stmt() {
    let err = error("import dns;\ndns::hdr(id: nosuch1, flags: nosuch2);");
    assert!(
        matches!(&err.kind, UnknownName(n) if &**n == "nosuch1") && err.loc == Loc::new(2, 14),
        "{err:?}"
    );
}

/// Errors in separate statements are all reported, in source order
#[test]
fn check_errors_in_each_stmt() {
    let errs = errors("import ipv4;\nnosuch1;\nnosuch2;");
    assert!(
        matches!(
            &errs[..],
            [
                SemanticError { loc: l1, kind: UnknownName(n1) },
                SemanticError { loc: l2, kind: UnknownName(n2) },
            ] if &**n1 == "nosuch1" && *l1 == Loc::new(2, 1)
                && &**n2 == "nosuch2" && *l2 == Loc::new(3, 1)
        ),
        "{errs:?}"
    );
}

// Warnings

/// A discarded value is warned about at the start of its statement
#[test]
fn check_discarded_value_at_stmt_start() {
    assert_eq!(warning_locs("let x = 1.2.3.4;\nx / 80;"), [Loc::new(2, 1)]);
    assert_eq!(
        warning_locs(&format!("{FLOW}c.client_hdr();")),
        [Loc::new(3, 1)]
    );
    assert_eq!(
        checked("\"abc\";").1,
        [(Loc::new(1, 1), "discarded value of type bytes".to_owned())]
    );
}

/// The warning names the type, never a symbol table
#[test]
fn check_discarded_value_names_type() {
    assert_eq!(
        checked(&format!("{FLOW}c;\nipv4::tcp::flow;\nc.open;")).1,
        [
            (Loc::new(3, 1), "discarded value of type TcpFlow".to_owned()),
            (
                Loc::new(4, 1),
                "discarded value of type function flow".to_owned()
            ),
            (
                Loc::new(5, 1),
                "discarded value of type method TcpFlow.open".to_owned()
            ),
        ]
    );
}

/// Warnings come in source order, from one pass
#[test]
fn check_warning_order() {
    assert_eq!(
        checked("import std;\nimport text;\nstd::be16(1);\nimport std;").1,
        [
            (Loc::new(3, 1), "discarded value of type bytes".to_owned()),
            (Loc::new(4, 8), "multiple imports of \"std\"".to_owned()),
        ]
    );
}

/// A repeated import is warned about, whatever happens when the program runs
#[test]
fn check_repeated_import() {
    assert_eq!(
        warning_locs("import io;\nlet x = io::file(\"no-such-file.der\");\nimport io;"),
        [Loc::new(3, 8)]
    );
}

/// Warnings are given even when checking fails
#[test]
fn check_warning_before_error() {
    let (res, warnings) = check_src("\"abc\";\nnosuch;");
    let errs = res.expect_err("check succeeded");
    assert!(
        matches!(&errs[..], [SemanticError { loc, kind: UnknownName(n) }] if &**n == "nosuch" && *loc == Loc::new(2, 1)),
        "{errs:?}"
    );
    assert_eq!(
        warnings,
        [(Loc::new(1, 1), "discarded value of type bytes".to_owned())]
    );
}

/// Errors and warnings are given through the one callback, in source order
#[test]
fn check_diagnostics_in_source_order() {
    let (res, diags) = diagnostics("\"abc\";\nnosuch;\n\"def\";");
    assert_eq!(
        res.expect_err("check succeeded"),
        ErrorSummary {
            errors: NonZeroUsize::MIN,
            warnings: 2,
        }
    );
    assert!(
        matches!(
            &diags[..],
            [
                Diagnostic { loc: l1, kind: DiagnosticKind::Warning(WarningKind::DiscardedValue(Ty::Bytes)) },
                Diagnostic { loc: l2, kind: DiagnosticKind::Error(UnknownName(n)) },
                Diagnostic { loc: l3, kind: DiagnosticKind::Warning(WarningKind::DiscardedValue(Ty::Bytes)) },
            ] if *l1 == Loc::new(1, 1) && &**n == "nosuch" && *l2 == Loc::new(2, 1)
                && *l3 == Loc::new(3, 1)
        ),
        "{diags:?}"
    );
}

/// The summary under a failed check's errors names each count with its noun, and leaves out no
/// warnings
#[test]
fn check_error_summary_display() {
    let summary = |errors, warnings| ErrorSummary {
        errors: NonZeroUsize::new(errors).expect("no errors"),
        warnings,
    };
    assert_eq!(summary(1, 0).to_string(), "1 error");
    assert_eq!(summary(2, 1).to_string(), "2 errors, 1 warning");
    assert_eq!(summary(1, 2).to_string(), "1 error, 2 warnings");
}

// Lowering

/// FuncDef assigned to a local is a const and that gets folded without wasting a local slot
#[test]
fn lower_call_through_local() {
    let (prog, _) = checked("import std;\nlet f = std::be16;\nlet x = f(1);\nx;");
    assert_eq!(
        prog.to_string(),
        "(let $0 (call func:be16 (: val u16:0x1)))\n(discard $0)"
    );
    assert!(
        matches!(
            &prog.stmts()[0].kind,
            StmtKind::Let { value: Expr{ kind: ExprKind::Call(call), .. }, ..} if matches!(call.callee.kind, ExprKind::Const(Const::Func(f)) if f == func("std::be16"))
        ),
        "{prog}"
    );
    assert_eq!(prog.slot_name(crate::hir::SlotId(0)), "x");
}

/// a bound method held in a slot, called twice
#[test]
fn lower_bound_method_in_slot() {
    assert_eq!(
        lower(&format!("{FLOW}let m = c.open;\nm();\nm();")),
        "(let $0 (call func:flow (: cl 1.2.3.4:1) (: sv 5.6.7.8:2) (: cl_seq u32:0x1) (: sv_seq u32:0x1) (: raw false)))\n\
         (let $1 (. $0 open))\n\
         (emit (call $1))\n\
         (emit (call $1))"
    );
}

/// Each statement kind, chosen from its type
#[test]
fn lower_stmt_kinds() {
    assert_eq!(
        lower("import time;\ntime::jump_seconds(1);\n\"abc\";"),
        "(wait (call func:jump_seconds (: seconds u32:0x1)))\n(discard \"abc\")"
    );
    assert_eq!(
        lower(&format!("{FLOW}c.client_hole(1);")).lines().last(),
        Some("(eval (call (. $0 client_hole) (: bytes u32:0x1)))")
    );
}

/// Written arguments, then defaults in parameter order, with an absent nullable parameter as
/// `nil`, then the collect arguments
#[test]
fn lower_call_layout() {
    assert_eq!(
        lower(&format!("{FLOW}c.client_message(seq: 5, \"x\", \"y\");"))
            .lines()
            .last(),
        Some(
            "(emit (call (. $0 client_message) (: seq u32:0x5) (: send_ack true) (: ack nil) \
             (: frag_off u16:0x0) (* \"x\" \"y\")))"
        )
    );
}

/// An absent nullable parameter lowers to `nil`
#[test]
fn lower_absent_nullable() {
    assert_eq!(
        lower(&format!("{FLOW}c.client_message(\"x\");"))
            .lines()
            .last(),
        Some(
            "(emit (call (. $0 client_message) (: send_ack true) (: seq nil) (: ack nil) \
             (: frag_off u16:0x0) (* \"x\")))"
        )
    );
}

/// Module constants lower at their own width
#[test]
fn lower_module_constants() {
    assert_eq!(
        lower("import dns;\nimport text;\nlet a = dns::rtype::A;\nlet b = text::CRLF; a; b;"),
        "(discard u16:0x1)\n(discard \"|0d 0a|\")"
    );
}

/// arguments are held in the order they were written, each with its parameter
#[test]
fn lower_args_in_source_order() {
    let src = |first, second| {
        format!(
            "{FLOW}import dhcp;\n\
             let h = dhcp::hdr({first}: c.client_hdr(bytes: 1), {second}: c.client_hdr(bytes: 1));\n\
             h;"
        )
    };
    let hdr = |first: &str, second: &str| {
        format!(
            "(let $1 (call func:hdr \
             (: {first} (call (. $0 client_hdr) (: bytes u32:0x1) (: csum u16:0x0))) \
             (: {second} (call (. $0 client_hdr) (: bytes u32:0x1) (: csum u16:0x0))) "
        )
    };

    let g01 = lower(&src("file", "sname"));
    assert!(g01.contains(&hdr("file", "sname")), "{g01}");
    let g02 = lower(&src("sname", "file"));
    assert!(g02.contains(&hdr("sname", "file")), "{g02}");
}

/// Every stdlib constant, default and return type has a checker type or constant
#[test]
fn stdlib_types_lower() {
    fn func(func: &FuncDef) {
        assert!(
            Ty::try_from(func.return_type).is_ok(),
            "{}: return type {}",
            func.name,
            func.return_type
        );
        for desc in func.args {
            if let ArgDecl::Optional(def) = desc.typ {
                assert!(
                    !matches!(def, ValDef::Nil),
                    "{}: {} defaults to nil",
                    func.name,
                    desc.name
                );
            }
        }
    }
    fn constant(name: &str, def: ValDef) {
        assert!(
            !matches!(def, ValDef::Nil | ValDef::Type(_)),
            "{name}: {def:?}"
        );
    }
    fn module(m: &Module) {
        for desc in m.symtab {
            match desc.sym {
                Symbol::Module(inner) => module(inner),
                Symbol::Func(f) => func(f),
                Symbol::Val(def) => constant(desc.name, def),
                Symbol::Class(cls) => {
                    for desc in cls.symtab {
                        match desc.sym {
                            Symbol::Func(f) => func(f),
                            Symbol::Val(def) => constant(desc.name, def),
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    module(&STDLIB);
}

/// A property of a local is its class's constant alone: reading a local has no effects
#[test]
fn lower_property_of_local() {
    assert_eq!(
        lower_in(
            &object::ROOT,
            "import obj;\nlet t = obj::tcp();\nt.client_message;"
        ),
        "(eval (call func:tcp))\n(discard u64:0x1)"
    );
}

/// A property of a call still calls it
#[test]
fn lower_property_of_call() {
    assert_eq!(
        lower_in(&object::ROOT, "import obj;\nobj::tcp().client_message;"),
        "(discard (seq (call func:tcp) u64:0x1))"
    );
}

/// A property of a local is a constant, so a port from one folds
#[test]
fn lower_slash_port_property_of_local() {
    assert_eq!(
        lower_in(
            &object::ROOT,
            "import obj;\nlet t = obj::tcp();\nlet s = 1.2.3.4 / t.client_message;\ns;"
        ),
        "(eval (call func:tcp))\n(discard 1.2.3.4:1)"
    );
}

/// A property of a call is a constant after the call, so a port from one folds, keeping the call
/// for its effects. The `let` hoists it, and binds a constant.
#[test]
fn lower_slash_port_property_of_call() {
    let (res, diags) = diagnostics_in(
        &object::ROOT,
        "import obj;\nlet s = 1.2.3.4 / obj::tcp().client_message;\ns;",
    );
    assert_eq!(
        res.expect("check failed").to_string(),
        "(eval (call func:tcp))\n(discard 1.2.3.4:1)"
    );
    assert_eq!(diags.len(), 1, "only the discard warns: {diags:?}");
}

/// `/` folds only when every operand's value is a constant. Here the left is a call, so the
/// right's call stays where it is and runs after it. The port still narrows through its sequence.
#[test]
fn lower_slash_keeps_effect_order() {
    assert_eq!(
        lower_in(
            &object::ROOT,
            "import obj;\nlet s = obj::ip() / obj::tcp().client_message;"
        ),
        "(eval (/ (call func:ip) (seq (call func:tcp) u16:0x1)))"
    );
}

/// An argument that is a property of a call narrows its constant value, in place, so it doesn't
/// warn `Overflow`
#[test]
fn lower_arg_property_of_call() {
    let (res, diags) = diagnostics_in(
        &object::ROOT,
        "import obj;\nobj::u8(obj::tcp().client_message);",
    );
    assert_eq!(
        res.expect("check failed").to_string(),
        "(eval (call func:u8 (: val (seq (call func:tcp) u8:0x1))))"
    );
    assert!(diags.is_empty(), "{diags:?}");
}

// Dead `let`s

/// A dead `let` whose value is impure is evaluated for its effects
#[test]
fn lower_dead_impure_let() {
    assert_eq!(
        lower("import std;\nlet x = std::be16(1);"),
        "(eval (call func:be16 (: val u16:0x1)))"
    );
}

/// A dead `let` that is evaluated still reads its slots, so they stay live
#[test]
fn lower_dead_impure_let_keeps_reads() {
    assert_eq!(
        lower(&format!("{FLOW}let h = c.client_hdr(bytes: 5);")),
        "(let $0 (call func:flow (: cl 1.2.3.4:1) (: sv 5.6.7.8:2) (: cl_seq u32:0x1) (: sv_seq u32:0x1) (: raw false)))\n\
         (eval (call (. $0 client_hdr) (: bytes u32:0x5) (: csum u16:0x0)))"
    );
}

/// A dead `let` whose value is pure is removed, and its reads don't count, so the flow it read
/// is dead too
#[test]
fn lower_dead_pure_let_cascades() {
    assert_eq!(
        lower(&format!("{FLOW}let m = c.open;")),
        "(eval (call func:flow (: cl 1.2.3.4:1) (: sv 5.6.7.8:2) (: cl_seq u32:0x1) (: sv_seq u32:0x1) (: raw false)))"
    );
}

/// A dead alias is removed, and so is what it aliased
#[test]
fn lower_dead_alias_cascades() {
    assert_eq!(
        lower_in(
            &object::ROOT,
            "import obj;\nlet a = obj::tcp();\nlet b = a;"
        ),
        "(eval (call func:tcp))"
    );
}

/// An alias that is read keeps its slot, and so does what it aliased
#[test]
fn lower_read_alias_kept() {
    assert_eq!(
        lower_in(
            &object::ROOT,
            "import obj;\nlet a = obj::tcp();\nlet b = a;\nb;"
        ),
        "(let $0 (call func:tcp))\n(let $1 $0)\n(discard $1)"
    );
}

/// A dead `let` frees its slot, and the `let` after it is renumbered into it
#[test]
fn lower_dead_let_renumbers() {
    let (prog, _) = checked(
        "import ipv4;\n\
         let a = ipv4::tcp::flow(1.2.3.4:1, 5.6.7.8:2);\n\
         let b = ipv4::tcp::flow(1.2.3.4:3, 5.6.7.8:4);\n\
         b.open();",
    );
    assert_eq!(
        prog.to_string(),
        "(eval (call func:flow (: cl 1.2.3.4:1) (: sv 5.6.7.8:2) (: cl_seq u32:0x1) (: sv_seq u32:0x1) (: raw false)))\n\
         (let $0 (call func:flow (: cl 1.2.3.4:3) (: sv 5.6.7.8:4) (: cl_seq u32:0x1) (: sv_seq u32:0x1) (: raw false)))\n\
         (emit (call (. $0 open)))"
    );
    assert_eq!(prog.slot_name(crate::hir::SlotId(0)), "b");
}
