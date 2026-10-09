use crate::err::Error::{self, NameError, NotCallable, TypeError};
use crate::lex::Lexer;
use crate::loc::Loc;
use crate::parse::parse;
use crate::program::Program;
use crate::val::ValType;

type RunResult = Result<(), (Loc, Error)>;

/// Run a program without a pcap, returning its result and every warning it gave
fn run(src: &str) -> (RunResult, Vec<(Loc, String)>) {
    let stmts = parse(Lexer::lex(src.lines()).expect("lex failed")).expect("parse failed");

    let mut warnings = Vec::new();
    let mut warn = |loc: Loc, msg: &str| warnings.push((loc, msg.to_owned()));
    let res = {
        let mut prog = Program::dummy();
        prog.set_warning(&mut warn);
        prog.run(stmts)
    };

    (res, warnings)
}

fn run_err(src: &str) -> (Loc, Error) {
    run(src).0.unwrap_err()
}

/// Where each warning was given
fn warning_locs(src: &str) -> Vec<Loc> {
    let (res, warnings) = run(src);
    res.expect("run failed");
    warnings.into_iter().map(|(loc, _)| loc).collect()
}

const FLOW: &str = "import ipv4;\nlet f = ipv4::tcp::flow(1.1.1.1:1, 2.2.2.2:2);\n";

#[test]
fn run_member_of_function_is_type_error() {
    // Used to panic in eval_extern_ref
    assert_eq!(
        run_err("import ipv4;\nipv4::tcp::flow.new;"),
        (Loc::new(2, 17), TypeError)
    );
}

#[test]
fn run_member_of_method_is_type_error() {
    // Used to be TooManyComponents
    assert_eq!(
        run_err(&format!("{FLOW}f.client_message.b;")),
        (Loc::new(3, 18), TypeError)
    );
}

#[test]
fn run_module_path_error_at_failing_segment() {
    assert_eq!(
        run_err("import dns;\ndns::nmae(\"x\");"),
        (Loc::new(2, 6), NameError("nmae".into()))
    );
    assert_eq!(
        run_err("dns::name(\"x\");"),
        (Loc::new(1, 1), Error::NotImported("dns".into()))
    );
    assert_eq!(
        run_err("import ipv4;\nipv4::nosuch::flow;"),
        (Loc::new(2, 7), NameError("nosuch".into()))
    );
    assert_eq!(
        run_err("import ipv4;\nipv4::tcp.flow;"),
        (Loc::new(2, 7), Error::NotAValue("tcp".into()))
    );
}

#[test]
fn run_local_ref_error_at_identifier() {
    assert_eq!(
        run_err("import dns;\ndns::name(nosuch);"),
        (Loc::new(2, 11), NameError("nosuch".into()))
    );
}

#[test]
fn run_call_errors_at_called_name() {
    // Trunk reported these at the last argument evaluated
    assert_eq!(
        run_err("import dns;\ndns::name(nosuch: \"x\");"),
        (
            Loc::new(2, 6),
            Error::NoSuchArg {
                func: "name".into(),
                arg: "nosuch".into()
            }
        )
    );
    assert_eq!(
        run_err(&format!("{FLOW}f.client_message(nosuch: 1);")),
        (
            Loc::new(3, 3),
            Error::NoSuchArg {
                func: "client_message".into(),
                arg: "nosuch".into()
            }
        )
    );
}

#[test]
fn run_not_callable() {
    assert_eq!(
        run_err("let x = 1.2.3.4;\nx();"),
        (Loc::new(2, 1), NotCallable(ValType::Ip4))
    );
    // The outer call of `f()()` points at the start of the callee
    assert_eq!(
        run_err("import dns;\ndns::name(\"x\")();"),
        (Loc::new(2, 1), NotCallable(ValType::Str))
    );
}

#[test]
fn run_slash_operand_errors() {
    assert_eq!(run_err("let x = 80 / 80;"), (Loc::new(1, 9), TypeError));
    assert_eq!(
        run_err("let x = 1.2.3.4 / 1.2.3.4;"),
        (Loc::new(1, 19), TypeError)
    );
}

#[test]
fn run_discarded_value_at_stmt_start() {
    assert_eq!(warning_locs("let x = 1.2.3.4;\nx / 80;"), [Loc::new(2, 1)]);
    assert_eq!(
        warning_locs(&format!("{FLOW}f.client_hdr();")),
        [Loc::new(3, 1)]
    );
    assert_eq!(warning_locs("\"abc\";"), [Loc::new(1, 1)]);
}

#[test]
fn run_locals_and_modules_are_separate() {
    // As in examples/tls.rsyn
    assert_eq!(
        warning_locs("import dns;\nlet dns = 1.2.3.4;\ndns::name(\"x\");\ndns;"),
        [Loc::new(3, 1), Loc::new(4, 1)]
    );
}

#[test]
fn run_let_and_import_errors_at_name() {
    assert_eq!(
        run_err("let x = 1;\nlet x = 2;"),
        (Loc::new(2, 5), Error::MultipleAssignError("x".into()))
    );
    assert_eq!(
        run_err("import nosuch;"),
        (Loc::new(1, 8), Error::ImportError("nosuch".into()))
    );
}
