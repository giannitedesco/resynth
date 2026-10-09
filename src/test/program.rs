use crate::lex::Lexer;
use crate::loc::Loc;
use crate::parse::parse;
use crate::program::Program;
use crate::program::RuntimeError;
use crate::program::RuntimeErrorKind::{
    ImportError, MultipleAssignError, NameError, NoSuchArg, NotAValue, NotCallable, NotImported,
    TypeError,
};
use crate::val::ValType;

type RunResult = Result<(), RuntimeError>;

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

fn run_err(src: &str) -> RuntimeError {
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
    let err = run_err("import ipv4;\nipv4::tcp::flow.new;");
    assert!(
        matches!(&err.kind, TypeError) && err.loc == Loc::new(2, 17),
        "{err:?}"
    );
}

#[test]
fn run_member_of_method_is_type_error() {
    // Used to be TooManyComponents
    let err = run_err(&format!("{FLOW}f.client_message.b;"));
    assert!(
        matches!(&err.kind, TypeError) && err.loc == Loc::new(3, 18),
        "{err:?}"
    );
}

#[test]
fn run_module_path_error_at_failing_segment() {
    let err = run_err("import dns;\ndns::nmae(\"x\");");
    assert!(
        matches!(&err.kind, NameError(n) if &**n == "nmae") && err.loc == Loc::new(2, 6),
        "{err:?}"
    );
    let err = run_err("dns::name(\"x\");");
    assert!(
        matches!(&err.kind, NotImported(n) if &**n == "dns") && err.loc == Loc::new(1, 1),
        "{err:?}"
    );
    let err = run_err("import ipv4;\nipv4::nosuch::flow;");
    assert!(
        matches!(&err.kind, NameError(n) if &**n == "nosuch") && err.loc == Loc::new(2, 7),
        "{err:?}"
    );
    let err = run_err("import ipv4;\nipv4::tcp.flow;");
    assert!(
        matches!(&err.kind, NotAValue(n) if &**n == "tcp") && err.loc == Loc::new(2, 7),
        "{err:?}"
    );
}

#[test]
fn run_local_ref_error_at_identifier() {
    let err = run_err("import dns;\ndns::name(nosuch);");
    assert!(
        matches!(&err.kind, NameError(n) if &**n == "nosuch") && err.loc == Loc::new(2, 11),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "2:11: unknown name \"nosuch\"");
}

#[test]
fn run_call_errors_at_called_name() {
    // Trunk reported these at the last argument evaluated
    let err = run_err("import dns;\ndns::name(nosuch: \"x\");");
    assert!(
        matches!(&err.kind, NoSuchArg { func, arg } if &**func == "name" && &**arg == "nosuch")
            && err.loc == Loc::new(2, 6),
        "{err:?}"
    );
    let err = run_err(&format!("{FLOW}f.client_message(nosuch: 1);"));
    assert!(
        matches!(&err.kind, NoSuchArg { func, arg } if &**func == "client_message" && &**arg == "nosuch")
            && err.loc == Loc::new(3, 3),
        "{err:?}"
    );
}

#[test]
fn run_not_callable() {
    let err = run_err("let x = 1.2.3.4;\nx();");
    assert!(
        matches!(&err.kind, NotCallable(ValType::Ip4)) && err.loc == Loc::new(2, 1),
        "{err:?}"
    );
    // The outer call of `f()()` points at the start of the callee
    let err = run_err("import dns;\ndns::name(\"x\")();");
    assert!(
        matches!(&err.kind, NotCallable(ValType::Str)) && err.loc == Loc::new(2, 1),
        "{err:?}"
    );
}

#[test]
fn run_slash_operand_errors() {
    let err = run_err("let x = 80 / 80;");
    assert!(
        matches!(&err.kind, TypeError) && err.loc == Loc::new(1, 9),
        "{err:?}"
    );
    let err = run_err("let x = 1.2.3.4 / 1.2.3.4;");
    assert!(
        matches!(&err.kind, TypeError) && err.loc == Loc::new(1, 19),
        "{err:?}"
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
    let err = run_err("let x = 1;\nlet x = 2;");
    assert!(
        matches!(&err.kind, MultipleAssignError(n) if &**n == "x") && err.loc == Loc::new(2, 5),
        "{err:?}"
    );
    let err = run_err("import nosuch;");
    assert!(
        matches!(&err.kind, ImportError(n) if &**n == "nosuch") && err.loc == Loc::new(1, 8),
        "{err:?}"
    );
}
