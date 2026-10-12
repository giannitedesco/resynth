use crate::ast::Stmt;
use crate::lex::Lexer;
use crate::loc::Loc;
use crate::parse::parse;
use crate::program::Program;
use crate::program::RuntimeError;
use crate::program::RuntimeErrorKind::{
    ImportError, MultipleAssignError, NameError, NoSuchArg, NotAValue, NotCallable, NotImported,
    PortOutOfRange, TooManyArgs, TypeError,
};
use crate::stdlib::toplevel_module;
use crate::val::{Val, ValType};

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
fn run_slash_port_range() {
    run("let x = 1.2.3.4 / 65535;").0.expect("run failed");

    let err = run_err("let x = 1.2.3.4 / 65536;");
    assert!(
        matches!(&err.kind, PortOutOfRange(65536)) && err.loc == Loc::new(1, 19),
        "{err:?}"
    );
    let err = run_err("let p = 18446744073709551615;\nlet x = 1.2.3.4 / p;");
    assert!(
        matches!(&err.kind, PortOutOfRange(u64::MAX)) && err.loc == Loc::new(2, 19),
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

/// The packets of a program's final statement, which must be an expression
fn last_packets(src: &str) -> Vec<Vec<u8>> {
    let mut stmts = parse(Lexer::lex(src.lines()).expect("lex failed")).expect("parse failed");
    let Some(Stmt::Expr(last)) = stmts.pop() else {
        panic!("the last statement must be an expression");
    };
    let mut prog = Program::dummy();
    prog.run(stmts).expect("run failed");
    match prog.eval(last).expect("run failed") {
        Val::Pkt(pkt) => vec![pkt.to_vec()],
        Val::PktGen(pkts) => pkts.iter().map(|pkt| pkt.to_vec()).collect(),
        val => panic!("expected packets, got {val:?}"),
    }
}

/// The code in each ```resynth block of a doc comment, joined into one program
fn doc_program(doc: &str) -> String {
    let mut prog = String::new();
    let mut in_block = false;

    for line in doc.lines().map(str::trim_start) {
        match line {
            "```resynth" => in_block = true,
            "```" => in_block = false,
            code if in_block => {
                prog.push_str(code);
                prog.push('\n');
            }
            _ => {}
        }
    }

    prog
}

/// The tls module's handshake example runs. It used to load a file that didn't exist.
#[test]
fn run_tls_module_doc_example() {
    let frames = last_packets(&doc_program(toplevel_module("tls").expect("no tls").doc));

    // The server flight holds the Server Key Exchange record: handshake, TLS 1.2, 556 bytes,
    // then a server_key_exchange message of 552 bytes
    let ske: &[u8] = &[0x16, 0x03, 0x03, 0x02, 0x2c, 0x0c, 0x00, 0x02, 0x28];
    assert!(frames[0].windows(ske.len()).any(|w| w == ske));
}

/// Functions with no use for extra arguments reject them. Passing them used to abort the process.
#[test]
fn run_extra_args_rejected() {
    let err = run_err("import io;\nio::file(\"a\", \"b\");");
    assert!(matches!(err.kind, TooManyArgs { .. }), "{err}");

    let src = "import ipv4;\n\
               let pkt = ipv4::frag(10.0.0.1, 10.0.0.2, \"01234567\");\n";
    for call in [
        "pkt.fragment(0, 1, false, \"x\");",
        "pkt.tail(0, false, \"x\");",
        "pkt.datagram(false, \"x\");",
    ] {
        let err = run_err(&format!("{src}{call}"));
        assert!(matches!(err.kind, TooManyArgs { .. }), "{call}: {err}");
    }
}
