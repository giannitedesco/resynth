use crate::ast::Ident;
use crate::check::SemanticError;
use crate::check::SemanticErrorKind::{
    ArgType, CollectArgType, DuplicateArg, MissingArg, TooFewArgs, TooManyArgs,
    UnexpectedCollectArgs, UnexpectedNamedArg, UnknownArg,
};
use crate::check::bind::{ArgIn, Bound};
use crate::check::{Found, Ty, TypedValue, Value};
use crate::hir::{Const, Expr, ExprKind};
use crate::libapi::FuncDef;
use crate::loc::Loc;
use crate::val::{Val, ValDef, ValType};

/// Where the call is, for errors about a missing argument
const CALL: Loc = Loc::new(9, 9);

/// The `n`th argument, anonymous, at column `n` of line 2. Its value is the constant `n`, so a
/// binding shows where each argument went.
fn anon(n: usize, ty: Ty) -> ArgIn {
    let loc = Loc::new(2, n);
    ArgIn {
        name: None,
        loc,
        value: Value::Typed(TypedValue {
            expr: Expr::new(loc, ExprKind::Const(Const::U64(n as u64))),
            ty,
        }),
    }
}

/// The `n`th argument, written `name: n`. Its name is at column `n` of line 1, and its value at
/// column `n` of line 2.
fn named(n: usize, name: &str, ty: Ty) -> ArgIn {
    ArgIn {
        name: Some(Ident {
            loc: Loc::new(1, n),
            name: name.into(),
        }),
        ..anon(n, ty)
    }
}

/// `args` bound to `func`, as `param=value` in the order the binding holds them, then `|` and
/// the collect arguments
fn bound(func: &'static FuncDef, args: Vec<ArgIn>) -> String {
    let Bound { args, collect } =
        Bound::bind(func, CALL, args, &mut |_, _| {}).expect("bind failed");
    let mut out: Vec<String> = args
        .iter()
        .map(|(arg, slot)| format!("{}={arg}", func.args[*slot].name))
        .collect();
    if !collect.is_empty() {
        out.push("|".into());
        out.extend(collect.iter().map(ToString::to_string));
    }
    out.join(" ")
}

fn bind_err(func: &'static FuncDef, args: Vec<ArgIn>) -> SemanticError {
    match Bound::bind(func, CALL, args, &mut |_, _| {}) {
        Ok(_) => panic!("bind succeeded"),
        Err(err) => err,
    }
}

static PLAIN: FuncDef = func! {
    /// PLAIN
    resynth fn PLAIN(
        /// First positional integer
        a: U64,
        /// Second positional string
        b: Str,
        =>
        /// Optional integer
        c: U64 = 123,
        /// Optional string
        d: Str = b"hello",
        /// Optional type value
        e: Type = ValType::Bool,
        =>
        Void
    ) -> Void
    |_args| {
        Ok(Val::Nil)
    }
};

/// Just supply the positional arguments. The rest take their defaults, in parameter order, and
/// the nullable one is absent.
#[test]
fn bind_simple() {
    assert_eq!(
        bound(&PLAIN, vec![anon(0, Ty::U64), anon(1, Ty::Bytes)]),
        "a=u64:0x0 b=u64:0x1 c=u64:0x7b d=\"hello\" e=nil",
    );
}

/// Supply a nullable argument. It comes before the defaults, because it was written.
#[test]
fn bind_nullable() {
    assert_eq!(
        bound(
            &PLAIN,
            vec![
                anon(0, Ty::U64),
                anon(1, Ty::Bytes),
                named(2, "e", Ty::Bool)
            ]
        ),
        "a=u64:0x0 b=u64:0x1 e=u64:0x2 c=u64:0x7b d=\"hello\"",
    );
}

/// A type-mismatched positional argument is reported at its value
#[test]
fn bind_type_mismatch_positional() {
    let err = bind_err(&PLAIN, vec![anon(0, Ty::U64), anon(1, Ty::Sock4)]);
    assert!(
        matches!(
            &err.kind,
            ArgType {
                func: "PLAIN",
                arg: "b",
                expected: ValType::Str,
                found: Found::Ty(Ty::Sock4)
            }
        ) && err.loc == Loc::new(2, 1),
        "{err:?}"
    );
}

/// A type-mismatched named positional argument is reported at its name
#[test]
fn bind_type_mismatch_named_positional() {
    let err = bind_err(&PLAIN, vec![anon(0, Ty::U64), named(1, "b", Ty::Sock4)]);
    assert!(
        matches!(
            &err.kind,
            ArgType {
                func: "PLAIN",
                arg: "b",
                ..
            }
        ) && err.loc == Loc::new(1, 1),
        "{err:?}"
    );
}

/// A type-mismatched named optional argument
#[test]
fn bind_type_mismatch_named_optional() {
    let err = bind_err(
        &PLAIN,
        vec![
            anon(0, Ty::U64),
            anon(1, Ty::Bytes),
            named(2, "c", Ty::U64),
            named(3, "d", Ty::Sock4),
        ],
    );
    assert!(
        matches!(
            &err.kind,
            ArgType {
                func: "PLAIN",
                arg: "d",
                ..
            }
        ) && err.loc == Loc::new(1, 3),
        "{err:?}"
    );
}

/// Positional arguments can optionally be named
#[test]
fn bind_named_positionals() {
    assert_eq!(
        bound(
            &PLAIN,
            vec![named(0, "a", Ty::U64), named(1, "b", Ty::Bytes)]
        ),
        "a=u64:0x0 b=u64:0x1 c=u64:0x7b d=\"hello\" e=nil",
    );
}

/// Named arguments are held in the order they were written, not parameter order
#[test]
fn bind_named_in_source_order() {
    assert_eq!(
        bound(
            &PLAIN,
            vec![named(0, "b", Ty::Bytes), named(1, "a", Ty::U64)]
        ),
        "b=u64:0x0 a=u64:0x1 c=u64:0x7b d=\"hello\" e=nil",
    );
}

/// Without collect arguments, an optional parameter can be given in order
#[test]
fn bind_optional_in_order() {
    assert_eq!(
        bound(
            &PLAIN,
            vec![anon(0, Ty::U64), anon(1, Ty::Bytes), anon(2, Ty::U64)]
        ),
        "a=u64:0x0 b=u64:0x1 c=u64:0x2 d=\"hello\" e=nil",
    );
}

/// Supply not enough arguments
#[test]
fn bind_not_enough_args() {
    let err = bind_err(&PLAIN, vec![anon(0, Ty::U64)]);
    assert!(
        matches!(
            &err.kind,
            TooFewArgs {
                func: "PLAIN",
                got: 1,
                want: 2
            }
        ) && err.loc == CALL,
        "{err:?}"
    );
}

/// Enough arguments, but a positional one is missing
#[test]
fn bind_missing_positional() {
    let err = bind_err(&PLAIN, vec![anon(0, Ty::U64), named(1, "c", Ty::U64)]);
    assert!(
        matches!(
            &err.kind,
            MissingArg {
                func: "PLAIN",
                arg: "b"
            }
        ) && err.loc == CALL,
        "{err:?}"
    );
}

/// With any argument named, a missing positional is named too, however many optionals are given
#[test]
fn bind_missing_positional_with_only_optionals() {
    for args in [
        vec![named(0, "c", Ty::U64)],
        vec![named(0, "c", Ty::U64), named(1, "d", Ty::Bytes)],
    ] {
        let err = bind_err(&PLAIN, args);
        assert!(
            matches!(
                &err.kind,
                MissingArg {
                    func: "PLAIN",
                    arg: "a"
                }
            ) && err.loc == CALL,
            "{err:?}"
        );
    }
}

/// Specify a positional argument positionally, and also by name
#[test]
fn bind_duplicate_positional() {
    let err = bind_err(
        &PLAIN,
        vec![anon(0, Ty::U64), anon(1, Ty::Bytes), named(2, "a", Ty::U64)],
    );
    assert!(
        matches!(&err.kind, DuplicateArg { func: "PLAIN", arg } if &**arg == "a")
            && err.loc == Loc::new(1, 2),
        "{err:?}"
    );
}

/// Specify an optional argument positionally, and also by name
#[test]
fn bind_duplicate_optional() {
    let err = bind_err(
        &PLAIN,
        vec![
            anon(0, Ty::U64),
            anon(1, Ty::Bytes),
            anon(2, Ty::U64),
            named(3, "c", Ty::U64),
        ],
    );
    assert!(
        matches!(&err.kind, DuplicateArg { func: "PLAIN", arg } if &**arg == "c")
            && err.loc == Loc::new(1, 3),
        "{err:?}"
    );
}

/// Specify an optional argument by name, twice
#[test]
fn bind_duplicate_named_optional() {
    let err = bind_err(
        &PLAIN,
        vec![
            anon(0, Ty::U64),
            anon(1, Ty::Bytes),
            named(2, "c", Ty::U64),
            named(3, "c", Ty::U64),
        ],
    );
    assert!(
        matches!(&err.kind, DuplicateArg { func: "PLAIN", arg } if &**arg == "c")
            && err.loc == Loc::new(1, 3),
        "{err:?}"
    );
}

/// An anonymous argument after a named one, for a function without collect arguments
#[test]
fn bind_unexpected_collect_args() {
    let err = bind_err(&PLAIN, vec![named(0, "a", Ty::U64), anon(1, Ty::Bytes)]);
    assert!(
        matches!(&err.kind, UnexpectedCollectArgs { func: "PLAIN" }) && err.loc == Loc::new(2, 1),
        "{err:?}"
    );
}

static COLLECT: FuncDef = func! {
    /// COLLECT
    resynth fn COLLECT(
        /// Positional integer
        a: U64,
        =>
        /// Optional integer
        b: U64 = 123,
        =>
        Str
    ) -> Void
    |_args| {
        Ok(Val::Nil)
    }
};

/// Empty set of collect args
#[test]
fn bind_collect_none() {
    assert_eq!(
        bound(&COLLECT, vec![anon(0, Ty::U64), named(1, "b", Ty::U64)]),
        "a=u64:0x0 b=u64:0x1",
    );
}

/// Supply collect args
#[test]
fn bind_collect_with_named() {
    assert_eq!(
        bound(
            &COLLECT,
            vec![
                anon(0, Ty::U64),
                named(1, "b", Ty::U64),
                anon(2, Ty::Bytes),
                anon(3, Ty::Bytes),
            ]
        ),
        "a=u64:0x0 b=u64:0x1 | u64:0x2 u64:0x3",
    );
}

/// Supply collect args, leaving off an optional arg
#[test]
fn bind_collect_with_defaults() {
    assert_eq!(
        bound(
            &COLLECT,
            vec![anon(0, Ty::U64), anon(1, Ty::Bytes), anon(2, Ty::Bytes)]
        ),
        "a=u64:0x0 b=u64:0x7b | u64:0x1 u64:0x2",
    );
}

/// Supply collect args of the wrong type
#[test]
fn bind_collect_bad_type() {
    let err = bind_err(
        &COLLECT,
        vec![
            anon(0, Ty::U64),
            named(1, "b", Ty::U64),
            anon(2, Ty::Bytes),
            anon(3, Ty::Sock4),
        ],
    );
    assert!(
        matches!(
            &err.kind,
            CollectArgType {
                func: "COLLECT",
                expected: ValType::Str,
                found: Found::Ty(Ty::Sock4)
            }
        ) && err.loc == Loc::new(2, 3),
        "{err:?}"
    );
}

/// A named argument after collect arguments
#[test]
fn bind_unexpected_named_arg() {
    let err = bind_err(
        &COLLECT,
        vec![anon(0, Ty::U64), anon(1, Ty::Bytes), named(2, "b", Ty::U64)],
    );
    assert!(
        matches!(&err.kind, UnexpectedNamedArg { func: "COLLECT", arg } if &**arg == "b")
            && err.loc == Loc::new(1, 2),
        "{err:?}"
    );
}

/// A named argument that isn't a parameter is reported as unknown, wherever it was written
#[test]
fn bind_unknown_arg_before_order() {
    let err = bind_err(
        &COLLECT,
        vec![
            anon(0, Ty::U64),
            anon(1, Ty::Bytes),
            named(2, "nope", Ty::U64),
        ],
    );
    assert!(
        matches!(&err.kind, UnknownArg { func: "COLLECT", arg } if &**arg == "nope")
            && err.loc == Loc::new(1, 2),
        "{err:?}"
    );
}

static EMPTY: FuncDef = func! {
    /// EMPTY
    resynth fn EMPTY(
        =>
        =>
        Str
    ) -> Void
    |_args| {
        Ok(Val::Nil)
    }
};

/// A function which takes no arguments
#[test]
fn bind_empty() {
    assert_eq!(bound(&EMPTY, vec![]), "");
}

/// A function which takes only collect arguments
#[test]
fn bind_empty_extra() {
    assert_eq!(
        bound(&EMPTY, vec![anon(0, Ty::Bytes), anon(1, Ty::Bytes)]),
        "| u64:0x0 u64:0x1",
    );
}

static NAMED: FuncDef = func! {
    /// NAMED
    resynth fn NAMED(
        =>
        /// Optional integer
        a: U64 = 123,
        /// Optional string
        b: Str = b"hello",
        /// Optional boolean
        c: Bool = true,
        =>
        Void
    ) -> Void
    |_args| {
        Ok(Val::Nil)
    }
};

/// Supply optional arguments in order
#[test]
fn bind_optional_anonymous() {
    assert_eq!(
        bound(&NAMED, vec![anon(0, Ty::U64), anon(1, Ty::Bytes)]),
        "a=u64:0x0 b=u64:0x1 c=true",
    );
}

/// Supply more arguments than parameters. The error points at the first one too many.
#[test]
fn bind_too_many_args() {
    let err = bind_err(
        &NAMED,
        vec![
            anon(0, Ty::U64),
            anon(1, Ty::Bytes),
            anon(2, Ty::Bool),
            anon(3, Ty::U64),
            anon(4, Ty::U64),
        ],
    );
    assert!(
        matches!(
            &err.kind,
            TooManyArgs {
                func: "NAMED",
                got: 5,
                want: 3
            }
        ) && err.loc == Loc::new(2, 3),
        "{err:?}"
    );
}

static OPTIONAL_COLLECT_STR: FuncDef = func! {
    /// OPTIONAL_COLLECT_STR
    resynth fn OPTIONAL_COLLECT_STR(
        =>
        /// Optional boolean
        a: Bool = true,
        /// Optional integer
        b: U64 = 123,
        /// Optional string
        c: Str = b"hello",
        =>
        Str
    ) -> Void
    |_args| {
        Ok(Val::Nil)
    }
};

/// With optional parameters and string collect arguments, optional arguments must be named, so
/// anonymous arguments are collected
#[test]
fn bind_optional_collect_str() {
    assert_eq!(
        bound(
            &OPTIONAL_COLLECT_STR,
            vec![anon(0, Ty::U64), anon(1, Ty::Bytes)]
        ),
        "a=true b=u64:0x7b c=\"hello\" | u64:0x0 u64:0x1",
    );
}

static OPTIONAL_COLLECT_U64: FuncDef = func! {
    /// OPTIONAL_COLLECT_U64
    resynth fn OPTIONAL_COLLECT_U64(
        =>
        /// Optional integer
        a: U64 = 123,
        /// Optional string
        b: Str = b"hello",
        /// Optional boolean
        c: Bool = true,
        =>
        U64
    ) -> Void
    |_args| {
        Ok(Val::Nil)
    }
};

/// As above, with integer collect arguments, so a string among them is the wrong type
#[test]
fn bind_optional_collect_u64() {
    let err = bind_err(
        &OPTIONAL_COLLECT_U64,
        vec![anon(0, Ty::U64), anon(1, Ty::Bytes)],
    );
    assert!(
        matches!(
            &err.kind,
            CollectArgType {
                func: "OPTIONAL_COLLECT_U64",
                expected: ValType::U64,
                found: Found::Ty(Ty::Bytes)
            }
        ) && err.loc == Loc::new(2, 1),
        "{err:?}"
    );
}

/// Check that each type fits its corresponding value type:
/// - all ints and bools freely exchangable
/// - anything that converts to bytes for bytes
/// - a packet for a packet sequence
#[test]
fn ty_fits() {
    let ints = [Ty::Bool, Ty::U8, Ty::U16, Ty::U64];
    for param in [
        ValType::Bool,
        ValType::U8,
        ValType::U16,
        ValType::U32,
        ValType::U64,
    ] {
        for ty in ints {
            assert!(ty.fits(param), "{ty} fits {param}");
        }
        for ty in [Ty::Bytes, Ty::Ip4, Ty::Pkt] {
            assert!(!ty.fits(param), "{ty} doesn't fit {param}");
        }
    }
    for ty in ints.into_iter().chain([Ty::Bytes, Ty::Pkt, Ty::Ip4]) {
        assert!(ty.fits(ValType::Str), "{ty} fits bytes");
    }
    for ty in [Ty::Sock4, Ty::PktGen, Ty::TimeJump, Ty::Void] {
        assert!(!ty.fits(ValType::Str), "{ty} doesn't fit bytes");
    }
    assert!(Ty::Pkt.fits(ValType::PktGen));
    assert!(!Ty::PktGen.fits(ValType::Pkt));
    assert!(!Ty::Void.fits(ValType::Void));
}
