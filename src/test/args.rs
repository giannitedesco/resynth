use crate::args::{ArgSpec, ArgVec};
use crate::err::Error;
use crate::libapi::FuncDef;
use crate::str::Buf;
use crate::val::{Val, ValDef};

const PLAIN: FuncDef = func! {
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

/// Just supply the positional arguments
#[test]
fn argvec_simple() {
    let args = vec![ArgSpec::from(1), ArgSpec::from(b"pos")];

    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(
                Val::U64(1),
                Val::str(b"pos"),
                Val::U64(123),
                Val::str(b"hello"),
                Val::Nil,
            ),
            vec!(),
        )),
        PLAIN.argvec(None, args)
    )
}

/// Supply a nullable argument
#[test]
fn argvec_nullable() {
    let args = vec![
        ArgSpec::from(1),
        ArgSpec::from(b"pos"),
        ArgSpec::from(("e", true)),
    ];

    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(
                Val::U64(1),
                Val::str(Buf::from(b"pos")),
                Val::U64(123),
                Val::str(b"hello"),
                Val::Bool(true),
            ),
            vec!(),
        )),
        PLAIN.argvec(None, args)
    )
}

/// Supply a type-mismatched positional argument
#[test]
fn argvec_type_mismatch_1() {
    let args = vec![ArgSpec::from(1), ArgSpec::from(true)];

    assert_eq!(
        Err(Error::ArgTypeMismatch {
            func: "PLAIN".into(),
            arg: "b".into()
        }),
        PLAIN.argvec(None, args)
    )
}

/// Supply a type-mismatched positional argument
#[test]
fn argvec_type_mismatch_2() {
    let args = vec![ArgSpec::from(1), ArgSpec::from(("b", ValDef::Bool(true)))];

    assert_eq!(
        Err(Error::ArgTypeMismatch {
            func: "PLAIN".into(),
            arg: "b".into()
        }),
        PLAIN.argvec(None, args)
    )
}

/// Supply a type-mismatched named argument
#[test]
fn argvec_type_mismatch_3() {
    let args = vec![
        ArgSpec::from(1),
        ArgSpec::from(b"hello"),
        ArgSpec::from(("c", ValDef::U64(3))),
        ArgSpec::from(("d", ValDef::Bool(true))),
    ];

    assert_eq!(
        Err(Error::ArgTypeMismatch {
            func: "PLAIN".into(),
            arg: "d".into()
        }),
        PLAIN.argvec(None, args)
    )
}

/// Positional arguments can optionally be named
#[test]
fn argvec_named_positionals() {
    let args = vec![
        ArgSpec::from(("a", ValDef::U64(0))),
        ArgSpec::from(("b", ValDef::Str(b"goodbye"))),
    ];
    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(
                Val::U64(0),
                Val::str(b"goodbye"),
                Val::U64(123),
                Val::str(b"hello"),
                Val::Nil,
            ),
            vec!()
        )),
        PLAIN.argvec(None, args),
    )
}

/// Supply too many positionals: ie. positionally supply a named argument
#[test]
fn argvec_too_many_positionals() {
    let args = vec![ArgSpec::from(1), ArgSpec::from(b"pos"), ArgSpec::from(2)];
    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(
                Val::U64(1),
                Val::str(b"pos"),
                Val::U64(2),
                Val::str(b"hello"),
                Val::Nil,
            ),
            vec!()
        )),
        PLAIN.argvec(None, args),
    )
}

/// Supply not enough arguments
#[test]
fn argvec_not_enough_args() {
    let args = vec![ArgSpec::from(1)];
    assert_eq!(
        Err(Error::TooFewArgs {
            func: "PLAIN".into(),
            got: 1,
            want: 2
        }),
        PLAIN.argvec(None, args),
    )
}

/// Specify a positional argument positionally, and also by name
#[test]
fn argvec_multiple_positional() {
    let args = vec![
        ArgSpec::from(1),
        ArgSpec::from(b"hello"),
        ArgSpec::from(("a", ValDef::U64(2))),
    ];
    assert_eq!(
        Err(Error::ArgMultiplySpecified {
            func: "PLAIN".into(),
            arg: "a".into()
        }),
        PLAIN.argvec(None, args),
    )
}

/// Specify an optional argument positionally, and also by name
#[test]
fn argvec_multiple_optional() {
    let args = vec![
        ArgSpec::from(1),
        ArgSpec::from(b"hello"),
        ArgSpec::from(111),
        ArgSpec::from(("c", ValDef::U64(222))),
    ];
    assert_eq!(
        Err(Error::ArgMultiplySpecified {
            func: "PLAIN".into(),
            arg: "c".into()
        }),
        PLAIN.argvec(None, args),
    )
}

/// Specify an optional argument by name, twice
#[test]
fn argvec_multiple_named_optional() {
    let args = vec![
        ArgSpec::from(1),
        ArgSpec::from(b"hello"),
        ArgSpec::from(("c", ValDef::U64(111))),
        ArgSpec::from(("c", ValDef::U64(222))),
    ];
    assert_eq!(
        Err(Error::ArgMultiplySpecified {
            func: "PLAIN".into(),
            arg: "c".into()
        }),
        PLAIN.argvec(None, args),
    )
}

const COLLECT: FuncDef = func! {
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
fn collect_none() {
    let args = vec![ArgSpec::from(1), ArgSpec::from(("b", ValDef::U64(234)))];
    assert_eq!(
        Ok(ArgVec::new(None, vec!(Val::U64(1), Val::U64(234),), vec!())),
        COLLECT.argvec(None, args),
    )
}

/// Supply collect args
#[test]
fn collect_with_named() {
    let args = vec![
        ArgSpec::from(1),
        ArgSpec::from(("b", ValDef::U64(234))),
        ArgSpec::from(b"hello"),
        ArgSpec::from(b"world"),
    ];
    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(Val::U64(1), Val::U64(234),),
            vec!(Val::str(b"hello"), Val::str(b"world"),),
        )),
        COLLECT.argvec(None, args),
    )
}

/// Supply collect args, leaving off an optional arg
#[test]
fn collect_with_defaults() {
    let args = vec![
        ArgSpec::from(1),
        ArgSpec::from(b"hello"),
        ArgSpec::from(b"world"),
    ];
    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(Val::U64(1), Val::U64(123),),
            vec!(Val::str(b"hello"), Val::str(b"world"),),
        )),
        COLLECT.argvec(None, args),
    )
}

/// Supply collect args of the wrong type
#[test]
fn collect_bad_type() {
    let args = vec![
        ArgSpec::from(1),
        ArgSpec::from(("b", ValDef::U64(234))),
        ArgSpec::from(b"hello"),
        ArgSpec::from(true),
    ];
    assert_eq!(
        Err(Error::CollectArgTypeMismatch {
            func: "COLLECT".into()
        }),
        COLLECT.argvec(None, args),
    )
}

const EMPTY: FuncDef = func! {
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

/// Test a func which takes no args
#[test]
fn argvec_empty() {
    let args = vec![];

    assert_eq!(
        Ok(ArgVec::new(None, vec!(), vec!(),)),
        EMPTY.argvec(None, args)
    )
}

/// Test a func which takes no args, that it has collect args
#[test]
fn argvec_empty_extra() {
    let args = vec![ArgSpec::from(b"hello"), ArgSpec::from(b"world")];

    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(),
            vec!(Val::str(b"hello"), Val::str(b"world"),),
        )),
        EMPTY.argvec(None, args)
    )
}

const NAMED: FuncDef = func! {
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

/// Supply named arguments in a positional manner
#[test]
fn argvec_optional_anonymous() {
    let args = vec![ArgSpec::from(1u64), ArgSpec::from(b"supplied")];

    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(Val::U64(1), Val::str(b"supplied"), Val::Bool(true),),
            vec!(),
        )),
        NAMED.argvec(None, args)
    )
}

const OPTIONAL_COLLECT_STR: FuncDef = func! {
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

/// This time, we have optional arguments and string collect-args. Now optional arguments MUST be
/// named, so the unnamed arguments are interpreted as strings for collect.
#[test]
fn argvec_optional_collect_str() {
    let args = vec![ArgSpec::from(1u64), ArgSpec::from(b"supplied")];

    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(Val::Bool(true), Val::U64(123), Val::str(b"hello"),),
            vec!(Val::U64(1), Val::str(b"supplied"),),
        )),
        OPTIONAL_COLLECT_STR.argvec(None, args)
    )
}

const OPTIONAL_COLLECT_U64: FuncDef = func! {
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

/// This time, we have optional arguments and int collect-args. Now optional arguments MUST be
/// named, so the unnamed arguments are interpreted as integers for collect. Pass in some arguments
/// of the wrong type to make sure that they throw an error
#[test]
fn argvec_optional_collect_u64() {
    let args = vec![ArgSpec::from(1u64), ArgSpec::from(b"supplied")];

    assert_eq!(
        Err(Error::CollectArgTypeMismatch {
            func: "OPTIONAL_COLLECT_U64".into()
        }),
        OPTIONAL_COLLECT_U64.argvec(None, args)
    )
}
