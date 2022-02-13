use phf::phf_ordered_map;
use crate::err::Error;
use crate::args::{ArgVec, ArgSpec};
use crate::libapi::{FuncDef, ArgDecl};
use crate::val::{Val, ValDef, ValType};
use crate::str::Buf;

const PLAIN: FuncDef = func_def! {
        "PLAIN";
        ValType::Void;

        "a" => ValType::U64,
        "b" => ValType::Str,
        =>
        "c" => ValDef::U64(123),
        "d" => ValDef::Str(b"hello"),
        "e" => ValDef::Type(ValType::Bool),
        =>
        ValType::Void;

        |_args| {
            Ok(Val::Nil)
        }
};

/// Just supply the positional arguments
#[test]
fn argvec_simple() {
    let args = vec!(
        ArgSpec::from(1),
        ArgSpec::from(b"hello"),
    );

    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(
                Val::U64(1),
                Val::Str(Buf::from(Buf::from(b"hello"))),
                Val::U64(123),
                Val::Str(Buf::from(b"hello")),
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
    let args = vec!(
        ArgSpec::from(1),
        ArgSpec::from(b"hello"),
        ArgSpec::from(("e", true)),
    );

    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(
                Val::U64(1),
                Val::Str(Buf::from(Buf::from(b"hello"))),
                Val::U64(123),
                Val::Str(Buf::from(b"hello")),
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
    let args = vec!(
        ArgSpec::from(1),
        ArgSpec::from(true),
    );

    assert_eq!(
        Err(Error::TypeError),
        PLAIN.argvec(None, args)
    )
}

/// Supply a type-mismatched positional argument
#[test]
fn argvec_type_mismatch_2() {
    let args = vec!(
        ArgSpec::from(1),
        ArgSpec::from(("b", ValDef::Bool(true))),
    );

    assert_eq!(
        Err(Error::TypeError),
        PLAIN.argvec(None, args)
    )
}

/// Supply a type-mismatched named argument
#[test]
fn argvec_type_mismatch_3() {
    let args = vec!(
        ArgSpec::from(1),
        ArgSpec::from(b"hello"),
        ArgSpec::from(("c", ValDef::U64(3))),
        ArgSpec::from(("d", ValDef::Bool(true))),
    );

    assert_eq!(
        Err(Error::TypeError),
        PLAIN.argvec(None, args)
    )
}

/// Positional arguments can optionally be named
#[test]
fn argvec_named_positionals() {
    let args = vec!(
        ArgSpec::from(("a", ValDef::U64(0))),
        ArgSpec::from(("b", ValDef::Str(b"goodbye"))),
    );
    assert_eq!(
        Ok(ArgVec::new(None, vec!(
            Val::U64(0),
            Val::Str(Buf::from(b"goodbye")),
            Val::U64(123),
            Val::Str(Buf::from(b"hello")),
            Val::Nil,
        ), vec!())),
        PLAIN.argvec(None, args),
    )
}

/// Supply too many arguments
#[test]
fn argvec_too_many_positionals() {
    let args = vec!(
        ArgSpec::from(1),
        ArgSpec::from(b"hello"),
        ArgSpec::from(2),
    );
    assert_eq!(
        Err(Error::TypeError),
        PLAIN.argvec(None, args),
    )
}

/// Supply not enough arguments
#[test]
fn argvec_not_enough_args() {
    let args = vec!(
        ArgSpec::from(1),
    );
    assert_eq!(
        Err(Error::TypeError),
        PLAIN.argvec(None, args),
    )
}

/// Supply many named args, check that the last named arg is the one which is applied
#[test]
fn argvec_many_named_args() {
    let args = vec!(
        ArgSpec::from(1),
        ArgSpec::from(b"hello"),
        ArgSpec::from(("a", ValDef::U64(2))),
        ArgSpec::from(("a", ValDef::U64(3))),
        ArgSpec::from(("a", ValDef::U64(4))),
        ArgSpec::from(("a", ValDef::U64(5))),
    );
    assert_eq!(
        Ok(ArgVec::new(None, vec!(
            Val::U64(5),
            Val::Str(Buf::from(b"hello")),
            Val::U64(123),
            Val::Str(Buf::from(b"hello")),
            Val::Nil,
        ), vec!())),
        PLAIN.argvec(None, args),
    )
}

const COLLECT: FuncDef = func_def! {
        "COLLECT";
        ValType::Void;

        "a" => ValType::U64,
        =>
        "b" => ValDef::U64(123),
        =>
        ValType::Str;

        |_args| {
            Ok(Val::Nil)
        }
};

/// Empty set of collect args
#[test]
fn collect_none() {
    let args = vec!(
        ArgSpec::from(1),
        ArgSpec::from(("b", ValDef::U64(234))),
    );
    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(
                Val::U64(1),
                Val::U64(234),
            ),
            vec!()
        )),
        COLLECT.argvec(None, args),
    )
}

/// Supply collect args
#[test]
fn collect_with_named() {
    let args = vec!(
        ArgSpec::from(1),
        ArgSpec::from(("b", ValDef::U64(234))),
        ArgSpec::from(b"hello"),
        ArgSpec::from(b"world"),
    );
    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(
                Val::U64(1),
                Val::U64(234),
            ),
            vec!(
                Val::Str(Buf::from(b"hello")),
                Val::Str(Buf::from(b"world")),
            ),
        )),
        COLLECT.argvec(None, args),
    )
}

/// Supply collect args, leaving off an optional arg
#[test]
fn collect_with_defaults() {
    let args = vec!(
        ArgSpec::from(1),
        ArgSpec::from(b"hello"),
        ArgSpec::from(b"world"),
    );
    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(
                Val::U64(1),
                Val::U64(123),
            ),
            vec!(
                Val::Str(Buf::from(b"hello")),
                Val::Str(Buf::from(b"world")),
            ),
        )),
        COLLECT.argvec(None, args),
    )
}

/// Supply collect args of the wrong type
#[test]
fn collect_bad_type() {
    let args = vec!(
        ArgSpec::from(1),
        ArgSpec::from(("b", ValDef::U64(234))),
        ArgSpec::from(b"hello"),
        ArgSpec::from(true),
    );
    assert_eq!(
        Err(Error::TypeError),
        COLLECT.argvec(None, args),
    )
}

const EMPTY: FuncDef = func_def! {
        "COLLECT";
        ValType::Void;

        =>
        =>
        ValType::Str;

        |_args| {
            Ok(Val::Nil)
        }
};

/// Test a func which takes no args
#[test]
fn argvec_empty() {
    let args = vec!(
    );

    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(
            ),
            vec!(),
        )),
        EMPTY.argvec(None, args)
    )
}


/// Test a func which takes no args, that it has collect args
#[test]
fn argvec_empty_extra() {
    let args = vec!(
        ArgSpec::from(b"hello"),
        ArgSpec::from(b"world"),
    );

    assert_eq!(
        Ok(ArgVec::new(
            None,
            vec!(
            ),
            vec!(
                Val::Str(Buf::from(b"hello")),
                Val::Str(Buf::from(b"world")),
            ),
        )),
        EMPTY.argvec(None, args)
    )
}

