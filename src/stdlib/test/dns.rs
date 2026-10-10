use crate::args::Args;
use crate::program::RuntimeErrorKind;
use crate::stdlib::dns::DNS_NAME;
use crate::val::{Val, ValDef};

/// Construct a root name
#[test]
fn test_name_root() -> Result<(), RuntimeErrorKind> {
    let ret = (DNS_NAME.exec)(Args::new(None, vec![Val::from(true)], vec![]))?;

    let buf: &[u8] = ret.as_ref();

    assert_eq!(buf, b"\x00");

    Ok(())
}

/// Construct an empty name
#[test]
fn test_name_nothing() -> Result<(), RuntimeErrorKind> {
    let ret = (DNS_NAME.exec)(Args::new(None, vec![Val::from(false)], vec![]))?;

    let buf: &[u8] = ret.as_ref();

    assert_eq!(buf, b"");

    Ok(())
}

/// Parse a name
#[test]
fn test_name_parse() -> Result<(), RuntimeErrorKind> {
    let ret = (DNS_NAME.exec)(Args::new(
        None,
        vec![Val::from(true)],
        vec![Val::from(ValDef::Str(b"www.google.com"))],
    ))?;

    let buf: &[u8] = ret.as_ref();

    assert_eq!(buf, b"\x03www\x06google\x03com\x00");

    Ok(())
}

/// Construct a single label
#[test]
fn test_single_label() -> Result<(), RuntimeErrorKind> {
    let ret = (DNS_NAME.exec)(Args::new(
        None,
        vec![Val::from(false)],
        vec![Val::from(ValDef::Str(b"com"))],
    ))?;

    let buf: &[u8] = ret.as_ref();

    assert_eq!(buf, b"\x03com");

    Ok(())
}

/// One empty argument is the root, but used to encode as two root labels
#[test]
fn test_name_empty_string() {
    assert_eq!(super::bytes("import dns;\ndns::name(\"\");"), b"\x00");
}

/// A dotted name and its labels as separate arguments are the same name
#[test]
fn test_name_labels_equal_dotted() {
    assert_eq!(
        super::bytes("import dns;\ndns::name(\"www\", \"example\", \"com\");"),
        super::bytes("import dns;\ndns::name(\"www.example.com\");"),
    );
}

/// With several arguments, each is one label, even with a dot in it
#[test]
fn test_name_labels_are_raw() {
    assert_eq!(
        super::bytes("import dns;\ndns::name(\"www\", \"example.com\");"),
        b"\x03www\x0bexample.com\x00",
    );
}

/// An open name with one argument used to be one label, dots and all
#[test]
fn test_name_open_dotted() {
    assert_eq!(
        super::bytes("import dns;\ndns::name(complete: false, \"www.example\");"),
        b"\x03www\x07example",
    );
}
