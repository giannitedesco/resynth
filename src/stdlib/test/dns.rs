use std::net::Ipv4Addr;

use pkt::dns::dns_hdr;
use pkt::ipv4::udp_hdr;

use crate::args::Args;
use crate::program::RuntimeErrorKind;
use crate::stdlib::dns::DNS_NAME;
use crate::val::{Val, ValDef};

use super::{Call, s};

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
    assert_eq!(Call::func("dns::name").extra(s("")).bytes(), b"\x00");
}

/// A dotted name and its labels as separate arguments are the same name
#[test]
fn test_name_labels_equal_dotted() {
    assert_eq!(
        Call::func("dns::name")
            .extra(s("www"))
            .extra(s("example"))
            .extra(s("com"))
            .bytes(),
        Call::func("dns::name").extra(s("www.example.com")).bytes(),
    );
}

/// With several arguments, each is one label, even with a dot in it
#[test]
fn test_name_labels_are_raw() {
    assert_eq!(
        Call::func("dns::name")
            .extra(s("www"))
            .extra(s("example.com"))
            .bytes(),
        b"\x03www\x0bexample.com\x00",
    );
}

/// An open name with one argument used to be one label, dots and all
#[test]
fn test_name_open_dotted() {
    assert_eq!(
        Call::func("dns::name")
            .named("complete", false)
            .extra(s("www.example"))
            .bytes(),
        b"\x03www\x07example",
    );
}

/// The response must copy RD from the query, but used to clear it
#[test]
fn test_host_response_flags() {
    let frames = Call::func("dns::host")
        .arg(Val::Ip4(Ipv4Addr::new(10, 0, 0, 1)))
        .arg(s("www.example.com"))
        .extra(Val::Ip4(Ipv4Addr::new(192, 0, 2, 1)))
        .frames();

    let flags: Vec<u16> = frames
        .iter()
        .map(|f| f.l4::<dns_hdr>(size_of::<udp_hdr>()).get_flags())
        .collect();

    assert_eq!(flags, [0x0100, 0x8180], "query RD, response QR RD RA");
}
