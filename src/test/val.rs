//! Type-coercion in resynth is facilitated by two separate pieces of code that must agree:
//!
//! - `Typed::compatible_with` (and `ValDef::arg_compatible`) decides whether `libapi` accepts an
//!   argument for a parameter type.
//! - `From<Val> for T` is what the stdlib function then calls on the accepted value.
//!
//! If the first accepts something the second doesn't handle, we hit an `unreachable!()` at run
//! time. Each test here runs every sample value against one parameter type, so that adding or
//! removing a coercion on one side, but not the other, fails here instead.

use std::fmt::Debug;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;

use pkt::Packet;

use crate::str::Buf;
use crate::val::{Typed, Val, ValDef, ValType};

fn pkt(bytes: &[u8]) -> Packet {
    let pkt = Packet::default();
    pkt.push_bytes(bytes);
    pkt
}

/// Every value each parameter type is checked against. Any value a test doesn't list as accepted
/// must be rejected.
fn samples() -> Vec<Val> {
    vec![
        Val::Nil,
        Val::Bool(false),
        Val::Bool(true),
        Val::U8(0),
        Val::U16(0xabcd),
        Val::U32(0x0102_0304),
        // Low bits are all zero: truncating gives 0, but as a bool it's still true. Silent
        // truncation is today's behaviour, not a decision.
        Val::U64(0x1_0000_0000),
        Val::Ip4(Ipv4Addr::new(1, 2, 3, 4)),
        Val::Sock4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80)),
        Val::str(b"ab"),
        Val::from(pkt(&[0xde, 0xad])),
        Val::from(vec![pkt(b"a"), pkt(b"b")]),
    ]
}

/// `accepted` says yes to exactly the values in `accepts`, and each one converts to `T`
fn check_with<T>(label: &str, accepted: impl Fn(&Val) -> bool, accepts: &[(Val, T)])
where
    T: From<Val> + PartialEq + Debug,
{
    for val in samples() {
        let want = accepts.iter().find(|(v, _)| *v == val).map(|(_, t)| t);
        let msg = format!("{label} <- {val:?}");

        assert_eq!(accepted(&val), want.is_some(), "{msg}");
        if let Some(want) = want {
            assert_eq!(T::from(val), *want, "{msg}");
        }
    }
}

/// A `param` parameter accepts exactly the values in `accepts`, and converts each one to `T`
fn check<T>(param: ValType, accepts: &[(Val, T)])
where
    T: From<Val> + PartialEq + Debug,
{
    check_with(&param.to_string(), |v| param.compatible_with(v), accepts)
}

/// A nullable `param` parameter, `name: Type = ValType::X`, accepts exactly the values in
/// `accepts`, and converts each one to `Option<T>`
fn check_nullable<T>(param: ValType, accepts: &[(Val, Option<T>)])
where
    Option<T>: From<Val> + PartialEq + Debug,
{
    check_with(
        &format!("Option<{param}>"),
        |v| ValDef::Type(param).arg_compatible(v),
        accepts,
    )
}

/// A nullable parameter accepts nil, plus exactly what the plain parameter accepts, and converts
/// it the same way
fn nullable<T>(plain: Vec<(Val, T)>) -> Vec<(Val, Option<T>)> {
    std::iter::once((Val::Nil, None))
        .chain(plain.into_iter().map(|(v, t)| (v, Some(t))))
        .collect()
}

fn u8_cases() -> Vec<(Val, u8)> {
    vec![
        (Val::Bool(false), 0),
        (Val::Bool(true), 1),
        (Val::U8(0), 0),
        (Val::U16(0xabcd), 0xcd),
        (Val::U32(0x0102_0304), 0x04),
        (Val::U64(0x1_0000_0000), 0),
    ]
}

fn u16_cases() -> Vec<(Val, u16)> {
    vec![
        (Val::Bool(false), 0),
        (Val::Bool(true), 1),
        (Val::U8(0), 0),
        (Val::U16(0xabcd), 0xabcd),
        (Val::U32(0x0102_0304), 0x0304),
        (Val::U64(0x1_0000_0000), 0),
    ]
}

fn u32_cases() -> Vec<(Val, u32)> {
    vec![
        (Val::Bool(false), 0),
        (Val::Bool(true), 1),
        (Val::U8(0), 0),
        (Val::U16(0xabcd), 0xabcd),
        (Val::U32(0x0102_0304), 0x0102_0304),
        (Val::U64(0x1_0000_0000), 0),
    ]
}

fn u64_cases() -> Vec<(Val, u64)> {
    vec![
        (Val::Bool(false), 0),
        (Val::Bool(true), 1),
        (Val::U8(0), 0),
        (Val::U16(0xabcd), 0xabcd),
        (Val::U32(0x0102_0304), 0x0102_0304),
        (Val::U64(0x1_0000_0000), 0x1_0000_0000),
    ]
}

fn ip4_cases() -> Vec<(Val, Ipv4Addr)> {
    vec![(
        Val::Ip4(Ipv4Addr::new(1, 2, 3, 4)),
        Ipv4Addr::new(1, 2, 3, 4),
    )]
}

fn bytes_cases() -> Vec<(Val, Buf)> {
    vec![
        (Val::Bool(false), Buf::from(&[0x00])),
        (Val::Bool(true), Buf::from(&[0x01])),
        (Val::U8(0), Buf::from(&[0x00])),
        (Val::U16(0xabcd), Buf::from(&[0xab, 0xcd])),
        (Val::U32(0x0102_0304), Buf::from(&[0x01, 0x02, 0x03, 0x04])),
        (
            Val::U64(0x1_0000_0000),
            Buf::from(&[0, 0, 0, 1, 0, 0, 0, 0]),
        ),
        (
            Val::Ip4(Ipv4Addr::new(1, 2, 3, 4)),
            Buf::from(&[1, 2, 3, 4]),
        ),
        (Val::str(b"ab"), Buf::from(b"ab")),
        (Val::from(pkt(&[0xde, 0xad])), Buf::from(&[0xde, 0xad])),
    ]
}

#[test]
fn to_bool() {
    check::<bool>(
        ValType::Bool,
        &[
            (Val::Bool(false), false),
            (Val::Bool(true), true),
            (Val::U8(0), false),
            (Val::U16(0xabcd), true),
            (Val::U32(0x0102_0304), true),
            (Val::U64(0x1_0000_0000), true),
        ],
    );
}

#[test]
fn to_u8() {
    check(ValType::U8, &u8_cases());
}

#[test]
fn to_u16() {
    check(ValType::U16, &u16_cases());
}

#[test]
fn to_u32() {
    check(ValType::U32, &u32_cases());
}

#[test]
fn to_u64() {
    check(ValType::U64, &u64_cases());
}

#[test]
fn to_ip4() {
    check(ValType::Ip4, &ip4_cases());
}

#[test]
fn to_sock4() {
    let sock = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80);
    check(ValType::Sock4, &[(Val::Sock4(sock), sock)]);
}

#[test]
fn to_bytes() {
    check(ValType::Str, &bytes_cases());
}

#[test]
fn to_pkt() {
    check::<Rc<Packet>>(
        ValType::Pkt,
        &[(Val::from(pkt(&[0xde, 0xad])), Rc::new(pkt(&[0xde, 0xad])))],
    );
}

#[test]
fn to_pktgen() {
    check::<Rc<Box<[Packet]>>>(
        ValType::PktGen,
        &[
            (
                Val::from(pkt(&[0xde, 0xad])),
                Rc::new(vec![pkt(&[0xde, 0xad])].into_boxed_slice()),
            ),
            (
                Val::from(vec![pkt(b"a"), pkt(b"b")]),
                Rc::new(vec![pkt(b"a"), pkt(b"b")].into_boxed_slice()),
            ),
        ],
    );
}

#[test]
fn to_u8_nullable() {
    check_nullable(ValType::U8, &nullable(u8_cases()));
}

#[test]
fn to_u16_nullable() {
    check_nullable(ValType::U16, &nullable(u16_cases()));
}

#[test]
fn to_u32_nullable() {
    check_nullable(ValType::U32, &nullable(u32_cases()));
}

#[test]
fn to_u64_nullable() {
    check_nullable(ValType::U64, &nullable(u64_cases()));
}

#[test]
fn to_ip4_nullable() {
    check_nullable(ValType::Ip4, &nullable(ip4_cases()));
}

#[test]
fn to_bytes_nullable() {
    check_nullable(ValType::Str, &nullable(bytes_cases()));
}
