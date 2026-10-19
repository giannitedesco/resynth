---
name: resynth-stdlib
description: >
  How to add functions, constants, and modules to the resynth standard library.
---

# Writing Resynth Stdlib Modules

You are adding new protocol helpers to the resynth standard library. The stdlib
is a tree of `Module`, `FuncDef`, and constant values written in Rust, compiled
into the `resynth` binary.

## Before You Write Anything

Run the stdlib JSON export to understand what already exists:

```sh
resynth --output-stdlib-json | python3 -m json.tool | grep -i <protocol>
```

Also read the relevant `docs/<module>/README.md` — these are generated from the
doc comments and show the current API at a glance.

## The Three-Crate Split

Resynth is a Rust workspace with three crates. Understanding which one to reach
into is the first decision when implementing a stdlib function.

```
pkt/    — raw protocol structs, headers, and constants (no flow logic)
ezpkt/  — stateful flow abstractions built on top of pkt
src/    — the language runtime and stdlib (src/stdlib/)
```

**`pkt/`** is where protocol wire formats live: header structs, bitfield
builders, constant tables (opcodes, type codes, flags). If you need to build a
DNS header, encode a NetBIOS name, or reference an ICMP type constant, it's in
`pkt`. Use it directly from stdlib:

```rust
use pkt::dns::{DnsFlags, DnsName, dns_hdr, rrtype};
use pkt::netbios::{name, ns};
```

**`ezpkt/`** is where stateful multi-packet flows live: `TcpFlow`, `UdpFlow`,
`IpFrag`, `GreFlow`, etc. These track sequence numbers, handle ACKs, manage
fragmentation IDs, and so on. If the function you're writing emits multiple
packets with shared state, the implementation belongs in `ezpkt` and the stdlib
just wraps it:

```rust
use ezpkt::{TcpFlow, UdpFlow, UdpDgram};
```

**`src/stdlib/`** is the glue. It exposes `pkt` and `ezpkt` types to the
resynth language via `func!`, `module!`, and `class!` macros. Encoding
utilities, length-prefix helpers, and anything that operates purely on `bytes`
values without packet-level state live here directly (e.g. `std.rs`).

### Decision guide

| What you're implementing | Where the logic goes |
|---|---|
| Protocol constants (opcodes, type codes) | `pkt/src/<proto>.rs` |
| Header struct / bitfield builder | `pkt/src/<proto>.rs` |
| Single-packet constructor | `pkt/src/<proto>.rs`, wrapped in stdlib |
| Stateful flow (TCP, UDP, fragmentation) | `ezpkt/src/<proto>.rs`, wrapped in stdlib |
| Pure bytes encoding / framing | `src/stdlib/<module>.rs` directly |

For pure protocol helpers that just assemble bytes from arguments (like
`netbios::ns::name_entry` or `std::len_be16`), writing the logic directly in
the stdlib closure is fine — no `pkt` or `ezpkt` changes needed.

**If the function does anything more complex than basic byte assembly — parses
input, applies protocol-specific encoding rules, tracks state, or has
non-trivial edge cases — the logic belongs in `pkt` or `ezpkt`, not inline in
the stdlib closure.** The stdlib closure should then be a thin wrapper. This
matters because `pkt` and `ezpkt` have unit tests; stdlib closures do not.

Unit tests for `pkt` live in `pkt/src/test/`:

```
pkt/src/
  lib.rs          # declares: #[cfg(test)] mod test;
  test/
    mod.rs        # declares submodules
    dns.rs        # dns tests
    netbios.rs    # netbios tests — e.g. test_nb_encode
```

Add a test module file and declare it in `test/mod.rs` when adding logic to
a new `pkt` module. Each test should verify a concrete encoding result:

```rust
// pkt/src/test/myproto.rs
use crate::myproto::encode_thing;

#[test]
fn test_encode_thing() {
    let result = encode_thing(b"input", 0x03).unwrap();
    assert_eq!(result.as_ref(), b"\x00\x03input\x00");
}
```

Run with `scripts/check.sh`

## File Layout

```
src/stdlib/
  mod.rs          # top-level registry — add new modules here
  std.rs          # std module
  dns.rs          # dns module
  netbios.rs      # netbios module
  ipv4/           # multi-file modules use a directory
    mod.rs
    tcp.rs
    udp.rs
  ...
```

Each file declares `static FuncDef` values, `Module` constants, and (for OOP
types) `static ClassDef` values. A `pub const MODULE: Module` (or similar
name) is the entry point imported in `mod.rs`.

`FuncDef` and `ClassDef` must be `static`, never `const`. They are compared
by pointer identity, and only a `static` has a stable address.

To add a new top-level module:

1. Create `src/stdlib/myproto.rs`
2. Add `mod myproto;` in `src/stdlib/mod.rs`
3. Add `myproto => Symbol::Module(&myproto::MODULE)` to the `STDLIB` module in
   `mod.rs`

## The `func!` Macro

Every stdlib function is declared with the `func!` macro:

```rust
static MY_FUNC: FuncDef = func!(
    /// Doc comment shown in `docs/` and `--output-stdlib-json`
    resynth fn my_func(
        // ── section 1: positional (required) args ──
        src: Ip4,
        dst: Ip4,
        =>
        // ── section 2: optional args with defaults ──
        /// TTL value
        ttl: U8 = 64,
        =>
        // ── section 3: collect-args type (Void = none) ──
        Str
    ) -> Str
    |mut args| {
        let src: Ipv4Addr = args.next().into();
        let dst: Ipv4Addr = args.next().into();
        let ttl: u8       = args.next().into();
        let payload: Buf  = args.join_extra(b"").into();
        // ...
        Ok(Val::str(result))
    }
);
```

### The Three Sections Are Always Required

The two `=>` separators are **mandatory** even if a section is empty.

| Function shape | Signature skeleton |
|---|---|
| Positional only | `(arg: T, => => Void)` |
| Optional only | `(=> opt: T = v, => Void)` |
| Collect only | `(=> => Str)` |
| All three | `(pos: T, => opt: T = v, => Str)` |

A common mistake: writing `(=> Str)` for a collect-only function. This
compiles but the macro parses `Str` as an optional arg, not the collect type.
Always write `(=> => Str)`.

### Argument Types

Use these DSL type names in the `func!` signature:

| DSL type | Rust type from `args.next().into()` |
|---|---|
| `U8` | `u8` |
| `U16` | `u16` |
| `U32` | `u32` |
| `U64` | `u64` |
| `Bool` | `bool` |
| `Ip4` | `Ipv4Addr` |
| `Sock4` | `SocketAddrV4` |
| `Str` | `Buf` (collect args: `args.join_extra(b"")`) |
| `Void` | — (collect section only; means no collect args) |

Read args in **declaration order** with `args.next().into()`. Read collect
args last with `args.join_extra(b"")`. In a method, call `args.take_this()`
first to get the object.

Optional arg defaults are `ValDef` expressions, the const counterpart of the
runtime `Val`.

### Return Values

| Return type | Rust expression |
|---|---|
| `Str` | `Ok(Val::str(vec_or_slice))` |
| `U8` | `Ok(Val::U8(n))` |
| `U16` | `Ok(Val::U16(n))` |
| `U32` | `Ok(Val::U32(n))` |
| `U64` | `Ok(Val::U64(n))` |
| `Pkt` | `Ok(Val::Pkt(packet))` |

Note: `Val::U16(n)` — variants are **uppercase**. There is no `Val::u16()`.

### Calling Conventions at the Call Site

When a function has collect args, all optional args **must be named** and must
appear **before** the collect args:

```resynth
# WRONG — suffix after collect arg
netbios::ns::name_entry("BILLG", suffix: 0x03)

# CORRECT — named optional before collect args
netbios::ns::name_entry(suffix: 0x03, "BILLG")
```

Document this in your function's doc comment if the ordering is non-obvious.

## The `module!` Macro

```rust
pub const MODULE: Module = module! {
    /// # Module doc heading
    ///
    /// Prose description. Shown in docs/mymodule/README.md.
    resynth mod mymodule {
        MY_FUNC   => Symbol::Func(&MY_FUNC_DEF),
        SUB       => Symbol::Module(&SUB_MODULE),
        CONST_U8  => Symbol::u8(42),
        CONST_U16 => Symbol::u16(0x0200),
        CONST_U32 => Symbol::u32(0xdeadbeef),
    }
};
```

### Symbol Constructors for Constants

| Rust value | Constructor |
|---|---|
| `u8` | `Symbol::u8(value)` |
| `u16` | `Symbol::u16(value)` |
| `u32` | `Symbol::u32(value)` |
| `u64` | `Symbol::u64(value)` |

**Do not** use `Symbol::Val(Val::U64(...))` — use the shorthand constructors.

## Naming

**Don't repeat the namespace in a symbol name.** The module path is already
context — adding it again is redundant and makes call sites verbose:

```resynth
http::http_status_code(200)   # redundant — "http" appears twice
http::status_code(200)        # correct

netbios::ns::nb_flags(...)    # redundant — already inside netbios::ns
netbios::ns::flags(...)       # correct
```

The same applies to submodules and constants:

```resynth
dns::dns_opcode::QUERY        # redundant
dns::opcode::QUERY            # correct
```

When naming a symbol, read the full qualified path aloud. If any word appears
twice, remove the redundant one.

## Constant Submodules (Enums)

For a set of named constants (opcodes, types, rcodes), declare a `const
Module` and nest it under the parent:

```rust
const OPCODE: Module = module! {
    /// # DNS Opcode constants
    resynth mod opcode {
        QUERY  => Symbol::u8(0),
        STATUS => Symbol::u8(2),
    }
};

pub const MODULE: Module = module! {
    /// # My protocol
    resynth mod myproto {
        opcode => Symbol::Module(&OPCODE),
        // ...
    }
};
```

## Bitfield Functions: Always Include `reserved:`

Resynth is designed to produce **malformed packets** as well as well-formed
ones — exercising how a DPI engine handles unexpected values in reserved fields
is a valid and important test case.

**Every bitfield function must include a `reserved:` optional parameter**,
even if the spec says the bits must be zero. Accept the appropriate unsigned
type (usually `U16`), default it to `0`, and OR it into the result without
masking:

```rust
static MY_FLAGS: FuncDef = func!(
    /// Build the FLAGS field.
    ///
    /// Flags layout (MSB first): A(1) B(2) reserved(13)
    ///
    /// Pass `reserved:` with a non-zero value to test DPI engine behaviour
    /// on unexpected reserved-bit patterns.
    resynth fn my_flags(
        =>
        /// Bit A
        a: Bool = false,
        /// Bits B (0–3)
        b: U8 = 0,
        /// Reserved bits; normally zero
        reserved: U16 = 0,
        =>
        Void
    ) -> U16
    |mut args| {
        let a: bool       = args.next().into();
        let b: u8         = args.next().into();
        let reserved: u16 = args.next().into();

        Ok(Val::U16(
            ((a as u16) << 15)
            | ((b as u16 & 0x3) << 13)
            | reserved
        ))
    }
);
```

## Doc Comments

Doc comments on `func!`, `module!`, and `class!` feed directly into the
generated `docs/` tree and the `--output-stdlib-json` output. Keep them
accurate and useful — they are the primary API reference for users and AI
agents.

Rules:
- One-line summary on the first `///` line
- Blank `///` line, then extended description
- Document each arg with `///` above its declaration in the `func!` body
- If a function has collect args and optional args, note the calling-order
  requirement explicitly
- For bitfield functions, include the bit-layout table in the doc comment

## Workflow

### After adding or changing stdlib symbols

```sh
# Format check, lints, tests, rustdoc, and regenerate docs/
scripts/check.sh

# docs/ is committed, so commit the regenerated files with the change
git add docs/
```

### Validate with test cases

Any new stdlib function that isn't completely trivial (i.e. more than a single
integer encoding) needs an example `.rsyn` file in `examples/` that exercises
it. The example is both documentation and a regression check.

**Write the example first using the new function**, then validate the pcap with
tshark to confirm the wire format is correct:

```sh
resynth -v examples/my-example.rsyn

# For well-known protocols on standard ports, deep-validate with tshark:
tshark -Vnr my-example.pcap
```

Confirm tshark decodes the protocol correctly — field names, values, and
structure should match what you intended. A build that succeeds is not
sufficient; only tshark output confirms the wire format is right.

**Revalidate with tshark after every change to an `.rsyn` file**, even when
only swapping a literal for a helper function or renaming a constant. The
wire format must stay identical.

If no well-known port exists for the protocol, or the test is intentionally
using a non-standard port, use `resynth -v` for a hex-dump sanity check and
verify the key bytes manually.

### Update doc examples in source

When you add a helper that improves on a previous pattern (e.g. a new
`nb_flags()` replacing `std::be16(0x0000)`), search the module's doc comments
for the old pattern and update them too:

```sh
grep -rn "std::be16(0x0000)" src/stdlib/
```
