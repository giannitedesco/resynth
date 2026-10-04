# Resynth Language Grammar

This document specifies the complete grammar of the resynth language in ABNF
notation, followed by the type system and semantic rules.

## ABNF Grammar

```abnf
program        = *( statement )

statement      = import-stmt
               / assign-stmt
               / expr-stmt

import-stmt    = "import" identifier ";"
assign-stmt    = "let" identifier "=" expr ";"
expr-stmt      = expr ";"

; "/" is the only binary operator; left-associative: a/b/c = (a/b)/c
; At runtime, Ip4 / integer → Sock4
expr           = expr "/" expr
               / call
               / object-ref
               / literal

call           = object-ref "(" arg-list ")"

; "::" components form the module path (determines which `import` is needed)
; "."  components form the object/method path (called on a runtime value)
; Once "." is used, "::" may not appear again in the same reference
object-ref     = identifier *( "::" identifier ) *( "." identifier )

arg-list       = [ arg *( "," arg ) ]
arg            = [ identifier ":" ] expr   ; named or anonymous

literal        = boolean-lit
               / sock4-lit                 ; ipv4 ":" port — resolved before ipv4-lit
               / ipv4-lit
               / hex-int-lit
               / decimal-int-lit
               / string-lit                ; adjacent string literals are concatenated

boolean-lit       = "true" / "false"
sock4-lit         = ipv4-lit ":" port         ; produces Sock4; port is decimal only
ipv4-lit          = d8 "." d8 "." d8 "." d8   ; produces Ip4 (native type)
hex-int-lit       = "0x" 1*HEXDIG             ; produces u64
decimal-int-lit   = 1*DIGIT                   ; produces u64
port              = 1*DIGIT                   ; decimal only, valid range 0–65535

; String literals may contain inline hex escapes.
; Adjacent string literals are concatenated by the lexer (no operator needed).
string-lit        = DQUOTE *( str-char / hex-escape ) DQUOTE
hex-escape        = "|" *( 2HEXDIG [ SP ] ) "|"   ; e.g. |de ad be ef|

; Comments: "#" or "//" to end of line; "#!" shebang on line 1 is also a comment
comment           = ( "#!" / "#" / "//" ) *VCHAR
```

## Literals

| Form | Example | Type | Notes |
|------|---------|------|-------|
| Boolean | `true`, `false` | `bool` | |
| Decimal integer | `42`, `-1` | `u64` | |
| Hex integer | `0xdeadbeef` | `u64` | |
| IPv4 address | `1.2.3.4` | `Ip4` | Native type |
| Socket address (colon) | `1.2.3.4:80` | `Sock4` | Literal form; port decimal only |
| Socket address (slash) | `1.2.3.4/80` | `Sock4` | Operator form; works with variables |
| String | `"hello"` | `bytes` | Inline hex escapes: `"|de ad|"` |
| Inline hex | `"|de ad be ef|"` | `bytes` | Embedded in string literal |

Adjacent string literals are concatenated by the lexer:
```resynth
"foo" "bar"       # same as "foobar"
"hello " "world"  # same as "hello world"
```

## The `/` Operator

`/` is the **only binary operator**. It is left-associative and combines an
`Ip4` value with a port integer to produce a `Sock4`:

```resynth
1.2.3.4 / 80        # Sock4 literal form

let ip = 1.2.3.4;
ip / 8080           # variable on the left
ip / port           # both sides can be variables
```

The colon form (`1.2.3.4:80`) is a lexer-level literal that only accepts a
plain decimal port; it cannot be used with variables. The slash form is more
flexible.

## Type System

| Type | Description | Coerces to bytes as |
|------|-------------|---------------------|
| `bool` | Boolean | 1 byte (`0x00` / `0x01`) |
| `u8` | 8-bit unsigned integer | 1 byte |
| `u16` | 16-bit unsigned integer | 2 bytes, big-endian |
| `u32` | 32-bit unsigned integer | 4 bytes, big-endian |
| `u64` | 64-bit unsigned integer | 8 bytes, big-endian |
| `Ip4` | IPv4 address | 4 bytes, big-endian (network order) |
| `Sock4` | IPv4 socket address | not directly coercible to bytes |
| `bytes` | Byte string | as-is |
| `Pkt` | A single packet | raw bytes |
| `PktGen` | A sequence of packets | concatenation of frame bytes |
| `TimeJump` | A timestamp offset | N/A |

### Integer compatibility

All integer types (`u8`, `u16`, `u32`, `u64`, `bool`) are mutually compatible
and will be implicitly narrowed or widened as required by the function
parameter type. `bytes` accepts any string-coercible value. `PktGen` accepts
`Pkt`.

### Coercion to bytes

> [!IMPORTANT]
> When an integer is used where `bytes` is expected (e.g. as a collect-arg),
> it is encoded **big-endian at its full width**. Since all integer literals
> are `u64`, a bare literal like `42` becomes 8 big-endian bytes
> (`|00 00 00 00 00 00 00 2a|`). This is almost never what you want.
>
> Always use `std::u8()`, `std::be16()`, `std::be32()`, `std::le32()` etc. to
> specify both width and endianness explicitly.

## Object References

An object reference navigates the module/symbol tree using two separators:

- `::` — navigates the **module** hierarchy (compile-time; determines the `import`)
- `.` — navigates the **object** hierarchy (runtime; calls a method on a value)

Once `.` is used, `::` may not appear again in the same reference.

```resynth
import ipv4;

ipv4::tcp::flow(...)       # module path only; calls a module-level function
flow.client_message(...)   # object path only; calls a method on a runtime value
```

## Function Calling Conventions

Functions have three kinds of parameters:

1. **Positional** — required, must be supplied first
2. **Optional** — have default values, come after positionals
3. **Collect** — variadic; zero or more extra values of a specified type,
   concatenated together (for `bytes` collect-type, all extra args are joined
   into a single byte string)

### Rules

| Rule | Description |
|------|-------------|
| **P-FIRST** | Positional args must be supplied before optional args |
| **P-NAME-OPTIONAL** | Positional args may be named or anonymous |
| **ANON-FIRST** | Once any arg is named, all subsequent positional and optional args must also be named |
| **COLLECT-NAME-OPTS** | If the function has collect args, all optional args **must** be named |
| **NOCOLLECT-ANON-OPTS** | If the function has no collect args, optional args may be anonymous |
| **COLLECT-AFTER-NAMED** | Collect args must come after the last named arg |

### Examples

```resynth
# All positional, all anonymous
let flow = ipv4::tcp::flow(10.0.0.1/1234, 10.0.0.2/80);

# Named positional args (all subsequent must also be named)
ipv4::udp::broadcast(src: 0.0.0.0/67, dst: 255.255.255.255/68, srcip: 0.0.0.0,
    payload_bytes);

# Named optional arg before collect args (required when collect args present)
flow.client_message(
    send_ack: false,     # named optional, collect args follow
    "GET / HTTP/1.1|0d 0a|"
    "Host: example.com|0d 0a|",
);

# Optional arg anonymous (no collect args, so this is allowed)
ipv4::tcp::flow(10.0.0.1/1234, 10.0.0.2/80, 1234);  # 1234 is the optional cl_seq arg
```

### Collect args and `bytes` concatenation

A commonly followed idiom in the language is that if a function accepts
arbitrary payload data, it will have a collect argument of type `bytes`.
The function will join all the collect args into a single byte string. This
means you can pass payload components as comma-separated arguments rather than
wrapping them in `text::concat()`:

```resynth
# These are equivalent:
flow.client_message(std::be16(0x0001), std::be16(42), "data");
flow.client_message(text::concat(std::be16(0x0001), std::be16(42), "data"));
```

## Statements and Evaluation

- **`import`** — brings a top-level module into scope. Module path of any
  referenced symbol determines which import is needed (e.g.
  `ipv4::tcp::flow` requires `import ipv4`).
- **`let`** — binds the result of an expression to a name. Defers packet
  emission if the expression produces `Pkt` or `PktGen`.
- **Expression statement** — evaluates the expression. If the result is `Pkt`
  or `PktGen`, the packets are emitted to the pcap output immediately.
  If the result is `TimeJump`, it advances the timestamp clock.

```resynth
import ipv4;

# Deferred: packets not emitted yet
let greeting = flow.client_message("GET / HTTP/1.1|0d 0a 0d 0a|");
let reply    = flow.server_message("HTTP/1.1 200 OK|0d 0a 0d 0a|");

# Emit in reverse order, as if the packets have been reordered in transit
reply;
greeting;
```
