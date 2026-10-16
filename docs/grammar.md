# The Resynth Language

This document defines the resynth language as it is implemented: its lexical
structure, its syntax, the static rules a program must satisfy before it runs,
and what a program does when it runs.

The language is young and will change. Sections marked _informative_ describe
how the current implementation behaves, such as the wording of its messages,
without making that behaviour part of the language.

1. [Notation](#1-notation)
2. [Source text](#2-source-text)
3. [Lexical structure](#3-lexical-structure)
4. [Syntax](#4-syntax)
5. [Names and scope](#5-names-and-scope)
6. [Types](#6-types)
7. [Typing expressions](#7-typing-expressions)
8. [Integers and narrowing](#8-integers-and-narrowing)
9. [Calls](#9-calls)
10. [Statements](#10-statements)
11. [Evaluation](#11-evaluation)
12. [Diagnostics (informative)](#12-diagnostics-informative)
13. [Standard library conventions (informative)](#13-standard-library-conventions-informative)

## 1. Notation

Grammars are written in ABNF ([RFC 5234]), with the case-sensitive string
syntax of [RFC 7405]: `%s"let"` matches `let` only, while a plain `"a"`
matches `a` or `A`. The core rules `ALPHA`, `DIGIT`, `HEXDIG`, `SP`, `HTAB`,
`CR`, `LF` and `DQUOTE` are those of RFC 5234. `HEXDIG` matches either case.

There are two grammars:

- The **lexical grammar** (§3) is over characters. It splits the source into
  tokens.
- The **syntactic grammar** (§4) is over tokens. In it, a quoted string such
  as `";"` or `%s"let"` stands for the token with that spelling, and rule
  names in capitals, such as `IDENT`, stand for a class of tokens.

A rule that ABNF can't express is stated in prose next to the grammar.

[RFC 5234]: https://www.rfc-editor.org/rfc/rfc5234
[RFC 7405]: https://www.rfc-editor.org/rfc/rfc7405

## 2. Source text

A program is a sequence of Unicode characters, encoded as UTF-8, divided into
lines by `LF`. A `CR` before the `LF` is accepted, and is otherwise
whitespace. Source that is not valid UTF-8 is an error.

A location in the source is a line and a column, both counted from 1. The
column counts **bytes** of UTF-8, not characters.

A whole program, given as a file or on standard input, is lexed, parsed and
checked before any of it runs. An error
in any of those phases means no statement runs. Warnings don't stop a program
from running.

## 3. Lexical structure

### 3.1 Tokens and trivia

The source is read left to right, one line at a time. At each position, the
longest lexeme that can start there is taken. A lexeme is either _trivia_
(whitespace or a comment), which is dropped, or a token.

```abnf
line          = *( trivia / token )

trivia        = 1*white / comment
white         = <any character with the Unicode White_Space property, except LF>
comment       = ( "#" / "//" ) *comment-char
comment-char  = <any character except LF>

token         = punct / word / number / string
punct         = "::" / ":" / "(" / ")" / "." / ";" / "=" / "," / "/"
```

A comment runs to the end of its line. There are no block comments. A `#!`
line at the start of a file is an ordinary `#` comment.

Because `//` always starts a comment, `ip //80` is `ip` followed by a
comment, not a division. Write `ip / 80`.

No lexeme spans two lines, so neither does any token except a joined string
(§3.4). Trivia may appear between any two tokens, so
`std :: be16 ( 1 )` and `1.2.3.4 : 80` are both valid.

A character that can't start any lexeme is an error.

### 3.2 Words: identifiers, keywords and booleans

```abnf
word          = word-start *word-char
word-start    = ALPHA / "_"
word-char     = ALPHA / DIGIT / "_"
```

Words are ASCII only. These words are reserved, and are never identifiers:

| Word | Token |
|------|-------|
| `import` | the keyword `import` |
| `let` | the keyword `let` |
| `true`, `false` | `BOOL`, a boolean literal |

Every other word is an `IDENT`. Identifiers are case-sensitive.

### 3.3 Numbers: integers and IPv4 addresses

A number starts with a digit. Its lexeme is chosen like this:

1. If the source matches `1*DIGIT "." 1*DIGIT "." 1*DIGIT "." 1*DIGIT` here,
   that is a dotted quad. Otherwise, the lexeme is a single digit.
2. In either case, the lexeme then extends over every `word-char` that
   directly follows it.

So `123abc`, `1_000` and `1.2.3.4a` are each one lexeme, and an error, rather
than a number followed by an identifier. `1.2.3` is not a dotted quad, so it
is `1`, `.`, `2`, `.`, `3`. The lexeme must then match one of these rules:

```abnf
number        = ip4-lit / hex-lit / dec-lit             ; the lexeme chosen above

ip4-lit       = octet "." octet "." octet "." octet      ; token IP4
octet         = "0" / %x31-39 *2DIGIT                     ; 0 to 255

hex-lit       = %s"0x" 1*HEXDIG                           ; token HEX
dec-lit       = "0" / %x31-39 *DIGIT                      ; token DEC
```

- An `octet` is at most 255, with no leading zeros: `01.2.3.4` is an error.
- The `x` of `0x` is lower case: `0XFF` is an error. Hex digits may be either
  case.
- A decimal literal has no leading zeros: `0123` is an error.
- An integer literal's value must be at most 2<sup>127</sup> − 1. A larger
  one is an error.
- There are no negative literals, no digit separators, and no suffixes.

`HEX` and `DEC` tokens carry their value as an _untyped integer_ (§8).

### 3.4 Strings

```abnf
string        = DQUOTE *str-char DQUOTE
str-char      = <any character except DQUOTE and LF>
```

A string literal ends at the next `"` on the same line. If there is none, it
is an error. There are no backslash escapes.

The text between the quotes, the _body_, is decoded into bytes. A body that
doesn't match `body` is an error.

```abnf
body          = *( text-char / hex-seq )
text-char     = %x20-21 / %x23-7B / %x7D-7E   ; printable ASCII, not " or |
hex-seq       = "|" *hex-sep *hex-byte "|"
hex-byte      = HEXDIG *hex-sep HEXDIG *hex-sep
hex-sep       = SP / ":" / "." / "_" / "-" / "'" / "`"
```

- A `text-char` is the byte of its ASCII code.
- A `hex-seq` is one byte per `hex-byte`, the first digit being the high
  nibble. Separators are ignored, even between the two digits of a byte, so
  `"|d e|"` is the single byte `0xde`. `"||"` is no bytes.
- Every other byte, including `"` and `|`, must be written in hex: `"|22|"`,
  `"|7c|"`. So must any character outside printable ASCII, such as a tab or
  `é` (`"|c3 a9|"`).
- A hex sequence must close in the literal it opened in.

**Joining.** A maximal run of string literals separated only by trivia, on
one line or several, is one `STRING` token. Its value is the concatenation of
each literal's decoded bytes, and its location is that of the first literal.
Each literal is decoded on its own, so a hex sequence can't continue into the
next literal.

```resynth
let a = "foo" "bar";        # one token, the bytes of "foobar"
let b = "GET / HTTP/1.1|0d 0a|"
  # a comment between literals doesn't stop them joining
  "Host: example.com|0d 0a|";
```

### 3.5 End of input

The token stream ends with an `EOF` token, located at column 1 of the line
after the last.

## 4. Syntax

### 4.1 Grammar

```abnf
program       = *stmt EOF

stmt          = import-stmt / let-stmt / expr-stmt
import-stmt   = %s"import" IDENT ";"
let-stmt      = %s"let" IDENT "=" expr ";"
expr-stmt     = expr ";"

expr          = postfix *( "/" postfix )
postfix       = primary *( "." IDENT / "(" [ args ] ")" )

args          = arg *( "," arg ) [ "," ]
arg           = [ IDENT ":" ] expr

primary       = BOOL / DEC / HEX / STRING
              / sock4-lit / IP4
              / module-path
              / IDENT

sock4-lit     = IP4 ":" DEC
module-path   = IDENT 1*( "::" IDENT )
```

### 4.2 Disambiguation and constraints

- **Socket address literals.** An `IP4` followed by `:` is always the start
  of a `sock4-lit`. Its `DEC` must be at most 65535, or it is an error. The
  port can't be hex, and can't be an expression: for that, use `/` (§7.6).
- **Named arguments.** An argument is named only when it starts with an
  `IDENT` token followed by the token `:`, so `f(x : 1)` is named too.
  `f(x.y: 1)` and `f(a / b: 1)` are errors.
- **Module paths.** An `IDENT` followed by `::` starts a module path, which
  has at least two segments. A module path can only start a `postfix`, so
  `a::b.c` is valid but `a.b::c` is not.
- There are no grouping parentheses: `(1)` is an error. There is no empty
  statement: `;` alone is an error.
- A call's arguments may end with a comma, but `f(,)` is an error.

### 4.3 Precedence

| Operator | Kind | Associativity | Binds |
|----------|------|---------------|-------|
| `.` _name_, `(` _args_ `)` | postfix | left to right | tightest |
| `/` | binary infix | left | loosest |

So `a.b(1).c(2)` is `((a.b)(1)).c`, called with `2`, and `a / b.c()` is
`a / (b.c())`. `a / b / c` is `(a / b) / c`, which parses but never type
checks (§7.6).

### 4.4 Abstract syntax

The parser produces these forms, which the rest of this document refers to:

| Form | From |
|------|------|
| `import m` | `import-stmt` |
| `let x = e` | `let-stmt` |
| `e;` | `expr-stmt` |
| literal | `BOOL`, `DEC`, `HEX`, `STRING`, `IP4`, `sock4-lit` |
| local `x` | a lone `IDENT` |
| path `m::s₁::…::sₙ::x` | `module-path`, with module `m`, inner segments `sᵢ` and item `x` |
| member `e.x` | `"." IDENT` |
| call `e(a₁, …, aₙ)` | `"(" [ args ] ")"`, each `aᵢ` anonymous or named |
| `e₁ / e₂` | `"/"` |

The parser stops at the first error.

## 5. Names and scope

There are three separate namespaces. A name in one never hides a name in
another.

| Namespace | Holds | Bound by | Looked up by |
|-----------|-------|----------|--------------|
| modules | top-level modules | `import` | the first segment of a path |
| locals | values | `let` | a lone `IDENT` |
| members | an object's methods and properties | its class | `e.x` |

So `import dns; let dns = 1.2.3.4;` is valid: `dns::name("x")` names the
module and `dns / 80` the local.

**Imports.** `import m;` makes the top-level module `m` available to paths.
`m` must be a top-level module of the standard library. An import takes
effect from the statement after it, so a path used before its module's import
is an error. Importing a module twice gives a warning, and the second import
does nothing.

**Paths.** In `m::s₁::…::sₙ::x`, `m` must be imported, each `sᵢ` must be a
submodule of the one before it, and `x` must be a constant or a function in
the last module. A path naming a module or a class is an error, because
neither is a value.

**Locals.** `let x = e;` binds `x` from the end of that statement to the end
of the program. So `let x = x;` is always an error, since `x` is not yet bound
on its right. Binding a name that is already bound is an error: there is no
shadowing.

**Members.** In `e.x`, `x` is looked up in the class of `e`'s value (§7.4).

The program is the body of one implicit procedure. Its locals are not
globals.

## 6. Types

Every expression has a type, worked out before the program runs.

| Type | Values | As bytes (§8.4) |
|------|--------|-----------------|
| `void` | none: the result of a call to a function that returns nothing | not allowed |
| `bool` | `true`, `false` | 1 byte, `00` or `01` |
| `u8`, `u16`, `u32`, `u64` | unsigned integers of 8, 16, 32 and 64 bits | 1, 2, 4 or 8 bytes, big-endian |
| `Ip4` | an IPv4 address | 4 bytes, network order |
| `Sock4` | an IPv4 address and a 16-bit port | not allowed |
| `bytes` | a byte string | itself |
| `Pkt` | one packet | the packet's bytes |
| `PktGen` | a sequence of packets | not allowed |
| `TimeJump` | an amount of time, in nanoseconds | not allowed |
| a class, such as `TcpFlow` | an object of that class | not allowed |
| `function f` | the function `f` | not allowed |
| `method C.f` | the method `f` of class `C`, bound to an object | not allowed |

There is also the **untyped integer**, the type of an integer literal. It is
not a type that any value has when the program runs: every use of an untyped
integer gives it a type first (§8).

The **integral** types are `bool`, `u8`, `u16`, `u32` and `u64`, of widths 1,
8, 16, 32 and 64 bits. `true` is 1 and `false` is 0.

Each function and each method has its own type, so `let f = std::be16;` gives
`f` the type `function be16`, and calling `f` binds its arguments against
`be16`'s parameters.

### 6.1 Constant values

Some expressions have a **constant value**, known before the program runs.
Evaluating one may still have effects: in `f().p`, `f` is still called.

- Every literal has a constant value.
- A path names a constant value: a module constant, or a function.
- A local bound to a constant value, or to an untyped integer, has that
  value.
- A property `e.p` has a constant value, the class's constant, whatever `e`
  is.
- `e₁ / e₂` has a constant value when both operands do.

Calls and methods don't. A local bound to any other value doesn't either.

Whether a value is constant only changes which warnings narrowing gives
(§8.2). It never changes what a program does when it runs.

## 7. Typing expressions

A rule's conditions are checked in the order given, and the first that fails
is the error. **Value position** means anywhere other than the whole
expression of an expression statement. A `void` expression in value position
is an error.

### 7.1 Literals

| Literal | Type |
|---------|------|
| `BOOL` | `bool` |
| `DEC`, `HEX` | untyped integer |
| `IP4` | `Ip4` |
| `sock4-lit` | `Sock4` |
| `STRING` | `bytes` |

### 7.2 Locals

A local `x` must be bound (§5). Its type is the type of the value it was
bound to. A local bound to an untyped integer is untyped too, and is narrowed
afresh at each use (§8).

### 7.3 Paths

A path to a constant has the constant's type. A path to a function `f` has
type `function f`.

### 7.4 Members

For `e.x`:

1. `e`, in value position, must have a class type `C`.
2. `C` must have a member `x`.
3. If `x` is a method, `e.x` has type `method C.x`. If `x` is a property, it
   has the property's type.

A member that names a module or class is an error.

### 7.5 Calls

For `e(a₁, …, aₙ)`:

1. `e`, in value position, must have type `function f` or `method C.f`.
2. Each argument's expression is typed, in value position, in source order.
3. The arguments are bound to `f`'s parameters (§9).
4. The call's type is `f`'s declared return type, which may be `void`.

### 7.6 Socket addresses: `/`

For `e₁ / e₂`:

1. `e₁`, in value position, must have type `Ip4` exactly.
2. `e₂`, in value position, must be integral or an untyped integer. It is
   narrowed to `u16` (§8.2).
3. `e₁ / e₂` has type `Sock4`.

Since `e₁ / e₂` is a `Sock4`, `a / b / c` is always an error. There are no
other operators.

```resynth
let server = 10.0.0.2;
let port = 8080;
let a = server / port;      # Sock4, 10.0.0.2:8080
let b = 10.0.0.2:8080;      # the same, as a literal
```

## 8. Integers and narrowing

### 8.1 Untyped integers

An integer literal is an untyped integer `n`, with 0 ≤ n < 2<sup>127</sup>.
It has no width until the place it is used gives it one. There are four
kinds of place:

| Where | What it becomes |
|-------|-----------------|
| an integer parameter, or the right of `/` | that type, by narrowing (§8.2) |
| a `bool` parameter | `n ≠ 0` |
| a `bytes` parameter or collect argument, or an expression statement | the **narrowest** of `u8`, `u16`, `u32`, `u64` that holds `n` |
| any other parameter | an error |

If no type holds `n` in the third case, because n ≥ 2<sup>64</sup>, it is an
error. So `5;` is a `u8` and `300;` a `u16`, and each is a discarded value
(§10). `text::concat("a", 300)` is the three bytes `61 01 2c`.

`let x = n;` doesn't give `n` a type. Each use of `x` is narrowed as if `n`
were written there, so after `let p = 80;`, both `std::u8(p)` and
`1.2.3.4 / p` are fine.

### 8.2 Narrowing to an integer type

Narrowing a value `v` to one of the integer types `τ`, of width `w`, keeps
its low `w` bits:

- If `v` has a constant value `n` (an untyped integer, or a constant of an
  integral type), it becomes the constant `n mod 2ʷ` of type `τ`. If `n` is
  not less than 2ʷ, this gives the warning **truncated**.
- Otherwise, if `v` has an integral type `σ`, it is converted when the
  program runs (§11.4). If `σ` is wider than `τ`, this gives the warning
  **may be truncated**, since the value might not fit.
- Otherwise, it is an error.

```resynth
import std;
import text;
let a = std::u8(300);               # warning: truncated; passes 0x2c
let b = 1.2.3.4 / 65536;            # warning: truncated; the port is 0
let c = 1.2.3.4 / text::len("ab");  # warning: may be truncated (a u64 port)
```

The `let`s are there so that these give no other warnings: as expression
statements, each would also be a discarded value (§10).

### 8.3 Parameter compatibility

A value of type `σ` may be passed for a parameter of type `π` when:

| Parameter `π` | Accepts `σ` |
|---------------|-------------|
| `bool`, `u8`, `u16`, `u32`, `u64` | any integral type |
| `bytes` | any integral type, `bytes`, `Pkt`, `Ip4` |
| `PktGen` | `PktGen`, `Pkt` |
| `Ip4`, `Sock4`, `Pkt`, `TimeJump` | that type only |
| a class `C` | `C` only |
| a function | any function type |
| a method | any method type |

An untyped integer follows §8.1. An argument for an integer parameter is
narrowed (§8.2). An argument for a `bool` or `bytes` parameter that is
already typed is passed as it is, and converted when the function is called
(§11.4).

### 8.4 Integers as bytes

An integral value passed as bytes is written big-endian, at the width of its
type. An untyped integer has the narrowest width that holds it, but a typed
one keeps its full width, so a `u64` such as the result of `text::len(..)` is
8 bytes. To get a given width and byte order, use a standard library function
such as `std::u8()`, `std::be16()` or `std::le32()`.

Narrowing only warns about the parameter's declared type (§8.2), and the
parameter of `std::be16()`, `std::be32()`, `std::le16()` and `std::le32()` is
a `u64`. Each of those functions keeps the low bits of its argument itself,
when it runs, so a value too wide for the field loses its high bits without a
warning. `std::u8()` declares a `u8` parameter, so it does warn.

## 9. Calls

### 9.1 Parameters

A function `f` declares a list of parameters `p₀ … pₖ₋₁`, each with a name
and a type, and possibly a **collect type** `c`.

- The first `m` parameters are **positional**, and must be given.
- The rest are **optional**. Each has a default value, or is **nullable**: a
  nullable parameter that isn't given receives "no value", which no source
  syntax can write.
- If `f` has a collect type, it takes any number of further **collect
  arguments** of that type, after its parameters. For `bytes`, the function
  usually joins them (§13).

### 9.2 Binding

The arguments `a₁ … aₙ` of a call are bound to `f`'s parameters like this.

First, every named argument must name a parameter of `f`.

Then each argument is taken in source order, by a binder in one of three
modes, starting in _positional_ mode:

- **Positional mode.** For an anonymous argument:
  - If `f` has a collect type and `m` arguments have been bound, switch to
    _collect_ mode.
  - Otherwise, if all `k` parameters have been bound, it is an error: too
    many arguments.
  - Otherwise, bind the argument to the next parameter in order.

  A named argument switches to _named_ mode.
- **Named mode.** A named argument binds to the parameter it names. If that
  parameter is already bound, it is an error. An anonymous argument switches
  to _collect_ mode.
- **Collect mode.** If `f` has no collect type, it is an error. A named
  argument is an error. An anonymous argument is a collect argument.

Switching modes takes the same argument again in the new mode.

As soon as an argument is bound, it is converted to its parameter's type, or
a collect argument to the collect type, as §8 describes. If that fails, it is
the error, and no later argument is bound. So `std::u8("x", 1)` is an error
because `"x"` is not an integer, not because there are too many arguments.

After the last argument:

1. If no argument was named and fewer than `m` were bound, it is an error:
   not enough arguments.
2. Each positional parameter not bound is an error: argument not given.
3. Each optional parameter not bound takes its default, or no value.

### 9.3 Consequences

The binding rules mean that:

- Positional parameters may be given in order or by name.
- Once one argument is named, every later argument that fills a parameter
  must be named too.
- If `f` takes collect arguments, its optional parameters can only be given
  by name, and its collect arguments come after the last named argument. An
  anonymous argument after the positionals is a collect argument, even if it
  looks like an optional parameter's value.
- If `f` doesn't take collect arguments, its optional parameters may also be
  given in order.

```resynth
import ipv4;

# Positional parameters in order. tcp::flow takes no collect arguments, so
# its optional cl_seq may be given in order too.
let flow = ipv4::tcp::flow(10.0.0.1/1234, 10.0.0.2/80, 1234);

# client_message takes collect arguments, so its optional send_ack must be
# named, and comes before them.
flow.client_message(
  send_ack: false,
  "GET / HTTP/1.1|0d 0a|"
  "Host: example.com|0d 0a|",
);
```

## 10. Statements

| Statement | Rule |
|-----------|------|
| `import m;` | §5 |
| `let x = e;` | `e` is typed in value position, and `x` is bound to it |
| `e;` | classified by the type of `e`, as below |

An expression statement `e;` is one of:

| Type of `e` | Statement | When it runs |
|-------------|-----------|--------------|
| `Pkt`, `PktGen` | emit | write the packets |
| `TimeJump` | wait | advance the clock |
| `void` | evaluate | evaluate `e` |
| anything else | discard | evaluate `e` and drop its value, with the warning **discarded value** |

An untyped integer in an expression statement is narrowed first (§8.1), so
`5;` discards a `u8`.

Because only expression statements emit packets, `let` can be used to make
packets now and send them later, in a different order:

```resynth
import ipv4;

let flow = ipv4::tcp::flow(10.0.0.1/32768, 10.0.0.2/80);
flow.open();

let greeting = flow.client_message("GET / HTTP/1.1|0d 0a 0d 0a|");
let reply = flow.server_message("HTTP/1.1 200 OK|0d 0a 0d 0a|");

# Emit in reverse order, as if the packets were reordered in transit
reply;
greeting;
```

## 11. Evaluation

### 11.1 State

A running program has:

- a **frame**, holding the value bound to each local;
- a **clock**, in nanoseconds since the Unix epoch, held in 64 bits. It
  starts at a time the program is given (for the `resynth` command, its
  `--start-time`);
- an output sequence of packets, each with a timestamp.

### 11.2 Statements

Statements run in order. A `let` runs when it is reached, evaluating its
value once.

- **let** `x = e`: evaluate `e`, and bind its value to `x`.
- **emit** `e`: evaluate `e`. For each packet in order, advance the clock by
  the packet's transmission time, then write the packet with the clock's
  time. The transmission time is one nanosecond per bit, at 1 Gb/s, of the
  packet plus 24 bytes of Ethernet framing overhead.
- **wait** `e`: evaluate `e`, and advance the clock by its `TimeJump`.
- **evaluate** and **discard** `e`: evaluate `e`.

The clock never wraps: advancing it past the largest 64-bit value leaves it
there.

A local holds a value, not an expression. So after `let p = flow.client_message("x");`,
the packets are made once, and `p; p;` writes them twice, with two
timestamps.

### 11.3 Expressions

Expressions are evaluated left to right, with no part skipped:

- A literal, path or constant evaluates to its value. A local evaluates to
  the value in its frame slot.
- `e.x` evaluates `e` to an object `o`. A method is then `x`, bound to `o`. A
  property is its class's constant, but `e` is still evaluated, for its
  effects.
- `e(a₁, …, aₙ)` evaluates `e`, then each argument in source order, then
  calls the function. Defaults have no effects.
- `e₁ / e₂` evaluates `e₁`, then `e₂`, and converts `e₂` to `u16`.

Objects are shared, not copied: after `let g = flow;`, `g` and `flow` are the
same object. Methods such as `client_message` change the object's state, for
example its TCP sequence numbers.

### 11.4 Conversions when a function is called

A typed value passed for a parameter is converted to the parameter's type:

| From | To | Conversion |
|------|----|------------|
| any integral type | an integer type | keep the low bits |
| any integral type | `bool` | non-zero is `true` |
| an integral type, `bytes`, `Pkt`, `Ip4` | `bytes` | as in the table in §6 |
| `Pkt` | `PktGen` | a sequence of that one packet |

### 11.5 Errors when running

A program stops at the first run-time error. Packets already written stay
written, though the `resynth` command deletes its output file on error unless
given `--keep`. A run-time error is one of:

- a standard library function failing, such as `io::file` being unable to
  read its file;
- a standard library function that isn't implemented;
- a packet failing to be written.

An error from a function is located at the called name. An error writing a
packet is located at the statement.

## 12. Diagnostics (informative)

The current implementation reports errors and warnings like this. Neither the
wording, nor the order, nor how many are reported is part of the language.

- **Lexing and parsing** stop at the first error.
- **Checking** reports at most one error per statement, and carries on with
  the next. A `let` or `import` that fails leaves its name _poisoned_: later
  statements that use it stop checking without reporting anything more.

| Phase | Message | Cause |
|-------|---------|-------|
| lex | `unexpected character 'c'` | §3.1 |
| lex | `unterminated string literal` | §3.4 |
| lex | `'c' is not allowed in a string literal, write it as \|..\|` | §3.4 |
| lex | `invalid hex digit 'c' in string literal` | §3.4 |
| lex | `odd number of hex digits in string literal` | §3.4 |
| lex | `unterminated hex sequence in string literal` | §3.4 |
| lex | `integer literal out of range` | above 2<sup>127</sup> − 1 |
| lex | `decimal integer literal with leading zero` | §3.3 |
| lex | `integer literal with invalid suffix` | §3.3 |
| lex | `invalid IPv4 literal` | §3.3 |
| parse | `expected …, found …`, listing every token that was valid | §4 |
| parse | `integer literal out of range` | a `sock4-lit` port above 65535 |
| semantic | `unknown name "x"` | §5 |
| semantic | `unknown name "x" in module m` | §5 |
| semantic | `C has no member "x"` | §7.4 |
| semantic | `unknown module "m"` | §5 |
| semantic | `module "m" not imported` | §5 |
| semantic | `"x" is not a module` | §5 |
| semantic | `"x" is not a value` | §5, §7.4 |
| semantic | `"x" is already bound, at line:col` | §5 |
| semantic | `value of type T has no members` | §7.4 |
| semantic | `left operand of / must be Ip4, found T`, or `right`, `u16` | §7.6 |
| semantic | `value of type T is not callable` | §7.5 |
| semantic | `f: too many arguments: n > k` | §9.2 |
| semantic | `f: not enough arguments: n < m` | §9.2 |
| semantic | `f: argument "p" not specified` | §9.2 |
| semantic | `f: unknown argument "p"` | §9.2 |
| semantic | `f: argument "p" given more than once` | §9.2 |
| semantic | `f: unexpected collect-arguments` | §9.2 |
| semantic | `f: unexpected named argument: "p"` | §9.2 |
| semantic | `f: argument "p" must be π, found T` | §8.3 |
| semantic | `f: collect argument must be c, found T` | §8.3 |
| semantic | `void value used as a value` | §7 |
| semantic | `integer literal is too large for any integral type` | §8.1 |
| warning | `multiple imports of "m"` | §5 |
| warning | `discarded value of type T` | §10 |
| warning | `integer n truncated to τ` | §8.2 |
| warning | `value of type σ may be truncated to τ` | §8.2 |
| runtime | the I/O error, such as a missing file | §11.5 |
| runtime | `unimplemented stdlib call` | §11.5 |
| runtime | a message from the standard library function | §11.5 |

In these messages an untyped integer's type is written `integer`.

## 13. Standard library conventions (informative)

These are conventions the standard library follows, not rules of the
language.

**Payloads are collect arguments.** A function that takes arbitrary payload
data usually has a collect type of `bytes`, and joins its collect arguments
into one byte string. So payload pieces can be passed as separate arguments,
without `text::concat()`:

```resynth
import ipv4;
import std;
import text;

let flow = ipv4::tcp::flow(10.0.0.1/32768, 10.0.0.2/80);

# These send the same payload
flow.client_message(std::be16(0x0001), std::be16(42), "data");
flow.client_message(text::concat(std::be16(0x0001), std::be16(42), "data"));
```

**Encoding functions fix width and byte order.** Since a typed integer
passed as bytes keeps the width of its type, and an untyped one gets the
narrowest width, protocol fields are written with `std::u8()`,
`std::be16()`, `std::be32()`, `std::le32()` and so on, never as bare
integers. Apart from `std::u8()`, these take a `u64`, so the checker doesn't
warn when a value is too wide for the field (§8.4).
