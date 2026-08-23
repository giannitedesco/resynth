---
name: resynth
description: >
  How to write resynth programs: a packet synthesis language for building
  precise, readable network captures for DPI engine and protocol decoder testing.
---

# Writing Resynth Programs

You are a systems engineer writing `.rsyn` files to generate `.pcap` captures
for testing DPI engines and protocol decoders.
Resynth programs are compiled to pcap by the `resynth` binary, which is always
available in this environment.

## Primary Use Case: Test Cases for DPI Engines

The most common tasks are:
- **Protocol recognition** — cause a DPI engine to identify a specific
  application-layer protocol
- **Rule triggering** — generate the exact traffic that fires a DPI rule
  (e.g. a Suricata/Snort signature)
- **Protocol decoder event** — exercise a specific parser code path, e.g.
  "a TLS flow where the client presents a certificate", or "an SMB negotiation
  that selects dialect 3.1.1". Here you need enough of the protocol to reach
  the event, but no more.
- **Protocol decoder testing** — exercise a parser for correctness or fuzzing

In all cases the goal is the same: the **minimum traffic** needed to trigger
the desired behaviour.

### Workflow

1. **Understand the protocol**:
   - If a spec file is provided (e.g. `../docs/proto/foo/spec.md`), read it
     before writing any code.
   - Well-known protocols (HTTP, TLS, DNS, SMTP, FTP, SMB…) are likely in your
     training data — use that knowledge, but cross-check against the spec if
     one is available.
   - For obscure, proprietary, or vendor-specific protocols, **ask for the
     spec** if none has been provided. Do not guess at wire formats.

2. **Understand the match criteria**:
   - For *rule triggering*: read the rule. If no rule is provided, ask for
     it — the rule is the ground truth for what traffic must look like.
   - For *protocol recognition*: know which classifier or signature will be
     tested, and what it inspects (port, magic bytes, etc.).
   - For *decoder events*: know exactly which event or code path should fire
     (e.g. "client certificate in TLS handshake"), and confirm whether a
     specific test harness assertion will be checked against the output.
   - If the criteria is ambiguous, **ask before writing any packets**.

3. **Understand what the engine needs**:
   - For *protocol recognition*: identify magic bytes, version fields, or other
     characteristic patterns a classifier inspects.
   - For *rule triggering*: read the rule carefully. Note `state:` keywords
     (`established`, `new`), which direction the payload must appear in, and
     any `flowbits` or multi-packet state dependencies. For
     `state:established`, `flow.open()` is mandatory — engines discard data
     segments that arrive without a prior handshake.
   - For both: identify transport (TCP/UDP) and port(s).

2. **Run `resynth --output-stdlib-json`** to discover available stdlib symbols.
   If a dedicated module exists for the protocol you are writing (e.g. `tls`,
   `dns`, `netbios`), **use it**. Also check for **related** modules: many
   protocols are structurally derived from another (e.g. NBNS is DNS-over-UDP,
   LDAP shares ASN.1/BER framing with other directory protocols). Search the
   JSON for parent/sibling protocol names too — their helpers may handle framing
   you would otherwise have to write by hand. Fall back to `std::be*` /
   `std::le*` / `std::len_*` only when no relevant helpers exist.

3. **Write the minimal flow**:
   - Use the **minimum number of packets** needed — often just one. For UDP,
     one packet is almost always sufficient. For TCP, one data segment is
     typical. Only add more packets when prior context is genuinely required
     (e.g. a challenge/response, a `flowbits` dependency).
   - `flow.open()` generates a TCP 3-way handshake. It is **only** needed
     for IDS rule testing where the rule requires `state:established` — the
     engine discards data on flows without a prior handshake. For DPI/CBAR
     protocol recognition testing, `open()` is unnecessary and should be
     omitted to keep the test minimal.
   - Include only the fields the engine actually inspects. You are writing a
     *test case*, not a full protocol implementation.
   - Use the correct port(s) — engines often use port as a pre-filter.

4. **Encode fields explicitly** using `std::be16()`, `std::le32()`, etc. rather
   than raw hex blobs. This documents the intent and makes the test case
   maintainable when field values need to change.

5. **Validate the output**:

   Always compile and inspect the pcap before considering the task done.

   ```sh
   # Compile to pcap (written to foo.pcap by default alongside the source)
   resynth foo.rsyn

   # Compile to a specific output file
   resynth foo.rsyn -o /tmp/foo.pcap

   # Compile and print a human-readable packet summary to stdout
   resynth -v foo.rsyn
   ```

   A non-zero exit code means the program failed to compile or a runtime error
   occurred — fix the error before proceeding.

   **Deep validation with tshark**: for well-known protocols where you are
   writing a well-formed packet (not an intentionally malformed exploit
   payload), use `tshark -Vnr foo.pcap` to fully parse and display the decoded
   fields. This confirms the wire format is correct. Note that tshark uses port
   numbers to identify protocols, so this only works reliably on well-known
   ports.

   **Port substitution workflow**: if the task requires a non-standard port
   (e.g. a protocol-identification test where the classifier must recognise the
   protocol regardless of port), follow this sequence:
   1. Write the `.rsyn` file using the well-known port.
   2. Compile and validate with `tshark -Vnr` — confirm the protocol decodes
      correctly.
   3. Change the port to the required non-standard port and recompile.
   4. Do a final `resynth -v` sanity check on the non-standard-port pcap.

   **Revalidate after every edit**: any time you modify an `.rsyn` file —
   even to change a single field value or swap a literal for a helper
   function — recompile and re-run `tshark -Vnr`. A successful build only
   means the program is syntactically valid; it does not mean the wire format
   is still correct.

6. **Deliver the `.rsyn` file**:

   The `.rsyn` source file is the deliverable — not the pcap. Ask the user
   where to write it if not specified. Do not leave it in `/tmp`. Typical
   locations are the project's test data directory (e.g.
   `tests/data/proto-name/`) or `examples/`. Present the final file path and a
   one-line summary of what tshark decoded it as.

7. **Report stdlib gaps**:

   After delivering the `.rsyn` file, review it and identify any places where
   the code is fragile, repetitive, or opaque due to missing stdlib helpers.
   Deliver a short bulleted list of functions you would want to add, with:
   - The proposed fully-qualified name (e.g. `netbios::ns::name_entry`)
   - A one-line description of what it would do
   - Which line(s) in the delivered file it would replace, and why it is
     better (less fragile, self-documenting, reusable)

   This list is useful input for stdlib development. Be specific — "add more
   helpers" is not useful; "add `netbios::ns::name_entry(name, suffix, flags)`
   to replace the manual 15-byte space-padding in the NBSTAT name table" is.



```resynth
import ipv4;
import std;

let client = 10.0.0.1;
let server = 10.0.0.2;

let flow = ipv4::tcp::flow(client/54321, server/1494);  # ICA default port

flow.client_message(
  std::be16(0x7f7f),    # ICA magic
  std::u8(0x01),        # protocol version
  std::u8(0x00),        # reserved
  std::be16(0x0001),    # command: connect
  std::len_be16("ICA"), # payload with length prefix
);
```

## Step 2: Discover the Stdlib

**Before writing any code**, run:

```sh
resynth --output-stdlib-json
```

The JSON output has three flat namespaces:

- **`functions`** — keyed by fully-qualified path, e.g. `"ipv4::tcp::flow"`.
  The key tells you exactly what to `import`: `import ipv4;`.
- **`classes`** — keyed by class name (e.g. `"TcpFlow"`), with methods nested
  inside. Classes are returned by functions; you never import them directly.
- **`constants`** — keyed by fully-qualified path, e.g. `"tls::version::TLS_1_2"`.

> [!IMPORTANT]
> Only use functions, classes, methods, and constants that appear in the JSON
> output. Never invent symbol names.

## Grammar Quick Reference

The full grammar and type system are documented in
[docs/grammar.md](../../../docs/grammar.md). Key points:

### Statements

There are exactly three statement forms:

```resynth
import ipv4;                         # import a top-level module
let flow = ipv4::tcp::flow(...);     # bind result to a name (defers packet emit)
flow.open();                         # expression statement (emits packets immediately)
```

A `let` binding defers emission. An expression statement emits immediately.
Use `let` to control packet ordering:

```resynth
let req  = flow.client_message("GET / HTTP/1.1" "|0d 0a 0d 0a|");
let resp = flow.server_message("HTTP/1.1 200 OK" "|0d 0a 0d 0a|");
resp;   # emit response first
req;    # then request — useful for reorder testing
```

### Literals

| Form | Example | Type |
|------|---------|------|
| Boolean | `true`, `false` | `bool` |
| Decimal integer | `42` | `u64` |
| Hex integer | `0xdeadbeef` | `u64` |
| IPv4 address | `1.2.3.4` | `Ip4` |
| Socket address (literal) | `1.2.3.4:80` | `Sock4` |
| Socket address (operator) | `1.2.3.4/80` or `ip/port` | `Sock4` |
| String | `"hello"` | `bytes` |
| Inline hex bytes | `"|de ad be ef|"` | `bytes` (embedded in string) |

> [!WARNING]
> **No backslash escapes exist — by design. If you're an LLM writing resynth,
> assuming `\n`/`\r`/`\x00` work is a hallucination, not a reasonable
> inference — verify with `tshark -x`.**
> Resynth string literals do **not** process backslash escape sequences at
> all. This is intentional, not a missing feature: resynth is designed for
> binary payloads as much as text ones, and a C-style backslash-escape scheme
> is a text-oriented convention that gets ambiguous over arbitrary binary data
> (e.g. what a literal `\` byte means next to an escape). The `"|hex bytes|"`
> convention sidesteps that entirely — it's an explicit, unambiguous
> mode-switch that works the same way for text and binary content alike, so
> there's no separate "binary vs. text" escaping story to get wrong.
>
> Every language you were trained on treats backslash-escapes as a near-
> universal string-literal default, which is exactly why this is worth
> stating explicitly rather than trusting pattern-matching from other
> languages: resynth deliberately does not follow that convention.
>
> Practically, this means `\n`, `\r`, `\t`, `\x00`, etc. are **not** special —
> they are two literal ASCII characters each. `"\r\n"` compiles fine but
> produces the four bytes `5c 72 5c 6e` (`\`, `r`, `\`, `n`), **not** a
> carriage-return/linefeed. This is invisible from the source alone: the
> program compiles and looks correct, and the mistake only shows up as wrong
> bytes on the wire.
>
> The **only** special embedded-byte syntax is the `"|hex bytes|"` form shown
> above. For a real byte value, use one of:
> - `"|0d 0a|"` — write the bytes directly as inline hex
> - `text::crlflines(...)` / `text::CRLF` — for CRLF-joined line-oriented text
> - `std::u8(0x00)`, `std::be16(...)`, etc. — for a single encoded value
>
> Never write `\x00`, `\n`, `\r`, `\t` etc. expecting escape processing —
> always use one of the forms above instead. **After writing any payload that
> looks like it contains an escape sequence, validate with `tshark -x`** (not
> just `resynth -v`) to confirm the actual bytes on the wire, since a
> compile success proves nothing here.

Adjacent string literals are concatenated by the lexer — no operator needed:

```resynth
"hello " "world"    # same as "hello world"
```

> [!WARNING]
> **String pasting vs. commas in collect args.** Adjacent string literals
> (including `"|hex|"` forms) paste together silently — no comma needed. But a
> function call like `std::be16()` is **not** a string literal: it is a
> separate collect argument and **must** be separated by commas from its
> neighbours.
>
> ```resynth
> # WRONG — std::be16() silently becomes a new collect arg;
> #          the preceding string is a separate (shorter) arg
> flow.client_dgram(
>   "|21 12 a4 42|"   // magic
>   "SOpCii5Jfc1z"    // transaction id
>   std::be16(0x0001) // attr type  ← parse error or wrong payload
>   "|00 08|"         // attr len
> );
>
> # RIGHT — commas delimit collect args, strings paste within each arg
> flow.client_dgram(
>   "|21 12 a4 42|"    // magic
>   "SOpCii5Jfc1z",   // transaction id  ← comma: end of this arg
>   std::be16(0x0001), // attr type      ← comma: separate arg
>   "|00 08|"          // attr len (pastes with nothing, stands alone)
> );
> ```
>
> **Rule of thumb:** put a comma **before and after** every `std::` call (or
> any non-literal expression) in a collect-arg list. Omit commas only between
> adjacent string literals that you want pasted into a single argument.

### The `/` Operator

`/` is the **only binary operator**. It combines an `Ip4` with a port to
produce a `Sock4`. It works with variables, unlike the colon literal form:

```resynth
let server = 10.0.0.1;
let flow = ipv4::tcp::flow(10.0.0.2/5000, server/80);
```

### Object References

- `::` navigates the **module** hierarchy (determines the `import`)
- `.` navigates the **object** hierarchy (calls a method on a runtime value)

```resynth
ipv4::tcp::flow(...)       # module path → needs: import ipv4
flow.client_message(...)   # method on a runtime object
```

### Type System and Coercion

| Type | Coerces to bytes as |
|------|---------------------|
| `u8` | 1 byte |
| `u16` | 2 bytes, big-endian |
| `u32` | 4 bytes, big-endian |
| `u64` | 8 bytes, big-endian |
| `Ip4` | 4 bytes, big-endian (network order) |
| `bytes` | as-is |

> [!WARNING]
> All integer literals are `u64`. Passing a bare `42` where `bytes` is expected
> produces **8 big-endian bytes** (`|00 00 00 00 00 00 00 2a|`). Always use
> `std::u8()`, `std::be16()`, `std::be32()`, `std::le32()` etc. to specify
> both width and endianness explicitly.

### Calling Conventions

Functions have three parameter sections, separated by `=>` in their signature:

```
resynth fn example(src: Ip4, dst: Ip4, => ttl: U8 = 64, id: U16 = 0, => Str) -> Pkt
                   ─────────────────    ────────────────────────────    ───
                   positional (req'd)   optional+defaults               collect-type
```

The calling rules all exist to prevent ambiguity — the parser must always be
able to tell unambiguously which slot each argument fills.

**Positional args may be anonymous or named:**

```resynth
example(10.0.0.1, 10.0.0.2)               # anonymous — order determines slot
example(dst: 10.0.0.2, src: 10.0.0.1)     # named — order doesn't matter
example(10.0.0.1, dst: 10.0.0.2)          # mix: anonymous first, then named
```

**Don't use anonymous args after named args** — the parser can't tell which
slot the anonymous arg fills:

```resynth
# Don't do this:
example(src: 10.0.0.1, 10.0.0.2)
# Instead:
example(src: 10.0.0.1, dst: 10.0.0.2)
```

**Without collect args, optional args may be anonymous (in order) or named:**

```resynth
example(10.0.0.1, 10.0.0.2, 128)              # ttl=128 by position
example(10.0.0.1, 10.0.0.2, 128, 7)           # ttl=128, id=7 by position
example(10.0.0.1, 10.0.0.2, id: 7)            # skip ttl, set id by name
example(10.0.0.1, 10.0.0.2, id: 7, ttl: 128)  # both named, any order
```

**With collect args, don't pass optional args anonymously** — the parser can't
tell whether an anonymous value is an optional arg or the start of the collect
payload. Instead, name them:

```resynth
# Don't do this:
example(10.0.0.1, 10.0.0.2, 128, "payload")
# Instead:
example(10.0.0.1, 10.0.0.2, ttl: 128, "payload")
```

**With collect args, don't put named optional args after the collect payload**
— once the parser starts consuming collect args it can't go back. Instead, put
named optional args before the payload:

```resynth
# Don't do this:
example(10.0.0.1, 10.0.0.2, "payload", ttl: 128)
# Instead:
example(10.0.0.1, 10.0.0.2, ttl: 128, "payload")

# Real example — same rule:
netbios::ns::name_entry("BILLG", suffix: 0x03)   # Don't do this
netbios::ns::name_entry(suffix: 0x03, "BILLG")   # Instead, do this
```

If you get an "Unexpected named argument" error, this ordering is almost always
the cause.

---

## Core Stdlib Reference

These modules are present in every resynth installation and used in almost
every program.

### `ipv4` — IP flows and datagrams

```resynth
import ipv4;
```

#### TCP flow — `ipv4::tcp::flow`

```resynth
let flow = ipv4::tcp::flow(
  10.0.0.1/54321,   # client src
  10.0.0.2/80,      # server dst
);

flow.open();                              # 3-way handshake (SYN/SYN-ACK/ACK)
flow.client_message("GET / HTTP/1.1" "|0d 0a 0d 0a|");
flow.server_message("HTTP/1.1 200 OK" "|0d 0a 0d 0a|");
flow.close();                             # FIN/FIN-ACK/ACK
```

Key methods on `TcpFlow`:

| Method | Returns | Description |
|--------|---------|-------------|
| `open()` | `PktGen` | 3-way handshake |
| `client_message(...)` | `PktGen` | Data segment + ACK from server |
| `server_message(...)` | `PktGen` | Data segment + ACK from client |
| `client_segment(...)` | `Pkt` | Single segment, no ACK emitted |
| `server_segment(...)` | `Pkt` | Single segment, no ACK emitted |
| `close()` | `PktGen` | Client-initiated FIN/ACK teardown |

`client_message` and `server_message` accept optional named args before the
collect payload:

```resynth
flow.client_message(
  send_ack: false,   # suppress ACK (for reorder/fragmentation tests)
  seq: 100,          # override sequence number
  "payload data",
);
```

#### UDP unicast — `ipv4::udp::unicast`

```resynth
ipv4::udp::unicast(10.0.0.1/5000, 10.0.0.2/53, "query bytes");
```

#### UDP flow — `ipv4::udp::flow`

```resynth
let udp = ipv4::udp::flow(10.0.0.1/5000, 10.0.0.2/53);
udp.client_dgram("query");
udp.server_dgram("response");
```

#### IP fragmentation — `ipv4::frag`

```resynth
let pkt = ipv4::frag(10.0.0.1, 10.0.0.2, proto: ipv4::proto::UDP, "payload");
pkt.fragment(0, 8);       # first fragment, offset 0, 8-byte units
pkt.tail(1);              # final fragment at offset 1 (= 8 bytes in)
```

---

### `std` — Encoding utilities

```resynth
import std;
```

| Function | Description |
|----------|-------------|
| `std::u8(v)` | 1-byte encoding |
| `std::be16(v)` | 2 bytes, big-endian |
| `std::be32(v)` | 4 bytes, big-endian |
| `std::be64(v)` | 8 bytes, big-endian |
| `std::le16(v)` | 2 bytes, little-endian |
| `std::le32(v)` | 4 bytes, little-endian |
| `std::le64(v)` | 8 bytes, little-endian |
| `std::len_u8(...)` | 1-byte length prefix + payload |
| `std::len_be16(...)` | 2-byte BE length prefix + payload |
| `std::len_be32(...)` | 4-byte BE length prefix + payload |
| `std::len_le16(...)` | 2-byte LE length prefix + payload |
| `std::len_le32(...)` | 4-byte LE length prefix + payload |

The `len_*` functions take an optional `adjust:` parameter and `bytes`
collect args as payload:

```resynth
std::len_be32("hello")                  # |00 00 00 05| hello
std::len_be16(adjust: 4, "payload")     # length = len("payload") + 4
```

---

### `text` — String utilities

```resynth
import text;
```

| Symbol | Description |
|--------|-------------|
| `text::concat(...)` | Concatenate byte strings |
| `text::crlflines(...)` | Join lines with `\r\n` |
| `text::len(...)` | Return length of concatenated strings as `u64` |
| `text::CRLF` | The `\r\n` constant |

```resynth
flow.client_message(
  text::crlflines(
    "EHLO mail.example.com",
    "MAIL FROM:<user@example.com>",
    text::CRLF,   # trailing blank line
  ),
);
```

---

### `time` — Timestamp control

```resynth
import time;
```

Emit a `TimeJump` expression to advance the pcap clock between packets:

```resynth
flow.client_message("first packet");
time::jump_seconds(5);
flow.server_message("five seconds later");
```

| Function | Description |
|----------|-------------|
| `time::jump_seconds(n)` | Advance clock by N seconds |
| `time::jump_millis(n)` | Advance clock by N milliseconds |
| `time::jump_micros(n)` | Advance clock by N microseconds |
| `time::jump_nanos(n)` | Advance clock by N nanoseconds |

---

### `io` — File and buffer I/O

```resynth
import io;
```

| Function | Description |
|----------|-------------|
| `io::file(path)` | Load file contents as `bytes` |
| `io::bufio(...)` | Create a sequential read buffer from `bytes` |

`io::bufio` is useful for splitting a pre-built payload across multiple packets:

```resynth
let buf = io::bufio(io::file("./payload.bin"));
flow.client_message(buf.read(15));    # first 15 bytes
flow.client_message(buf.read_all()); # remainder
```

---

### `dns` — DNS helpers

```resynth
import dns;
```

`dns::host(client, name)` generates a complete DNS query + response exchange:

```resynth
dns::host(10.0.0.1, "www.example.com");
dns::host(10.0.0.1, "www.example.com", ttl: 300, ns: 8.8.8.8);
```

---

## Style Guide

### Line Length

Keep all lines to **100 columns or fewer**. Break long argument lists by
putting each argument on its own line, indented by 4 spaces:

```resynth
# Too long
flow.client_message(std::be16(0x0003), std::len_be16(adjust: 4, std::be16(0x0001), "payload data here"));

# Good
flow.client_message(
  std::be16(0x0003),
  std::len_be16(
    adjust: 4,
    std::be16(0x0001),
    "payload data here",
  ),
);
```

#### Breaking long strings

When a string literal exceeds 100 columns, use string pasting (adjacent string
literals concatenate automatically) to split it across lines. **Always break at
meaningful boundaries** — never at arbitrary character positions:

- **Text protocols**: break at field separators (spaces between tokens, commas
  between JSON keys, `::` between URN components)
- **URLs**: break at path or query boundaries (`/`, `?`, `&`)
- **Hex blobs**: break at 16-byte lines

```resynth
# Bad — breaks mid-token
  "{|22|request|22|:|22|active checks|22|,|22|host|22|:|22|Test-agent|22|,|22|host_metad"
  "ata|22|:|22|linux|22|}"

# Good — breaks at JSON comma boundaries
  "{|22|request|22|:|22|active checks|22|,"
  "|22|host|22|:|22|Test-agent|22|,"
  "|22|host_metadata|22|:|22|linux|22|}"

# Bad — breaks mid-UUID
  "Location:http://example.com/udhisapi.dll?content=uuid:11a6f064-4791-4477-a680-e0"
  "b3ce8c79c3",

# Good — breaks at query boundary
  "Location:http://example.com/udhisapi.dll"
  "?content=uuid:11a6f064-4791-4477-a680-e0b3ce8c79c3",
```

#### Large hex blobs

Format large hex blobs at **16 bytes per line**. This matches standard hexdump
conventions and keeps lines well within the limit:

```resynth
  "|b6 02 bd f4 e8 0e cf c6 1d 1b 48 49 59 e0 2b ef|",
  "|e9 4b 1f 2d c8 69 f4 7d 7a e0 00 27 9c 26 f9 c1|",
  "|40 9c c2 2c 9a 33 a3 25 8a a2 ce 55 e9 2c 57 2d|",
```

#### Breaking inline comments

When a line is too long because of a trailing comment, and that comment is
**column-aligned** with comments on surrounding lines, keep the comment inline
on the first line and continue it on the next line at the same column — don't
move it above the code:

```resynth
# Bad — breaks the column alignment pattern
  // ERR_CTIME, generalized time -- inner tag len exceeds outer tag len
  "|a2 11 18 12|",
  "|a3 05 02 03 0c 70 f7|", //          ERR_CUSEC, u32

# Good — comment stays inline, continuation at same column
  "|a2 11 18 12|",          //          ERR_CTIME, generalized time
                             //          inner tag len exceeds outer tag len
  "|a3 05 02 03 0c 70 f7|", //          ERR_CUSEC, u32
```

For standalone comments (not column-aligned), placing the comment on the line
above is fine:

```resynth
  // Frame size and length are the only things being checked
  // for response, so if they are valid it will pass
  std::be32(66),
```

### Basic Patterns

#### TCP (text protocol — HTTP, SMTP, FTP…)

For IDS rule testing where `state:established` is required, call `open()`
first. For DPI/CBAR protocol recognition testing, omit `open()` — it adds
unnecessary handshake packets. Use `text::crlflines` for line-oriented
protocols:

```resynth
import ipv4;
import text;

let client = 192.168.1.10;
let server = 93.184.216.34;

let flow = ipv4::tcp::flow(client/54321, server/80);

flow.client_message(
  text::crlflines(
    "GET /index.html HTTP/1.1",
    "Host: www.example.com",
    "Connection: close",
    text::CRLF,
  ),
);

flow.server_message(
  text::crlflines(
    "HTTP/1.1 200 OK",
    "Content-Type: text/html",
    "Content-Length: 13",
    text::CRLF,
  ),
  "<html></html>",
);

flow.close();
```

#### TCP (binary protocol)

Use `std::be*` / `std::le*` for structured fields. Short magic values and
padding are fine as inline hex; full protocol fields should use explicit
encoding functions:

```resynth
import ipv4;
import std;

let flow = ipv4::tcp::flow(10.0.0.1/32860, 10.0.0.2/3260);

flow.client_message(
  std::u8(0x03),           # opcode
  std::u8(0x80),           # flags
  "|00 00|",               # reserved
  std::be32(0x00000020),   # data segment length
  std::be64(0),            # LUN
  std::be32(0x00000001),   # initiator task tag
  std::be32(0x00000000),   # expected data transfer length
  std::be32(0x01),         # cmd_sn
  std::be32(0x00),         # exp_stat_sn
  "INQUIRY" "|00 00 00 00 00 00 00 00 00|",  # CDB (16 bytes)
);
```

#### UDP

```resynth
import ipv4;

ipv4::udp::unicast(10.0.0.1/5000, 10.0.0.2/53,
  "|00 01|"                # transaction ID
  "|01 00|",               # flags: standard query
  std::be16(1),            # questions: 1
  "|00 00 00 00 00 00|",   # answer/auth/additional: 0
  std::len_u8("example"), std::len_u8("com"), "|00|",  # QNAME: len-prefixed labels + terminator
  std::be16(1),            # QTYPE: A
  std::be16(1),            # QCLASS: IN
);
```

---

### Writing Readable Payloads

> [!IMPORTANT]
> Avoid building packets entirely from `"|de ad be ef|"` hex blobs. Such
> programs are brittle — they break whenever field values change — and are
> barely more readable than a binary pcap.

**Prefer explicit encoding functions:**

```resynth
# Bad — opaque, brittle
"|00 00 00 2a|"

# Good — self-documenting
std::be32(42)
std::be32(0x0000002a)   # hex literal where it aids clarity
```

**Use length-prefix functions instead of hard-coded lengths:**

```resynth
# Bad — breaks if "data" changes
"|00 00 00 04|data"

# Good — length computed automatically
std::len_be32("data")
```

**For headers with an embedded length field that includes the header itself,
use `adjust:`:**

```resynth
# Header: {be16 type; be16 len; be16 flags} where len includes the whole header
std::be16(type),
std::len_be16(
  adjust: 4,           # len covers the 2-byte len field + 2-byte flags field too
  std::be16(flags),
  "payload data",
),
```

A real-world example — TPKT + X.224 + T.125 (RDP):

```resynth
flow.client_message(
  std::u8(3),          // TPKT magic
  std::u8(0),          // reserved
  std::len_be16(
    adjust: 4,       // len includes the 4-byte TPKT header itself
    std::len_u8("|f0 80|"),        // X.224 DT PDU (len byte + header)
    std::u8(0x64),                 // T.125 DomainMCSPDU choice
    std::be16(6),                  // initiator
    std::be16(1003),               // channel id
    std::u8(0x70),                 // data priority / segmentation
    std::le32(0x0201),             // RDP security flags (LE)
    std::le32(72),                 // encrypted client random length (LE)
    io::file("./client_random.bin"),
  ),
);
```

**Hex blobs are acceptable only for genuinely opaque data** (encrypted
payloads, binary certificates, pre-computed digests) where no better
representation exists.
