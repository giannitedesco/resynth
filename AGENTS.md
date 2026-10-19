# Agent instructions for resynth

## What this project is

Resynth is a **packet synthesis language**: the `resynth` binary compiles
`.rsyn` source files to `.pcap` captures. It is a Rust workspace with three
crates:

- **`pkt/`**: low-level packet structs, protocol headers and constants. No
  high-level abstractions.
- **`ezpkt/`**: higher-level flow abstractions (TCP and UDP flows, IP
  fragmentation, etc.) built on `pkt`.
- **`src/`** (root crate): the language (lexer, parser, checker, interpreter),
  the CLI and REPL, and the standard library in `src/stdlib/`.

## Pipeline

1. **Lex** (`src/lex.rs`): a hand-written lexer, with no regex, that turns each
   line into tokens.
2. **Parse** (`src/parse.rs`): recursive descent, with Pratt parsing for
   expressions. Produces the AST (`src/ast.rs`).
3. **Check** (`src/check.rs`): resolves names, binds call arguments, checks
   types, and lowers the whole program to the HIR (`src/hir.rs`) before
   anything runs.
4. **Run** (`TreeInterp`, `src/interp.rs`): runs the HIR one statement at a
   time. Each packet, wait and discarded value is an `Effect` for the caller
   to handle. The CLI (`src/cli.rs`) writes packets with `pkt::PcapWriter`.

The crate docs in `src/lib.rs` describe each phase and its error type.

## Checking a change

```sh
scripts/check.sh
```

This runs `cargo fmt --check`, clippy with warnings as errors on all targets
(once with default features and once with `--all-features`), all workspace
tests with `--all-features`, and `cargo doc`. It also regenerates the stdlib
reference in `docs/`. A warm run takes a few seconds, so run all of it rather
than a filtered subset. The `--all-features` runs cover the `repl` feature
(`src/repl.rs`), which the default build leaves out.

`.githooks/pre-commit` is the git hook. It runs `scripts/check.sh` and then stages
`docs/` with `git add docs`. Don't run it just to check your work.

To iterate on one test, use `cargo test --all-features <name>`.

## Where the truth lives

- **The language**: `docs/grammar.md` is the formal description of the
  syntax, types, narrowing, call binding and evaluation. It describes what the
  code does, so if they disagree, fix the doc.
- **The stdlib API**: the generated `docs/<module>/` tree, or
  `resynth --output-stdlib-json` (a hidden flag, missing from `--help`) to
  search everything at once.
- **Writing `.rsyn` programs**: the `resynth` skill.
- **Adding to or changing the stdlib** (`func!`, `module!`, `class!`, argument
  types, naming, doc comments, validation with tshark): the `resynth-stdlib`
  skill.

## Conventions

- Doc comments on `func!`, `module!` and `class!` become the `docs/` API
  reference. After changing any of them, or adding or removing a stdlib
  symbol, run `scripts/check.sh` and commit the regenerated `docs/`.
- `src/stdlib/mod.rs` sets `#![allow(clippy::upper_case_acronyms)]`, because
  protocol constants like `TCP`, `UDP` and `DNS` are all-caps on purpose.
- Protocol header structs in `pkt/` are plain `bytemuck` POD types.
- Tests:
  - `src/test/`: lexer, parser, checker, interpreter and values.
  - `src/stdlib/test/`: the stdlib.
  - `pkt/` and `ezpkt/`: each crate tests its own code.
  - `tests/cli.rs`: runs the built binary.
- Commit subjects are `area: Imperative summary`, e.g. `hir: Eliminate dead
  stores` or `cli/repl: Add a reedline repl`.
