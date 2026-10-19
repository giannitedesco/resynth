#!/bin/sh
#
# Everything a change must pass: formatting, lints, tests and rustdoc. Also
# regenerates the stdlib reference in docs/, without staging it.

set -euo pipefail

cd "$(dirname "$0")/.."

cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings                  # default features
cargo clippy --workspace --all-targets --all-features -- -D warnings   # + repl
cargo test --workspace --all-features
cargo doc --workspace --all-features
cargo run --all-features -- --output-docs docs
