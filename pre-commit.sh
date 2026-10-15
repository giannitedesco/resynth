#!/bin/sh

set -euo pipefail

exec 1>&2

cargo fmt --check
cargo clippy --workspace -- -D warnings                  # default features
cargo clippy --workspace --all-features -- -D warnings   # + repl
cargo test --workspace --all-features
cargo doc --workspace --all-features
cargo run --all-features -- --output-docs docs
git add docs
