#!/bin/sh
# SPDX-License-Identifier: MPL-2.0

set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"
PATH="$HOME/.cargo/bin:$PATH"
export PATH

status=$(git status --porcelain --untracked-files=normal)
if [ -n "$status" ]; then
    echo "verification requires a clean working tree" >&2
    exit 1
fi

commit=$(git rev-parse HEAD)
echo "Lantern v0.1 verification"
echo "commit: $commit"

if ! command -v clang >/dev/null 2>&1; then
    echo "clang is missing; install it with pacman" >&2
    exit 1
fi

cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build -p lantern-cli --release --locked
cargo test --workspace --all-targets --all-features --locked

python_bin="$repository/simulator/.venv/bin/python"
if [ ! -x "$python_bin" ]; then
    echo "simulator/.venv is missing; follow simulator/README.md" >&2
    exit 1
fi

(
    cd simulator
    "$python_bin" -m ruff format --check lantern_sim tests
    "$python_bin" -m ruff check lantern_sim tests
    "$python_bin" -m pytest
)

echo "verification passed for commit $commit"
