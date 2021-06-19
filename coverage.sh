#!/bin/bash

set -e           # exit if any command has a non-zero exit code
set -u           # exit if any referenced variable has not been previously defined
unset CDPATH
IFS=$' \n\t'
: "${BASH_SOURCE?'BASH_SOURCE variable not defined, not running in bash'}"

# change into the directory this script resides in
cd "$(dirname "${BASH_SOURCE[0]}")"

TARGET_DIR="$(pwd)/target/coverage"

COV_CARGO_ENV='RUSTFLAGS=-Zinstrument-coverage RUSTDOCFLAGS=-Zinstrument-coverage'
COV_CARGO_ENV="$COV_CARGO_ENV CARGO_INCREMENTAL=0"

# https://rust-lang.github.io/rustup-components-history/
# rustup +nightly-2021-05-31 component add llvm-tools-preview
NIGHTLY_TOOLCHAIN=nightly-2021-05-31

IGNORED_FILE_NAMES='/\.cargo/registry/ /rustc/ /tests.rs$$ ^'"$TARGET_DIR/"

# cargo install rustfilt
LLVM_COV_FLAGS=$(sed 's: : --ignore-filename-regex=:g' <<< " $IGNORED_FILE_NAMES")
LLVM_COV_FLAGS="$LLVM_COV_FLAGS --Xdemangler=rustfilt"

RUST_SYS_ROOT=$(rustc "+$NIGHTLY_TOOLCHAIN" --print sysroot)
LLVM_PROFDATA=$(find "$RUST_SYS_ROOT" -type f -name llvm-profdata | head -1)
LLVM_COV=$(find "$RUST_SYS_ROOT" -type f -name llvm-cov | head -1)

mkdir -p "$TARGET_DIR"
rm -f "$TARGET_DIR"/test-*.failed "$TARGET_DIR"/*.profraw

env $COV_CARGO_ENV 'LLVM_PROFILE_FILE=/dev/null' \
    cargo "+$NIGHTLY_TOOLCHAIN" test --tests --workspace \
    --target-dir "$TARGET_DIR" --no-run --message-format=json | \
    jq -r 'select(.profile.test == true) | .filenames[]' \
    > "$TARGET_DIR/tests-paths.list"

TESTS_PATHS=$(sed 's:^:--object=:' "$TARGET_DIR/tests-paths.list" | tr '\n' ' ')

#grcov $(sed 's:^:--binary-path=:g' "$TARGET_DIR/tests-paths.list" | tr '\n' ' ') -s "$(pwd)" --parallel --llvm -t html --branch --ignore-not-existing -o "$TARGET_DIR/grcov" "$(pwd)"

env $COV_CARGO_ENV "LLVM_PROFILE_FILE=$TARGET_DIR/%m.profraw" \
    cargo "+$NIGHTLY_TOOLCHAIN" test --tests --workspace \
    --target-dir "$TARGET_DIR" \
    || touch "$TARGET_DIR/test-workspace.failed"

$LLVM_PROFDATA merge --sparse \
    "--output=$TARGET_DIR/coverage.profdata" "$TARGET_DIR"/*.profraw

$LLVM_COV export $LLVM_COV_FLAGS --format=lcov \
    "--instr-profile=$TARGET_DIR/coverage.profdata" \
    $TESTS_PATHS > "$TARGET_DIR/lcov.info"

$LLVM_COV show $LLVM_COV_FLAGS --format=html --show-line-counts-or-regions \
    --show-instantiations "--output-dir=$TARGET_DIR" \
    "--instr-profile=$TARGET_DIR/coverage.profdata" $TESTS_PATHS

patch "--directory=$TARGET_DIR" < 'coverage-style.css.patch'

test '!' -f "$TARGET_DIR/test-workspace.failed"
