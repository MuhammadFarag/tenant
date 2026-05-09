# Show available recipes
default:
    @just --list

# Format Rust source in place
fmt:
    cargo fmt --all

# Verify formatting; non-zero exit + diff on dirty files
check-fmt:
    cargo fmt --all -- --check

# Run clippy with warnings as errors
clippy:
    cargo clippy --all-targets -- -D warnings

# Run tests
test:
    cargo test

# Pre-merge gate: everything that should pass before push
check: check-fmt clippy test
