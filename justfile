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

# Run the binary, forwarding args (e.g. `just run create dev --dry-run -v`)
run *ARGS:
    @cargo run --quiet -- {{ARGS}}

# Build a release binary (target/release/tenant)
build:
    cargo build --release
    @echo "Built: target/release/tenant"

# Install to ~/.cargo/bin/tenant (must be on PATH for `tenant` to resolve)
install:
    cargo install --path .

# Pre-merge gate: everything that should pass before push
check: check-fmt clippy test
