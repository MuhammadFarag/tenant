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

# Tag a release locally (no push). Bumps Cargo.toml from -dev to the exact
# VERSION, refreshes Cargo.lock, commits, tags. Run release-publish to push,
# or abort with `git reset --hard HEAD~1 && git tag -d vVERSION`.
release-prepare VERSION:
    @echo '{{VERSION}}' | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$' || (echo "VERSION must be X.Y.Z or X.Y.Z-PRERELEASE (no v prefix)" >&2; exit 1)
    @test -z "$(git status --porcelain | grep -v '^.. RELEASE_NOTES.md$')" || (echo "working tree dirty (only RELEASE_NOTES.md edits are allowed pre-prepare); commit or stash other changes first" >&2; exit 1)
    @test "$(git rev-parse --abbrev-ref HEAD)" = "main" || (echo "not on main" >&2; exit 1)
    @git fetch origin main --quiet
    @test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" || (echo "local main is not up-to-date with origin/main; pull first" >&2; exit 1)
    @! git rev-parse --verify "v{{VERSION}}" >/dev/null 2>&1 || (echo "tag v{{VERSION}} already exists locally" >&2; exit 1)
    @test -s RELEASE_NOTES.md || (echo "RELEASE_NOTES.md is empty; write notes before preparing a release" >&2; exit 1)
    @! grep -q '<!-- TEMPLATE:' RELEASE_NOTES.md || (echo "RELEASE_NOTES.md still contains the TEMPLATE sentinel; write real release notes first" >&2; exit 1)
    @grep -q '^version = ".*-dev"$' Cargo.toml || (echo "Cargo.toml version must end in -dev; run release-bump-dev after the last release" >&2; exit 1)
    cargo check --locked
    sed -i '' 's/^version = ".*"/version = "{{VERSION}}"/' Cargo.toml
    cargo build || (git checkout -- Cargo.toml Cargo.lock; exit 1)
    git add Cargo.toml Cargo.lock RELEASE_NOTES.md
    git commit -m "Release v{{VERSION}}"
    git tag -a "v{{VERSION}}" -m "Release v{{VERSION}}"
    @echo "Tagged v{{VERSION}} locally. Run \`just release-publish\` to push, or abort with \`git reset --hard HEAD~1 && git tag -d v{{VERSION}}\` (only safe BEFORE \`release-publish\`)."

# Push the prepared release (HEAD + the latest tag) to origin.
release-publish:
    @test -z "$(git status --porcelain)" || (echo "working tree dirty" >&2; exit 1)
    @test "$(git rev-parse --abbrev-ref HEAD)" = "main" || (echo "not on main" >&2; exit 1)
    git push --follow-tags origin main

# Bump main to NEXT_VERSION-dev after release-publish.
release-bump-dev NEXT_VERSION:
    @echo '{{NEXT_VERSION}}' | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || (echo "NEXT_VERSION must be X.Y.Z (no v prefix, no suffix)" >&2; exit 1)
    @test -z "$(git status --porcelain)" || (echo "working tree dirty" >&2; exit 1)
    @test "$(git rev-parse --abbrev-ref HEAD)" = "main" || (echo "not on main" >&2; exit 1)
    sed -i '' 's/^version = ".*"/version = "{{NEXT_VERSION}}-dev"/' Cargo.toml
    cargo build
    git add Cargo.toml Cargo.lock
    git commit -m "Bump to v{{NEXT_VERSION}}-dev"
    git push origin main
